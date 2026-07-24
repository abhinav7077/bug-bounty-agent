"""Phase 5: automated multi-stage vulnerability-assessment pipeline, wired as its own LangGraph.

Phase 4's counterpart (see agent/recon_pipeline.py's own docstring for the
full rationale, which applies here unchanged): docs/DEVELOPMENT_PLAN.md's
Phase 5 "Goal" line describes a FIXED sequence — "tech stack -> prioritized
vuln checklist -> targeted scanning -> human-confirmed findings" — not
something to re-derive via the generic LLM planner (agent/graph.py) each
time. Every stage still goes through the same propose -> gate -> execute
triad agent/graph.py and agent/recon_pipeline.py both use; a stage's risk
level is the same fixed classification agent/risk.py already gives its
tool(s).

Input is a PRIOR recon run's output (live_hosts/js_urls/all_findings from
agent/recon_pipeline.py's checkpoint), not a bare domain — this pipeline
assesses already-discovered surface, it doesn't discover surface itself.
run_vuln_pipeline() loads the latest recon checkpoint for `target` when
live_hosts isn't passed explicitly; if no recon checkpoint exists yet, it
returns an error state telling the caller to run "recon <target>" first
rather than silently operating on nothing.

The "gate" stage is architecturally different from every other stage in
both this file and agent/recon_pipeline.py: every other stage's HITL
approval is a single "proceed with this whole stage or not" decision (see
node_gate). This pipeline's entire Phase 5 purpose is a PER-FINDING human
decision (approve/reject/escalate, per docs/DEVELOPMENT_PLAN.md's own
wording) — that can't collapse into one yes/no, so the "gate" stage's own
propose/gate/execute triad only covers "does the human want to start the
per-finding review session now" (informational, low-friction), and the
actual per-finding decisions happen INSIDE node_execute via
agent/hitl.py's request_batch_approval, one prompt per (tool, risk) group
rather than one prompt per finding — same batching this project already
uses everywhere else to avoid approval-fatigue rubber-stamping.

The "xss_probe" stage is ALSO an exception to the single-approval-per-stage
rule, for a narrower reason than "gate": its baseline tools (run_kxss,
run_dalfox) are MEDIUM, but skills/waf_bypass_prober.py's probe_waf_bypass
(only invoked conditionally, when run_kxss confirms a reflection but
run_dalfox's own docstring-documented "zero findings isn't confirmed-clean"
case fires) is HIGH — an active bypass-payload retry, not passive
inspection. Folding that under the stage's own MEDIUM approval would smuggle
a HIGH action past the human the same way agent/recon_pipeline.py's own
"dirs" stage deliberately excludes run_kiterunner to avoid (see MEMORY.md's
"Immediate next steps" for that precedent) — so node_execute calls
request_approval directly, with its own explicit HIGH-risk action, for each
candidate before ever calling probe_waf_bypass.

The "auth_probe" stage stays a clean single-approval stage, just gated
differently: check_idor/check_jwt_weaknesses/map_auth_flow all need a real
test credential the human must explicitly supply (run_vuln_pipeline's
auth_token/auth_other_identity_token params, or main.py's
`"assess <target> token=... [other_token=...]"` command syntax) — with none
supplied, this stage is a same-risk-either-way no-op (LOW, nothing runs);
with one supplied, EVERYTHING in the stage is inherently a HIGH-risk active
auth-bypass attempt, so the whole stage proposes as HIGH and gates with one
explicit "yes," no nested approval needed.

OOB (out-of-band) monitoring here is deliberately scoped down from what
"attribute any hits to specific payloads" might imply: this pipeline runs
nuclei (which has its OWN built-in interactsh integration for oast-tagged
templates, wired independently of anything here) and read-only
introspection — it never crafts and injects a custom SSRF/blind-injection
payload embedding OUR OWN interactsh domain into a request the way a human
using the generic agent/graph.py path might (e.g. via run_ffuf/run_dalfox
with a hand-chosen parameter). So this pipeline's own interactsh session
can only attribute a callback to "happened sometime during this pipeline
run," not to a specific finding/payload — documented here rather than
overclaiming precision the underlying mechanism doesn't have, the same
scope-honesty precedent as skills/hacktivity_checker.py and the Shodan/
Censys query builder (see MEMORY.md's "Differentiation strategy" section).
"""
import asyncio
import json
import re

from langchain_core.messages import HumanMessage
from langchain_ollama import ChatOllama
from langgraph.graph import END, START, StateGraph

from agent.hitl import request_approval, request_batch_approval
from agent.memory import save_confirmed_findings_to_memory, save_findings_to_memory
from agent.session import load_latest, save_checkpoint
from agent.state import VulnPipelineState
from config.settings import settings
from skills.auth_mapper import check_idor, check_jwt_weaknesses, map_auth_flow
from skills.chain_analyzer import analyze_chains
from skills.eligibility_filter import check_eligibility
from skills.graphql_mapper import introspect_graphql
from skills.poc_builder import build_poc
from skills.tech_analyzer import analyze_tech, select_nuclei_tags
from skills.vuln_assessor import assess_findings
from skills.waf_bypass_prober import probe_waf_bypass
from tools.api import interactsh_poll, interactsh_start, interactsh_stop
from tools.scanner import run_nuclei
from tools.vuln_specific import run_dalfox, run_kxss

VULN_STAGES = [
    "tech_profile", "targeted_scan", "xss_probe", "auth_probe", "graphql_probe",
    "assess", "chain", "business_logic_hints", "gate", "finalize",
]

# Same rationale as agent/recon_pipeline.py's own bounds: every wrapper here
# is individually rate-limit-paced, so a wide fan-out compounds into minutes
# — every cap surfaces in that stage's own human_note when it truncates.
_MAX_HOSTS_TECH = 5
_MAX_HOSTS_NUCLEI = 10
_MAX_HOSTS_XSS = 5
_MAX_HOSTS_AUTH = 3  # tighter than the others -- check_idor/check_jwt_weaknesses are HIGH-risk real bypass attempts
_MAX_GRAPHQL_ENDPOINTS = 5
_MIN_GATE_CONFIDENCE = 4  # below this, a finding is auto-filtered without asking a human at all
_DEFAULT_XSS_BYPASS_PROBE_PAYLOAD = "<script>alert(1)</script>"

_llm = ChatOllama(
    base_url=settings.OLLAMA_BASE_URL, model=settings.OLLAMA_MODEL,
    temperature=settings.LLM_TEMPERATURE, num_ctx=settings.OLLAMA_NUM_CTX,
)

_VULN_PLANNER_PROMPT_TEMPLATE = """You are a vulnerability-assessment planner for a bug bounty hunt.
Given a target's fingerprinted tech stack across its live hosts, output a short prioritized \
checklist naming which vuln class / tool to run for each SPECIFIC signal actually present below \
(e.g. "WordPress detected -> run wpscan + nuclei tags=wordpress,wp-plugin", "React frontend -> \
check stored XSS + CORS misconfig", "PHP backend -> check SQLi + LFI", "cloud_provider=aws -> \
cloud_enum/s3scanner", "session_cookie auth -> check_idor/check_jwt_weaknesses candidates").
Ground every line in an ACTUAL field value from the profiles below — never invent tech that
isn't shown as present.

TARGET: {target}
TECH PROFILES (host -> fingerprint):
{profiles_json}

Return a short numbered checklist as plain text, not JSON. If no useful signal was fingerprinted
at all, say so plainly and recommend the broad default nuclei tag set instead.
"""

_BIZ_HINT_PROMPT_TEMPLATE = """You are a business-logic triage analyst for a bug bounty hunt.
Payload-based scanning (XSS/SQLi/nuclei) is commodity and already covered elsewhere in this
pipeline — your ONLY job is to flag which of these discovered URLs look like they belong to a
multi-step, stateful FLOW (checkout, invite, password reset, refund, coupon/redeem, account
takeover via password change, admin/role-gated action) that deserves a human manually walking
the full sequence and running map_business_logic/map_auth_flow on the captured steps. Do not
invent flows that aren't suggested by the URL paths given.

TARGET: {target}
DISCOVERED URLS (sample, deduplicated):
{urls_json}

Return a short numbered list of {{flow guess}}: {{why, which URLs suggest it}}. If nothing looks
flow-shaped, say so plainly rather than inventing one.
"""


def _tool_findings(result: dict) -> list[dict]:
    return result.get("parsed") or []


def _fresh_state(
    target: str, live_hosts: list[str], js_urls: list[str], seed_findings: list[dict],
    auth_token: str = "", auth_other_identity_token: str = "",
) -> VulnPipelineState:
    return {
        "target": target, "stage": "tech_profile", "stage_index": 0, "human_note": "",
        "live_hosts": live_hosts, "js_urls": js_urls, "tech_profiles": {}, "nuclei_tags": [],
        "vuln_checklist": None, "graphql_endpoints": [], "all_findings": list(seed_findings),
        "assessments": [], "chain_suggestions": None, "business_logic_hints": None,
        "gate_decisions": {}, "confirmed_pocs": [], "interactsh_domain": None,
        "interactsh_session_id": None, "oob_findings": [], "error": None,
        "auth_token": auth_token, "auth_other_identity_token": auth_other_identity_token,
    }


def load_recon_surface(target: str) -> dict | None:
    """Pull live_hosts/js_urls/all_findings out of a prior recon checkpoint for `target`.

    Returns None if no recon checkpoint exists, or if what's there doesn't
    look like a recon checkpoint at all (missing "live_hosts") — callers
    should treat that as "run recon first," not silently start this
    pipeline against an empty surface.
    """
    checkpoint = load_latest(target)
    if checkpoint is None or "live_hosts" not in checkpoint:
        return None
    return {
        "live_hosts": checkpoint.get("live_hosts") or [],
        "js_urls": checkpoint.get("js_urls") or [],
        "all_findings": checkpoint.get("all_findings") or [],
    }


# --- propose functions ---

def _propose_tech_profile(state: VulnPipelineState) -> tuple[str, str]:
    n = min(len(state["live_hosts"]), _MAX_HOSTS_TECH)
    return f"Fingerprint tech stack via analyze_tech on {n} live host(s), then plan a targeted vuln checklist", "MEDIUM"


def _propose_targeted_scan(state: VulnPipelineState) -> tuple[str, str]:
    n = min(len(state["live_hosts"]), _MAX_HOSTS_NUCLEI)
    tags = ",".join(state["nuclei_tags"]) or "cve,exposure,misconfig"
    return f"Targeted nuclei scan (tags={tags}) on {n} live host(s), informed by the tech profile", "MEDIUM"


def _propose_xss_probe(state: VulnPipelineState) -> tuple[str, str]:
    n = min(len(state["live_hosts"]), _MAX_HOSTS_XSS)
    return (
        (
            f"Reflected-XSS check (kxss + dalfox) on {n} live host(s) — any blocked-looking "
            "reflection gets its own separate HIGH-risk approval prompt to retry WAF-bypass variants"
        ),
        "MEDIUM",
    )


def _propose_auth_probe(state: VulnPipelineState) -> tuple[str, str]:
    if not state.get("auth_token"):
        return (
            (
                "No test credentials supplied — skipping check_idor/check_jwt_weaknesses/map_auth_flow "
                "(pass auth_token to run_vuln_pipeline, or \"assess <target> token=...\", to enable)"
            ),
            "LOW",
        )
    n = min(len(state["live_hosts"]), _MAX_HOSTS_AUTH)
    return (
        (
            f"Credentialed auth checks (check_idor + check_jwt_weaknesses if the token looks like a "
            f"JWT + map_auth_flow) on {n} live host(s), using the supplied test credential"
        ),
        "HIGH",
    )


def _propose_graphql_probe(state: VulnPipelineState) -> tuple[str, str]:
    endpoints = _discover_graphql_endpoints(state)
    if not endpoints:
        return "No /graphql endpoints discovered in recon data — skipping introspection", "LOW"
    return f"GraphQL introspection on {len(endpoints)} discovered endpoint(s)", "MEDIUM"


def _propose_assess(state: VulnPipelineState) -> tuple[str, str]:
    return f"LLM false-positive/confidence triage of {len(state['all_findings'])} accumulated findings", "LOW"


def _propose_chain(state: VulnPipelineState) -> tuple[str, str]:
    n = sum(1 for a in state["assessments"] if not a.get("likely_false_positive"))
    return f"Vulnerability chain analysis across {n} plausibly-real finding(s)", "LOW"


def _propose_business_logic_hints(state: VulnPipelineState) -> tuple[str, str]:
    return "LLM scan of discovered URLs for business-logic flows needing manual testing", "LOW"


def _propose_gate(state: VulnPipelineState) -> tuple[str, str]:
    n = sum(
        1 for a in state["assessments"]
        if not a.get("likely_false_positive") and a.get("confidence", 0) >= _MIN_GATE_CONFIDENCE
    )
    if n == 0:
        return "No finding cleared the confidence bar for human review — nothing to gate", "LOW"
    return f"Human review gate: approve/reject/escalate {n} candidate finding(s) individually", "MEDIUM"


def _propose_finalize(state: VulnPipelineState) -> tuple[str, str]:
    n = sum(1 for d in state["gate_decisions"].values() if d.get("decision") == "confirmed")
    return (
        (
            f"Eligibility filter + PoC build for {n} confirmed finding(s), OOB callback check, "
            "persist confirmed findings to memory"
        ),
        "LOW",
    )


_PROPOSE_FNS = {
    "tech_profile": _propose_tech_profile, "targeted_scan": _propose_targeted_scan,
    "xss_probe": _propose_xss_probe, "auth_probe": _propose_auth_probe,
    "graphql_probe": _propose_graphql_probe, "assess": _propose_assess, "chain": _propose_chain,
    "business_logic_hints": _propose_business_logic_hints, "gate": _propose_gate,
    "finalize": _propose_finalize,
}


# --- execute functions ---

def _build_vuln_checklist(target: str, profiles: dict[str, dict]) -> str:
    if not any(profiles.values()):
        return "No tech signals fingerprinted on any live host — run the broad default nuclei tag set."
    prompt = _VULN_PLANNER_PROMPT_TEMPLATE.format(target=target, profiles_json=json.dumps(profiles))
    response = _llm.invoke([HumanMessage(content=prompt)])
    return response.content.strip()


async def _execute_tech_profile(state: VulnPipelineState) -> dict:
    hosts = state["live_hosts"][:_MAX_HOSTS_TECH]
    truncated = len(state["live_hosts"]) > _MAX_HOSTS_TECH

    profiles: dict[str, dict] = {}
    findings: list[dict] = []
    for host in hosts:
        result = await analyze_tech.ainvoke({"url": host})
        stage_findings = _tool_findings(result)
        findings += stage_findings
        for f in stage_findings:
            if f.get("type") == "tech_profile":
                try:
                    profiles[host] = json.loads(f["detail"])
                except (ValueError, TypeError):
                    pass

    tags: set[str] = set()
    for profile in profiles.values():
        tags.update(select_nuclei_tags.invoke({
            "cms": profile.get("cms", ""), "framework": profile.get("framework", ""),
            "cloud_provider": profile.get("cloud_provider", ""), "language": profile.get("language", ""),
        }))

    # interactsh_start takes ~10-15s to register (see tools/api.py) — kicked off
    # here, once, so it's listening for the rest of the pipeline's active stages;
    # polled/stopped in the finalize stage.
    session_id = f"vuln_{state['target']}"
    interactsh_result = await interactsh_start.ainvoke({"session_id": session_id})
    interactsh_domain = None
    for f in _tool_findings(interactsh_result):
        if f.get("type") == "interactsh_session_started":
            interactsh_domain = f.get("target")

    return {
        "tech_profiles": profiles, "nuclei_tags": sorted(tags),
        "vuln_checklist": _build_vuln_checklist(state["target"], profiles),
        "all_findings": state["all_findings"] + findings,
        "interactsh_session_id": session_id, "interactsh_domain": interactsh_domain,
        "human_note": state.get("human_note", "") + (
            f" [tech-profiled first {_MAX_HOSTS_TECH} of {len(state['live_hosts'])} live hosts]" if truncated else ""
        ),
    }


async def _execute_targeted_scan(state: VulnPipelineState) -> dict:
    hosts = state["live_hosts"][:_MAX_HOSTS_NUCLEI]
    tags = ",".join(state["nuclei_tags"]) or "cve,exposure,misconfig"
    findings: list[dict] = []
    for host in hosts:
        result = await run_nuclei.ainvoke({"target": host, "tags": tags})
        findings += _tool_findings(result)
    return {"all_findings": state["all_findings"] + findings}


_KXSS_PARAM_RE = re.compile(r"param=(\S+)")


async def _execute_xss_probe(state: VulnPipelineState) -> dict:
    hosts = state["live_hosts"][:_MAX_HOSTS_XSS]
    findings: list[dict] = []

    kxss_result = await run_kxss.ainvoke({"urls": hosts})
    kxss_findings = _tool_findings(kxss_result)
    findings += kxss_findings
    reflected_by_host = {f["target"]: f for f in kxss_findings if f.get("type") == "reflected_param"}

    for host in hosts:
        dalfox_result = await run_dalfox.ainvoke({"url": host})
        dalfox_findings = _tool_findings(dalfox_result)
        findings += dalfox_findings

        # kxss confirmed a reflection at this exact URL but dalfox came back with
        # ZERO findings there -- per run_dalfox's own docstring this specifically
        # does NOT mean "confirmed clean," it can mean the payload got filtered.
        # This is the concrete "blocked/filtered payload response" signal Phase 5's
        # own checklist wording asks for -- react to it, don't just move on.
        reflected = reflected_by_host.get(host)
        if reflected and not dalfox_findings:
            param_match = _KXSS_PARAM_RE.search(reflected.get("detail", ""))
            param = param_match.group(1) if param_match else "q"
            probe_action = {
                "action": "probe_waf_bypass", "target": host, "risk_level": "HIGH",
                "reason": (
                    f"kxss confirmed param={param!r} reflects special characters at {host}, but "
                    "dalfox found zero exploitable findings there -- retrying WAF-bypass variants "
                    "of a generic XSS payload to check whether the original was simply filtered"
                ),
                "args": {},
            }
            approval = request_approval(probe_action)
            if approval.decision == "approve":
                probe_result = await probe_waf_bypass.ainvoke({
                    "url": host, "param": param, "blocked_payload": _DEFAULT_XSS_BYPASS_PROBE_PAYLOAD,
                })
                findings += _tool_findings(probe_result)

    return {"all_findings": state["all_findings"] + findings}


def _looks_like_jwt(token: str) -> bool:
    return token.count(".") == 2


async def _execute_auth_probe(state: VulnPipelineState) -> dict:
    token = state.get("auth_token", "")
    if not token:
        return {}

    hosts = state["live_hosts"][:_MAX_HOSTS_AUTH]
    findings: list[dict] = []

    for host in hosts:
        idor_result = await check_idor.ainvoke({
            "url": host, "token": token,
            "other_identity_token": state.get("auth_other_identity_token", ""),
        })
        findings += _tool_findings(idor_result)

    # One representative host is enough for JWT forgery/replay -- repeating it
    # per host would just multiply real forged-token requests against the
    # target for no extra signal (the token itself, not the host, is what's
    # being tested).
    if hosts and _looks_like_jwt(token):
        jwt_result = await check_jwt_weaknesses.ainvoke({"token": token, "target_url": hosts[0]})
        findings += _tool_findings(jwt_result)

    if hosts:
        steps = [
            {"method": "GET", "path": host, "notable_state": "authenticated request using the supplied test credential"}
            for host in hosts
        ]
        flow_result = map_auth_flow.invoke({
            "flow_name": f"{state['target']}-supplied-credential", "steps_json": json.dumps(steps),
        })
        try:
            for item in json.loads(flow_result):
                findings.append({
                    "type": "auth_flow_hint", "target": state["target"],
                    "detail": json.dumps(item), "severity": item.get("potential_severity", "info"),
                    "tool_source": "auth_mapper", "timestamp": "",
                })
        except (ValueError, TypeError):
            pass

    return {"all_findings": state["all_findings"] + findings}


_GRAPHQL_URL_RE = re.compile(r"graphql", re.IGNORECASE)


def _discover_graphql_endpoints(state: VulnPipelineState) -> list[str]:
    candidates = set(state["live_hosts"]) | {f.get("target", "") for f in state["all_findings"]}
    endpoints = sorted({url for url in candidates if url and _GRAPHQL_URL_RE.search(url)})
    return endpoints[:_MAX_GRAPHQL_ENDPOINTS]


async def _execute_graphql_probe(state: VulnPipelineState) -> dict:
    endpoints = _discover_graphql_endpoints(state)
    if not endpoints:
        return {"graphql_endpoints": []}

    findings: list[dict] = []
    for endpoint in endpoints:
        result = await introspect_graphql.ainvoke({"endpoint_url": endpoint})
        findings += _tool_findings(result)
    return {"graphql_endpoints": endpoints, "all_findings": state["all_findings"] + findings}


async def _execute_assess(state: VulnPipelineState) -> dict:
    result_json = assess_findings.invoke({"findings_json": json.dumps(state["all_findings"])})
    return {"assessments": json.loads(result_json)}


async def _execute_chain(state: VulnPipelineState) -> dict:
    plausible = [
        f for f, a in zip(state["all_findings"], state["assessments"])
        if not a.get("likely_false_positive")
    ]
    if not plausible:
        return {"chain_suggestions": "[]"}
    result = analyze_chains.invoke({"findings_json": json.dumps(plausible)})
    return {"chain_suggestions": result}


async def _execute_business_logic_hints(state: VulnPipelineState) -> dict:
    urls = sorted({f.get("target", "") for f in state["all_findings"] if f.get("target")})[:100]
    if not urls:
        return {"business_logic_hints": "No discovered URLs to analyze."}
    prompt = _BIZ_HINT_PROMPT_TEMPLATE.format(target=state["target"], urls_json=json.dumps(urls))
    response = _llm.invoke([HumanMessage(content=prompt)])
    return {"business_logic_hints": response.content.strip()}


def _gate_candidates(state: VulnPipelineState) -> list[int]:
    return [
        i for i, a in enumerate(state["assessments"])
        if not a.get("likely_false_positive") and a.get("confidence", 0) >= _MIN_GATE_CONFIDENCE
    ]


async def _execute_gate(state: VulnPipelineState) -> dict:
    candidates = _gate_candidates(state)
    gate_decisions: dict[int, dict] = {
        i: {"decision": "false_positive", "note": "auto-filtered: below confidence bar or LLM-flagged false positive"}
        for i in range(len(state["all_findings"])) if i not in candidates
    }
    if not candidates:
        return {"gate_decisions": gate_decisions}

    actions = [
        {
            "action": f"confirm_finding:{state['all_findings'][i]['type']}",
            "risk_level": "MEDIUM",
            "target": state["all_findings"][i].get("target", ""),
            "reason": state["assessments"][i].get("rationale", ""),
        }
        for i in candidates
    ]
    results = request_batch_approval(actions)

    _DECISION_MAP = {"approve": "confirmed", "modify": "escalate", "reject": "false_positive"}
    for i, result in zip(candidates, results):
        gate_decisions[i] = {"decision": _DECISION_MAP.get(result.decision, "false_positive"), "note": result.note}

    return {"gate_decisions": gate_decisions}


_VULN_TYPE_HINTS = (
    ("xss", "xss"), ("sqli", "sqli"), ("sql", "sqli"), ("ssrf", "ssrf"),
)


def _infer_vuln_type(finding_type: str) -> str:
    lowered = finding_type.lower()
    for needle, vuln_type in _VULN_TYPE_HINTS:
        if needle in lowered:
            return vuln_type
    return finding_type


async def _execute_finalize(state: VulnPipelineState) -> dict:
    confirmed_findings = [
        state["all_findings"][i] for i, d in state["gate_decisions"].items()
        if d.get("decision") == "confirmed"
    ]

    eligible_findings: list[dict] = []
    pocs: list[dict] = []
    for finding in confirmed_findings:
        # Best-effort category: check_eligibility only auto-rejects a KNOWN
        # low-value category (self_xss, missing_security_headers, ...) — a
        # raw finding.type like "nuclei_match" simply won't match any of
        # those and passes through as eligible, which is the safe default
        # (never silently drop a real hit for lack of a normalized category).
        eligibility = check_eligibility.invoke({"vuln_category": finding.get("type", "")})
        if not eligibility.get("eligible"):
            continue
        eligible_findings.append(finding)

        # build_poc needs parameter/payload this pipeline doesn't capture
        # per-finding (no per-parameter fuzzing artifact survives to here) —
        # best-effort fill from the finding's own detail text rather than
        # inventing one, documented limitation, not silently fabricated data.
        poc = build_poc.invoke({
            "vuln_type": _infer_vuln_type(finding.get("type", "")),
            "target_url": finding.get("target", ""),
            "parameter": "unknown",
            "payload": finding.get("detail", "")[:200],
        })
        pocs.append({"finding": finding, "poc": poc})

    save_findings_to_memory(state["target"], state["all_findings"])
    saved_count = save_confirmed_findings_to_memory(state["target"], eligible_findings)

    oob_findings: list[dict] = []
    if state.get("interactsh_session_id"):
        poll_result = await interactsh_poll.ainvoke({"session_id": state["interactsh_session_id"]})
        for f in _tool_findings(poll_result):
            oob_findings.append({
                **f,
                "detail": f.get("detail", "") + (
                    " [coarse attribution only — this session's domain was not embedded in a "
                    "specific crafted payload by this pipeline; treat as \"happened sometime "
                    "during this run\", not tied to one finding]"
                ),
            })
        await interactsh_stop.ainvoke({"session_id": state["interactsh_session_id"]})

    return {
        "confirmed_pocs": pocs,
        "oob_findings": oob_findings,
        "all_findings": state["all_findings"] + oob_findings,
        "human_note": state.get("human_note", "") + f" [{saved_count} confirmed finding(s) saved to memory]",
    }


_EXECUTE_FNS = {
    "tech_profile": _execute_tech_profile, "targeted_scan": _execute_targeted_scan,
    "xss_probe": _execute_xss_probe, "auth_probe": _execute_auth_probe,
    "graphql_probe": _execute_graphql_probe, "assess": _execute_assess, "chain": _execute_chain,
    "business_logic_hints": _execute_business_logic_hints, "gate": _execute_gate,
    "finalize": _execute_finalize,
}


# --- graph nodes (same generic dispatch shape as agent/recon_pipeline.py) ---

def node_propose(state: VulnPipelineState) -> VulnPipelineState:
    stage_name = VULN_STAGES[state["stage_index"]]
    summary, risk = _PROPOSE_FNS[stage_name](state)
    pending_plan = {
        "action": f"vuln_pipeline:{stage_name}", "target": state["target"],
        "risk_level": risk, "reason": summary, "args": {},
    }
    return {**state, "pending_plan": pending_plan, "stage": stage_name, "error": None}


def node_gate(state: VulnPipelineState) -> VulnPipelineState:
    result = request_approval(state["pending_plan"])
    return {**state, "decision": result.decision, "human_note": result.note}


def node_execute(state: VulnPipelineState) -> VulnPipelineState:
    stage_name = state["stage"]
    try:
        delta = asyncio.run(_EXECUTE_FNS[stage_name](state))
    except Exception as exc:  # a tool wrapper raising should stop the pipeline, not crash the process
        return {**state, "stage": "error", "error": f"stage {stage_name!r} failed: {exc}"}

    new_state = {**state, **delta, "stage_index": state["stage_index"] + 1}
    save_checkpoint(f"{state['target']}__vuln", new_state)
    return new_state


def node_done(state: VulnPipelineState) -> VulnPipelineState:
    """See agent/recon_pipeline.py's node_done for why stage_index, not this
    node's own "done"/"rejected" string, is the authoritative progress marker
    resume_vuln_pipeline checks — the exact same reject-vs-finish bug this
    codebase already found and fixed once in the recon pipeline would
    reappear here if this node were copy-pasted without the fix."""
    finished = state["stage_index"] >= len(VULN_STAGES)
    return {**state, "stage": "done" if finished else "rejected"}


def node_error(state: VulnPipelineState) -> VulnPipelineState:
    return {**state, "stage": "error"}


def _route_after_gate(state: VulnPipelineState) -> str:
    return "execute" if state.get("decision") == "approve" else "done"


def _route_after_execute(state: VulnPipelineState) -> str:
    if state["stage"] == "error":
        return "error"
    if state["stage_index"] >= len(VULN_STAGES):
        return "done"
    return "propose"


def build_vuln_graph():
    graph = StateGraph(VulnPipelineState)
    graph.add_node("propose", node_propose)
    graph.add_node("gate", node_gate)
    graph.add_node("execute", node_execute)
    graph.add_node("done", node_done)
    graph.add_node("error", node_error)

    graph.add_edge(START, "propose")
    graph.add_edge("propose", "gate")
    graph.add_conditional_edges("gate", _route_after_gate, {"execute": "execute", "done": "done"})
    graph.add_conditional_edges("execute", _route_after_execute, {"propose": "propose", "done": "done", "error": "error"})
    graph.add_edge("done", END)
    graph.add_edge("error", END)

    return graph.compile()


def run_vuln_pipeline(
    target: str, live_hosts: list[str] | None = None, resume_state: VulnPipelineState | None = None,
    auth_token: str = "", auth_other_identity_token: str = "",
) -> VulnPipelineState:
    """Run (or continue) the fixed-stage vuln-assessment pipeline for one target.

    live_hosts=None (the normal case) loads the latest recon checkpoint via
    load_recon_surface() — pass it explicitly only to assess a hand-picked
    host subset without touching that checkpoint. recursion_limit matches
    agent/recon_pipeline.py's own reasoning: now 10 stages * 3 nodes = 30
    transitions minimum, above LangGraph's default 25 (raised the same way
    that pipeline already does, not a new pattern).

    auth_token/auth_other_identity_token gate the "auth_probe" stage's
    credentialed checks (check_idor/check_jwt_weaknesses/map_auth_flow) —
    see that stage's own comments. Ignored when resume_state is given: a
    resumed run keeps whatever credentials its checkpoint already carries,
    the same way every other field survives a resume.
    """
    graph = build_vuln_graph()
    if resume_state is not None:
        initial = resume_state
    else:
        surface = load_recon_surface(target) if live_hosts is None else {
            "live_hosts": live_hosts, "js_urls": [], "all_findings": [],
        }
        if surface is None:
            return {
                "target": target, "stage": "error", "stage_index": 0,
                "error": f"no recon checkpoint found for {target!r} — run \"recon {target}\" first",
            }
        initial = _fresh_state(
            target, surface["live_hosts"], surface["js_urls"], surface["all_findings"],
            auth_token=auth_token, auth_other_identity_token=auth_other_identity_token,
        )
    return graph.invoke(initial, config={"recursion_limit": 100})


def resume_vuln_pipeline(target: str) -> VulnPipelineState | None:
    """Load the latest vuln-pipeline checkpoint for target and continue an incomplete run.

    Checkpoints are stored under a target key distinct from the recon
    pipeline's own ("<target>__vuln") — see node_execute — so resuming one
    pipeline never collides with or shadows the other's checkpoint history.
    Returns None if there's no checkpoint, or the last one already ran to
    completion (stage_index is authoritative — see node_done).
    """
    checkpoint = load_latest(f"{target}__vuln")
    if checkpoint is None:
        return None
    if checkpoint.get("stage_index", 0) >= len(VULN_STAGES):
        return None
    return run_vuln_pipeline(target, resume_state=checkpoint)
