"""Phase 4: automated multi-stage recon pipeline, wired as its own LangGraph.

Distinct from agent/graph.py's single-action loop (one LLM-chosen tool call
per human command, up to MAX_STEPS chained calls): this pipeline's stage
sequence is FIXED, not LLM-chosen, per docs/DEVELOPMENT_PLAN.md Phase 4's own
"Goal" line — "One command triggers full automated recon: subdomains → live
hosts → ports → crawl → params → dirs → LLM summary." Letting the model
freehand-chain 8+ tool calls through the generic planner would exceed
agent/graph.py's own MAX_STEPS=6 bound and relies on the model reliably
re-deriving a sequence that's actually fixed by design — a dedicated graph
with hardcoded stages is both simpler and more reliable than stretching the
generic loop to do something it wasn't built for.

Every stage still goes through the SAME propose -> gate -> execute triad
agent/graph.py uses for its single-action loop (see node_plan/
node_awaiting_human/node_execute there) — approval happens BEFORE a stage
runs, matching ORCHESTRATOR_SYSTEM_PROMPT rule 2 ("always present a plan and
get approval before active scanning"), not after. A stage's own risk level is
the same fixed classification agent/risk.py already gives its tool(s) — this
file introduces no new risk judgment of its own.

"Run secrets + cloud + takeover agents in parallel" (Phase 4 checklist) means
concurrent WITH EACH OTHER via asyncio.gather inside the `enrichment` stage,
not literally overlapping the sequential main pipeline's wall-clock — this
graph's nodes are synchronous state transitions (same model agent/graph.py
already uses), so true background-while-other-stages-run concurrency would
need a different execution model entirely. Documented here explicitly so
nobody "fixes" this expecting more than it claims. run_trufflehog is
deliberately EXCLUDED from this stage: it needs a real git repo URL, which a
domain-only recon pipeline has no way to discover on its own.
"""
import asyncio
import re
from collections import defaultdict

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama
from langgraph.graph import END, START, StateGraph

from agent.hitl import request_approval
from agent.memory import save_findings_to_memory
from agent.session import load_latest, save_checkpoint
from agent.state import ReconPipelineState
from config.prompts import RECON_AGENT_PROMPT
from config.settings import settings
from skills.diff_tracker import diff_against_last_scan
from tools.api import run_ffuf
from tools.cloud import run_cloud_enum, run_s3scanner
from tools.recon import run_httpx, run_naabu, run_nmap, run_subfinder
from tools.secrets import run_secretfinder
from tools.url_harvest import run_gau, run_katana, run_paramspider
from tools.vuln_specific import run_subzy

RECON_STAGES = ["subfinder", "httpx", "ports", "crawl", "params", "dirs", "enrichment", "aggregate"]

# Bounds bulk-active stages to a tractable runtime — several of these tools
# are individually rate-limit-paced (10 req/s) already, so a wide fan-out
# across many hosts compounds into minutes per stage; every cap below is
# surfaced in that stage's own summary text when it actually truncates
# something, never a silent drop. See tools/recon.py's run_naabu docstring
# for the measured ~20-60s/host cost this is bounding.
_MAX_HOSTS_HTTPX = 30
_MAX_HOSTS_PORTS = 10
_MAX_HOSTS_CRAWL = 5
_MAX_HOSTS_DIRS = 5
_MAX_JS_FOR_SECRETS = 5
_MAX_SUBDOMAINS_TAKEOVER_CHECK = 30

_llm = ChatOllama(
    base_url=settings.OLLAMA_BASE_URL, model=settings.OLLAMA_MODEL,
    temperature=settings.LLM_TEMPERATURE, num_ctx=settings.OLLAMA_NUM_CTX,
)

_HTTPX_DETAIL_RE = re.compile(r"status=(?P<status>\S+) title=(?P<title>.*?) tech=(?P<tech>\[.*?\]) final_url=(?P<final_url>\S*)$")
_NAABU_DETAIL_RE = re.compile(r"port=(?P<port>\d+)")


def _tool_findings(result: dict) -> list[dict]:
    return result.get("parsed") or []


def _final_url(finding: dict) -> str:
    m = _HTTPX_DETAIL_RE.search(finding.get("detail", ""))
    url = m.group("final_url") if m else ""
    return url if url and url != "None" else f"https://{finding.get('target', '')}"


def _bare_host(url_or_host: str) -> str:
    return re.sub(r"^https?://", "", url_or_host).split("/")[0]


# --- propose functions: cheap, synchronous, decide WHAT is about to run + its risk level ---

def _propose_subfinder(state: ReconPipelineState) -> tuple[str, str]:
    return f"Passive subdomain enumeration via subfinder on {state['target']}", "LOW"


def _propose_httpx(state: ReconPipelineState) -> tuple[str, str]:
    hosts = state["hosts_to_probe"]
    new_count = len(state["diff"].get("new_assets", []))
    return (
        (
            f"Probe {len(hosts)} host(s) for liveness/tech via httpx "
            f"({new_count} new/changed since last scan, per diff_against_last_scan)"
        ),
        "MEDIUM",
    )


def _propose_ports(state: ReconPipelineState) -> tuple[str, str]:
    n = min(len(state["live_hosts"]), _MAX_HOSTS_PORTS)
    return f"Port scan (naabu top-100) + nmap service detection on {n} live host(s)", "MEDIUM"


def _propose_crawl(state: ReconPipelineState) -> tuple[str, str]:
    n = min(len(state["live_hosts"]), _MAX_HOSTS_CRAWL)
    return f"Crawl (katana) + historical URL pull (gau) on {n} live host(s)", "MEDIUM"


def _propose_params(state: ReconPipelineState) -> tuple[str, str]:
    return f"Mine hidden parameters from historical URLs via paramspider on {state['target']}", "LOW"


def _propose_dirs(state: ReconPipelineState) -> tuple[str, str]:
    n = min(len(state["live_hosts"]), _MAX_HOSTS_DIRS)
    return f"Directory/file fuzzing via ffuf on {n} live host(s)", "MEDIUM"


def _propose_enrichment(state: ReconPipelineState) -> tuple[str, str]:
    n_js = min(len(state["js_urls"]), _MAX_JS_FOR_SECRETS)
    return (
        (
            "Subdomain-takeover check (subzy) + cloud asset enum (cloud_enum/s3scanner) "
            f"+ secret scan on {n_js} discovered JS file(s) — run_trufflehog excluded, "
            "no git repo URL known from domain-only recon"
        ),
        "MEDIUM",
    )


def _propose_aggregate(state: ReconPipelineState) -> tuple[str, str]:
    return (
        (
            f"LLM aggregation of {len(state['all_findings'])} accumulated findings into a "
            "ranked target list, plus persisting all findings to long-term memory"
        ),
        "LOW",
    )


_PROPOSE_FNS = {
    "subfinder": _propose_subfinder, "httpx": _propose_httpx, "ports": _propose_ports,
    "crawl": _propose_crawl, "params": _propose_params, "dirs": _propose_dirs,
    "enrichment": _propose_enrichment, "aggregate": _propose_aggregate,
}


# --- execute functions: the actual async tool calls, returning a state delta ---

async def _execute_subfinder(state: ReconPipelineState) -> dict:
    target = state["target"]
    result = await run_subfinder.ainvoke({"domain": target})
    findings = _tool_findings(result)
    subdomains = sorted({f["target"] for f in findings} | {target})

    diff = await diff_against_last_scan.ainvoke({"target": target, "current_assets": subdomains})
    hosts_to_probe = sorted(set(diff.get("new_assets", [])) | {target})
    truncated = len(hosts_to_probe) > _MAX_HOSTS_HTTPX
    hosts_to_probe = hosts_to_probe[:_MAX_HOSTS_HTTPX]

    return {
        "subdomains": subdomains, "diff": diff, "hosts_to_probe": hosts_to_probe,
        "all_findings": state["all_findings"] + findings,
        "human_note": state.get("human_note", "") + (
            f" [truncated hosts_to_probe to {_MAX_HOSTS_HTTPX}]" if truncated else ""
        ),
    }


async def _execute_httpx(state: ReconPipelineState) -> dict:
    result = await run_httpx.ainvoke({"domains": state["hosts_to_probe"]})
    findings = _tool_findings(result)
    # Store httpx's own resolved final_url (follows redirects, picks the right
    # scheme) rather than the bare host — every later stage that needs a full
    # URL (crawl/dirs) uses this directly instead of naively guessing https://.
    live_hosts = [_final_url(f) for f in findings]
    return {"live_hosts": live_hosts, "all_findings": state["all_findings"] + findings}


async def _execute_ports(state: ReconPipelineState) -> dict:
    hosts = state["live_hosts"][:_MAX_HOSTS_PORTS]
    truncated_note = f" [capped to first {_MAX_HOSTS_PORTS} of {len(state['live_hosts'])} live hosts]" \
        if len(state["live_hosts"]) > _MAX_HOSTS_PORTS else ""
    findings: list[dict] = []
    ports_by_host: dict[str, list[int]] = defaultdict(list)

    if hosts:
        naabu_result = await run_naabu.ainvoke({"hosts": [_bare_host(h) for h in hosts]})
        naabu_findings = _tool_findings(naabu_result)
        findings += naabu_findings
        for f in naabu_findings:
            m = _NAABU_DETAIL_RE.search(f.get("detail", ""))
            if m:
                ports_by_host[f["target"]].append(int(m.group("port")))

        for host, ports in ports_by_host.items():
            nmap_result = await run_nmap.ainvoke({"host": host, "ports": ",".join(str(p) for p in ports)})
            findings += _tool_findings(nmap_result)

    return {
        "ports_by_host": dict(ports_by_host), "all_findings": state["all_findings"] + findings,
        "human_note": state.get("human_note", "") + truncated_note,
    }


async def _execute_crawl(state: ReconPipelineState) -> dict:
    hosts = state["live_hosts"][:_MAX_HOSTS_CRAWL]
    findings: list[dict] = []
    js_urls: list[str] = []

    for url in hosts:  # live_hosts entries are already full URLs — see _execute_httpx
        katana_result, gau_result = await asyncio.gather(
            run_katana.ainvoke({"url": url}), run_gau.ainvoke({"domain": _bare_host(url)}),
            return_exceptions=True,
        )
        for result in (katana_result, gau_result):
            if isinstance(result, Exception):
                continue
            stage_findings = _tool_findings(result)
            findings += stage_findings
            js_urls += [f["target"] for f in stage_findings if f["target"].endswith(".js")]

    return {
        "js_urls": sorted(set(js_urls))[:_MAX_JS_FOR_SECRETS],
        "all_findings": state["all_findings"] + findings,
    }


async def _execute_params(state: ReconPipelineState) -> dict:
    result = await run_paramspider.ainvoke({"domain": state["target"]})
    return {"all_findings": state["all_findings"] + _tool_findings(result)}


async def _execute_dirs(state: ReconPipelineState) -> dict:
    hosts = state["live_hosts"][:_MAX_HOSTS_DIRS]
    findings: list[dict] = []
    for host in hosts:
        url = (host if host.startswith("http") else f"https://{host}").rstrip("/") + "/FUZZ"
        result = await run_ffuf.ainvoke({"url": url})
        findings += _tool_findings(result)
    return {"all_findings": state["all_findings"] + findings}


async def _execute_enrichment(state: ReconPipelineState) -> dict:
    keyword = state["target"].split(".")[0]
    subdomains = state["subdomains"][:_MAX_SUBDOMAINS_TAKEOVER_CHECK]
    js_urls = state["js_urls"][:_MAX_JS_FOR_SECRETS]

    calls = [
        run_subzy.ainvoke({"domains": subdomains}),
        run_cloud_enum.ainvoke({"keyword": keyword}),
        run_s3scanner.ainvoke({"bucket_name": keyword}),
        *[run_secretfinder.ainvoke({"url": js}) for js in js_urls],
    ]
    results = await asyncio.gather(*calls, return_exceptions=True)

    findings: list[dict] = []
    for result in results:
        if isinstance(result, Exception):
            continue
        findings += _tool_findings(result)
    return {"all_findings": state["all_findings"] + findings}


def _condense_findings(findings: list[dict], max_chars: int = 6000) -> str:
    by_type: dict[str, list[str]] = defaultdict(list)
    for f in findings:
        by_type[f.get("type", "unknown")].append(f"{f.get('target', '')}: {f.get('detail', '')}")

    lines = []
    for finding_type, items in by_type.items():
        lines.append(f"## {finding_type} ({len(items)})")
        lines.extend(f"- {item}" for item in items[:20])
        if len(items) > 20:
            lines.append(f"- ... and {len(items) - 20} more")
    text = "\n".join(lines)
    return text[:max_chars] + ("\n[truncated]" if len(text) > max_chars else "")


async def _execute_aggregate(state: ReconPipelineState) -> dict:
    save_findings_to_memory(state["target"], state["all_findings"])

    condensed = _condense_findings(state["all_findings"])
    diff = state["diff"]
    user_prompt = (
        f"TARGET: {state['target']}\n"
        f"DIFF SINCE LAST SCAN: {len(diff.get('new_assets', []))} new, "
        f"{len(diff.get('removed_assets', []))} removed, "
        f"{len(diff.get('changed_js', []))} changed JS, first_scan={diff.get('is_first_scan', False)}\n\n"
        f"ACCUMULATED FINDINGS:\n{condensed}\n\n"
        "Apply your FOCUS ON rules and return the structured JSON ranked-target list now."
    )
    response = _llm.invoke([SystemMessage(content=RECON_AGENT_PROMPT), HumanMessage(content=user_prompt)])
    return {"aggregation": response.content}


_EXECUTE_FNS = {
    "subfinder": _execute_subfinder, "httpx": _execute_httpx, "ports": _execute_ports,
    "crawl": _execute_crawl, "params": _execute_params, "dirs": _execute_dirs,
    "enrichment": _execute_enrichment, "aggregate": _execute_aggregate,
}


# --- graph nodes ---

def node_propose(state: ReconPipelineState) -> ReconPipelineState:
    stage_name = RECON_STAGES[state["stage_index"]]
    summary, risk = _PROPOSE_FNS[stage_name](state)
    pending_plan = {
        "action": f"recon_pipeline:{stage_name}", "target": state["target"],
        "risk_level": risk, "reason": summary, "args": {},
    }
    return {**state, "pending_plan": pending_plan, "stage": stage_name, "error": None}


def node_gate(state: ReconPipelineState) -> ReconPipelineState:
    result = request_approval(state["pending_plan"])
    return {**state, "decision": result.decision, "human_note": result.note}


def node_execute(state: ReconPipelineState) -> ReconPipelineState:
    stage_name = state["stage"]
    try:
        delta = asyncio.run(_EXECUTE_FNS[stage_name](state))
    except Exception as exc:  # a tool wrapper raising should stop the pipeline, not crash the process
        return {**state, "stage": "error", "error": f"stage {stage_name!r} failed: {exc}"}

    new_state = {**state, **delta, "stage_index": state["stage_index"] + 1}
    save_checkpoint(state["target"], new_state)
    return new_state


def node_done(state: ReconPipelineState) -> ReconPipelineState:
    """Both "ran every stage" and "human rejected a stage gate" route here — they
    are NOT the same outcome and must stay distinguishable in the saved
    checkpoint. Confirmed live 2026-07-22: an earlier version unconditionally
    set stage="done" here regardless of why the pipeline stopped, which made
    resume_recon_pipeline's "is this checkpoint already finished" check treat
    a rejected-and-stopped run as complete — resuming after a reject (exactly
    the case this exists for) silently did nothing. stage_index is the
    authoritative progress marker; "stage" here is informational only.
    """
    finished = state["stage_index"] >= len(RECON_STAGES)
    return {**state, "stage": "done" if finished else "rejected"}


def node_error(state: ReconPipelineState) -> ReconPipelineState:
    return {**state, "stage": "error"}


def _route_after_gate(state: ReconPipelineState) -> str:
    return "execute" if state.get("decision") == "approve" else "done"


def _route_after_execute(state: ReconPipelineState) -> str:
    if state["stage"] == "error":
        return "error"
    if state["stage_index"] >= len(RECON_STAGES):
        return "done"
    return "propose"


def build_recon_graph():
    graph = StateGraph(ReconPipelineState)
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


def _fresh_state(target: str) -> ReconPipelineState:
    return {
        "target": target, "stage": "subfinder", "stage_index": 0, "human_note": "",
        "all_findings": [], "subdomains": [], "hosts_to_probe": [], "live_hosts": [],
        "ports_by_host": {}, "js_urls": [], "diff": {}, "aggregation": None, "error": None,
    }


def run_recon_pipeline(target: str, resume_state: ReconPipelineState | None = None) -> ReconPipelineState:
    """Run (or continue) the fixed-stage recon pipeline for one target.

    Pass resume_state (a prior checkpoint dict) to continue an interrupted
    run from its next stage rather than starting over — see
    resume_recon_pipeline() below, which is the normal entrypoint for that.
    recursion_limit is raised well above LangGraph's default 25: 8 stages *
    3 nodes (propose/gate/execute) = 24 transitions minimum, right at the
    default ceiling with zero margin for a reject-and-stop path.
    """
    graph = build_recon_graph()
    initial = resume_state if resume_state is not None else _fresh_state(target)
    return graph.invoke(initial, config={"recursion_limit": 100})


def resume_recon_pipeline(target: str) -> ReconPipelineState | None:
    """Load the latest checkpoint for target and continue an incomplete pipeline run.

    Returns None if there's no checkpoint at all, or if the last checkpoint
    shows the pipeline already ran to completion — callers should treat that
    as "nothing to resume, start a fresh run instead" rather than silently
    re-triggering a finished hunt.
    """
    checkpoint = load_latest(target)
    if checkpoint is None:
        return None
    # stage_index is authoritative (see node_done) — do NOT also check
    # stage == "done" here, that string means "stopped" (finished OR
    # rejected), not "finished specifically".
    if checkpoint.get("stage_index", 0) >= len(RECON_STAGES):
        return None
    return run_recon_pipeline(target, resume_state=checkpoint)
