"""Bug bounty report generator — Phase 8.

Three genuinely separate concerns, each handled the way this codebase
already prefers for its own kind (see agent/risk.py's own precedent: never
trust an LLM with something that has one deterministically correct answer):
1. CVSS 3.1 base score — a PURE, deterministic calculation per the official
   FIRST.org formula, verified live against four independent known-correct
   reference vectors before this module was built on top of it (a classic
   unauthenticated-RCE-shape vector -> 9.8, CVE-2021-44228 Log4Shell's own
   NVD vector -> 10.0, a typical reflected-XSS vector -> 6.1, a typical
   IDOR vector -> 7.5 — see the test script referenced in MEMORY.md).
   `calculate_cvss` never guesses; the metric VALUES fed into it for a given
   finding come from `_CVSS_PROFILE_BY_FINDING_TYPE`/`_CVSS_PROFILE_BY_SEVERITY`
   below, which ARE approximations (see their own docstrings) — the
   arithmetic on top of them is exact.
2. The narrative (executive summary, impact) — genuinely needs an LLM, per
   VULN_AGENT_PROMPT/REPORT_AGENT_PROMPT's own existing rules ("impact must
   name the specific business risk, not a generic 'data breach possible'").
3. Remediation text — a static lookup by finding type/category, not an LLM
   guess: a fix suggestion for "jwt_weak_secret" doesn't change per-run, and
   a wrong static suggestion is easier to catch/fix once than a
   hallucinated one repeating across every report.

Report assembly (render_report) and export (export_report) are template-
driven and deterministic; only the narrative section calls an LLM at all.
"""
import html
import json
import re
from datetime import datetime
from pathlib import Path

from jinja2 import Template
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from pydantic import BaseModel
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer

from agent.memory import get_confirmed_findings
from agent.vuln_pipeline import _infer_vuln_type
from config.prompts import REPORT_AGENT_PROMPT
from config.report_templates import TEMPLATES_BY_PLATFORM
from config.settings import settings
from skills.poc_builder import build_poc

# --- 1. CVSS 3.1 base score -- verified live against 4 known-correct reference vectors ---

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


class CVSSResult(BaseModel):
    score: float
    severity: str  # None | Low | Medium | High | Critical
    vector: str
    justification: str


def _roundup(x: float) -> float:
    """CVSS's own specified rounding: the smallest 1-decimal-place number >= x.

    NOT standard round() -- the spec defines this exact integer-arithmetic
    procedure specifically to sidestep floating-point comparison errors at
    the boundary (e.g. a raw value of 4.0000000001 must round to 4.0, not
    4.1) — implemented exactly as FIRST.org's own reference calculator does.
    """
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (int_input // 10000 + 1) / 10


def _severity_for_score(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def calculate_cvss(av: str, ac: str, pr: str, ui: str, scope: str, c: str, i: str, a: str) -> CVSSResult:
    """Compute a CVSS 3.1 base score from its 8 metric letters.

    av: N/A/L/P (Network/Adjacent/Local/Physical) — attack vector
    ac: L/H — attack complexity
    pr: N/L/H — privileges required
    ui: N/R — user interaction
    scope: U/C — unchanged/changed
    c/i/a: N/L/H — confidentiality/integrity/availability impact

    Pure arithmetic, no network/LLM call — see this module's own docstring
    for why CVSS math specifically must never be LLM-estimated.
    """
    pr_val = (_PR_CHANGED if scope == "C" else _PR_UNCHANGED)[pr]
    iss = 1 - (1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope == "C" else 6.42 * iss
    exploitability = 8.22 * _AV[av] * _AC[ac] * pr_val * _UI[ui]

    if impact <= 0:
        score = 0.0
    elif scope == "C":
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = _roundup(min(impact + exploitability, 10))

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"
    justification = (
        f"AV:{av} (attack vector), AC:{ac} (complexity), PR:{pr} (privileges required), "
        f"UI:{ui} (user interaction), S:{scope} (scope), C:{c}/I:{i}/A:{a} "
        f"(confidentiality/integrity/availability impact) -> impact subscore {impact:.2f}, "
        f"exploitability subscore {exploitability:.2f}."
    )
    return CVSSResult(score=score, severity=_severity_for_score(score), vector=vector, justification=justification)


# --- CVSS metric profiles per finding type -- APPROXIMATIONS, not measured
# per-finding vectors (this codebase has no per-finding attack-complexity/
# scope telemetry) -- picked to match this vuln CLASS's well-established,
# commonly-published CVSS shape for a typical instance of it. A human must
# still review/adjust before submitting, same as every other report field. ---

_CVSS_PROFILE_BY_FINDING_TYPE: dict[str, tuple[str, str, str, str, str, str, str, str]] = {
    "bola_id_mutation": ("N", "L", "L", "N", "U", "H", "N", "N"),
    "bola_differential_auth": ("N", "L", "L", "N", "U", "H", "N", "N"),
    "graphql_bola_id_mutation": ("N", "L", "L", "N", "U", "H", "N", "N"),
    "graphql_bola_differential_auth": ("N", "L", "L", "N", "U", "H", "N", "N"),
    "jwt_signature_not_verified": ("N", "L", "N", "N", "U", "H", "H", "H"),
    "jwt_weak_secret": ("N", "L", "N", "N", "U", "H", "H", "H"),
    "jwt_alg_none_accepted": ("N", "L", "N", "N", "U", "H", "H", "H"),
    "jwt_alg_confusion": ("N", "L", "N", "N", "U", "H", "H", "H"),
    "sql_injection": ("N", "L", "N", "N", "U", "H", "H", "H"),
    "waf_bypass_confirmed": ("N", "L", "N", "R", "C", "L", "L", "N"),
    "xss_finding": ("N", "L", "N", "R", "C", "L", "L", "N"),
    "subdomain_takeover": ("N", "L", "N", "N", "C", "H", "H", "N"),
    "graphql_introspection_enabled": ("N", "L", "N", "N", "U", "L", "N", "N"),
    "graphql_sensitive_mutation": ("N", "L", "L", "N", "U", "N", "H", "N"),
}

# Fallback when a finding's type isn't in the table above (most commonly
# run_nuclei matches, which already carry a tool-assigned severity but no
# CVSS vector) -- approximated from that severity tier's own typical shape,
# documented in the justification text as such rather than presented as a
# literal per-finding measurement.
_CVSS_PROFILE_BY_SEVERITY: dict[str, tuple[str, str, str, str, str, str, str, str]] = {
    "critical": ("N", "L", "N", "N", "U", "H", "H", "H"),
    "high": ("N", "L", "N", "N", "U", "H", "L", "N"),
    "medium": ("N", "L", "N", "R", "U", "L", "L", "N"),
    "low": ("N", "H", "N", "R", "U", "L", "N", "N"),
    "info": ("N", "H", "N", "R", "U", "N", "N", "N"),
}

_BUGCROWD_PRIORITY_BY_SEVERITY = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "None": 5}


def infer_cvss_for_finding(finding: dict) -> CVSSResult:
    """Best-effort CVSS for a finding: an exact-type profile if this codebase
    has one, else a severity-tier fallback -- never fabricated per-finding
    metrics with no grounding at all.
    """
    finding_type = finding.get("type", "")
    if finding_type in _CVSS_PROFILE_BY_FINDING_TYPE:
        profile = _CVSS_PROFILE_BY_FINDING_TYPE[finding_type]
        source_note = f"profile matched on finding type {finding_type!r}"
    else:
        severity = finding.get("severity", "info").lower()
        profile = _CVSS_PROFILE_BY_SEVERITY.get(severity, _CVSS_PROFILE_BY_SEVERITY["info"])
        source_note = (
            f"no specific CVSS profile for finding type {finding_type!r} -- approximated from "
            f"its own reported severity tier ({severity!r}), not a literal per-finding vector"
        )
    result = calculate_cvss(*profile)
    result.justification = f"{result.justification} ({source_note}.)"
    return result


# --- 3. Remediation -- static lookup, not LLM-guessed (see module docstring) ---

_REMEDIATION_BY_FINDING_TYPE = {
    "bola_id_mutation": "Enforce object-level authorization server-side on every request that accepts an ID — verify the authenticated identity actually owns or is permitted to access the specific object requested, not just that a valid session exists.",
    "bola_differential_auth": "Enforce object-level authorization server-side on every request that accepts an ID — verify the authenticated identity actually owns or is permitted to access the specific object requested, not just that a valid session exists.",
    "graphql_bola_id_mutation": "Apply the same per-object authorization check inside GraphQL resolvers as REST endpoints — a valid token alone must not be sufficient to read an arbitrary object by ID.",
    "graphql_bola_differential_auth": "Apply the same per-object authorization check inside GraphQL resolvers as REST endpoints — a valid token alone must not be sufficient to read an arbitrary object by ID.",
    "jwt_signature_not_verified": "Verify the JWT signature on every request server-side using a trusted library — never trust the token's own claims without cryptographic verification against the issuer's real key.",
    "jwt_weak_secret": "Replace the HMAC signing secret with a cryptographically random value of at least 256 bits, stored outside source control, and rotate it immediately given the old one may already be compromised.",
    "jwt_alg_none_accepted": "Reject any JWT whose header declares alg=none or any algorithm not explicitly allow-listed by the verifying library/server configuration.",
    "jwt_alg_confusion": "Pin the expected signing algorithm server-side (e.g. RS256 only) rather than trusting the token header's own `alg` claim, and never use the same key material for both signing and verification across algorithm families.",
    "sql_injection": "Use parameterized queries/prepared statements for every database call — never concatenate or interpolate user-controlled input directly into SQL text.",
    "waf_bypass_confirmed": "Fix the underlying output-encoding gap rather than relying on filter/WAF pattern-matching — apply context-aware output encoding (HTML/attribute/JS/URL as appropriate) at the point of output, which the bypass variant found in this report already evaded once.",
    "xss_finding": "Apply context-aware output encoding at the point of output and set a restrictive Content-Security-Policy as defense in depth.",
    "subdomain_takeover": "Remove the dangling DNS record pointing at the unclaimed third-party resource, or reclaim/reconfigure that resource so it can no longer be registered by an unrelated party.",
    "graphql_introspection_enabled": "Disable GraphQL introspection in production, or gate it behind authentication if it's needed for internal tooling.",
    "graphql_sensitive_mutation": "Confirm this mutation enforces the same authorization/role checks as its REST equivalent — review who can call it and with what object-level checks.",
}
_GENERIC_REMEDIATION = "Manually review this finding's root cause with the relevant engineering team — no specific pre-written remediation exists for this finding type yet; treat the detail/evidence above as the starting point for the fix."


def _remediation_for_finding(finding: dict) -> str:
    return _REMEDIATION_BY_FINDING_TYPE.get(finding.get("type", ""), _GENERIC_REMEDIATION)


# --- 2. Narrative -- the one genuinely LLM-driven piece ---

_llm = ChatOllama(
    base_url=settings.OLLAMA_BASE_URL, model=settings.OLLAMA_MODEL,
    temperature=settings.LLM_TEMPERATURE, num_ctx=settings.OLLAMA_NUM_CTX,
)

_NARRATIVE_USER_PROMPT_TEMPLATE = """TARGET: {target}

CONFIRMED FINDINGS:
{findings_json}

Write the report narrative now. Return ONLY this exact format, no extra commentary:
### EXECUTIVE_SUMMARY
<2-4 sentences a triage engineer can read in under 30 seconds: what was found, how many findings, overall risk>
### IMPACT
<specific business risk this creates for THIS target — name concrete consequences (account takeover, \
data exposure of a specific kind, financial/reputational risk), never a generic "data breach possible">
"""


def generate_report_narrative(target: str, findings: list[dict]) -> dict:
    """LLM call for the executive-summary + impact sections only — every
    other report field (CVSS, remediation, repro steps) is deterministic.

    Defensive parsing, same pattern as skills/chain_analyzer.py and
    skills/vuln_assessor.py: a malformed response never crashes report
    generation, it falls back to a plain, honest placeholder instead.
    """
    condensed = [
        {"type": f.get("type", ""), "target": f.get("target", ""), "detail": f.get("detail", "")[:400],
         "severity": f.get("severity", "info")}
        for f in findings
    ]
    prompt = _NARRATIVE_USER_PROMPT_TEMPLATE.format(target=target, findings_json=json.dumps(condensed))
    response = _llm.invoke([SystemMessage(content=REPORT_AGENT_PROMPT), HumanMessage(content=prompt)])
    content = response.content.strip()

    summary_match = re.search(r"### EXECUTIVE_SUMMARY\s*(.*?)\s*### IMPACT", content, re.DOTALL)
    impact_match = re.search(r"### IMPACT\s*(.*)", content, re.DOTALL)

    return {
        "executive_summary": summary_match.group(1).strip() if summary_match else content,
        "impact": impact_match.group(1).strip() if impact_match else (
            "Impact narrative unavailable (model output was malformed) — reviewer must write this "
            "section manually before submission."
        ),
    }


# --- Assembly + export ---

def _build_finding_context(finding: dict) -> dict:
    cvss = infer_cvss_for_finding(finding)
    poc = build_poc.invoke({
        "vuln_type": _infer_vuln_type(finding.get("type", "")),
        "target_url": finding.get("target", ""), "parameter": "unknown",
        "payload": finding.get("detail", "")[:200],
    })
    return {
        "type": finding.get("type", "unknown"), "target": finding.get("target", ""),
        "detail": finding.get("detail", ""), "severity": finding.get("severity", "info"),
        "tool_source": finding.get("tool_source", ""),
        "cvss": cvss.model_dump(),
        "bugcrowd_priority": _BUGCROWD_PRIORITY_BY_SEVERITY.get(cvss.severity, 5),
        "remediation": _remediation_for_finding(finding),
        "poc": poc,
    }


def render_report(target: str, findings: list[dict], narrative: dict, platform: str = "hackerone") -> str:
    """Render the full Markdown report. Pure/deterministic given its inputs
    (including the already-generated narrative) — call
    generate_report_narrative() separately first, so a caller (e.g.
    ui/app.py) can let a human edit the narrative before this assembles the
    final document, per the plan's own "human review + edit step... before
    export" requirement.
    """
    template_str = TEMPLATES_BY_PLATFORM.get(platform, TEMPLATES_BY_PLATFORM["hackerone"])
    template = Template(template_str)
    return template.render(
        target=target,
        generated_date=datetime.now().strftime("%Y-%m-%d"),
        executive_summary=narrative.get("executive_summary", ""),
        impact=narrative.get("impact", ""),
        findings=[_build_finding_context(f) for f in findings],
    )


# --- Markdown -> PDF -- a deliberately scoped-down renderer matching
# exactly what THIS module's own templates emit (headers, plain paragraphs,
# fenced code blocks, **bold**), not a general markdown parser nobody asked
# for. ---

_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")


def _inline_markdown_to_reportlab_markup(line: str) -> str:
    escaped = html.escape(line, quote=False)
    return _BOLD_RE.sub(r"<b>\1</b>", escaped)


def _markdown_to_flowables(markdown_text: str) -> list:
    styles = getSampleStyleSheet()
    flowables = []
    in_code_block = False
    code_lines: list[str] = []

    for line in markdown_text.splitlines():
        if line.strip().startswith("```"):
            if in_code_block:
                flowables.append(Preformatted("\n".join(code_lines), styles["Code"]))
                code_lines = []
            in_code_block = not in_code_block
            continue
        if in_code_block:
            code_lines.append(line)
            continue
        if not line.strip():
            flowables.append(Spacer(1, 0.15 * inch))
        elif line.startswith("# "):
            flowables.append(Paragraph(_inline_markdown_to_reportlab_markup(line[2:]), styles["Title"]))
        elif line.startswith("## "):
            flowables.append(Paragraph(_inline_markdown_to_reportlab_markup(line[3:]), styles["Heading2"]))
        elif line.startswith("### "):
            flowables.append(Paragraph(_inline_markdown_to_reportlab_markup(line[4:]), styles["Heading3"]))
        else:
            flowables.append(Paragraph(_inline_markdown_to_reportlab_markup(line), styles["BodyText"]))

    if code_lines:  # an unterminated fence shouldn't silently drop content
        flowables.append(Preformatted("\n".join(code_lines), styles["Code"]))
    return flowables


def _write_pdf(markdown_text: str, pdf_path: Path) -> None:
    doc = SimpleDocTemplate(str(pdf_path), pagesize=LETTER)
    doc.build(_markdown_to_flowables(markdown_text))


def export_report(target: str, markdown_text: str, timestamp: str | None = None) -> dict:
    """Write the (possibly human-edited) report Markdown to
    reports/<target>/<date>-report.md and a rendered .pdf alongside it.
    """
    timestamp = timestamp or datetime.now().strftime("%Y%m%dT%H%M%S")
    safe_target = target.strip().strip("/") or "unknown-target"
    directory = Path(settings.REPORTS_DIR) / safe_target
    directory.mkdir(parents=True, exist_ok=True)

    md_path = directory / f"{timestamp}-report.md"
    pdf_path = directory / f"{timestamp}-report.pdf"
    md_path.write_text(markdown_text)
    _write_pdf(markdown_text, pdf_path)

    return {"md_path": str(md_path), "pdf_path": str(pdf_path)}


@tool
def generate_report(target: str, platform: str = "hackerone") -> dict:
    """Generate a bug bounty report from this target's human-confirmed findings.

    LOW risk — reads this project's own local ChromaDB store and calls the
    LLM for the narrative sections only; writes to reports/<target>/
    locally. No request reaches the actual target or any external service.
    `platform` selects section-naming convention: "hackerone" (default),
    "bugcrowd", or "immunefi" — see config/report_templates.py.

    Pulls confirmed findings via agent.memory.get_confirmed_findings(target)
    — findings a vuln-assessment pipeline's HITL gate already approved, per
    agent/vuln_pipeline.py's finalize stage. Returns an error (not an
    exception) if none exist yet for this target.
    """
    findings = get_confirmed_findings(target)
    if not findings:
        return {
            "error": f"no confirmed findings on record for {target!r} — run \"assess {target}\" "
                     "and approve at least one finding first",
            "markdown": "", "md_path": "", "pdf_path": "",
        }

    narrative = generate_report_narrative(target, findings)
    markdown = render_report(target, findings, narrative, platform=platform)
    paths = export_report(target, markdown)
    return {"markdown": markdown, "error": None, **paths}
