"""Scope safety gate.

Every target must pass through here before any tool or skill touches it.
The regex/keyword pass below is a cheap pre-filter; the orchestrator LLM
still does the real judgment call and must ask the human when unsure
(see ORCHESTRATOR_SYSTEM_PROMPT rule 6).
"""
import re

from langchain_core.tools import tool
from pydantic import BaseModel, Field

_DOMAIN_RE = re.compile(r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", re.IGNORECASE)
_OUT_OF_SCOPE_MARKERS = ("out of scope", "not in scope", "excluded", "out-of-scope")
_IN_SCOPE_MARKERS = ("in scope", "in-scope", "eligible", "included")
# Matches lines like "Critical: $5,000" or "High - $2000" so roi_prioritizer
# has real payout numbers to rank against instead of flat guesses.
_PAYOUT_RE = re.compile(r"\b(critical|high|medium|low)\b[^\d$]{0,20}\$\s?([\d,]+(?:\.\d+)?)", re.IGNORECASE)

# A program with no payout tiers and language like this pays in reputation/
# swag, not cash — worth knowing before sinking hunt time in, not after.
_VDP_ONLY_MARKERS = (
    "no monetary reward", "non-monetary", "swag only", "hall of fame",
    "points only", "reputation only", "no cash reward", "no bounty is paid",
)

# Domain knowledge: categories most programs reject even when technically
# true, unless the hunter demonstrates real impact. Kept here (not just in
# eligibility_filter.py) so a program's OWN explicit rejection list — which
# may add to or differ from the defaults — gets captured during parsing.
# See skills/eligibility_filter.py for how this list is actually enforced.
_EXCLUDED_CATEGORY_MARKERS = {
    "self_xss": ("self-xss", "self xss"),
    "clickjacking_non_sensitive": ("clickjacking",),
    "missing_security_headers": ("missing security headers", "missing http headers", "security headers"),
    "verbose_error_messages": ("verbose error", "stack trace"),
    "logout_csrf": ("logout csrf", "csrf on logout"),
    "rate_limit_non_sensitive": ("rate limiting", "rate-limiting", "lack of rate limit"),
    "spf_dkim_missing": ("spf record", "dkim", "dmarc"),
    "autocomplete_password": ("autocomplete",),
    "tls_best_practice": ("tls best practice", "weak cipher", "ssl best practice"),
    "version_disclosure": ("version disclosure", "banner disclosure"),
    "http_options_trace": ("http options", "trace method"),
}


class ScopePolicy(BaseModel):
    allowed_domains: list[str] = Field(default_factory=list)
    forbidden_domains: list[str] = Field(default_factory=list)
    allowed_vuln_types: list[str] = Field(default_factory=list)
    max_severity: str = "critical"
    payout_tiers: dict[str, float] = Field(default_factory=dict)
    program_type: str = "unknown"  # "paid" | "vdp_no_reward" | "unknown"
    excluded_finding_categories: list[str] = Field(default_factory=list)
    notes: str = ""


_ALL_SECTION_MARKERS = sorted(
    set(_OUT_OF_SCOPE_MARKERS) | set(_IN_SCOPE_MARKERS), key=len, reverse=True
)
_SECTION_MARKER_RE = re.compile(
    "(" + "|".join(re.escape(marker) for marker in _ALL_SECTION_MARKERS) + ")", re.IGNORECASE
)


def _force_markers_onto_own_lines(scope_text: str) -> str:
    """Insert a newline before every section-marker occurrence.

    Bulleted HackerOne/Bugcrowd scope pages put "In scope"/"Out of scope" on
    their own line already, but plenty of programs write policy as prose —
    "In scope: example.com. Out of scope: internal.example.com." on one
    line/sentence. Without this, the line-based section classifier below
    only sees the LAST marker on a line and retroactively misattributes
    every earlier domain on it to the wrong section. Forcing each marker
    onto its own line makes that impossible regardless of input formatting.
    """
    return _SECTION_MARKER_RE.sub(lambda m: "\n" + m.group(0), scope_text)


def parse_scope(scope_text: str) -> ScopePolicy:
    """Extract a ScopePolicy from a program's raw scope page/text.

    Splits on lines, classifies each line as in-scope or out-of-scope based
    on nearby section markers, and pulls every domain-shaped token out of it.
    """
    allowed: set[str] = set()
    forbidden: set[str] = set()
    payout_tiers: dict[str, float] = {}
    section = "in_scope"  # HackerOne/Bugcrowd scope pages usually list in-scope first

    for raw_line in _force_markers_onto_own_lines(scope_text).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()

        if any(marker in lowered for marker in _OUT_OF_SCOPE_MARKERS):
            section = "out_of_scope"
        elif any(marker in lowered for marker in _IN_SCOPE_MARKERS):
            section = "in_scope"

        for domain in _DOMAIN_RE.findall(line):
            domain = domain.lower().rstrip(".")
            if section == "out_of_scope":
                forbidden.add(domain)
            else:
                allowed.add(domain)

        for severity, amount in _PAYOUT_RE.findall(line):
            payout_tiers[severity.lower()] = float(amount.replace(",", ""))

    # A domain explicitly called out as forbidden always wins over a
    # coincidental match in the allowed set.
    allowed -= forbidden

    lowered_full = scope_text.lower()
    excluded_categories = sorted(
        category for category, markers in _EXCLUDED_CATEGORY_MARKERS.items()
        if any(marker in lowered_full for marker in markers)
    )
    if any(marker in lowered_full for marker in _VDP_ONLY_MARKERS):
        program_type = "vdp_no_reward"
    elif payout_tiers:
        program_type = "paid"
    else:
        program_type = "unknown"

    return ScopePolicy(
        allowed_domains=sorted(allowed),
        forbidden_domains=sorted(forbidden),
        payout_tiers=payout_tiers,
        program_type=program_type,
        excluded_finding_categories=excluded_categories,
        notes="Parsed heuristically — verify with the human before relying on this for a new program.",
    )


def looks_like_scope_text(text: str) -> bool:
    """Heuristic: does this look like a program's actual scope/policy text?

    Used by agent/graph.py to gate parse_scope_policy/check_scope/
    check_policy_compliance — the model must never be allowed to fabricate
    scope text from its own training knowledge (verified live 2026-07-16 that
    it will: asked "is api.hackerone.com in scope for HackerOne" with no real
    policy text anywhere in the conversation, it invented a plausible-looking
    one from memory rather than asking the human — a prompt rule alone did
    not reliably stop this). A tool call to any of those three only proceeds
    if some HumanMessage in the conversation actually contains something
    scope-page-shaped: an explicit scope marker ("in scope"/"out of
    scope"/"eligible"/etc.) AND at least two distinct domain-shaped tokens —
    a real policy page lists several domains under those markers, whereas a
    short instruction naming one target domain ("is api.hackerone.com in
    scope?") deliberately does not pass, so it can't be mistaken for the
    real thing.
    """
    lowered = text.lower()
    has_marker = any(marker in lowered for marker in _IN_SCOPE_MARKERS + _OUT_OF_SCOPE_MARKERS)
    domain_count = len({d.lower().rstrip(".") for d in _DOMAIN_RE.findall(text)})
    return has_marker and domain_count >= 2


@tool
def parse_scope_policy(scope_text: str) -> dict:
    """Parse a program's raw scope page/policy text into a ScopePolicy.

    Call this ONCE per program, before check_scope ever runs for an individual
    target — pass the exact dict this returns straight through as check_scope's
    `policy` argument. Do NOT try to construct a ScopePolicy from memory:
    models reliably get its nested field names wrong (e.g. `allowed` instead
    of `allowed_domains`) when asked to freehand it, which makes check_scope
    silently return requires_human_confirm=True instead of a real answer —
    parse_scope_policy runs the same deterministic heuristic code either way,
    so there's no reason to reconstruct it by hand.
    """
    return parse_scope(scope_text).model_dump()


def _domain_matches(domain: str, pattern: str) -> bool:
    domain = domain.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]  # keep the leading dot: ".example.com"
        return domain.endswith(suffix) or domain == pattern[2:]
    return domain == pattern


@tool
def check_scope(domain: str, policy: ScopePolicy) -> dict:
    """Check whether a domain is in scope before scanning it.

    Call this before running ANY tool or skill against a new target.
    Returns {in_scope, reason, requires_human_confirm}. When neither the
    allowed nor forbidden list matches, requires_human_confirm is True and
    the orchestrator MUST ask the human rather than proceed.
    """
    if any(_domain_matches(domain, pattern) for pattern in policy.forbidden_domains):
        return {
            "domain": domain,
            "in_scope": False,
            "reason": "matched an explicit out-of-scope entry",
            "requires_human_confirm": False,
        }

    if any(_domain_matches(domain, pattern) for pattern in policy.allowed_domains):
        return {
            "domain": domain,
            "in_scope": True,
            "reason": "matched an in-scope entry",
            "requires_human_confirm": False,
        }

    return {
        "domain": domain,
        "in_scope": False,
        "reason": "no explicit match in either list",
        "requires_human_confirm": True,
    }
