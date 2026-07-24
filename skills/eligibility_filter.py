"""Eligibility pre-filter — kills or flags findings before report-writing time,
and tracks resolved findings for bypass retests.

Most bounty-report rejections aren't "wrong," they're "not eligible": self-XSS,
clickjacking on a non-sensitive page, missing security headers alone, verbose
errors, logout CSRF, missing rate-limiting on a non-sensitive endpoint,
SPF/DKIM/DMARC issues, autocomplete-on-password, TLS best-practice nits,
version disclosure with no linked CVE. Every program publishes some version of
this "won't fix" list, separate from domain scope. Checking a finding against
it is cheap; writing a PoC and report, then waiting on human review, is not —
this runs right before poc_builder, not after.

Also queues resolved findings for a bypass retest: once a program marks
something fixed, a confirmed bypass is a fresh (often larger) bounty, not a
duplicate. Nothing else in the pipeline remembers what got fixed.
"""
import json
from pathlib import Path

from langchain_core.tools import tool
from pydantic import BaseModel

from config.settings import settings

# Domain knowledge, not program-specific: these categories get rejected on
# most programs even when technically true, UNLESS the hunter has actually
# demonstrated real impact (chained it into something exploitable). Kept in
# sync with skills/scope_parser.py's _EXCLUDED_CATEGORY_MARKERS, which
# detects when a program's OWN policy text adds to or overrides this list.
_DEFAULT_LOW_VALUE_CATEGORIES = {
    "self_xss": "Requires the victim to paste attacker-controlled input into their own console/address bar.",
    "clickjacking_non_sensitive": "Clickjacking on a page with no sensitive state-changing action.",
    "missing_security_headers": "Missing CSP/HSTS/X-Frame-Options alone, no demonstrated exploit chain.",
    "verbose_error_messages": "Stack traces/debug info with no sensitive data or exploit path.",
    "logout_csrf": "CSRF on a logout endpoint — forces logout, not a security-relevant state change.",
    "rate_limit_non_sensitive": "Missing rate-limiting on a non-auth, non-financial endpoint.",
    "spf_dkim_missing": "Missing/weak SPF, DKIM, or DMARC with no demonstrated spoofing impact.",
    "autocomplete_password": "autocomplete not disabled on a password field.",
    "tls_best_practice": "TLS cipher/protocol best-practice nits, no demonstrated MITM impact.",
    "version_disclosure": "Software/version banner disclosure with no linked, unpatched CVE.",
    "http_options_trace": "HTTP OPTIONS/TRACE enabled with no demonstrated exploit.",
}


class EligibilityResult(BaseModel):
    eligible: bool
    reason: str
    requires_human_review: bool = False


@tool
def check_eligibility(
    vuln_category: str,
    has_demonstrated_impact: bool = False,
    program_excluded_categories: list[str] | None = None,
) -> dict:
    """Check whether a finding is worth taking to PoC/report at all.

    Call this right after a finding is technically confirmed, before
    build_poc. program_excluded_categories comes from
    ScopePolicy.excluded_finding_categories for this program. A category on
    the built-in low-value list OR the program's own list is auto-rejected
    UNLESS has_demonstrated_impact is True (e.g. self-XSS chained with CSRF
    into real account impact) — in that case it's flagged for human review
    instead of auto-rejected, since "commonly excluded" isn't "always
    excluded."
    """
    excluded = set(program_excluded_categories or []) | set(_DEFAULT_LOW_VALUE_CATEGORIES)
    category = vuln_category.lower().strip()

    if category not in excluded:
        return EligibilityResult(eligible=True, reason="not on any known low-value/excluded list").model_dump()

    if has_demonstrated_impact:
        return EligibilityResult(
            eligible=True,
            requires_human_review=True,
            reason=(
                f"'{category}' is commonly excluded but demonstrated impact was claimed — "
                "human must verify before reporting, don't auto-confirm."
            ),
        ).model_dump()

    known_note = _DEFAULT_LOW_VALUE_CATEGORIES.get(category, "excluded by this program's own policy")
    return EligibilityResult(
        eligible=False,
        reason=f"'{category}' is a commonly-rejected category with no demonstrated impact: {known_note}",
    ).model_dump()


class RetestCandidate(BaseModel):
    finding_id: str
    target: str
    resolved_on: str
    vuln_type: str
    notes: str = ""


def _retest_queue_path(target: str) -> Path:
    return Path(settings.SESSIONS_DIR) / target / "retest_queue.json"


@tool
def queue_for_retest(target: str, finding_id: str, vuln_type: str, resolved_on: str, notes: str = "") -> dict:
    """Queue a resolved finding for a bypass retest.

    Call this once a program marks a finding fixed. A confirmed bypass of a
    patched fix is a fresh, often larger, bounty — not a duplicate. Nothing
    else in the pipeline remembers what got fixed, so this is the only
    record of what's worth revisiting later.
    """
    path = _retest_queue_path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    queue = json.loads(path.read_text()) if path.exists() else []
    queue.append(RetestCandidate(
        finding_id=finding_id, target=target, resolved_on=resolved_on,
        vuln_type=vuln_type, notes=notes,
    ).model_dump())
    path.write_text(json.dumps(queue, indent=2))
    return {"queued": True, "queue_size": len(queue)}


@tool
def get_retest_queue(target: str) -> list[dict]:
    """List resolved findings still pending a bypass retest for this target.

    Call this at the start of a new session on a previously-hunted target,
    alongside diff_against_last_scan — retesting fixed bugs for bypasses is
    as valuable as finding new surface.
    """
    path = _retest_queue_path(target)
    if not path.exists():
        return []
    return json.loads(path.read_text())
