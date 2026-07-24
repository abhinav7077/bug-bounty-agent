"""Program-policy compliance gate — goes beyond domain scope.

check_scope() in scope_parser.py only answers "is this domain in scope."
Some programs additionally prohibit automated tooling outright ("manual
testing only", "no automated scanners") or bar specific techniques (DoS,
social engineering, physical access) regardless of domain. Running
automated tools against a program that says "no automated tools" is a
policy violation even when every domain touched is in scope — this check
must run once per program, before check_scope ever runs per-target.
"""
import re

from langchain_core.tools import tool
from pydantic import BaseModel, Field

_NO_AUTOMATION_MARKERS = (
    "no automated", "not automated", "manual testing only", "manual only",
    "no automated scanning", "no scanners", "no bots", "no scripts",
    "automated tools are not allowed", "automated testing is prohibited",
)
_PROHIBITED_TECHNIQUE_MARKERS = {
    "denial of service": "dos",
    "dos attack": "dos",
    "ddos": "dos",
    "social engineering": "social_engineering",
    "phishing": "social_engineering",
    "physical access": "physical",
    "physical security": "physical",
    "spam": "spam",
    "brute force": "brute_force",
    "brute-force": "brute_force",
}
_SAFE_HARBOR_MARKERS = ("safe harbor",)
# Looks for a day count in the same sentence as "disclos"/"embargo" so a
# stated disclosure embargo ("do not publicly disclose for 90 days after
# resolution") gets captured — going public early can forfeit a bounty
# entirely regardless of finding quality.
_DAY_COUNT_RE = re.compile(r"(\d{1,3})\s*days?", re.IGNORECASE)


class PolicyCompliance(BaseModel):
    automated_scanning_allowed: bool = True
    prohibited_techniques: list[str] = Field(default_factory=list)
    requires_human_override: bool = False
    safe_harbor_stated: bool = False
    disclosure_embargo_days: int | None = None
    notes: str = ""


def _extract_embargo_days(scope_text: str) -> int | None:
    for sentence in re.split(r"[.\n]", scope_text):
        lowered = sentence.lower()
        if "disclos" in lowered or "embargo" in lowered:
            match = _DAY_COUNT_RE.search(sentence)
            if match:
                return int(match.group(1))
    return None


def parse_policy(scope_text: str) -> PolicyCompliance:
    """Extract automation/technique/disclosure restrictions from a program's policy text."""
    lowered = scope_text.lower()

    automated_allowed = not any(marker in lowered for marker in _NO_AUTOMATION_MARKERS)
    prohibited = sorted({
        tag for marker, tag in _PROHIBITED_TECHNIQUE_MARKERS.items() if marker in lowered
    })
    safe_harbor = any(marker in lowered for marker in _SAFE_HARBOR_MARKERS)
    embargo_days = _extract_embargo_days(scope_text)

    return PolicyCompliance(
        automated_scanning_allowed=automated_allowed,
        prohibited_techniques=prohibited,
        requires_human_override=not automated_allowed,
        safe_harbor_stated=safe_harbor,
        disclosure_embargo_days=embargo_days,
        notes=(
            "Restrictions detected heuristically from policy text — verify with the human "
            "before running anything active, especially when automated_scanning_allowed is False "
            "or safe_harbor_stated is False."
        ),
    )


@tool
def check_policy_compliance(scope_text: str) -> dict:
    """Check a program's policy text for automation/technique/disclosure restrictions.

    Call this ONCE per program, before check_scope ever runs for an individual
    target. If automated_scanning_allowed is False, every active tool call for
    this program requires an explicit human "yes" regardless of risk_level —
    this overrides the normal LOW-risk auto-proceed rule. If prohibited_techniques
    is non-empty, never plan an action matching one of those tags, even if a
    human approves — surface it as a hard stop instead. If safe_harbor_stated is
    False, flag this to the human before any active testing — legal protection
    may not apply. Never discuss or publicly disclose a finding before
    disclosure_embargo_days have passed since the program marked it resolved,
    even if the human seems eager to write it up — going public early can
    forfeit the bounty entirely regardless of finding quality.
    """
    return parse_policy(scope_text).model_dump()
