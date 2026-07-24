"""ROI-aware target/vuln-type prioritization.

scope_parser now extracts payout tiers from a program's policy text, but
nothing used them until this. Scanning breadth-first (every vuln type
against every asset) wastes LLM/tool budget on low-expected-value work.
This ranks (asset, vuln_type) candidates by expected value = base_rate x
payout, so compute goes to what's actually likely to pay out, not just
what's easiest to automate.
"""
from langchain_core.tools import tool
from pydantic import BaseModel

# Rough, adjustable priors: P(a given vuln type yields a valid, payable
# finding) on an already-recon'd asset, drawn from general bounty-hunting
# experience rather than per-program data. Starting weights, not a claim
# of empirical accuracy — recalibrate per program as real findings land.
_DEFAULT_BASE_RATES = {
    "idor": 0.12,
    "business_logic": 0.10,
    "ssrf": 0.06,
    "auth_bypass": 0.05,
    "xss": 0.15,
    "sqli": 0.04,
    "open_redirect": 0.20,
    "subdomain_takeover": 0.03,
    "ssti": 0.02,
    "lfi": 0.03,
    "cors_misconfig": 0.10,
    "secrets_exposure": 0.08,
}

_SEVERITY_BY_VULN = {
    "idor": "high",
    "business_logic": "high",
    "ssrf": "critical",
    "auth_bypass": "critical",
    "xss": "medium",
    "sqli": "critical",
    "open_redirect": "low",
    "subdomain_takeover": "high",
    "ssti": "critical",
    "lfi": "high",
    "cors_misconfig": "medium",
    "secrets_exposure": "high",
}

_FALLBACK_PAYOUT = 500.0  # used when a program doesn't publish payout tiers


class PriorityTarget(BaseModel):
    asset: str
    vuln_type: str
    expected_severity: str
    payout_estimate: float
    base_rate: float
    expected_value: float
    rationale: str


@tool
def prioritize_targets(assets: list[str], payout_tiers: dict, allowed_vuln_types: list[str] | None = None) -> list[dict]:
    """Rank (asset, vuln_type) candidates by expected value before deep-scanning.

    Call this once recon has produced an asset list and check_scope /
    check_policy_compliance have cleared the program, before running the
    full active-scan tool suite. payout_tiers comes straight from
    ScopePolicy.payout_tiers (severity -> dollar amount) — falls back to a
    flat $500 estimate for any severity missing from it, so ranking still
    works on programs that don't publish a payout table. Returns candidates
    sorted highest expected_value first; spend scan budget top-down, not
    breadth-first across every vuln type on every asset.
    """
    vuln_types = allowed_vuln_types or list(_DEFAULT_BASE_RATES.keys())
    candidates = []

    for asset in assets:
        for vuln_type in vuln_types:
            base_rate = _DEFAULT_BASE_RATES.get(vuln_type, 0.05)
            severity = _SEVERITY_BY_VULN.get(vuln_type, "medium")
            payout = payout_tiers.get(severity, _FALLBACK_PAYOUT)
            expected_value = round(base_rate * payout, 2)

            candidates.append(PriorityTarget(
                asset=asset,
                vuln_type=vuln_type,
                expected_severity=severity,
                payout_estimate=payout,
                base_rate=base_rate,
                expected_value=expected_value,
                rationale=f"base_rate={base_rate} x payout(${payout} for {severity}) = ${expected_value}",
            ).model_dump())

    candidates.sort(key=lambda c: c["expected_value"], reverse=True)
    return candidates
