"""Risk-table contract (agent/risk.py).

The whole safety model rests on risk_level_for() being a fixed lookup that
fails CLOSED to HIGH for anything it doesn't recognize — never LLM-judged.
These tests pin that behavior so a future edit can't silently downgrade a
tool or open the default.
"""
import pytest

from agent.risk import _RISK_BY_TOOL, risk_level_for

_VALID_LEVELS = {"LOW", "MEDIUM", "HIGH"}


def test_unknown_tool_fails_closed_to_high():
    assert risk_level_for("some_tool_that_does_not_exist") == "HIGH"
    assert risk_level_for("") == "HIGH"


@pytest.mark.parametrize(
    "tool_name,expected",
    [
        # Passive recon / local-only / pure reasoning -> LOW
        ("run_subfinder", "LOW"),
        ("run_gau", "LOW"),
        ("run_gf", "LOW"),
        ("parse_scope_policy", "LOW"),
        ("check_scope", "LOW"),
        ("map_auth_flow", "LOW"),
        ("generate_report", "LOW"),
        # Active-but-non-destructive scanning -> MEDIUM
        ("run_httpx", "MEDIUM"),
        ("run_naabu", "MEDIUM"),
        ("run_nuclei", "MEDIUM"),
        ("run_katana", "MEDIUM"),
        # Exploit attempts / forged-auth replay / no-rate-limit -> HIGH
        ("run_sqlmap", "HIGH"),
        ("run_ghauri", "HIGH"),
        ("run_kiterunner", "HIGH"),
        ("check_jwt_weaknesses", "HIGH"),
        ("check_idor", "HIGH"),
        ("check_graphql_idor", "HIGH"),
        ("probe_waf_bypass", "HIGH"),
    ],
)
def test_representative_classifications(tool_name, expected):
    assert risk_level_for(tool_name) == expected


def test_every_table_entry_is_a_valid_level():
    bad = {name: lvl for name, lvl in _RISK_BY_TOOL.items() if lvl not in _VALID_LEVELS}
    assert not bad, f"invalid risk levels in table: {bad}"


def test_no_active_sql_injection_tool_is_below_high():
    # Guard the specific class of tool the README calls out as always-HIGH.
    for name in ("run_sqlmap", "run_ghauri"):
        assert risk_level_for(name) == "HIGH"
