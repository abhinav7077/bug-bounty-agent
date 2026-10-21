"""Payload loading/formatting contracts (skills/payload_loader.py).

Also serves as a smoke test that every shipped config/payloads/*.yaml file
parses as valid YAML — a malformed payload file would otherwise only surface
mid-hunt.
"""
from pathlib import Path

import pytest

from skills.payload_loader import get_payload_context, load_payloads

_PAYLOAD_DIR = Path(__file__).resolve().parent.parent / "config" / "payloads"
_SHIPPED = sorted(p.stem for p in _PAYLOAD_DIR.glob("*.yaml"))


def test_at_least_the_known_payload_sets_ship():
    # Lock in the sets the README/pipeline rely on existing.
    for expected in ("xss", "sqli", "ssrf", "ssti", "lfi", "open_redirect"):
        assert expected in _SHIPPED, f"missing payload set: {expected}"


@pytest.mark.parametrize("vuln_type", _SHIPPED)
def test_every_shipped_payload_file_loads_as_a_dict(vuln_type):
    data = load_payloads(vuln_type)
    assert isinstance(data, dict)
    assert data, f"{vuln_type}.yaml parsed empty"


@pytest.mark.parametrize("vuln_type", _SHIPPED)
def test_context_block_is_populated_for_shipped_sets(vuln_type):
    context = get_payload_context(vuln_type)
    assert context.startswith(f"Available {vuln_type.upper()} payloads:")
    assert "No curated payloads" not in context


def test_missing_payload_type_returns_empty_and_safe_message():
    assert load_payloads("not_a_real_vuln_type") == {}
    assert get_payload_context("not_a_real_vuln_type") == (
        "No curated payloads found for 'not_a_real_vuln_type'."
    )
