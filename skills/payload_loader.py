"""Loads config/payloads/*.yaml and formats them for injection into a prompt."""
from functools import cache
from pathlib import Path

import yaml

from config.settings import settings

_PAYLOAD_DIR = Path(__file__).resolve().parent.parent / settings.PAYLOADS_DIR


@cache
def load_payloads(vuln_type: str) -> dict:
    path = _PAYLOAD_DIR / f"{vuln_type}.yaml"
    if not path.exists():
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def get_payload_context(vuln_type: str) -> str:
    """Return payloads as a string block ready to inject into an LLM prompt."""
    data = load_payloads(vuln_type)
    if not data:
        return f"No curated payloads found for '{vuln_type}'."
    return f"Available {vuln_type.upper()} payloads:\n{yaml.dump(data, sort_keys=False)}"
