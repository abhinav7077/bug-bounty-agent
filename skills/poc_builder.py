"""Proof-of-concept generator.

Called once a finding is human-confirmed, so the report agent always has a
concrete curl command / repro script to attach instead of prose.
"""
from urllib.parse import quote

from langchain_core.tools import tool
from pydantic import BaseModel


class PoC(BaseModel):
    steps: list[str]
    code: str
    curl_command: str
    screenshot_path: str = ""


def _xss_poc(target_url: str, parameter: str, payload: str) -> PoC:
    encoded = quote(payload)
    return PoC(
        steps=[
            f"Navigate to {target_url}",
            f"Append ?{parameter}={encoded} to the URL, or submit it via the vulnerable form field",
            "Observe the payload executing (alert box, or the interactsh callback if a blind sink)",
        ],
        curl_command=f'curl -s "{target_url}?{parameter}={encoded}"',
        code=f'<a href="{target_url}?{parameter}={encoded}">Click me (XSS PoC)</a>',
    )


def _sqli_poc(target_url: str, parameter: str, payload: str) -> PoC:
    encoded = quote(payload)
    return PoC(
        steps=[
            f"Send a request to {target_url} with {parameter} = {payload}",
            "Compare the response/timing against a benign baseline request",
            "Repeat 3 times to confirm before marking this finding confirmed",
        ],
        curl_command=f'curl -s "{target_url}?{parameter}={encoded}"',
        code=f"# sqlmap repro\nsqlmap -u '{target_url}?{parameter}=1' -p {parameter} --batch --risk=1 --level=1",
    )


def _ssrf_poc(target_url: str, parameter: str, payload: str) -> PoC:
    return PoC(
        steps=[
            f"Send a POST to {target_url}",
            f"Set {parameter} = {payload}",
            "Observe the metadata/internal response body, or the interactsh callback for blind SSRF",
        ],
        curl_command=f'curl -s -X POST "{target_url}" -d "{parameter}={payload}"',
        code="",
    )


def _generic_poc(target_url: str, parameter: str, payload: str) -> PoC:
    return PoC(
        steps=[
            f"Send the payload to {target_url} via parameter {parameter}",
            "Compare the response against a benign baseline",
            "Manual verification required — no templated PoC for this vuln type yet",
        ],
        curl_command=f'curl -s "{target_url}?{parameter}={quote(payload)}"',
        code="",
    )


_BUILDERS = {
    "xss": _xss_poc,
    "sqli": _sqli_poc,
    "ssrf": _ssrf_poc,
}


@tool
def build_poc(vuln_type: str, target_url: str, parameter: str, payload: str) -> dict:
    """Build a proof-of-concept for a confirmed vulnerability.

    Call this once a finding is confirmed, before handing it to the report
    agent. Returns a PoC dict: steps, code, curl_command, screenshot_path.
    """
    builder = _BUILDERS.get(vuln_type.lower(), _generic_poc)
    return builder(target_url, parameter, payload).model_dump()
