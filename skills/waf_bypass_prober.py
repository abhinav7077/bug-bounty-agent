"""WAF/filter-bypass ACTIVE prober — closes the loop skills/bypass.py's
get_waf_bypasses deliberately leaves open.

get_waf_bypasses only GENERATES candidate variants for a blocked payload; it
never sends anything itself ("this function never sends a request itself" —
see its own docstring), leaving the actual retry to whichever caller has a
concrete blocked/filtered signal to react to. This is that caller: it
replays a payload's bypass variants via tools/http_client.py's send_request
(the same direct-HTTP primitive skills/auth_mapper.py and
skills/graphql_mapper.py already use for custom request/response logic with
no single CLI tool behind it).

Closes docs/DEVELOPMENT_PLAN.md's Phase 5 "On any blocked/filtered payload
response, invoke bypass.py to generate and retry variants" item — wired
into agent/vuln_pipeline.py's xss_probe stage, the first stage in this
pipeline that produces a genuine "blocked/filtered" signal to react to (see
that stage's own comment: run_kxss confirms a param reflects special
characters, but run_dalfox's own docstring warns a `findings: []` result
there does NOT mean "confirmed clean" — that combination is the trigger).
"""
from langchain_core.tools import tool

from skills.bypass import get_waf_bypasses
from tools.base import Finding, ToolResult
from tools.http_client import send_request

_MAX_VARIANTS_TRIED = 6  # bounded -- get_waf_bypasses can return 10+ variants, one hit is enough signal


def _reflects_unescaped(body: str, payload: str) -> bool:
    """True if `payload` survives verbatim in `body`.

    A WAF/sanitizer typically HTML-entity-encodes, strips, or blocks a
    payload outright rather than returning a non-200 — checking for the
    LITERAL payload substring (not just a status code) is what actually
    distinguishes "reflected unfiltered" from "the page loaded fine but the
    payload was neutralized," the same style of check
    tools/response_fingerprint.py's helpers use elsewhere in this codebase.
    """
    return payload in body


@tool
async def probe_waf_bypass(url: str, param: str, blocked_payload: str) -> dict:
    """Retry a blocked/filtered payload's bypass variants against the real target.

    HIGH risk — actively crafts and sends filter-evasion payload variants
    directly to the target, same reasoning as check_idor/check_jwt_weaknesses:
    an active bypass attempt, not passive inspection. Call check_scope on
    url's host first.

    Call this only once there's already a concrete signal the ORIGINAL
    payload got blocked/filtered (see this module's own docstring for the
    kxss+dalfox combination agent/vuln_pipeline.py uses to detect one).
    Re-sends `blocked_payload` once as a baseline re-confirmation, then up to
    6 of get_waf_bypasses' generated variants (its plain-English method/
    header-switch hints aren't retryable via a single GET and are skipped),
    stopping at the first variant whose exact text survives unescaped in the
    response body. Returns at most one Finding — one confirmed bypass is
    enough signal; this isn't trying to enumerate every working variant.
    """
    baseline = await send_request("GET", url, params={param: blocked_payload})
    if baseline.error:
        return ToolResult(
            tool="probe_waf_bypass", command_run=f"probe_waf_bypass({url}, {param})",
            raw_output="", parsed=[], duration_s=baseline.elapsed_ms / 1000, error=baseline.error,
        ).model_dump()

    if _reflects_unescaped(baseline.body, blocked_payload):
        # The "blocked" premise didn't hold on THIS request -- not an error,
        # just nothing to bypass right now.
        return ToolResult(
            tool="probe_waf_bypass", command_run=f"probe_waf_bypass({url}, {param})",
            raw_output=baseline.body[:500], parsed=[],
            duration_s=baseline.elapsed_ms / 1000, error=None,
        ).model_dump()

    # get_waf_bypasses appends a few plain-English instructions (method/
    # header-switch hints) after its real string-transform variants -- those
    # aren't single-GET-retryable, so skip anything that isn't a payload
    # transform at all (its own docstring: "retry as PUT/PATCH/TRACE...").
    raw_variants = get_waf_bypasses.invoke({"blocked_payload": blocked_payload})
    variants = [v for v in raw_variants if not v.lower().startswith("retry ")]

    findings = []
    for variant in variants[:_MAX_VARIANTS_TRIED]:
        resp = await send_request("GET", url, params={param: variant})
        if not resp.error and _reflects_unescaped(resp.body, variant):
            findings.append(Finding(
                type="waf_bypass_confirmed", target=url,
                detail=(
                    f"param={param} original_payload={blocked_payload!r} was filtered, "
                    f"bypass variant {variant!r} reflected unescaped"
                ),
                severity="high", tool_source="waf_bypass_prober",
            ))
            break

    return ToolResult(
        tool="probe_waf_bypass", command_run=f"probe_waf_bypass({url}, {param})",
        raw_output=baseline.body[:500], parsed=findings,
        duration_s=baseline.elapsed_ms / 1000, error=None,
    ).model_dump()
