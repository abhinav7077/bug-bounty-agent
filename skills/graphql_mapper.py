"""GraphQL introspection + schema mapping, plus a GraphQL-flavored BOLA/IDOR
check. Closes docs/DEVELOPMENT_PLAN.md's Phase 3 Tier 2 `graphql.py` item.

check_graphql_idor mirrors skills/auth_mapper.py's check_idor logic applied
to a GraphQL query body instead of a REST URL path — same false-positive
guards (tools/response_fingerprint's is_distinct_object/responses_equivalent),
same reasoning for why it's HIGH risk in agent/risk.py (an active identity/
object-access bypass attempt, not passive inspection).
"""
import json

from langchain_core.tools import tool

from tools.base import Finding, ToolResult
from tools.http_client import send_request
from tools.response_fingerprint import is_distinct_object, responses_equivalent

_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields { name args { name } }
    }
  }
}
"""

_SENSITIVE_MUTATION_KEYWORDS = (
    "delete", "remove", "update", "admin", "password", "transfer", "grant",
    "role", "permission", "escalate", "promote", "impersonate", "reset",
    "create", "disable", "enable", "ban", "suspend",
)

_ID_CANDIDATES_NUMERIC = ["0", "1", "2", "99", "100"]


@tool
async def introspect_graphql(endpoint_url: str) -> dict:
    """Run GraphQL introspection against a discovered /graphql endpoint and map its schema.

    MEDIUM risk — one real POST request to the target; purely informational,
    no mutation is ever called, only the schema is read. Call check_scope
    first. Many programs consider introspection-enabled-in-production a
    real (if low-severity) finding on its own — reported here as such rather
    than silently treated as just a means to an end.
    """
    resp = await send_request(
        "POST", endpoint_url,
        headers={"Content-Type": "application/json"},
        data=json.dumps({"query": _INTROSPECTION_QUERY}),
    )
    if resp.error:
        return ToolResult(
            tool="introspect_graphql", command_run=f"introspect_graphql({endpoint_url})",
            raw_output="", parsed=[], duration_s=resp.elapsed_ms / 1000, error=resp.error,
        ).model_dump()

    try:
        body = json.loads(resp.body)
    except ValueError:
        body = {}
    schema = (body.get("data") or {}).get("__schema") if isinstance(body, dict) else None

    if not schema:
        return ToolResult(
            tool="introspect_graphql", command_run=f"introspect_graphql({endpoint_url})",
            raw_output=resp.body[:2000], parsed=[], duration_s=resp.elapsed_ms / 1000,
            error=None,  # not an error condition — introspection being disabled is itself the signal
        ).model_dump()

    findings = [Finding(
        type="graphql_introspection_enabled", target=endpoint_url,
        detail="Introspection query succeeded — schema is fully readable without authentication.",
        severity="low", tool_source="graphql_mapper",
    )]

    mutation_type_name = (schema.get("mutationType") or {}).get("name")
    types_by_name = {t["name"]: t for t in schema.get("types", []) if t.get("name")}
    mutation_fields = (types_by_name.get(mutation_type_name) or {}).get("fields") or []

    for field in mutation_fields:
        name = field.get("name", "")
        if any(keyword in name.lower() for keyword in _SENSITIVE_MUTATION_KEYWORDS):
            args = ", ".join(a["name"] for a in field.get("args", []))
            findings.append(Finding(
                type="graphql_sensitive_mutation", target=endpoint_url,
                detail=f"mutation {name}({args}) — matches a sensitive-action keyword, review authorization on it",
                severity="medium", tool_source="graphql_mapper",
            ))

    return ToolResult(
        tool="introspect_graphql", command_run=f"introspect_graphql({endpoint_url})",
        raw_output=resp.body[:4000], parsed=findings, duration_s=resp.elapsed_ms / 1000, error=None,
    ).model_dump()


def _graphql_has_real_data(body: str) -> bool:
    try:
        parsed = json.loads(body)
    except ValueError:
        return False
    if not isinstance(parsed, dict) or parsed.get("errors"):
        return False
    data = parsed.get("data")
    if not data:
        return False
    return any(v not in (None, {}, []) for v in data.values())


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


@tool
async def check_graphql_idor(
    endpoint_url: str, query: str, original_id: str, token: str = "", other_identity_token: str = "",
) -> dict:
    """Check a single GraphQL query for BOLA/IDOR, the same way check_idor does for REST.

    HIGH risk — actively probes for access to objects the calling identity
    may not be authorized to see, and (with other_identity_token) presents a
    second identity's token against the same query. Call check_scope first.

    `query` is a full GraphQL query STRING with the object's real ID embedded
    as a literal (e.g. 'query { user(id: "42") { name email } }'); `original_id`
    is that same literal value ("42") — used both as the value to swap out for
    ID-mutation candidates and to confirm the substitution only touches the ID.

    Two independent techniques, each with its own false-positive guard,
    exactly mirroring check_idor:
    1. ID mutation: swaps original_id for a small bounded set of alternates
       (0/1/2/99/100) with the SAME token, flags a hit only if the response
       has real (non-null, non-error) data AND is a genuinely distinct object
       from the baseline. Stops at the first confirmed hit.
    2. Differential-auth (only if other_identity_token given): sends the
       identical query with both tokens, flags CRITICAL only if both
       responses are equivalent — two different identities served the same
       object — never the common, correct case of each seeing their own data.
    """
    baseline = await send_request(
        "POST", endpoint_url, headers={"Content-Type": "application/json", **_bearer(token)},
        data=json.dumps({"query": query}),
    )
    findings: list[Finding] = []

    if _graphql_has_real_data(baseline.body):
        for candidate in _ID_CANDIDATES_NUMERIC:
            if candidate == original_id or original_id not in query:
                continue
            mutated_query = query.replace(original_id, candidate)
            resp = await send_request(
                "POST", endpoint_url, headers={"Content-Type": "application/json", **_bearer(token)},
                data=json.dumps({"query": mutated_query}),
            )
            if _graphql_has_real_data(resp.body) and is_distinct_object(baseline.body, resp.body):
                findings.append(Finding(
                    type="graphql_bola_id_mutation", target=endpoint_url,
                    detail=f"Same token, id {original_id!r} -> {candidate!r}: got distinct real data back.",
                    severity="high", tool_source="graphql_mapper",
                ))
                break

        if other_identity_token:
            other_resp = await send_request(
                "POST", endpoint_url,
                headers={"Content-Type": "application/json", **_bearer(other_identity_token)},
                data=json.dumps({"query": query}),
            )
            if _graphql_has_real_data(other_resp.body) and responses_equivalent(baseline.body, other_resp.body):
                findings.append(Finding(
                    type="graphql_bola_differential_auth", target=endpoint_url,
                    detail="Two different identities' tokens both retrieved the SAME object via the identical query.",
                    severity="critical", tool_source="graphql_mapper",
                ))

    return ToolResult(
        tool="check_graphql_idor", command_run=f"check_graphql_idor({endpoint_url})",
        raw_output=baseline.body[:2000], parsed=findings,
        duration_s=baseline.elapsed_ms / 1000, error=baseline.error,
    ).model_dump()
