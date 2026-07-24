"""Business-logic / workflow-state reasoner.

Payload-based tools (XSS/SQLi/SSRF fuzzers, nuclei templates) are commodity —
every automated hunter runs the same ones. The value on a mature program is
in flaws that only exist because of *sequence* or *state*: step-skipping,
price/quantity tampering, coupon reuse, IDOR via predictable IDs introduced
mid-flow, races on rate-limited actions. Those require modeling the flow as
a state machine, not fuzzing individual parameters in isolation.
"""
import json

from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from pydantic import BaseModel

from config.settings import settings

_llm = ChatOllama(
    base_url=settings.OLLAMA_BASE_URL,
    model=settings.OLLAMA_MODEL,
    temperature=settings.LLM_TEMPERATURE,
    num_ctx=settings.OLLAMA_NUM_CTX,
)

_WORKFLOW_PROMPT_TEMPLATE = """You are a business-logic flaw analyst for a bug bounty hunt.
Given this sequence of observed HTTP requests that make up one user-facing flow \
(e.g. checkout, invite, password reset, refund), look for logic flaws that ONLY \
exist because of the sequence or state, not from any single request in isolation.

Look specifically for:
- Step-skipping: can a later step be called without completing an earlier one?
- Parameter tampering carried across steps: price, quantity, currency, role, \
or user_id trusted unchanged from an earlier step
- Coupon/discount/promo reuse or stacking
- IDOR via predictable/sequential IDs introduced mid-flow (e.g. order_id, invite_id)
- Race conditions on a rate-limited or one-time action (redeem, vote, withdraw)
- Missing re-authentication/re-authorization on a sensitive later step

FLOW NAME: {flow_name}
REQUEST SEQUENCE:
{steps_json}

Return ONLY a JSON array, no prose, in this shape:
[{{"suspected_flaw": "", "steps_involved": [], "how_to_test": [], "potential_severity": ""}}]
If nothing plausible, return [].
"""


class WorkflowFinding(BaseModel):
    suspected_flaw: str
    steps_involved: list[str]
    how_to_test: list[str]
    potential_severity: str


@tool
def map_business_logic(flow_name: str, steps_json: str) -> str:
    """Reason over a multi-step request flow for business-logic flaws.

    Call this once a crawl pass has grouped requests into a named flow
    (checkout, invite, password-reset, refund, etc). Input: flow_name plus a
    JSON array of the observed steps (method, path, params, notable state).
    Output: a JSON array of WorkflowFinding objects (may be empty). These
    findings are NEVER auto-confirmable — per VULN_AGENT_PROMPT, business
    logic flaws always require human review regardless of confidence.
    """
    prompt = _WORKFLOW_PROMPT_TEMPLATE.format(flow_name=flow_name, steps_json=steps_json)
    response = _llm.invoke([HumanMessage(content=prompt)])
    content = response.content.strip()

    try:
        start, end = content.index("["), content.rindex("]") + 1
        parsed = json.loads(content[start:end])
        [WorkflowFinding(**item) for item in parsed]  # validate shape
        return json.dumps(parsed)
    except (ValueError, TypeError, json.JSONDecodeError):
        return "[]"
