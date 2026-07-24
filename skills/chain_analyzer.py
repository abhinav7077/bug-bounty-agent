"""Vuln-chaining reasoner.

Called after each scan phase with the accumulated finding set. This is
where a pile of low/medium findings gets reasoned over for combinations
that add up to a critical — per VULN_AGENT_PROMPT, every finding must be
asked "can this chain with anything else found?"
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

_CHAIN_PROMPT_TEMPLATE = """You are a bug bounty chain analyst. Given these findings, identify any \
combinations that create a higher-severity vulnerability than each finding alone.

Common chains to look for:
- Open Redirect + CSRF -> account takeover
- Stored XSS + CSRF token leak -> full account takeover
- SSRF + cloud metadata -> credential theft -> RCE
- IDOR + info disclosure -> targeted attacks at scale
- Self-XSS + CSRF -> stored XSS exploitation
- Subdomain takeover + cookie scoping -> session hijack on main domain

FINDINGS:
{findings_json}

Return ONLY a JSON array, no prose, in this shape:
[{{"findings_used": [], "chain_type": "", "potential_severity": "", "steps_to_prove": []}}]
If no chain is plausible, return [].
"""


class ChainSuggestion(BaseModel):
    findings_used: list[str]
    chain_type: str
    potential_severity: str
    steps_to_prove: list[str]


@tool
def analyze_chains(findings_json: str) -> str:
    """Analyze a list of findings to identify vulnerability chains.

    Call this after each scan phase, not just once at the end — chains often
    only become visible once a new finding lands next to an older one.
    Input: JSON string of Finding objects (list of dicts).
    Returns: JSON string — a list of ChainSuggestion objects (may be empty).
    """
    prompt = _CHAIN_PROMPT_TEMPLATE.format(findings_json=findings_json)
    response = _llm.invoke([HumanMessage(content=prompt)])
    content = response.content.strip()

    # Defensive parse: keep the raw text if the model wraps it in prose/fences,
    # but never let a malformed response crash the calling pipeline.
    try:
        start, end = content.index("["), content.rindex("]") + 1
        parsed = json.loads(content[start:end])
        [ChainSuggestion(**item) for item in parsed]  # validate shape
        return json.dumps(parsed)
    except (ValueError, TypeError, json.JSONDecodeError):
        return "[]"
