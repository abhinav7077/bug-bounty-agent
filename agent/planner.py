"""LLM planner: turns a natural-language hunt command into a structured ActionPlan.

Originally asked the model to free-hand a JSON plan (phase/action/target/args/
risk_level) from prose instructions alone, per docs/DEVELOPMENT_PLAN.md's
original Phase 1 sketch. Tested against the live model on 2026-07-16: it
reliably picks the right tool and target, but regularly invents args that
don't match a tool's real pydantic schema (e.g. a `scope_policy` key with a
`disallowed_domains` field when `check_scope` actually needs `domain` +
`policy.forbidden_domains`) — silent execution failures every time. Switched
to `llm.bind_tools(ALL_TOOLS)`, which hands the model each tool's actual JSON
schema instead of asking it to reconstruct one from prose — this is the same
mechanism agent/orchestrator.py's create_react_agent uses internally.
risk_level is NOT taken from the model at all — see agent/risk.py for why.

This is a multi-step planner: plan_step() takes the full conversation so far
(system prompt, command, and any prior tool_call/tool_result turns) and
returns the next single action, or None once the model has no more tool
calls to make. agent/graph.py loops plan -> awaiting_human -> execute -> plan
so a compound task (e.g. parse_scope_policy then check_scope with its output)
runs as a sequence of individually HITL-gated steps, rather than requiring
either a single perfect tool call or an ungated autonomous tool loop.
"""
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from agent.orchestrator import ALL_TOOLS
from agent.risk import risk_level_for
from config.prompts import ORCHESTRATOR_SYSTEM_PROMPT
from config.settings import settings

llm = ChatOllama(
    base_url=settings.OLLAMA_BASE_URL,
    model=settings.OLLAMA_MODEL,
    temperature=settings.LLM_TEMPERATURE,
    num_ctx=settings.OLLAMA_NUM_CTX,
).bind_tools(ALL_TOOLS)

# Verified live 2026-07-16: this model sometimes emits a pseudo-function-call as plain text
# (e.g. "<function=parse_scope_policy>...</function>") instead of populating response.tool_calls
# via the real tool-calling API — response.tool_calls comes back empty either way, so without
# this check plan_step() would silently treat a FAILED tool-call attempt as "the model is done,
# no more actions" (a final answer) rather than the mangled action it actually intended. That's
# a worse failure mode than a crash: the intended action just silently never happens. Any of
# these markers in a tool-call-less response means "raise, don't treat as final" instead.
_MALFORMED_TOOL_CALL_MARKERS = ("<function=", "<tool_call>", "<|tool_call|>", "[TOOL_CALL]")


class PlanParseError(Exception):
    """Raised when the model appears to have attempted a tool call but failed to format it."""


def _extract_target(args: dict) -> str:
    for key in ("domain", "target", "scope_text"):
        value = args.get(key)
        if isinstance(value, str):
            return value
    return "unspecified"


def initial_messages(command: str) -> list[BaseMessage]:
    """Build the starting conversation for a brand-new command."""
    return [SystemMessage(content=ORCHESTRATOR_SYSTEM_PROMPT), HumanMessage(content=command)]


def plan_step(messages: list[BaseMessage]) -> tuple[dict | None, BaseMessage]:
    """Ask the LLM for the next single step, given the conversation so far.

    Returns (plan, ai_message). plan is None once the model has no further
    tool calls to make — treat that as a final answer (ai_message.content)
    and route to REPORTING. Otherwise plan is: phase, action, target, args,
    risk_level, reason, tool_call_id (the last needed to build the matching
    ToolMessage once the tool has actually run). Raises PlanParseError if the
    model appears to have attempted a tool call in malformed text rather than
    genuinely finishing — see _MALFORMED_TOOL_CALL_MARKERS above.
    """
    response = llm.invoke(messages)
    if not response.tool_calls:
        content = response.content or ""
        if any(marker in content for marker in _MALFORMED_TOOL_CALL_MARKERS):
            raise PlanParseError(
                f"model attempted a tool call as malformed text instead of a real tool call: {content!r}"
            )
        return None, response

    call = response.tool_calls[0]
    action = call["name"]
    args = call["args"]

    plan = {
        "phase": "unspecified",
        "action": action,
        "target": _extract_target(args),
        "args": args,
        "risk_level": risk_level_for(action),
        "reason": response.content.strip() or f"model selected {action}",
        "tool_call_id": call["id"],
    }
    return plan, response
