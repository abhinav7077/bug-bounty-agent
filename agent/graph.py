"""LangGraph state machine: IDLE -> PLANNING -> AWAITING_HUMAN -> EXECUTING -> REPORTING.

This loops: plan -> awaiting_human -> execute -> plan -> ... rather than a
single plan/execute pass, so a compound task (e.g. parse_scope_policy, then
check_scope using its output) runs as a sequence of individually HITL-gated
tool calls instead of needing either one perfect tool call or an ungated
autonomous loop. The model decides when it's done: plan_step() returning no
tool call means "final answer," which routes straight to REPORTING. A
MAX_STEPS bound guards against a runaway/looping model burning through
approval prompts indefinitely.

Reject at AWAITING_HUMAN routes to END (back to IDLE for the next command).
Modify at AWAITING_HUMAN loops back to PLANNING with the human's note appended
to the conversation. Any lookup/execution/LLM failure routes to ERROR -> END.
See docs/DEVELOPMENT_PLAN.md Phase 1 "LangGraph State Machine" and
agent/state.py for the schema.
"""
import asyncio
import json

from langchain_core.messages import HumanMessage, ToolMessage
from langgraph.graph import END, START, StateGraph

from agent.hitl import request_approval
from agent.orchestrator import ALL_TOOLS
from agent.planner import initial_messages, plan_step
from agent.state import HuntState, Stage
from skills.scope_parser import looks_like_scope_text

_TOOLS_BY_NAME = {t.name: t for t in ALL_TOOLS}
MAX_STEPS = 6  # bound on chained tool calls per command — see module docstring

# The scope-fabrication gap (see MEMORY.md "Phase 2 kickoff"): verified live that the model
# will invent a plausible-looking scope policy from its own training knowledge rather than
# asking the human, when none has actually been provided. A prompt rule alone (rule 1) was
# tried and confirmed NOT sufficient — this is the structural fix instead. Every tool here
# either consumes raw scope text directly or a ScopePolicy the model could equally fabricate
# by skipping parse_scope_policy — gate all three on the same real-text check, not just the
# one the original bug happened to surface.
_SCOPE_GATED_TOOLS = {"parse_scope_policy", "check_scope", "check_policy_compliance"}


def _human_provided_scope_text(messages: list) -> bool:
    """True if some HumanMessage anywhere in this conversation looks like real scope-page text.

    Deliberately checks the WHOLE conversation, including the very first message — the
    verified-live compound command from session 2 ("is www.example.com in scope, given this
    policy text: ...") pastes real scope text inline as part of the initial command itself,
    not as a separate later turn, and that must still pass. What must NOT pass is a command
    that only NAMES a target with no real policy text anywhere ("is api.hackerone.com in
    scope for HackerOne?") — looks_like_scope_text's marker+domain-count heuristic is what
    tells those two apart, not message position.
    """
    return any(
        looks_like_scope_text(m.content) for m in messages
        if isinstance(m, HumanMessage) and isinstance(m.content, str)
    )


def node_plan(state: HuntState) -> HuntState:
    messages = state.get("messages")
    if messages is None:
        messages = initial_messages(state["command"])
    elif state.get("decision") == "modify" and state.get("human_note"):
        messages = messages + [HumanMessage(
            content=f"The human rejected or modified the previous plan with this note: "
                    f"{state['human_note']}. Produce a revised plan."
        )]

    try:
        plan, ai_message = plan_step(messages)
    except Exception as exc:  # LLM call itself failing (connection, etc.) — never crash the graph
        return {**state, "stage": Stage.ERROR, "error": str(exc)}

    messages = messages + [ai_message]

    if plan is None:
        # No further tool calls — the model's text response is the final answer.
        return {**state, "stage": Stage.REPORTING, "messages": messages, "result": ai_message.content}

    if plan["action"] in _SCOPE_GATED_TOOLS and not _human_provided_scope_text(messages):
        # Refuse BEFORE the human ever sees an approval prompt for this — showing one would
        # imply the scope_text/policy is legitimate and invite a rushed approve. Routes to
        # ERROR instead of silently executing on the model's (possibly fabricated) args.
        return {
            **state,
            "stage": Stage.ERROR,
            "messages": messages,
            "error": (
                f"Refused to run {plan['action']!r}: no real scope/policy text has been "
                "provided in this conversation. The model may be about to fabricate a scope "
                "policy from its own training knowledge instead of asking you for the real "
                "one — paste the actual program scope/policy text and retry."
            ),
        }

    return {
        **state,
        "stage": Stage.AWAITING_HUMAN,
        "plan": plan,
        "messages": messages,
        "error": None,
        "decision": None,
        "human_note": "",
    }


def node_awaiting_human(state: HuntState) -> HuntState:
    result = request_approval(state["plan"])
    return {**state, "decision": result.decision, "human_note": result.note}


def node_execute(state: HuntState) -> HuntState:
    plan = state["plan"]
    action_name = plan.get("action", "")
    tool = _TOOLS_BY_NAME.get(action_name)
    messages = state.get("messages", [])

    if tool is None:
        return {
            **state,
            "stage": Stage.ERROR,
            "error": f"unknown action {action_name!r} — not registered in ALL_TOOLS "
                     f"(known: {sorted(_TOOLS_BY_NAME)})",
        }
    try:
        # ainvoke() (run via asyncio.run) rather than invoke(): works uniformly for both
        # sync skills (LangChain runs them in a thread executor) and async-only tool
        # wrappers like tools/recon.py's run_subfinder — plain invoke() raises
        # "StructuredTool does not support sync invocation" for the latter, confirmed live.
        result = asyncio.run(tool.ainvoke(plan.get("args", {})))
    except Exception as exc:  # tool wrappers can raise anything; never crash the graph
        return {**state, "stage": Stage.ERROR, "error": f"{action_name} failed: {exc}"}

    findings = list(state.get("findings", []))
    findings.append({"action": action_name, "target": plan.get("target"), "result": result})

    tool_message = ToolMessage(
        content=json.dumps(result, default=str),
        tool_call_id=plan.get("tool_call_id", ""),
    )
    messages = messages + [tool_message]

    step_count = state.get("step_count", 0) + 1
    next_stage = Stage.REPORTING if step_count >= MAX_STEPS else Stage.PLANNING

    return {
        **state,
        "stage": next_stage,
        "result": result,
        "findings": findings,
        "messages": messages,
        "step_count": step_count,
    }


def node_report(state: HuntState) -> HuntState:
    return {**state, "stage": Stage.IDLE}


def node_error(state: HuntState) -> HuntState:
    return {**state, "stage": Stage.ERROR}


def _route_after_plan(state: HuntState) -> str:
    if state["stage"] == Stage.ERROR:
        return "error"
    if state["stage"] == Stage.REPORTING:
        return "report"
    return "awaiting_human"


def _route_after_human(state: HuntState) -> str:
    decision = state.get("decision")
    if decision == "approve":
        return "execute"
    if decision == "modify":
        return "plan"
    return "end"  # reject


def _route_after_execute(state: HuntState) -> str:
    if state["stage"] == Stage.ERROR:
        return "error"
    if state["stage"] == Stage.REPORTING:
        return "report"
    return "plan"  # loop back — the model may have a follow-up tool call


def build_graph():
    graph = StateGraph(HuntState)
    graph.add_node("plan", node_plan)
    graph.add_node("awaiting_human", node_awaiting_human)
    graph.add_node("execute", node_execute)
    graph.add_node("report", node_report)
    graph.add_node("error", node_error)

    graph.add_edge(START, "plan")
    graph.add_conditional_edges(
        "plan", _route_after_plan, {"error": "error", "awaiting_human": "awaiting_human", "report": "report"}
    )
    graph.add_conditional_edges(
        "awaiting_human", _route_after_human, {"execute": "execute", "plan": "plan", "end": END}
    )
    graph.add_conditional_edges(
        "execute", _route_after_execute, {"error": "error", "plan": "plan", "report": "report"}
    )
    graph.add_edge("report", END)
    graph.add_edge("error", END)

    return graph.compile()


def run_command(command: str) -> HuntState:
    """Run one natural-language command through the full HITL-gated state machine."""
    graph = build_graph()
    initial: HuntState = {"command": command, "stage": Stage.PLANNING, "findings": []}
    return graph.invoke(initial)
