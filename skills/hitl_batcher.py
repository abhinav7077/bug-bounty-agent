"""Human-approval UX helpers — batching and explanation.

NOT registered as an LLM tool and must never be added to
agent/orchestrator.py's ALL_TOOLS — nothing here is meant to be called by
the model. These are plain functions for agent/hitl.py (not yet built, see
MEMORY.md) to import when it renders an approval prompt. Two problems this
solves: (1) asking for 50 individual approvals for 50 identical low-risk
probes is how humans start rubber-stamping without reading, and (2) a bare
"approve this?" prompt with no reasoning trains the human to stop thinking
about it too.
"""
from collections import defaultdict

from pydantic import BaseModel


class ApprovalBatch(BaseModel):
    tool_name: str
    risk_level: str
    targets: list[str]
    sample_action: dict
    count: int


def group_for_batch_approval(actions: list[dict]) -> list[ApprovalBatch]:
    """Group planned actions by (tool, risk_level) into one approval per group.

    Each action dict is expected to have at least: action (tool name),
    risk_level, target. Same tool + same risk_level == one approval prompt
    covering every target in the group, instead of one prompt per target.
    HIGH-risk actions should still be reviewed individually upstream in the
    orchestrator — batching is for LOW/MEDIUM repetitive work only.
    """
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for action in actions:
        key = (action.get("action", "unknown"), action.get("risk_level", "MEDIUM"))
        groups[key].append(action)

    batches = []
    for (tool_name, risk_level), group_actions in groups.items():
        batches.append(ApprovalBatch(
            tool_name=tool_name,
            risk_level=risk_level,
            targets=[a.get("target", "") for a in group_actions],
            sample_action=group_actions[0],
            count=len(group_actions),
        ))
    return batches


def explain_action(action: dict, triggered_rule: str) -> str:
    """Produce the one-line 'why' shown alongside every approval prompt.

    triggered_rule should name the specific ORCHESTRATOR_SYSTEM_PROMPT rule
    that put this action in front of the human (e.g. "rule 3: MEDIUM risk
    requires plan review" or "rule 6: scope unresolved, human must decide").
    Never show a bare action with no rationale attached.
    """
    tool_name = action.get("action", "unknown action")
    target = action.get("target", "unspecified target")
    risk = action.get("risk_level", "MEDIUM")
    reason = action.get("reason", "no stated reason")
    return f'[{risk}] {tool_name} -> {target}: "{reason}" (triggered {triggered_rule})'
