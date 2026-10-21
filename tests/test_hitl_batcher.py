"""Approval-batching UX contracts (skills/hitl_batcher.py).

Batching repetitive LOW/MEDIUM actions into one approval is how the project
avoids training a human to rubber-stamp a flood of near-identical prompts, so
the grouping key (tool + risk_level) and the per-group count are pinned here.
"""
from skills.hitl_batcher import ApprovalBatch, explain_action, group_for_batch_approval


def _action(tool, risk, target, reason="probe"):
    return {"action": tool, "risk_level": risk, "target": target, "reason": reason}


def test_same_tool_same_risk_collapses_to_one_batch():
    actions = [
        _action("run_httpx", "MEDIUM", "a.example.com"),
        _action("run_httpx", "MEDIUM", "b.example.com"),
        _action("run_httpx", "MEDIUM", "c.example.com"),
    ]
    batches = group_for_batch_approval(actions)
    assert len(batches) == 1
    batch = batches[0]
    assert isinstance(batch, ApprovalBatch)
    assert batch.tool_name == "run_httpx"
    assert batch.risk_level == "MEDIUM"
    assert batch.count == 3
    assert batch.targets == ["a.example.com", "b.example.com", "c.example.com"]


def test_different_tool_or_risk_stays_separate():
    actions = [
        _action("run_httpx", "MEDIUM", "a.example.com"),
        _action("run_subfinder", "LOW", "example.com"),
        _action("run_httpx", "MEDIUM", "b.example.com"),
    ]
    batches = {(b.tool_name, b.risk_level): b for b in group_for_batch_approval(actions)}
    assert set(batches) == {("run_httpx", "MEDIUM"), ("run_subfinder", "LOW")}
    assert batches[("run_httpx", "MEDIUM")].count == 2
    assert batches[("run_subfinder", "LOW")].count == 1


def test_missing_keys_fall_back_to_defaults_not_crash():
    batches = group_for_batch_approval([{}])
    assert len(batches) == 1
    assert batches[0].tool_name == "unknown"
    assert batches[0].risk_level == "MEDIUM"


def test_explain_action_includes_risk_tool_target_and_rule():
    line = explain_action(
        _action("run_nuclei", "MEDIUM", "example.com", reason="tech matched a template tag"),
        triggered_rule="rule 3: MEDIUM risk requires plan review",
    )
    assert "[MEDIUM]" in line
    assert "run_nuclei" in line
    assert "example.com" in line
    assert "tech matched a template tag" in line
    assert "rule 3" in line
