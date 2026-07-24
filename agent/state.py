"""Shared state schema for the hunt state machine.

Stage transitions: IDLE -> PLANNING -> AWAITING_HUMAN -> EXECUTING -> REPORTING -> IDLE,
with a REJECT/ERROR path back to IDLE/ERROR from AWAITING_HUMAN or PLANNING.
"""
from enum import Enum
from typing import Any, TypedDict


class Stage(str, Enum):
    IDLE = "IDLE"
    PLANNING = "PLANNING"
    AWAITING_HUMAN = "AWAITING_HUMAN"
    EXECUTING = "EXECUTING"
    REPORTING = "REPORTING"
    ERROR = "ERROR"


class ActionPlan(TypedDict, total=False):
    phase: str
    action: str
    target: str
    args: dict[str, Any]
    risk_level: str
    reason: str


class HuntState(TypedDict, total=False):
    command: str
    stage: str
    plan: ActionPlan | None
    decision: str | None  # "approve" | "reject" | "modify"
    human_note: str
    result: Any
    findings: list[dict]
    error: str | None
    messages: list[Any]  # running LangChain BaseMessage history for this command
    step_count: int  # tool-call steps taken this command, bounded by agent/graph.py's MAX_STEPS


class ReconPipelineState(TypedDict, total=False):
    """State for agent/recon_pipeline.py's fixed-stage automated recon graph.

    Distinct from HuntState: HuntState's `stage` is the Stage enum
    (PLANNING/AWAITING_HUMAN/...) for ONE LLM-chosen tool call. Here `stage`
    is a plain string naming which fixed RECON_STAGES entry is current
    (subfinder/httpx/ports/crawl/params/dirs/enrichment/aggregate/done/
    error) — the sequence itself is hardcoded, not LLM-chosen, per
    docs/DEVELOPMENT_PLAN.md Phase 4's own "Goal" line.
    """
    target: str
    stage: str
    stage_index: int
    decision: str | None
    human_note: str
    pending_plan: ActionPlan | None
    error: str | None
    subdomains: list[str]
    diff: dict
    hosts_to_probe: list[str]
    live_hosts: list[str]
    ports_by_host: dict[str, list[int]]
    js_urls: list[str]
    all_findings: list[dict]  # every Finding dict from every stage, in order — feeds aggregate + memory
    aggregation: str | None


class VulnPipelineState(TypedDict, total=False):
    """State for agent/vuln_pipeline.py's fixed-stage automated vuln-assessment graph.

    Phase 5's counterpart to ReconPipelineState (Phase 4) — same fixed-
    sequence-not-LLM-chosen design (see agent/vuln_pipeline.py's own
    docstring for why), consuming a prior recon run's live_hosts/js_urls
    instead of starting from a bare domain.
    """
    target: str
    stage: str
    stage_index: int
    decision: str | None
    human_note: str
    pending_plan: ActionPlan | None
    error: str | None
    live_hosts: list[str]
    js_urls: list[str]
    tech_profiles: dict[str, dict]  # host -> TechProfile dict
    nuclei_tags: list[str]
    vuln_checklist: str | None
    graphql_endpoints: list[str]
    all_findings: list[dict]  # every Finding dict from every stage, in order
    assessments: list[dict]  # FindingAssessment dicts, aligned by index with all_findings
    chain_suggestions: str | None
    business_logic_hints: str | None
    gate_decisions: dict[int, dict]  # all_findings index -> {"decision": ..., "note": ...}
    confirmed_pocs: list[dict]
    interactsh_domain: str | None
    interactsh_session_id: str | None
    oob_findings: list[dict]
    auth_token: str  # human-supplied test credential; empty means auth_probe is a no-op (see that stage)
    auth_other_identity_token: str  # optional second identity, enables check_idor's differential-auth check
