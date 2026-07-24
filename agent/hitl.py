"""Human-in-the-loop approval gate.

Per ORCHESTRATOR_SYSTEM_PROMPT rule 3: LOW risk (passive recon) auto-proceeds
(but is still shown, never silent), MEDIUM shows the plan and asks
approve/reject/modify, HIGH requires the literal word "yes" — anything else
is treated as reject, never defaulted to approve. This must fire before any
active scan, exploit attempt, submission, or new target (rule 2 + Phase 1
"Gate must fire before" list) — the orchestrator graph in agent/graph.py
routes every plan through here before EXECUTING.

Phase 6 addition: the actual I/O (how a decision reaches this module) is now
a pluggable, THREAD-LOCAL ApprovalBackend rather than hardcoded stdin. Every
caller (agent/graph.py, agent/recon_pipeline.py, agent/vuln_pipeline.py)
still just calls request_approval()/request_batch_approval() — swapping
backends is invisible to all three, and none of them needed a single line
changed. Thread-local, not a plain module global: ui/app.py runs one hunt
per background thread so two concurrent browser sessions (or one browser
session and the main.py terminal loop, in principle) never fight over which
backend is "active" — each thread that never opts in still gets the
original ConsoleApprovalBackend, byte-for-byte the same prompts/behavior as
before this refactor. See agent/web_hitl.py for the web-facing backend.
"""
import threading
from dataclasses import dataclass, field

from rich.console import Console
from rich.panel import Panel

from skills.hitl_batcher import explain_action, group_for_batch_approval

console = Console()

_RISK_STYLE = {"LOW": "cyan", "MEDIUM": "yellow", "HIGH": "bold red"}

_RULE_FOR_RISK = {
    "LOW": "rule 3: LOW risk (passive recon) — auto-proceeds, shown for visibility",
    "MEDIUM": "rule 2 + rule 3: MEDIUM risk (active scan) — plan shown, approval required",
    "HIGH": "rule 3: HIGH risk (exploit/submission) — explicit \"yes\" required",
}


@dataclass
class ApprovalResult:
    decision: str  # "approve" | "reject" | "modify"
    note: str = field(default="")


def triggered_rule_for(risk_level: str) -> str:
    return _RULE_FOR_RISK.get(risk_level.upper(), "rule 3: risk level unrecognized — treat as MEDIUM")


def _render(action: dict, triggered_rule: str) -> None:
    risk = action.get("risk_level", "MEDIUM").upper()
    style = _RISK_STYLE.get(risk, "yellow")
    console.print(Panel(
        explain_action(action, triggered_rule),
        title=f"[{style}]{risk} RISK ACTION[/{style}]",
        border_style=style,
    ))


class ApprovalBackend:
    """Pluggable HITL I/O. Every graph node calls the module-level
    request_approval()/request_batch_approval() functions below, never a
    backend directly — see set_approval_backend()'s own docstring for how
    a thread opts into a different one.
    """

    def request(self, action: dict, triggered_rule: str | None = None) -> ApprovalResult:
        raise NotImplementedError

    def request_batch(self, actions: list[dict]) -> list[ApprovalResult]:
        raise NotImplementedError


class ConsoleApprovalBackend(ApprovalBackend):
    """The original (pre-Phase-6) terminal behavior, extracted unchanged.

    Still the default for every thread that never calls
    set_approval_backend() — main.py's CLI loop is unaffected by this
    refactor, not just "mostly the same."
    """

    def request(self, action: dict, triggered_rule: str | None = None) -> ApprovalResult:
        risk = action.get("risk_level", "MEDIUM").upper()
        triggered_rule = triggered_rule or triggered_rule_for(risk)
        _render(action, triggered_rule)

        if risk == "LOW":
            console.print("[cyan]LOW risk — auto-proceeding.[/cyan]")
            return ApprovalResult(decision="approve")

        if risk == "HIGH":
            response = console.input(
                "[bold red]Type 'yes' to proceed with this HIGH-risk action (anything else rejects): [/bold red]"
            ).strip()
            if response.lower() == "yes":
                return ApprovalResult(decision="approve")
            return ApprovalResult(decision="reject", note=response)

        # MEDIUM
        response = console.input("[yellow]approve / reject / modify: [/yellow]").strip().lower()
        if response.startswith("a"):
            return ApprovalResult(decision="approve")
        if response.startswith("m"):
            note = console.input("What should change? ").strip()
            return ApprovalResult(decision="modify", note=note)
        return ApprovalResult(decision="reject", note=response)

    def request_batch(self, actions: list[dict]) -> list[ApprovalResult]:
        results_by_index: dict[int, ApprovalResult] = {}

        for batch in group_for_batch_approval(actions):
            indices = [
                i for i, a in enumerate(actions)
                if a.get("action") == batch.tool_name
                and a.get("risk_level", "MEDIUM").upper() == batch.risk_level.upper()
            ]

            if batch.risk_level.upper() == "HIGH":
                for i in indices:
                    results_by_index[i] = self.request(actions[i])
                continue

            style = _RISK_STYLE.get(batch.risk_level.upper(), "yellow")
            console.print(Panel(
                f"{batch.count}x {batch.tool_name} ({batch.risk_level}) across: {', '.join(batch.targets)}",
                title=f"Batch approval — {batch.tool_name}",
                border_style=style,
            ))
            response = console.input("approve all / reject all / review each: ").strip().lower()
            if response.startswith("a"):
                for i in indices:
                    results_by_index[i] = ApprovalResult(decision="approve")
            elif response.startswith("rev"):
                for i in indices:
                    results_by_index[i] = self.request(actions[i])
            else:
                for i in indices:
                    results_by_index[i] = ApprovalResult(decision="reject")

        return [results_by_index[i] for i in range(len(actions))]


_default_backend = ConsoleApprovalBackend()
_local = threading.local()


def _active_backend() -> ApprovalBackend:
    return getattr(_local, "backend", None) or _default_backend


def set_approval_backend(backend: ApprovalBackend) -> ApprovalBackend:
    """Opt THIS THREAD into a different ApprovalBackend, returning the
    previous one (so a caller can restore it, e.g. in a finally: block).

    Only affects the calling thread — deliberately not a plain module
    global, since two concurrent hunts (ui/app.py runs each in its own
    background thread) must never resolve each other's pending approvals.
    """
    global _local
    previous = _active_backend()
    _local.backend = backend
    return previous


def get_approval_backend() -> ApprovalBackend:
    return _active_backend()


def request_approval(action: dict, triggered_rule: str | None = None) -> ApprovalResult:
    """Gate a single action through whichever ApprovalBackend this thread is using.

    Call this for every MEDIUM/HIGH action, and even for LOW (it auto-approves
    but still renders, so the human sees everything that ran).
    """
    return _active_backend().request(action, triggered_rule)


def request_batch_approval(actions: list[dict]) -> list[ApprovalResult]:
    """Batch-approve repetitive LOW/MEDIUM actions, one prompt per (tool, risk) group.

    Returns one ApprovalResult per input action, same order as given.
    HIGH-risk actions are never batched (per skills/hitl_batcher.py's
    docstring) — each still gets its own request_approval() call. "review
    each" on a batch falls back to per-action prompts for that group only.
    """
    return _active_backend().request_batch(actions)
