"""Web-facing HITL approval backend for ui/app.py (Phase 6).

agent/hitl.py's ConsoleApprovalBackend blocks on stdin — fine for main.py's
terminal loop, useless in a browser session where "the human" is a button
click handled on a DIFFERENT thread (Gradio's own request-handling thread)
than the one running the hunt pipeline. WebApprovalBackend blocks on a
threading.Event instead of stdin: request()/request_batch() park a
pending-approval record in a HuntSession's shared state and wait for a
button-click callback to resolve it and signal the event — see
resolve_pending() below, which ui/app.py's Approve/Reject/Modify buttons call.

Deliberately reduced in scope from docs/DEVELOPMENT_PLAN.md's Phase 6
literal wording, documented here rather than silently divergent:
the plan describes a hand-rolled FastAPI WebSocket endpoint as the
backend<->browser transport. Gradio (already a FastAPI/Starlette app
underneath — `fastapi==0.139.2` is already in requirements.txt, confirmed
live) already runs its own live component-update transport for exactly this
"push state to the browser as it changes" need. Hand-rolling a SECOND,
redundant WebSocket protocol alongside the one Gradio already runs
internally would add real complexity (message schema, reconnect handling,
session multiplexing) for no visible capability gain in a single-user local
tool — the same "ship the honest, smaller version" call session 5's
Shodan/Hacktivity items already made for this project, not a shortcut taken
silently. ui/app.py's own gr.Timer-driven polling is what plays the role the
plan's WebSocket push would have played.

One HuntSession per hunt, not a module-level singleton: ui/app.py stores
one in Gradio's own per-browser-tab gr.State, so two open tabs (or two
users on the same local network) never share pending-approval state or
step on each other's activity log.
"""
import threading
from dataclasses import dataclass, field

from agent.hitl import ApprovalBackend, ApprovalResult


@dataclass
class PendingApproval:
    action: dict
    triggered_rule: str
    event: threading.Event = field(default_factory=threading.Event)
    result: ApprovalResult | None = None


class HuntSession:
    """Shared, thread-safe state between the background pipeline thread and
    Gradio's own request-handling thread(s) for ONE hunt.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.activity_log: list[str] = []
        self.findings: list[dict] = []
        self.status = "idle"  # idle | running | awaiting_approval | done | error
        self.pending: PendingApproval | None = None
        self.final_state: dict | None = None
        self.error: str | None = None

    def log(self, message: str) -> None:
        with self.lock:
            self.activity_log.append(message)

    def set_findings(self, findings: list[dict]) -> None:
        with self.lock:
            self.findings = list(findings)

    def snapshot(self) -> dict:
        """Everything ui/app.py's polling Timer needs, taken under one lock
        so the UI never renders a torn mix of before/after a mutation.
        """
        with self.lock:
            return {
                "activity_log": list(self.activity_log),
                "findings": list(self.findings),
                "status": self.status,
                "pending": self.pending,
                "error": self.error,
            }


class WebApprovalBackend(ApprovalBackend):
    """One instance per HuntSession — constructed with that session."""

    def __init__(self, session: HuntSession):
        self.session = session

    def request(self, action: dict, triggered_rule: str | None = None) -> ApprovalResult:
        pending = PendingApproval(action=action, triggered_rule=triggered_rule or "")
        with self.session.lock:
            self.session.pending = pending
            self.session.status = "awaiting_approval"
        self.session.log(
            f"[awaiting approval] {action.get('action', '?')} -> {action.get('target', '?')} "
            f"({action.get('risk_level', 'MEDIUM')}): {action.get('reason', '')}"
        )
        pending.event.wait()  # blocks the BACKGROUND PIPELINE thread only, never Gradio's own
        with self.session.lock:
            self.session.pending = None
            self.session.status = "running"
        self.session.log(f"[decision] {pending.result.decision} ({pending.result.note or 'no note'})")
        return pending.result

    def request_batch(self, actions: list[dict]) -> list[ApprovalResult]:
        # v1 has no batch-approval widget in the UI yet — fall back to one
        # request() per action rather than silently auto-approving a whole
        # batch. Slower (one prompt per action instead of one per group),
        # never less safe.
        return [self.request(action) for action in actions]


def resolve_pending(session: HuntSession, decision: str, note: str = "") -> bool:
    """Resolve the session's current pending approval, called from a Gradio
    button-click callback — a DIFFERENT thread than the one blocked inside
    WebApprovalBackend.request().

    Returns False if there was nothing pending (e.g. a stale click after the
    pipeline already moved past it) so the caller can no-op cleanly instead
    of raising on a race that's expected, not exceptional.
    """
    with session.lock:
        pending = session.pending
    if pending is None:
        return False
    pending.result = ApprovalResult(decision=decision, note=note)
    pending.event.set()
    return True
