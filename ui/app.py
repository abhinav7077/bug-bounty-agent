"""Phase 6: Gradio web console — full hunt orchestration from a browser.

Distinct execution model from main.py's terminal loop: every hunt here runs
in a background `threading.Thread` (started by a button click, which
returns immediately) rather than blocking the calling request, because a
Gradio event handler that blocks for an entire multi-stage pipeline run
would freeze the whole UI for that duration — including the very
Approve/Reject/Modify buttons the human needs to click to let it continue.
A `gr.Timer` polls the active hunt's `agent.web_hitl.HuntSession` roughly
once a second and renders whatever's there — status, activity log, the
current pending approval (if any), and accumulated findings.

Reuses agent/graph.py, agent/recon_pipeline.py, and agent/vuln_pipeline.py's
own `build_*graph()` functions and calls `.stream()` on them directly
(instead of those modules' own `run_*()`/`resume_*()` wrappers, which call
`.invoke()` and only return once the WHOLE pipeline finishes) — `.stream()`
yields `{node_name: full_state}` after every node, which is what actually
lets the activity log update stage-by-stage instead of going silent for an
entire hunt and then dumping everything at the end. Verified live via
`graph.stream()` before writing any of this: LangGraph's own default stream
mode already hands back this project's full node-return-shape (every node
here returns `{**state, **delta}`, never a bare delta), so no LangGraph
config tuning was needed to get this.

Deliberately reduced in scope from docs/DEVELOPMENT_PLAN.md's Phase 6
literal wording — see agent/web_hitl.py's own module docstring for the
"why no hand-rolled FastAPI WebSocket" reasoning; this file's gr.Timer
polling is what plays that role instead. Also v1-scoped: ONE hunt at a time
per browser tab (a single shared `gr.State` holds "the current HuntSession"
across all three tabs below, not one per tab) — running Recon and a Vuln
Assessment concurrently from the same browser tab isn't supported yet, only
sequentially. Batch approvals (agent/hitl.py's request_batch_approval) fall
back to one approval prompt per action in the web backend (see
agent/web_hitl.py's WebApprovalBackend.request_batch) rather than a
dedicated batch-approval widget — slower, never less safe.
"""
import threading

import gradio as gr
import pandas as pd

from agent import graph as nl_graph
from agent import recon_pipeline as rp
from agent import vuln_pipeline as vp
from agent.hitl import set_approval_backend
from agent.memory import get_confirmed_findings
from agent.session import load_latest
from agent.state import Stage
from agent.web_hitl import HuntSession, WebApprovalBackend, resolve_pending
from skills.report_generator import export_report, generate_report_narrative, render_report

_RECURSION_LIMIT = 100
_MAX_LOG_LINES_SHOWN = 300
_FINDING_COLUMNS = ["type", "target", "detail", "severity", "tool_source", "timestamp"]


def _empty_findings_df() -> pd.DataFrame:
    return pd.DataFrame(columns=_FINDING_COLUMNS)


def _findings_df(findings: list[dict]) -> pd.DataFrame:
    if not findings:
        return _empty_findings_df()
    return pd.DataFrame(findings)


# --- background pipeline runners -- each owns ONE HuntSession, sets this
# thread's approval backend, streams its graph, and never lets an exception
# escape unlogged (a background thread's traceback is otherwise invisible --
# it doesn't propagate to Gradio or the terminal the way a request-handler
# exception would). ---

def _stream_pipeline_stages(session: HuntSession, graph, initial: dict, stages: list[str]) -> dict:
    """Shared streaming loop for agent/recon_pipeline.py and
    agent/vuln_pipeline.py -- both share the exact same node names
    (propose/gate/execute/done/error) and state field names (stage,
    stage_index, pending_plan, decision, all_findings, error), unlike
    agent/graph.py's HuntState, which is genuinely different (see
    _run_command below) and gets its own loop rather than a forced-shared one.
    """
    last_state = initial
    for chunk in graph.stream(initial, config={"recursion_limit": _RECURSION_LIMIT}):
        for node_name, state in chunk.items():
            last_state = state
            session.set_findings(state.get("all_findings", []))
            if node_name == "propose":
                plan = state.get("pending_plan") or {}
                session.log(
                    f"[{state.get('stage')}] proposing: {plan.get('reason', '')} "
                    f"({plan.get('risk_level', '?')})"
                )
            elif node_name == "execute":
                session.log(
                    f"[{state.get('stage')}] executed (stage {state.get('stage_index')}/{len(stages)}), "
                    f"{len(state.get('all_findings', []))} finding(s) so far"
                )
            elif node_name == "done":
                session.log(f"[done] final stage={state.get('stage')}")
            elif node_name == "error":
                session.log(f"[error] {state.get('error')}")
    return last_state


def _run_recon(session: HuntSession, target: str, resume: bool) -> None:
    set_approval_backend(WebApprovalBackend(session))
    session.status = "running"
    session.log(f"{'Resuming' if resume else 'Starting'} recon pipeline for {target!r}")
    try:
        if resume:
            checkpoint = load_latest(target)
            if checkpoint is None or checkpoint.get("stage_index", 0) >= len(rp.RECON_STAGES):
                session.log(f"Nothing to resume for {target!r} — start a fresh recon instead.")
                session.status = "idle"
                return
            initial = checkpoint
        else:
            initial = rp._fresh_state(target)  # same internal state shape the pipeline itself uses

        final_state = _stream_pipeline_stages(session, rp.build_recon_graph(), initial, rp.RECON_STAGES)
        session.final_state = final_state
        session.status = "error" if final_state.get("stage") == "error" else "done"
    except Exception as exc:  # a background thread's exception is otherwise silently lost
        session.error = str(exc)
        session.status = "error"
        session.log(f"[fatal] {exc}")


def _run_vuln(session: HuntSession, target: str, resume: bool, auth_token: str, auth_other_identity_token: str) -> None:
    set_approval_backend(WebApprovalBackend(session))
    session.status = "running"
    session.log(f"{'Resuming' if resume else 'Starting'} vuln-assessment pipeline for {target!r}")
    try:
        if resume:
            checkpoint = load_latest(f"{target}__vuln")
            if checkpoint is None or checkpoint.get("stage_index", 0) >= len(vp.VULN_STAGES):
                session.log(f"Nothing to resume for {target!r} — start a fresh assessment instead.")
                session.status = "idle"
                return
            initial = checkpoint
        else:
            surface = vp.load_recon_surface(target)
            if surface is None:
                session.log(f"No recon checkpoint found for {target!r} — run Recon on this target first.")
                session.status = "error"
                session.error = f"no recon checkpoint for {target!r}"
                return
            initial = vp._fresh_state(
                target, surface["live_hosts"], surface["js_urls"], surface["all_findings"],
                auth_token=auth_token, auth_other_identity_token=auth_other_identity_token,
            )

        final_state = _stream_pipeline_stages(session, vp.build_vuln_graph(), initial, vp.VULN_STAGES)
        session.final_state = final_state
        session.status = "error" if final_state.get("stage") == "error" else "done"
    except Exception as exc:
        session.error = str(exc)
        session.status = "error"
        session.log(f"[fatal] {exc}")


def _run_command(session: HuntSession, command: str) -> None:
    set_approval_backend(WebApprovalBackend(session))
    session.status = "running"
    session.log(f"Running command: {command!r}")
    try:
        graph = nl_graph.build_graph()
        initial = {"command": command, "stage": Stage.PLANNING, "findings": []}
        last_state = initial
        for chunk in graph.stream(initial):
            for node_name, state in chunk.items():
                last_state = state
                session.set_findings(state.get("findings", []))
                if node_name == "plan":
                    plan = state.get("plan")
                    if plan:
                        session.log(f"[plan] proposing: {plan.get('action')} -> {plan.get('target')} ({plan.get('risk_level')})")
                    elif state.get("stage") == Stage.REPORTING:
                        session.log(f"[plan] final answer: {state.get('result')}")
                elif node_name == "execute":
                    session.log(f"[execute] ran {(state.get('plan') or {}).get('action')}, {len(state.get('findings', []))} total finding(s)")
                elif node_name == "report":
                    session.log("[report] done")
                elif node_name == "error":
                    session.log(f"[error] {state.get('error')}")
        session.final_state = last_state
        session.status = "error" if last_state.get("stage") == Stage.ERROR else "done"
    except Exception as exc:
        session.error = str(exc)
        session.status = "error"
        session.log(f"[fatal] {exc}")


# --- Gradio callbacks ---

def _start_recon(target: str, _session_state):
    target = (target or "").strip()
    if not target:
        return _session_state, "Enter a target domain first."
    session = HuntSession()
    threading.Thread(target=_run_recon, args=(session, target, False), daemon=True).start()
    return session, f"Started recon for **{target}**."


def _resume_recon(target: str, _session_state):
    target = (target or "").strip()
    if not target:
        return _session_state, "Enter a target domain first."
    session = HuntSession()
    threading.Thread(target=_run_recon, args=(session, target, True), daemon=True).start()
    return session, f"Attempting to resume recon for **{target}**."


def _start_vuln(target: str, token: str, other_token: str, _session_state):
    target = (target or "").strip()
    if not target:
        return _session_state, "Enter a target first."
    session = HuntSession()
    threading.Thread(
        target=_run_vuln, args=(session, target, False, (token or "").strip(), (other_token or "").strip()),
        daemon=True,
    ).start()
    return session, f"Started vuln assessment for **{target}**."


def _resume_vuln(target: str, _session_state):
    target = (target or "").strip()
    if not target:
        return _session_state, "Enter a target first."
    session = HuntSession()
    threading.Thread(target=_run_vuln, args=(session, target, True, "", ""), daemon=True).start()
    return session, f"Attempting to resume vuln assessment for **{target}**."


def _start_command(command: str, _session_state):
    command = (command or "").strip()
    if not command:
        return _session_state, "Enter a command first."
    session = HuntSession()
    threading.Thread(target=_run_command, args=(session, command), daemon=True).start()
    return session, "Running command..."


def _poll(session_state: HuntSession | None):
    if session_state is None:
        return (
            "status: no hunt started yet", "", "No pending approval right now.",
            _empty_findings_df(), gr.update(interactive=False), gr.update(interactive=False), gr.update(interactive=False),
        )

    snap = session_state.snapshot()
    status_line = f"status: {snap['status']}"
    if snap.get("error"):
        status_line += f" — error: {snap['error']}"

    log_text = "\n".join(snap["activity_log"][-_MAX_LOG_LINES_SHOWN:])

    pending = snap["pending"]
    if pending is not None:
        action = pending.action
        pending_text = (
            f"**{action.get('risk_level', '?')} RISK** — `{action.get('action', '?')}` "
            f"→ {action.get('target', '?')}\n\n{action.get('reason', '')}"
        )
        buttons_enabled = True
    else:
        pending_text = "No pending approval right now."
        buttons_enabled = False

    return (
        status_line, log_text, pending_text, _findings_df(snap["findings"]),
        gr.update(interactive=buttons_enabled), gr.update(interactive=buttons_enabled), gr.update(interactive=buttons_enabled),
    )


def _approve(session_state: HuntSession | None, note: str):
    if session_state is not None:
        resolve_pending(session_state, "approve", note or "")
    return ""


def _reject(session_state: HuntSession | None, note: str):
    if session_state is not None:
        resolve_pending(session_state, "reject", note or "")
    return ""


def _modify(session_state: HuntSession | None, note: str):
    if session_state is not None:
        resolve_pending(session_state, "modify", note or "")
    return ""


def _do_generate_report(target: str, platform: str):
    """Draft a report into the editable textbox -- does NOT write any file
    yet. Per docs/DEVELOPMENT_PLAN.md's own Phase 8 "human review + edit
    step... before export" requirement, export is a SEPARATE button
    (_do_export_report below) so a human can revise the LLM-written
    narrative first.
    """
    target = (target or "").strip()
    if not target:
        return "", "Enter a target first."
    findings = get_confirmed_findings(target)
    if not findings:
        return "", (
            f"No confirmed findings on record for {target!r} yet — run a Vuln Assessment "
            "and approve at least one finding first."
        )
    narrative = generate_report_narrative(target, findings)
    markdown = render_report(target, findings, narrative, platform=platform)
    return markdown, f"Draft generated from {len(findings)} confirmed finding(s) — review/edit below, then Export."


def _do_export_report(target: str, markdown_text: str):
    target = (target or "").strip()
    if not target or not (markdown_text or "").strip():
        return "Generate a report draft first."
    paths = export_report(target, markdown_text)
    return f"Exported.\n\nMarkdown: `{paths['md_path']}`\n\nPDF: `{paths['pdf_path']}`"


def build_app() -> gr.Blocks:
    with gr.Blocks(title="Bug Bounty Agent") as demo:
        gr.Markdown("# Bug Bounty Agent — Web Console")
        gr.Markdown(
            "One hunt at a time per browser tab. Approve/Reject/Modify below applies to "
            "whichever hunt (Recon, Vuln Assessment, or a Natural-Language Command) is currently running."
        )
        session_state = gr.State(None)

        with gr.Tabs():
            with gr.Tab("Automated Recon"):
                recon_target = gr.Textbox(label="Target domain", placeholder="example.com")
                with gr.Row():
                    recon_start_btn = gr.Button("Start Recon", variant="primary")
                    recon_resume_btn = gr.Button("Resume Recon")
                recon_msg = gr.Markdown()

            with gr.Tab("Automated Vuln Assessment"):
                gr.Markdown("Requires a completed (or in-progress) Recon run for this target first.")
                vuln_target = gr.Textbox(label="Target", placeholder="example.com")
                with gr.Row():
                    vuln_token = gr.Textbox(label="Test credential token (optional)", type="password")
                    vuln_other_token = gr.Textbox(label="Other-identity token (optional)", type="password")
                with gr.Row():
                    vuln_start_btn = gr.Button("Start Assessment", variant="primary")
                    vuln_resume_btn = gr.Button("Resume Assessment")
                vuln_msg = gr.Markdown()

            with gr.Tab("Natural-Language Command"):
                nl_command = gr.Textbox(
                    label="Command", lines=3,
                    placeholder='e.g. "check scope for example.com given this policy text: ..."',
                )
                nl_start_btn = gr.Button("Run Command", variant="primary")
                nl_msg = gr.Markdown()

        gr.Markdown("## Live Status")
        status_box = gr.Markdown("status: no hunt started yet")
        activity_log_box = gr.Textbox(label="Activity Log", lines=15, interactive=False, autoscroll=True)

        gr.Markdown("## Pending Approval")
        pending_box = gr.Markdown("No pending approval right now.")
        note_box = gr.Textbox(label="Note (used for reject/modify)")
        with gr.Row():
            approve_btn = gr.Button("Approve", variant="primary", interactive=False)
            reject_btn = gr.Button("Reject", interactive=False)
            modify_btn = gr.Button("Modify", interactive=False)

        gr.Markdown("## Findings")
        findings_table = gr.Dataframe(value=_empty_findings_df(), interactive=False)

        gr.Markdown("## Report")
        with gr.Row():
            report_target = gr.Textbox(label="Target", placeholder="example.com")
            report_platform = gr.Dropdown(choices=["hackerone", "bugcrowd", "immunefi"], value="hackerone", label="Platform")
        report_generate_btn = gr.Button("Generate Report Draft")
        report_gen_msg = gr.Markdown()
        report_markdown_box = gr.Textbox(label="Report (editable — review before exporting)", lines=25)
        report_export_btn = gr.Button("Export Report (.md + .pdf)", variant="primary")
        report_export_msg = gr.Markdown()

        recon_start_btn.click(_start_recon, inputs=[recon_target, session_state], outputs=[session_state, recon_msg])
        recon_resume_btn.click(_resume_recon, inputs=[recon_target, session_state], outputs=[session_state, recon_msg])
        vuln_start_btn.click(
            _start_vuln, inputs=[vuln_target, vuln_token, vuln_other_token, session_state],
            outputs=[session_state, vuln_msg],
        )
        vuln_resume_btn.click(_resume_vuln, inputs=[vuln_target, session_state], outputs=[session_state, vuln_msg])
        nl_start_btn.click(_start_command, inputs=[nl_command, session_state], outputs=[session_state, nl_msg])

        approve_btn.click(_approve, inputs=[session_state, note_box], outputs=[note_box])
        reject_btn.click(_reject, inputs=[session_state, note_box], outputs=[note_box])
        modify_btn.click(_modify, inputs=[session_state, note_box], outputs=[note_box])

        report_generate_btn.click(
            _do_generate_report, inputs=[report_target, report_platform],
            outputs=[report_markdown_box, report_gen_msg],
        )
        report_export_btn.click(
            _do_export_report, inputs=[report_target, report_markdown_box], outputs=[report_export_msg],
        )

        timer = gr.Timer(1.0)
        timer.tick(
            _poll, inputs=[session_state],
            outputs=[status_box, activity_log_box, pending_box, findings_table, approve_btn, reject_btn, modify_btn],
        )

    return demo


def main() -> None:
    demo = build_app()
    demo.queue()
    demo.launch(server_name="0.0.0.0", server_port=7860)


if __name__ == "__main__":
    main()
