"""Terminal entrypoint. Natural-language command in, HITL-gated action out.

Deliverable this satisfies (docs/DEVELOPMENT_PLAN.md Phase 1): a command
prompt loop that reads natural language, shows a live state/findings panel,
and runs every plan through the approve/reject/modify gate before anything
executes.
"""
import re
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agent.graph import build_graph
from agent.recon_pipeline import RECON_STAGES, resume_recon_pipeline, run_recon_pipeline
from agent.session import save_checkpoint
from agent.state import Stage
from agent.vuln_pipeline import VULN_STAGES, resume_vuln_pipeline, run_vuln_pipeline
from config.settings import settings
from skills.report_generator import generate_report

console = Console()

_EXIT_COMMANDS = {"exit", "quit", "q"}
# Phase 4: "recon <target>" / "resume <target>" route to the dedicated fixed-stage
# pipeline (agent/recon_pipeline.py) instead of the generic single-action graph —
# see that module's docstring for why a compound recon hunt needs its own graph.
_RECON_COMMAND_RE = re.compile(r"^recon\s+(\S+)$", re.IGNORECASE)
_RESUME_COMMAND_RE = re.compile(r"^resume(?:\s+recon)?\s+(\S+)$", re.IGNORECASE)
# Phase 5: "assess <target>" / "resume assess <target>" route to
# agent/vuln_pipeline.py, the same way recon/resume route to the recon
# pipeline — matched BEFORE _RESUME_COMMAND_RE below since "resume assess x"
# would otherwise also match _RESUME_COMMAND_RE's own optional "recon" group
# (it doesn't require the literal word "recon" at all).
# Optional trailing "token=<value>" / "other_token=<value>" supplies test
# credentials for the vuln pipeline's "auth_probe" stage (check_idor/
# check_jwt_weaknesses/map_auth_flow) — see that stage's own comments in
# agent/vuln_pipeline.py for why it's a no-op without one. Not accepted on
# "resume assess": a resumed run keeps whatever credentials its checkpoint
# already carries, same as every other field.
_ASSESS_COMMAND_RE = re.compile(
    r"^assess\s+(\S+?)(?:\s+token=(\S+))?(?:\s+other_token=(\S+))?$", re.IGNORECASE,
)
_RESUME_ASSESS_COMMAND_RE = re.compile(r"^resume\s+assess\s+(\S+)$", re.IGNORECASE)
# Phase 8: "report <target> [platform]" generates a report from whatever's
# already in the confirmed_findings ChromaDB collection for that target (see
# skills/report_generator.py) — platform defaults to "hackerone" if omitted.
_REPORT_COMMAND_RE = re.compile(r"^report\s+(\S+)(?:\s+(hackerone|bugcrowd|immunefi))?$", re.IGNORECASE)


def _run_report_command(target: str, platform: str) -> None:
    console.print(Panel(f"Generating {platform} report for [bold]{target}[/bold]...", style="bold blue"))
    result = generate_report.invoke({"target": target, "platform": platform})
    if result.get("error"):
        console.print(Panel(result["error"], title="[yellow]Nothing to report[/yellow]", border_style="yellow"))
        return
    console.print(Panel(
        f"Markdown: {result['md_path']}\nPDF: {result['pdf_path']}",
        title="[bold green]Report generated[/bold green]", border_style="green",
    ))
    console.print(result["markdown"])


def _recon_status_table(state: dict) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_row("[bold]Pipeline stage[/bold]", f"{state.get('stage', '?')} "
                  f"({state.get('stage_index', 0)}/{len(RECON_STAGES)})")
    table.add_row("[bold]Target[/bold]", state.get("target", "-"))
    table.add_row("[bold]Findings so far[/bold]", str(len(state.get("all_findings", []))))
    if state.get("human_note"):
        table.add_row("[bold]Notes[/bold]", state["human_note"])
    return table


def _run_recon_pipeline_command(target: str, resume: bool) -> None:
    console.print(Panel(
        f"{'Resuming' if resume else 'Starting'} automated recon pipeline for [bold]{target}[/bold]\n"
        f"Stages: {' -> '.join(RECON_STAGES)}",
        style="bold blue",
    ))
    try:
        if resume:
            final_state = resume_recon_pipeline(target)
            if final_state is None:
                console.print(Panel(
                    f"No incomplete pipeline found for {target!r} — nothing to resume. "
                    f"Use \"recon {target}\" to start a fresh run.",
                    title="[yellow]Nothing to resume[/yellow]", border_style="yellow",
                ))
                return
        else:
            final_state = run_recon_pipeline(target)
    except Exception as exc:
        console.print(Panel(str(exc), title="[bold red]Pipeline error[/bold red]", border_style="red"))
        return

    if final_state.get("stage") == "error":
        console.print(Panel(
            final_state.get("error", "unknown error"),
            title="[bold red]Pipeline ERROR[/bold red]", border_style="red",
        ))
    elif final_state.get("aggregation"):
        console.print(Panel(final_state["aggregation"], title="[bold green]Ranked targets[/bold green]"))
    elif final_state.get("stage_index", 0) < len(RECON_STAGES):
        console.print("[yellow]Pipeline stopped early (rejected at a stage gate) — partial results checkpointed.[/yellow]")

    console.print(_recon_status_table(final_state))


def _vuln_status_table(state: dict) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_row("[bold]Pipeline stage[/bold]", f"{state.get('stage', '?')} "
                  f"({state.get('stage_index', 0)}/{len(VULN_STAGES)})")
    table.add_row("[bold]Target[/bold]", state.get("target", "-"))
    table.add_row("[bold]Findings assessed[/bold]", str(len(state.get("all_findings", []))))
    confirmed = sum(1 for d in state.get("gate_decisions", {}).values() if d.get("decision") == "confirmed")
    table.add_row("[bold]Confirmed[/bold]", str(confirmed))
    if state.get("human_note"):
        table.add_row("[bold]Notes[/bold]", state["human_note"])
    return table


def _run_vuln_pipeline_command(target: str, resume: bool, auth_token: str = "", auth_other_identity_token: str = "") -> None:
    console.print(Panel(
        f"{'Resuming' if resume else 'Starting'} automated vuln-assessment pipeline for [bold]{target}[/bold]\n"
        f"Stages: {' -> '.join(VULN_STAGES)}"
        + ("\n[dim]test credential supplied — auth_probe will run[/dim]" if auth_token else ""),
        style="bold blue",
    ))
    try:
        if resume:
            final_state = resume_vuln_pipeline(target)
            if final_state is None:
                console.print(Panel(
                    f"No incomplete vuln-assessment pipeline found for {target!r} — nothing to resume. "
                    f"Use \"assess {target}\" to start a fresh run.",
                    title="[yellow]Nothing to resume[/yellow]", border_style="yellow",
                ))
                return
        else:
            final_state = run_vuln_pipeline(target, auth_token=auth_token, auth_other_identity_token=auth_other_identity_token)
    except Exception as exc:
        console.print(Panel(str(exc), title="[bold red]Pipeline error[/bold red]", border_style="red"))
        return

    if final_state.get("stage") == "error":
        console.print(Panel(
            final_state.get("error", "unknown error"),
            title="[bold red]Pipeline ERROR[/bold red]", border_style="red",
        ))
    else:
        if final_state.get("vuln_checklist"):
            console.print(Panel(final_state["vuln_checklist"], title="[bold cyan]Vuln checklist[/bold cyan]"))
        if final_state.get("business_logic_hints"):
            console.print(Panel(final_state["business_logic_hints"], title="[bold cyan]Business-logic hints[/bold cyan]"))
        if final_state.get("stage_index", 0) < len(VULN_STAGES):
            console.print("[yellow]Pipeline stopped early (rejected at a stage gate) — partial results checkpointed.[/yellow]")

    console.print(_vuln_status_table(final_state))


def _status_table(state: dict, findings_count: int) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_row("[bold]State[/bold]", str(state.get("stage", Stage.IDLE)))
    plan = state.get("plan") or {}
    table.add_row("[bold]Last action[/bold]", plan.get("action", "-"))
    table.add_row("[bold]Last target[/bold]", plan.get("target", "-"))
    table.add_row("[bold]Findings[/bold]", str(findings_count))
    return table


def _ping_ollama() -> bool:
    import httpx
    try:
        resp = httpx.get(f"{settings.OLLAMA_BASE_URL}/api/tags", timeout=3.0)
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


def main() -> None:
    console.print(Panel("Bug Bounty Agent — HITL terminal loop", style="bold green"))

    if not _ping_ollama():
        console.print(Panel(
            f"Cannot reach Ollama at {settings.OLLAMA_BASE_URL}. Start it first "
            "(see scripts/install_ollama.sh), then re-run.",
            title="[bold red]LLM unreachable[/bold red]",
            border_style="red",
        ))
        sys.exit(1)

    console.print("[bold green]Agent ready.[/bold green]")

    graph = build_graph()
    findings: list[dict] = []

    console.print("Type a natural-language hunt command (e.g. \"check scope for example.com given this policy text: ...\").")
    console.print(f"Type {'/'.join(_EXIT_COMMANDS)} to quit.\n")

    while True:
        try:
            command = console.input("[bold cyan]hunt>[/bold cyan] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\nExiting.")
            break

        if not command:
            continue
        if command.lower() in _EXIT_COMMANDS:
            break

        if resume_assess_match := _RESUME_ASSESS_COMMAND_RE.match(command):
            _run_vuln_pipeline_command(resume_assess_match.group(1), resume=True)
            console.print()
            continue
        if assess_match := _ASSESS_COMMAND_RE.match(command):
            _run_vuln_pipeline_command(
                assess_match.group(1), resume=False,
                auth_token=assess_match.group(2) or "", auth_other_identity_token=assess_match.group(3) or "",
            )
            console.print()
            continue
        if recon_match := _RECON_COMMAND_RE.match(command):
            _run_recon_pipeline_command(recon_match.group(1), resume=False)
            console.print()
            continue
        if resume_match := _RESUME_COMMAND_RE.match(command):
            _run_recon_pipeline_command(resume_match.group(1), resume=True)
            console.print()
            continue
        if report_match := _REPORT_COMMAND_RE.match(command):
            _run_report_command(report_match.group(1), (report_match.group(2) or "hackerone").lower())
            console.print()
            continue

        initial_state = {"command": command, "stage": Stage.PLANNING, "findings": findings}
        try:
            final_state = graph.invoke(initial_state)
        except Exception as exc:
            console.print(Panel(str(exc), title="[bold red]Unhandled error[/bold red]", border_style="red"))
            continue

        findings = final_state.get("findings", findings)

        if final_state.get("stage") == Stage.ERROR:
            console.print(Panel(
                final_state.get("error", "unknown error"),
                title="[bold red]ERROR[/bold red]", border_style="red",
            ))
        else:
            plan = final_state.get("plan") or {}
            target = plan.get("target", "session")
            checkpoint_path = save_checkpoint(target, final_state)
            console.print(f"[dim]checkpoint saved: {checkpoint_path}[/dim]")

        console.print(_status_table(final_state, len(findings)))
        console.print()


if __name__ == "__main__":
    main()
