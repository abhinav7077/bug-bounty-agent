# Contributing to Bug Bounty Agent

Thanks for your interest in improving this project. Contributions of all kinds are welcome —
bug fixes, new tool wrappers, documentation, and ideas.

## Ground rules

- **This is a security-testing tool.** Only ever run it against targets you are authorized to
  test. Do not open issues or PRs that contain findings, payloads, or logs from an unauthorized
  target. See [SECURITY.md](SECURITY.md).
- **Keep the safety model intact.** The human-in-the-loop approval gate, the fixed (never
  LLM-judged) risk table in `agent/risk.py`, and the "scope cannot be fabricated" guard are
  core design invariants. A change that weakens any of them needs a very good reason and should
  be called out explicitly in the PR.

## Development setup

```bash
git clone https://github.com/abhinav7077/bug-bounty-agent.git
cd bug-bounty-agent
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt       # full runtime stack
pip install -r requirements-dev.txt   # minimal test-only deps (enough to run the suite)
```

See the [README](README.md) for the Ollama and external-tool setup (`scripts/phase0_setup.sh`).

## Before you open a PR

Run the same checks CI runs — both must pass:

```bash
ruff check .
python -m pytest -q
```

- **Lint:** `ruff` config lives in `pyproject.toml`. The ignore list there is deliberate; read
  the comments before adding to it.
- **Tests:** the suite in `tests/` is pure-logic and needs no LLM, network, or external
  binaries. If you add logic, add a test for it. New `@tool`-decorated skills are invoked in
  tests via `.invoke({...})`, not called directly.

## Adding a new tool wrapper

1. Wrap the external CLI in `tools/` (or add a reasoning/HTTP skill in `skills/`), returning the
   shared `ToolResult` shape from `tools/base.py`.
2. **Add an explicit risk entry** for it in `agent/risk.py` — LOW (passive), MEDIUM (active,
   non-destructive), or HIGH (exploit/data-modifying). Unclassified tools fail closed to HIGH,
   but every registered tool must still have its own entry.
3. Register it where the orchestrator imports its tools.
4. Add a test and update the docs if it changes a documented command.

## Commit and PR conventions

- Keep commits focused and messages descriptive.
- Describe *what changed and why* in the PR body, and note anything that touches the safety
  model.
- Be kind in review. This is a volunteer project.

## Context for contributors

`MEMORY.md` is the session-by-session build history and the fastest way to understand why
things are the way they are. `docs/DEVELOPMENT_PLAN.md` is the phase-by-phase checklist. Read
both before a large change.
