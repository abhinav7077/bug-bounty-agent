# Bug Bounty Agent

A local, human-in-the-loop bug bounty hunting agent. It runs entirely on your own machine against
a local LLM (via [Ollama](https://ollama.com)) — recon, vulnerability assessment, and report
generation are all automated, but **every active or risky action is gated behind an explicit
human approval** before it ever touches a real target.

Built as a LangGraph state machine on top of ~65 tool wrappers and skills (subdomain enum, port
scanning, active scanners, auth/IDOR/JWT checks, GraphQL introspection, secret scanning, cloud
asset enumeration, CVE lookup, and more), with a terminal UI and a Gradio web console, both
driving the same underlying graphs.

## Why this exists

There are already public "bug bounty agent" projects that wire up nuclei + a fuzzer + an LLM
summary — that's commodity. This project's actual edge:

- **Sequence-aware reasoning, not just parameter fuzzing.** Business-logic and auth-flow flaws
  (step-skipping, price/quantity tampering, coupon reuse, session/token misuse) only show up when
  you model a *flow*, not a single request — see `skills/business_logic_mapper.py` and
  `skills/auth_mapper.py`'s `map_auth_flow`.
- **Economically aware, not breadth-first.** `skills/roi_prioritizer.py` ranks (asset, vuln type)
  candidates by expected value (base rate × a program's own published payout tiers) before
  spending scan budget, and `skills/eligibility_filter.py` kills known low-value findings
  (self-XSS, missing headers, etc.) before report-writing time.
- **A safety model that stays usable at scale.** Every action carries a fixed risk level
  (`agent/risk.py` — never LLM-judged, fail-closed to HIGH), and repetitive LOW/MEDIUM actions
  batch into one approval prompt (`skills/hitl_batcher.py`) instead of becoming permission-prompt
  spam that trains a human to stop reading them.

## Requirements

- **Ollama** reachable from this machine (local or, on WSL2, the Windows host — see
  "WSL2 + Ollama" below), with a model pulled and `.env`'s `OLLAMA_MODEL` pointing at it.
- **Python 3.11+** (developed against 3.14) and the security tool binaries `scripts/phase0_setup.sh`
  installs (subfinder, httpx, naabu, nmap, nuclei, ffuf, sqlmap, and ~30 others — see that
  script for the full list). Some tools need a one-time manual step it can't do unattended
  (e.g. `sudo apt install chromium-browser` for `run_gowitness`) — the script prints what's left.
- A **scope/authorization for whatever target you point this at.** This tool will refuse to
  fabricate a scope policy from its own training knowledge (see "Safety model" below) — you
  must paste the real program policy text yourself.

## Setup

```bash
git clone <this repo>
cd bug-bounty-agent
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then edit OLLAMA_BASE_URL/OLLAMA_MODEL if needed
bash scripts/phase0_setup.sh   # installs the ~30 external security tool binaries
```

### WSL2 + Ollama

If you're running this inside WSL2 with Ollama installed on the Windows side (the setup this
project was originally developed against), WSL2's own network gateway IP is what `.env`'s
`OLLAMA_BASE_URL` needs, not `localhost` — and that IP **is not stable across WSL restarts**:

```bash
ip route | grep default | awk '{print $3}'   # re-run this and update .env whenever Ollama stops responding
```

The Windows-side `ollama serve` process itself can be fragile under sustained GPU load (observed
crashing mid-session with a CUDA error and recovering on its own after a retry) — if a command
suddenly can't reach the model, check whether the Windows Ollama window is still alive before
assuming something in this codebase broke.

## Usage

### Terminal

```bash
python main.py
```

This drops you into a `hunt>` prompt. A few command shapes it understands directly (anything
else is treated as a natural-language instruction and routed through the LLM planner):

| Command | What it does |
|---|---|
| `recon <target>` | Runs the fixed 8-stage automated recon pipeline (subdomains → live hosts → ports → crawl → params → dirs → enrichment → LLM aggregation). |
| `resume <target>` | Continues an interrupted recon run from its last checkpoint. |
| `assess <target> [token=... [other_token=...]]` | Runs the 10-stage vulnerability-assessment pipeline against a target's **already-recon'd** surface — tech fingerprinting, targeted nuclei, reflected-XSS + WAF-bypass probing, credentialed auth checks (only if a token is supplied), GraphQL introspection, LLM false-positive triage, chain analysis, and a per-finding human review gate. |
| `resume assess <target>` | Continues an interrupted assessment run. |
| `report <target> [hackerone\|bugcrowd\|immunefi]` | Generates a Markdown + PDF report from whatever findings you've confirmed for that target, under `reports/<target>/`. |
| *(anything else)* | A free-form instruction, planned one tool call at a time by the LLM and gated the same way. |

Every MEDIUM/HIGH-risk step pauses and asks you to **approve / reject / modify** (or, for HIGH
risk, type the literal word `yes`) before it runs.

### Web UI

```bash
python ui/app.py
```

Then open `http://localhost:7860` in a browser (on WSL2, this is usually reachable from Windows
at `localhost:7860` directly; if not, use the WSL2 IP from `ip addr show eth0` instead). Three
tabs — Automated Recon, Automated Vuln Assessment, Natural-Language Command — share one live
activity log, pending-approval panel (Approve/Reject/Modify buttons), and findings table below.
A Report section lets you generate a draft, edit it in-browser, and export the final Markdown/PDF.

One hunt runs at a time per browser tab.

## Safety model

- **Every tool/skill has a fixed risk level** in `agent/risk.py` — LOW (passive/no request to the
  target), MEDIUM (active but non-destructive), or HIGH (exploit attempts, forged-auth replay,
  data-modifying actions). This is a static lookup table, never something the LLM self-assigns —
  a model that gets tool *arguments* wrong on a routine basis can't be trusted to self-assess
  something safety-critical either.
- **LOW auto-proceeds** (but is always shown, never silent). **MEDIUM** shows the plan and waits
  for approve/reject/modify. **HIGH** requires typing the literal word `yes` — anything else is
  treated as a reject, never defaulted to approve.
- **Scope can't be fabricated.** The agent refuses to run any scope/policy-checking tool at all
  unless real scope-page text has actually been pasted into the conversation — it will not recall
  or guess a well-known program's scope from its own training data.
- **Rate-limited to 10 req/s by default** (`MAX_REQ_PER_SEC` in `.env`) across every active
  wrapper that can enforce it. One documented exception (`run_kiterunner`) has no rate-limit flag
  at all and is classified HIGH specifically so it always needs an explicit human "yes."
- **A finding needs repeated, distinct evidence before it's treated as confirmed** — see
  `skills/confidence_scorer.py`/`skills/vuln_assessor.py`, not a single lucky request/response.

## Project layout

```
agent/       LangGraph state machines: the freeform command loop (graph.py), the fixed recon
             pipeline (recon_pipeline.py), the fixed vuln-assessment pipeline (vuln_pipeline.py),
             HITL approval backends (hitl.py, web_hitl.py), ChromaDB long-term memory (memory.py)
skills/      Callable LLM tools that reason or speak raw HTTP directly (no single CLI binary
             behind them) — scope parsing, chain analysis, business-logic/auth-flow mapping,
             CVSS/report generation, eligibility filtering, WAF-bypass probing, etc.
tools/       Wrappers around external CLI security tools (subfinder, nuclei, sqlmap, ...) plus
             the shared subprocess/HTTP primitives they're built on.
config/      Prompts, payload lists, and report templates — content, not logic.
ui/          The Gradio web console.
main.py      The terminal entrypoint.
docs/DEVELOPMENT_PLAN.md   The full phase-by-phase build checklist this project follows.
MEMORY.md    Session-by-session build history/handoff notes — read this before making changes.
```

## Status

All of Phases 1–9 of `docs/DEVELOPMENT_PLAN.md` are complete (recon pipeline, vuln
assessment pipeline, web UI, report generator, and CI/polish). See `MEMORY.md` for the full
build history, including every real bug found and fixed along the way via live testing.

### Tests & CI

A pure-logic test suite lives in `tests/` — it pins the safety-critical contracts (the fixed
risk table, the scope-fabrication gate, the eligibility filter, payload loading, approval
batching, and the subprocess runner's never-raise/always-set-`error` guarantees). It touches
no LLM, no network, and no external security-tool binaries, so it runs in ~1–2s:

```bash
pip install -r requirements-dev.txt   # minimal test-only deps, not the full runtime stack
python -m pytest -q
```

GitHub Actions (`.github/workflows/ci.yml`) runs two jobs on every push/PR to `main`: `lint`
(`ruff check`) and `test` (`pytest` against `requirements-dev.txt`). Both deliberately avoid
installing the heavy CUDA/Gradio runtime stack they don't need.
