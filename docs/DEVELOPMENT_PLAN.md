# Bug Bounty Agent — Development Plan

Model: Qwen3-Coder 30B · Runtime: WSL2 Ubuntu · Phases: 10 · Timeline: ~33 days

> Checkboxes below reflect verified repo state, not aspiration. See [MEMORY.md](../MEMORY.md)
> at the repo root for the current handoff summary and next steps. Live version with
> progress tracking: https://claude.ai/code/artifact/1bcab525-024f-4bb5-bd8d-f70ea5c0ff20


## Phase 0: Environment Setup

**Timeline:** Day 1 – 2

**Goal:** Everything installed, repo live on GitHub, Ollama API confirmed reachable from WSL


### WSL & System

- [x] WSL2 Ubuntu already running (confirmed 2026-07-16: Ubuntu 26.04 LTS "Resolute Raccoon",
  kernel 6.18.33.2-microsoft-standard-WSL2) — the manual install/VS Code steps below were
  already done before this session; nothing to redo [WSL]
- [ ] Run `sudo apt update && sudo apt upgrade -y` inside WSL terminal
- [ ] Install base packages — see `scripts/phase0_setup.sh` step [1/7]. Deviation: the plan
  says `python3.11`; this box ships Python 3.14 by default with no `python3.11` package
  available, so the script installs `python3-venv python3-pip` instead and everything uses
  3.14 (verified working — see Python Environment below)
- [ ] Add self to docker group — `scripts/phase0_setup.sh` step [2/7]
- [ ] **Blocked on Claude's side:** none of the `sudo`-gated steps above can be run by Claude
  in this environment — the Bash tool has no TTY, so `sudo` fails with "a terminal is
  required to authenticate" even with a cached password. User must run
  `scripts/phase0_setup.sh` themselves in their own WSL terminal. See MEMORY.md.

### Go + Security Tools

All of the below are bundled into `scripts/phase0_setup.sh` steps [3/7]–[6/7] (Go install,
go-installed tool list, trufflehog/gitleaks installer scripts, nuclei template update) and
step [7/7] (pipx-installed CLI tools + no-package git clones) — written and ready, not yet
run. Same sudo/TTY blocker as above for the apt/docker-group parts; the `go install` and pipx
steps themselves don't need sudo once Go/pipx are on PATH.

- [ ] Download + install Go 1.22 → run `scripts/phase0_setup.sh`
- [ ] Install ProjectDiscovery tools, ffuf/tomnomnom tools, dalfox/puredns/subjack/kiterunner/
  kxss/gowitness/hakrawler, trufflehog, gitleaks → run `scripts/phase0_setup.sh`
- [ ] Run `nuclei -update-templates` → included at the end of `scripts/phase0_setup.sh`
- [ ] Install pip tools (arjun, paramspider, corsy, wapiti3, theHarvester, ghauri, s3scanner,
  cloud_enum, shodan) via `pipx` → included in `scripts/phase0_setup.sh`
- [ ] Clone no-package tools into `~/tools/` (SecretFinder, LinkFinder, smuggler, joomscan,
  XSStrike) → included in `scripts/phase0_setup.sh`
- [ ] Verify all critical tools in PATH — last step of `scripts/phase0_setup.sh`, prints a
  `which` summary

### GitHub + Project Skeleton

- [ ] Configure git identity, SSH key, create GitHub repo — **explicitly deferred**: user
  chose to skip git/GitHub setup for this session. Repo is still not a git repo as of
  2026-07-16. Redo this section whenever the user wants version control back [GitHub]
- [x] Create folder tree: `agent/ tools/ ui/ config/ reports/ sessions/ tests/ .github/workflows/`
- [x] Create all `__init__.py` stubs and empty module files per the project structure
- [x] Create `.env.example` with all required vars (OLLAMA_BASE_URL, OLLAMA_MODEL, tool paths, UI port)
- [x] Create `.gitignore` (exclude `.env`, `.venv/`, `sessions/`, `reports/`, `__pycache__/`)

### Python Environment

- [x] Create venv — `python3 -m venv .venv` (deviation: `uv` wasn't available without the
  sudo-gated apt/pipx install in Phase 0's tool script, so plain `venv` was used instead;
  functionally equivalent)
- [x] Install agent deps — `pip install -r requirements.txt`, verified success on 2026-07-16.
  Deviation: box is Ubuntu 26.04 "Resolute" with Python 3.14 (no python3.11 package exists),
  so everything installed against 3.14 — langgraph 1.2.9, langchain 1.3.14, torch 2.13.0, all
  installed cleanly, no compatibility issues hit
- [x] Run `pip freeze > requirements.txt` (150 pinned packages)
- [x] Verify Ollama API reachable from WSL — **done 2026-07-16, but not via `scripts/install_ollama.sh`**:
  user already had Ollama running on Windows with a model loaded, so rather than a redundant
  ~18GB re-download inside WSL2, we reused it — set `OLLAMA_HOST=0.0.0.0:11434` inline when
  launching `ollama serve` on Windows (the persisted env-var + app-restart approach did NOT
  work — Explorer-launched processes don't pick up new env vars without a full logoff, a
  Windows gotcha, not a bug here), added a Windows Firewall rule for port 11434, and pointed
  `.env`'s `OLLAMA_BASE_URL` at the WSL2 gateway IP (`172.22.208.1` at time of writing — **this
  IP is not stable across WSL2/Windows restarts**, re-derive with
  `ip route | grep default | awk '{print $3}'` if connectivity breaks later). Model name also
  didn't match the plan's assumed `qwen3-coder:30b` — actual registered name is
  `huihui_ai/qwen3-coder-abliterated:30b-a3b-instruct-q3_K_M`, `.env` updated accordingly.
  `scripts/install_ollama.sh` is still there (now with a `zstd` prerequisite fix) as a fallback
  for a fully self-contained WSL2 install, just wasn't the path taken [LLM]
- [ ] First commit + push — **explicitly deferred**, user chose to skip git/GitHub setup for
  this session [GitHub]

**Deliverable:** `python main.py` loads config, pings Ollama, prints "Agent ready" — no errors.
**Fully verified 2026-07-16**, both paths: with Ollama down, loads config, pings, exits cleanly
with a clear "LLM unreachable" message; with Ollama up (reused the user's existing Windows
install — see MEMORY.md), prints "Agent ready" and runs a real command end-to-end.

## Phase 1: LLM Core + Human-in-the-Loop

**Timeline:** Day 3 – 5

**Goal:** Human types a command → agent parses intent → asks for approval → executes → reports result


### LLM Connection

- [x] Write `config/settings.py`: load all env vars with Pydantic BaseSettings, expose as typed singleton [LLM]
- [x] Write `config/prompts.py`: system prompt for Orchestrator — instructs model to parse commands into structured JSON plans, always seek human approval before active scans [LLM]
- [x] Wire `langchain-ollama` client in `agent/planner.py` → **tested live against the model on
  2026-07-16** (Windows-hosted Ollama, `huihui_ai/qwen3-coder-abliterated:30b-a3b-instruct-q3_K_M`,
  reached from WSL2 via the gateway IP — see MEMORY.md for that networking setup). First attempt
  used free-hand JSON prompting per the plan's original sketch; **found a real bug**: the model
  reliably chose the right tool but regularly invented args that didn't match the tool's actual
  schema. Rewrote to use `llm.bind_tools(ALL_TOOLS)` instead, which hands the model each tool's
  real JSON schema. Verified working for tools with flat args (`get_waf_bypasses`) end-to-end,
  live, through the full HITL loop. **Second issue found and fixed**: tools with deeply-nested
  required objects (`check_scope`'s `ScopePolicy`) still got partially-wrong nested keys from
  this model/quantization even with `bind_tools`. Fixed by exposing `parse_scope_policy` as its
  own tool (runs the deterministic heuristic parser instead of asking the model to freehand a
  `ScopePolicy`) plus rewriting the planner/graph for multi-step tool calling so the model can
  call `parse_scope_policy` then `check_scope` with its exact output in one command — see
  MEMORY.md "check_scope reliability" for the full writeup. Verified live end-to-end [LLM]
- [x] Implement structured output parsing — superseded by the `bind_tools` approach above:
  `agent/planner.py`'s `plan_step()` reads `response.tool_calls` (schema-validated by the
  framework) instead of parsing free JSON text, and takes the running conversation so far
  rather than a single command (multi-step support, see above); `risk_level` comes from a
  static table (`agent/risk.py`), deliberately not trusted to the model — see that module's
  docstring [LLM]

### LangGraph State Machine

- [x] Define state enum: `IDLE → PLANNING → AWAITING_HUMAN → EXECUTING → REPORTING → ERROR` —
  in `agent/state.py` (`Stage` enum + `HuntState`/`ActionPlan` TypedDicts), not inline in
  `agent/orchestrator.py` as the plan originally sketched — kept the state schema in its own
  module since `agent/graph.py` also needs it and `orchestrator.py` is about tool wiring, not
  state
- [x] Build LangGraph graph with nodes per state and conditional edges (approve/reject/modify
  transitions) — `agent/graph.py`, `StateGraph`. First verified 2026-07-16 as a single
  plan/execute pass (`plan → awaiting_human → execute → report`) by driving
  `node_awaiting_human` → `node_execute` → `node_report` directly with a scripted plan (no live
  LLM needed) — LOW-risk auto-approve, MEDIUM-risk reject, and HIGH-risk explicit-"yes"-approve
  paths all confirmed correct. **Rewritten same day** into a loop
  (`plan → awaiting_human → execute → plan → ...`, `MAX_STEPS = 6` bound) so a command can chain
  multiple HITL-gated tool calls — needed to fix `check_scope` (see LLM Connection above).
  Verified live end-to-end with a real chained command, and regression-checked against the
  original scripted single-step tests
- [x] Implement state persistence: save current graph state to `sessions/` so interrupted hunts
  are resumable — `agent/session.py`'s `save_checkpoint()`/`load_latest()`, wired into
  `main.py` after every command. Full `resume` command UX is still Phase 4 scope; this only
  covers the on-disk checkpoint write/read

### HITL Gate

- [x] Write `agent/hitl.py`: gate that pauses the state machine, surfaces action + details to
  human, waits for approve/reject/modify. Deviation: implemented as a synchronous
  stdin-blocking prompt (`console.input`), not `asyncio` — the terminal loop is single-threaded
  and blocking is the correct behavior here (there's nothing else to run concurrently while
  waiting on a human), so `async def` would have added ceremony with no benefit
- [x] Implement three responses: **approve** → continue, **reject** → back to IDLE (routes to
  `END`), **modify** → re-plan with human's correction (routes back to the `plan` node with
  `human_note` set) — all three verified in isolation
- [x] Add risk-level coloring in terminal output: `LOW` (cyan), `MEDIUM` (yellow), `HIGH` (bold
  red) — require explicit `yes` for HIGH actions. Verified: rendered correctly for all three
  levels in manual node tests
- [x] Gate must fire before: any active scan, any exploit attempt, any submission, any new
  target [CRITICAL] — structurally enforced: `agent/graph.py`'s `execute` node is only
  reachable from `awaiting_human`'s "approve" edge, there is no path from `plan` straight to
  `execute`
- [x] **Scope-fabrication gate** [CRITICAL] — closed 2026-07-18, was the top open item from
  session 2. Verified live that the model will invent a plausible-looking scope policy from
  its own training knowledge when asked about a well-known program with no real scope text
  anywhere in the conversation, rather than asking the human — a prompt rule alone
  (`ORCHESTRATOR_SYSTEM_PROMPT` rule 1) was tried and confirmed NOT sufficient. Structural fix:
  `skills/scope_parser.py`'s `looks_like_scope_text()` heuristic (requires an explicit scope
  marker AND ≥2 distinct domain-shaped tokens in some message) + `agent/graph.py`'s
  `node_plan()` refusing to run `parse_scope_policy`/`check_scope`/`check_policy_compliance` at
  all — routing straight to `ERROR`, before any HITL approval prompt is ever shown — unless some
  `HumanMessage` in the conversation actually looks like real scope-page content. **Verified
  live**: the exact original fabrication-trigger command ("Check if api.hackerone.com is in
  scope for the HackerOne bug bounty program") now refuses immediately with a clear error
  instead of executing on fabricated args; the session-2 compound command ("is example.com in
  scope? In scope: example.com. Out of scope: internal.example.com.") still runs
  `parse_scope_policy` → `check_scope` end-to-end with zero regressions

### Master Orchestrator Prompt Rules — embed in `ORCHESTRATOR_SYSTEM_PROMPT`

- [x] Rule: **ALWAYS** check scope before acting on any domain — call `parse_scope()` (built in Phase 3) before every new target [CRITICAL]
- [x] Rule: **NEVER** test out-of-scope assets, even if they look interesting [CRITICAL]
- [x] Rule: ALWAYS present a plan and get human approval before active scanning
- [x] Rule: rate-limit all active scans — max 10 req/sec unless human explicitly overrides
- [x] Rule: ALWAYS collect evidence (response body, screenshot, request/response pair) before marking a finding confirmed
- [x] Rule: risk classification — `LOW` (passive recon) auto-proceeds, `MEDIUM` (active scan) shows plan, `HIGH` (exploit attempt) requires explicit "yes"
- [x] Rule: when unsure if something is in scope → ask the human, never assume [CRITICAL]
- [x] Rule: if `safe_harbor_stated` is False, tell the human before any active testing — legal
  protection may not apply. Never disclose a finding before `disclosure_embargo_days` have
  passed since resolution, even if the human wants to write it up sooner [CRITICAL]
- [x] Rule: if `ScopePolicy.program_type` is `vdp_no_reward`, tell the human before investing
  hunt time — confirm they still want to proceed knowing there's no monetary reward

### Terminal Interface

- [x] Build terminal UI with `rich`: current state / last action / findings count — `main.py`'s
  `_status_table()`, printed after every command. Deviation: this is a static `rich.table`
  reprinted per command, not a `rich.live.Live` auto-refreshing panel — a persistent Live
  display can't coexist cleanly with the blocking `console.input()` calls inside the HITL gate
  in the same terminal, so a print-after-each-turn table was the simpler correct choice
- [x] Command prompt loop in `main.py`: reads natural language input → passes to planner → runs
  graph. **Verified fully live 2026-07-16**: ran an actual command through `main.py` end-to-end
  against the real model — "Agent ready" printed, command parsed into a real tool call
  (`get_waf_bypasses`), LOW-risk auto-approved and shown, executed, checkpoint saved, status
  table rendered. This is the first time any part of this project has run against a live LLM.
- [ ] Test full loop: type `"recon example.com subdomains"` → plan shown → human approves →
  subfinder runs → results printed — **not yet possible**: needs (1) Ollama running
  (`scripts/install_ollama.sh`, not yet run) and (2) a `run_subfinder` tool wrapper, which is
  Phase 2 scope and doesn't exist yet. What IS verified: the identical mechanism — plan →
  HITL gate → tool execution by name → findings list → checkpoint save — works correctly
  end-to-end against the 12 skills already registered in `ALL_TOOLS` (see LangGraph State
  Machine section above). Swapping in `run_subfinder` once Phase 2 lands is a registration
  change, not a mechanism change.

**Deliverable:** Working HITL terminal loop with one tool (subfinder). Approval gate blocks all
action until human confirms. **Partially met** — the HITL loop and approval gate are built and
verified against the existing skill tools; the specific `subfinder` demo is blocked on Phase 0
(tool install) and Phase 2 (tool wrapper), neither done yet.

## Phase 2: Tool Integration Layer

**Timeline:** Day 6 – 9

**Goal:** All 40+ security tools callable as async Python functions with uniform structured output


> **Prereq:**  Phase 1 complete. All Go/pip tools installed and in PATH (verified in Phase 0).


### Tool Contract (implement once, use everywhere)

- [x] Define `ToolResult`: `tool, command_run, raw_output, parsed: list[Finding], duration_s, error`
  — `tools/base.py`. Deviation: pydantic `BaseModel`, not a stdlib dataclass — every other
  structured return in this codebase (`ScopePolicy`, `PoC`, `ConfidenceScore`, ...) already is,
  kept that convention instead of introducing a second one
- [x] Define `Finding`: `type, target, detail, severity, tool_source, timestamp` — `tools/base.py`
- [x] Write base `run_tool()` async helper — `tools/base.py`. Handles: binary not on PATH,
  subprocess timeout, non-zero exit code, and `OSError` on launch failure — all returned as an
  `error` string rather than raised, so a tool wrapper always gets a usable result to build a
  `ToolResult` from, never an exception to handle itself. Binary resolution checks
  `~/go/bin/<tool>` BEFORE the normal `shutil.which()` PATH search (added 2026-07-18 — see
  `run_httpx` below): a same-named PyPI package can install a CLI script into `.venv/bin`, which
  sits earlier on PATH than `~/go/bin` once the venv is active, silently shadowing the real
  Go-installed tool. Gained an optional `stdin_input` parameter (added for `run_waybackurls`
  below — verified live that tool ignores a domain passed as a positional arg entirely and just
  hangs waiting on stdin, unlike every ProjectDiscovery tool wrapped so far); backward
  compatible, existing wrappers are unaffected since it defaults to `None` (unchanged
  `stdin=None`/inherit behavior). **Rewritten 2026-07-19 to fix an architectural gap flagged
  repeatedly but not yet fixed**: previously used `proc.communicate()` under
  `asyncio.wait_for(..., timeout=timeout_s)`, which only returns its buffered result on clean
  completion — killing the process on timeout discarded EVERYTHING read so far, even when
  `run_gau`/`run_amass`/`run_waybackurls` had real partial output sitting in the pipe. Now drains
  `stdout`/`stderr` incrementally via a background reader task per stream as the process runs,
  so a kill only cuts off future output, not what's already captured; also tries `SIGTERM`
  (`proc.terminate()`) with a 3s grace period before `SIGKILL`, giving a well-behaved tool the
  chance to flush on its own terms. `error` is still always set on a timeout — a timeout is
  never silently treated as a clean, complete result, even when partial data comes back.
  **Verified live**: (1) direct `run_tool()` test — a `bash -c` script that printed two lines
  then slept past a 2s timeout correctly returned `'line1\nline2\n'` with `error` set, instead
  of empty strings; (2) real-world confirmation — re-ran `run_gau` against `hackerone.com` (the
  known outlier domain from the `run_gau` entry above) and it now returns 24 real findings AND
  a clear `error: "gau timed out after 120s (partial output below, if any)"`, where it previously
  would have returned zero findings; (3) full regression sweep of all 8 existing wrappers
  (`run_subfinder`/`run_httpx`/`run_naabu`/`run_nmap`/`run_dnsx`/`run_tlsx`/`run_gau`/
  `run_waybackurls`) against `scanme.nmap.org` — all still return their expected result counts
  with `error: null`. Every wrapper's wrapper-level `raw_output=stdout if not error else stderr`
  and `if not error:` findings-parsing gate was also updated (`raw_output=stdout or stderr` /
  `if stdout:`) — otherwise the wrapper layer would have kept discarding the newly-available
  partial data even after the `run_tool()` fix. **Doesn't help `run_amass`**: its results live in
  a file (`-oA`), not stdout — whether amass flushes that file on `SIGTERM` rather than
  `SIGKILL` is unverified, so a timed-out amass run should still be assumed to have lost its
  results until that's confirmed live

### tools/recon.py

- [x] Wrap `subfinder`: passive subdomain enum → returns list of subdomains — `run_subfinder`,
  registered in `ALL_TOOLS`, classified `LOW` in `agent/risk.py`. **Fully verified live
  2026-07-16**: confirmed real `-d`/`-silent`/`-json`/`-timeout` flags and JSON output shape
  (`{"host": "...", "input": "...", "source": "..."}`) against the installed binary; ran the
  async wrapper directly (19 real subdomains for `hackerone.com`); ran it through the full
  live-LLM HITL graph, including the model autonomously chaining it recursively on newly
  discovered subdomains plus a `check_scope` call, terminating cleanly at `MAX_STEPS`. Three
  real bugs found and fixed along the way — see MEMORY.md "Phase 2 kickoff" for the full
  writeup: (1) `agent/graph.py`'s `node_execute` couldn't invoke an async-only tool at all
  (`tool.invoke()` → `asyncio.run(tool.ainvoke())`), (2) Ollama's runtime context window
  defaulted too small for a real tool result (`OLLAMA_NUM_CTX` added to `config/settings.py`,
  applied to every `ChatOllama` instantiation), (3) the model sometimes emits a malformed
  pseudo-tool-call as plain text that `agent/planner.py` was silently treating as "no more
  actions" — now raises `PlanParseError` instead
- [x] Wrap `amass`: OSINT subdomain enum (different sources than subfinder) — `run_amass`,
  registered in `ALL_TOOLS`, classified `LOW` in `agent/risk.py` (`-passive` flag, third-party
  sources only). **Root cause of the original "not installed" finding**:
  `scripts/phase0_setup.sh`'s `GOTOOLS` list simply never included it (every other Phase 0 tool
  used so far is in that list, amass genuinely was not — it's OWASP Amass, a different project
  from the ProjectDiscovery tools making up most of that list, easy to have overlooked). Not a
  failed install, never attempted. Fixed 2026-07-18: added
  `github.com/owasp-amass/amass/v4/cmd/amass@latest` to `GOTOOLS` for future setup runs, AND
  installed it directly this session (`go install` needs no sudo — installs to `~/go/bin`,
  unlike the apt/docker/Go-toolchain steps elsewhere in that script). **Verified live
  2026-07-18, with two real discoveries that make this wrapper structurally different from
  every other one in this file**: (1) amass v4 produces NO stdout output at all when run
  non-interactively (confirmed twice, with and without `-silent`) — its terminal UI appears to
  require a real TTY. Results only ever land in a file via `-oA` (a text relationship graph:
  `subject (FQDN) --> relation_type --> object (FQDN)` per line), so `run_amass` writes to a
  `tempfile.TemporaryDirectory()`, reads the file back after `run_tool()` returns, and cleans
  up — every other wrapper here relies on stdout alone. (2) Runtime is markedly slower than
  every other recon tool AND unpredictable: three live runs against the identical target
  (`hackerone.com`) took ~95s, then timed out past 150s with zero results, then finished at
  ~137s — depends on however long amass's upstream OSINT sources take to respond, no way to
  predict up front. This matters more here than elsewhere: a run that hits `run_tool()`'s outer
  timeout gets SIGKILLed before it can flush its `-oA` file, so timing out means TOTAL loss of
  results, not a partial list like every JSON-over-stdout wrapper falls back to. `timeout_s`
  bumped to 180s for headroom (a "usually enough" margin, not a guarantee) — confirmed working
  with a final run: 29 findings, `error: null`, ~137s
- [x] Wrap `httpx`: probe live hosts → returns url, status, title, tech stack, redirect chain —
  `run_httpx`, registered in `ALL_TOOLS`, classified `MEDIUM` in `agent/risk.py` (first tool
  wrapper that sends real traffic). **Verified live 2026-07-18**: confirmed real
  `-json`/`-status-code`/`-title`/`-tech-detect`/`-follow-redirects`/`-rate-limit` flags and
  JSON output shape (`status_code`, `title`, `tech`, `final_url`, `chain_status_codes`, ...)
  against the installed binary; a non-resolving host is silently omitted by `-silent` (exit 0,
  no error) rather than reported as a failure. Accepts a batch of domains in one call via `-u`
  repeated per-host (no stdin support needed in `run_tool()`) so a whole `run_subfinder` result
  gets probed under one HITL approval instead of one prompt per host. Passes
  `-rate-limit settings.MAX_REQ_PER_SEC` — httpx defaults to 150 req/s, far above
  `ORCHESTRATOR_SYSTEM_PROMPT` rule 4's 10 req/s cap, so this is the first place that rule is
  enforced in code rather than just stated in the prompt. **Real bug found and fixed getting
  here**: the PyPI `httpx` package (an HTTP client, pulled in as a dependency) installs its own
  `httpx` CLI script into `.venv/bin`, which shadowed the real Go-based tool once the venv was
  active — `shutil.which("httpx")` silently resolved to the wrong binary (wrong CLI entirely,
  exit 2 on the real flags). Fixed in `tools/base.py`'s binary resolution, not per-wrapper — see
  the `run_tool()` entry above
- [x] Wrap `naabu`: port scan → returns open ports per host — `run_naabu`, registered in
  `ALL_TOOLS`, classified `MEDIUM` in `agent/risk.py` (CONNECT scan, no raw-socket privileges
  needed). **Verified live 2026-07-18**: confirmed real `-host`/`-top-ports`/`-json`/`-rate`
  flags and JSON output shape (`host`, `ip`, `port`, `protocol`, `tls`) against the installed
  binary. `-top-ports` only accepts naabu's own presets (`"100"`/`"1000"`/`"full"`) — an
  arbitrary integer like `"20"` is rejected outright, confirmed live. Two environment-specific
  fixes needed to get a working scan at all: (1) passes `-Pn` unconditionally — naabu's default
  ICMP-based host-discovery probe hangs indefinitely in this sandbox (raw TCP connects work
  fine via `/dev/tcp`, confirmed separately; ICMP specifically does not), so every scan without
  it timed out with zero output; (2) `-rate` set from `settings.MAX_REQ_PER_SEC` (10, per
  `ORCHESTRATOR_SYSTEM_PROMPT` rule 4) makes port scanning inherently much slower than
  `run_httpx` — measured live that naabu's default `-retries 3` re-scans every port per retry
  round (~62s for ONE host at 100 ports/rate 10), so `run_naabu` passes `-retries 1` instead
  (~23s/host measured) and overrides `run_tool()`'s default 120s subprocess timeout to 300s to
  accommodate a several-host batch without spuriously timing out. Still reports the same open
  `(host, port)` more than once even at `-retries 1`, so results are deduped in the wrapper
  before building findings (verified: 12 raw JSON lines → 6 correctly-deduped findings across
  2 real hosts)
- [x] Wrap `nmap`: service/version detection on naabu-found ports — `run_nmap`, registered in
  `ALL_TOOLS`, classified `MEDIUM` in `agent/risk.py`. **Verified live 2026-07-18**: confirmed
  real `-sT`/`-sV`/`-Pn`/`-p`/`--max-rate`/`-oX -` flags and XML output shape (`host`/`address`/
  `ports/port/state`/`service` with `name`/`product`/`version`/`extrainfo` attributes) against
  the installed binary, parsed with stdlib `xml.etree.ElementTree` (no new dependency). Uses
  `-sT` (connect scan) not `-sS` (SYN scan) — this machine has no root/CAP_NET_RAW, confirmed
  via `id`, and `-sT` needs neither. Deliberately scoped to a caller-supplied port list (meant
  to be `run_naabu`'s open-port findings for the same host), not a blind sweep — nmap's `-sV`
  probing is far more expensive per port than naabu's plain connect check. Passes `-Pn` as a
  pure speed optimization here (the caller already knows the host is alive), NOT a hang
  workaround like `run_naabu` needed — verified live that nmap's own default host-discovery
  does NOT hang in this sandbox (falls back to a TCP-based probe rather than pure ICMP when
  unprivileged). `--max-rate` set from `settings.MAX_REQ_PER_SEC`, same policy as
  `run_httpx`/`run_naabu`. **One real bug found and fixed during verification**: the XML parser
  initially built `Finding.target` from nmap's own resolved `<address>` element, which returned
  the target's IP rather than the hostname the caller passed in — inconsistent with every other
  wrapper's convention (`target` = the caller's own identifier, not something the tool resolved
  on its own) and would have confused downstream hostname-keyed correlation
  (`diff_tracker`/`check_scope`). Fixed to use the `host` parameter directly; re-verified live
- [x] Wrap `dnsx`: DNS record enumeration (A, CNAME, MX, TXT) — `run_dnsx`, registered in
  `ALL_TOOLS`, classified `LOW` in `agent/risk.py` (queries public third-party DNS resolvers,
  never the target's own infrastructure — same rationale as `run_subfinder`). Also queries
  AAAA and NS, one flag away and cheap. **Verified live 2026-07-18**: confirmed real `-l`
  (comma-separated string accepted directly, no stdin/file needed)/`-a`/`-aaaa`/`-cname`/`-ns`/
  `-mx`/`-txt`/`-json` flags and JSON output shape (`host`, `resolver`, per-record-type arrays,
  `status_code`) against the installed binary. No rate-limit flag applies — dnsx has no `-rate`
  option, only `-threads` for concurrency, and resolving through public resolvers isn't the
  target-facing traffic `ORCHESTRATOR_SYSTEM_PROMPT` rule 4 is about. A non-resolving domain is
  silently omitted (verified: 3-domain batch including one dead domain → findings only for the
  2 real ones, `error: null`, no crash)
- [ ] Wrap `gowitness`: screenshot all live hosts → save to `sessions/<target>/screenshots/` —
  **blocked**: `gowitness` itself is installed and runs (`go install` succeeded, on PATH), but
  its actual screenshot function needs a real Chrome/Chromium binary — verified live 2026-07-18
  it fails with `failed to initialize chrome context: exec: "google-chrome": executable file not
  found in $PATH`. No browser binary exists in this environment (`which chromium
  chromium-browser google-chrome` all empty; `apt-cache policy chromium-browser` shows only a
  snap-transitional candidate, nothing installed). Added `sudo apt install -y chromium-browser`
  to `scripts/phase0_setup.sh`'s step 1 — genuinely sudo-gated this time (unlike `amass`, which
  only needed a plain `go install`), so this one does need the user to run the script
  themselves before `run_gowitness` can be built and verified live
- [x] Wrap `tlsx`: TLS cert analysis → expiry, SANs, weak ciphers — `run_tlsx`, registered in
  `ALL_TOOLS`, classified `MEDIUM` in `agent/risk.py` (opens a real TLS connection directly to
  the target, unlike `run_dnsx`'s third-party-resolver queries). **Verified live 2026-07-18**:
  confirmed real `-u` (comma-separated, same batching as `run_httpx`)/`-json`/`-silent` flags
  and JSON output shape (`host`, `tls_version`, `cipher`, `not_before`, `not_after`,
  `subject_cn`, `subject_an`, `issuer_cn`, `wildcard_certificate`, ...) against the installed
  binary. No rate-limit flag applies (confirmed via `-h` — one handshake per host, same
  lightweight profile as `run_httpx`, not `run_naabu`'s per-port volume). Deliberately does NOT
  pass `-expired`/`-self-signed`/`-wildcard-cert`/`-mismatched` — verified live these didn't
  change output when combined with `-json` (e.g. `wildcard_certificate` was already present
  when true with no flag at all), and their "display host with X certificate" wording reads
  like an undocumented text-mode filter not worth the risk of silently dropping non-matching
  hosts from a JSON batch; expiry is computed directly from `not_after` instead (ties into
  `RECON_AGENT_PROMPT`'s existing rule to flag expired SSL certs — a `Finding.severity="low"`
  is set when the certificate has actually expired). A host with no HTTPS listener on 443 is
  silently omitted (verified live against `scanme.nmap.org`), same non-error pattern as
  `run_httpx`/`run_naabu`

### tools/url_harvest.py

- [x] Wrap `gau`: pull historical URLs from Wayback + CommonCrawl + AlienVault — `run_gau` in
  new `tools/url_harvest.py`, registered in `ALL_TOOLS`, classified `LOW` in `agent/risk.py`
  (queries third-party archives, never the target). **Verified live 2026-07-18**: confirmed real
  `--json`/`--providers`/`--blacklist`/`--from` flags and JSON output shape (`{"url": "..."}`)
  against the installed binary. Single domain per call, not a batch — verified live that two
  domains as positional args didn't behave like `run_httpx`'s repeated `-u` (didn't finish in
  25s where one domain reliably does), so this follows `run_nmap`'s single-target precedent
  instead of guessing at undocumented multi-arg behavior. Deliberately restricts
  `--providers wayback,otx` (skips commoncrawl/urlscan) — verified live that even this narrower
  set returned 47,000+ URLs and still hadn't finished after 60s for `hackerone.com` specifically
  (a decade-old, high-profile platform), while a smaller/newer domain (`scanme.nmap.org`)
  finished in ~19s with 42 URLs — this is normal gau behavior for that kind of target, not a
  bug. `tools/base.py`'s `run_tool()` discards stdout entirely on a timeout, so a run that hits
  it comes back as `error`, not a partial list — added an optional `from_date` (YYYYMM) param
  as the escape hatch, since gau has no result-count limit flag, only date-range narrowing
- [x] Wrap `waybackurls`: Wayback Machine URL extraction — `run_waybackurls`, registered in
  `ALL_TOOLS`, classified `LOW` in `agent/risk.py` (third-party archive query, same as
  `run_gau`). Takes NO domain flag/positional arg at all — verified live it ignores one
  entirely and hangs on stdin instead — so this is the first wrapper to use `run_tool()`'s new
  `stdin_input` parameter rather than a CLI arg. **A reliability caveat found and documented,
  not hidden**: three live runs against the identical domain (`hackerone.com`) returned wildly
  different results — 1189 URLs (killed at 60s), 0 URLs (exited 0/"success" at ~61s), 302 URLs
  (killed at 90s). The Wayback CDX API this tool queries appears to intermittently return
  partial/empty results with no error surfaced by either waybackurls or this wrapper — unlike
  every other wrapper here, an error-free empty result from `run_waybackurls` does NOT reliably
  mean "no history," and the docstring says so explicitly. Verified live end-to-end through the
  actual wrapper (not just the raw binary) against `scanme.nmap.org`: 84 findings, `error: null`,
  ~37s
- [x] Wrap `katana`: active JS crawl → find endpoints, forms, APIs — `run_katana`, registered in
  `ALL_TOOLS`, classified `MEDIUM` in `agent/risk.py` (sends real HTTP requests directly to the
  target as it crawls). **Critical scope-safety bug found and fixed via live testing, not
  assumed safe**: katana's default `-fs rdn` (root-domain-name) scope sent a REAL request
  (confirmed via a populated `response` field in JSONL output, distinguishing it from
  discovered-but-never-fetched links) to `nmap.org` itself when crawling
  `http://scanme.nmap.org` — a different host than the one passed in, just sharing its
  root/registrable domain. An authorized subdomain does NOT imply the root domain is
  authorized in a real bug-bounty program; this would have been a genuine scope violation.
  Every other discovered link (`facebook.com`, `github.com`, `npcap.com`, etc.) had no
  `response` field at all — confirmed those are normal, safe, never-fetched extracted
  references, not requests. Fixed with `-fs fqdn` (exact host match); verified live this
  restricts every actual HTTP request to precisely the target passed in — re-ran the same
  crawl and confirmed only `scanme.nmap.org` ever appears with a populated `response`. Also
  passes `-omit-raw -omit-body` (default JSONL embeds entire HTML/CSS/JS response bodies per
  line — verified live this bloats output for no benefit, `parsed` findings only need
  endpoint/method/tag/status) and `-rate-limit` from `settings.MAX_REQ_PER_SEC`. Single URL per
  call, matching `run_nmap`/`run_gau`'s single-target precedent. **Verified live**:
  `http://scanme.nmap.org`, depth 2 → 6 findings, `error: null`, ~14s, confirmed only
  `scanme.nmap.org` appears across every finding's URL
- [x] Wrap `hakrawler`: fast web spider → `run_hakrawler`, registered in `ALL_TOOLS`, classified
  `MEDIUM` in `agent/risk.py` (sends real HTTP requests directly to the target as it crawls).
  **Critical scope-safety bug found via a controlled local test (two local HTTP servers, not
  assumed safe), same class as `run_katana`'s default-scope bug**: hakrawler has no flag
  equivalent to katana's `-fs`; its `-i` flag is documented as "only crawl inside path" but
  verified live that's actually what confines the crawl to the seed host — without it, a
  seed page linking to a completely unrelated second local server got that server a REAL GET
  request (confirmed via its own access log), not just the link being extracted. With `-i`,
  zero requests reached the unrelated server while same-host crawling still worked. `-i` is
  therefore passed unconditionally, never caller-optional; `-subs` deliberately never passed,
  same reasoning as katana's `-fs fqdn`. Takes its URL via stdin (positional arg silently
  ignored, verified live), same `run_tool(stdin_input=...)` path as `run_waybackurls`.
  **Verified live**: `http://scanme.nmap.org`, depth 2 → 8 findings, `error: null`, ~0.8s;
  `agent/orchestrator.py` imports cleanly with 24 tools total
- [x] Wrap `gf`: pattern grep over URL list (xss, sqli, ssrf, redirect, lfi patterns) →
  `run_gf`, registered in `ALL_TOOLS`, classified `LOW` in `agent/risk.py` — genuinely
  different from every other wrapper in this file: pure local grep over an already-harvested
  URL list, zero network activity. **Blocker found and fixed, no sudo needed**: the `gf` binary
  itself (installed via `GOTOOLS`) is non-functional out of the box — `gf -list` was empty and
  `gf xss` returned "no such pattern" (exit 0) on a fresh install, confirmed live 2026-07-19,
  because the binary alone ships with no pattern files. Fixed by cloning
  `github.com/1ndianl33t/Gf-Patterns` into `~/.gf/*.json` (14 patterns: debug_logic, idor,
  img-traversal, interestingEXT, interestingparams, interestingsubs, jsvar, lfi, rce, redirect,
  sqli, ssrf, ssti, xss) — plain git clone, no sudo, so done directly rather than deferred to
  the user; also added to `scripts/phase0_setup.sh` for future fresh installs. `run_gf` takes
  `urls: list[str]` + `pattern: str`, validates `pattern` against the installed set and returns
  an explicit `error` for an unknown one (gf itself silently prints "no such pattern" with
  exit 0, which would otherwise look identical to "ran fine, matched nothing"). **Verified
  live**: `xss`/`redirect` patterns against a 4-URL test list gave correct matches (3 and 1
  respectively); unknown-pattern case returns the expected error; `agent/orchestrator.py`
  imports cleanly with 25 tools total, `run_gf` classified `LOW`
- [x] Wrap `paramspider`: mine parameters from historical URLs → `run_paramspider`, registered
  in `ALL_TOOLS`, classified `LOW` in `agent/risk.py` (queries the Wayback Machine CDX API
  directly, never the target). Was blocked earlier in session 4 (not on PATH, needs a git-clone
  + dedicated venv, not a real PyPI package) — unblocked the same session by `pip install -e`
  into `~/tools/.venv-scripts` with a real console-script entry point, referenced by absolute
  path (`_PARAMSPIDER_BIN` in `tools/url_harvest.py`) since that venv isn't this project's own.
  **Verified live 2026-07-19** against `scanme.nmap.org`: 2 findings, `error: null`, ~3s;
  confirmed it does NOT litter a stray `results/` directory into the project root (worked
  around via `run_tool(..., cwd=<tempdir>)`, a new parameter added to `run_tool()` this session).

### tools/scanner.py — all built session 4, see MEMORY.md "Session 4 summary" for full detail

- [x] Wrap `nuclei`: run with specific template tags, parse JSON output → structured findings —
  `run_nuclei`, MEDIUM. Safe default `tags` + unconditional `-etags dos,fuzz`
- [x] Wrap `nikto`: web server misconfiguration scan — `run_nikto`, MEDIUM. XML via `-o -`
  (no JSON option on this build), `-Tuning x6809` excludes DoS/cmd-exec/upload/SQLi by default
- [x] Wrap `wapiti`: full web vuln scan (different engine = different finds) — `run_wapiti`,
  MEDIUM. **Critical finding**: wapiti's own defaults (`exec`+`file`) and its `common` bundle
  (`exec`+`upload`+`ssrf`-to-external-callback+`permanentxss`) are NOT safe — this wrapper uses
  an explicit conservative module allowlist instead
- [x] Wrap `corsy`: CORS misconfiguration detection — `run_corsy`, MEDIUM. Worked around a real
  isatty/stdin hang bug in the vendored tool via `stdin_input=""`
- [x] Wrap `smuggler`: HTTP request smuggling detection — `run_smuggler`, MEDIUM. No JSON mode,
  parses its `-q -l <logfile>` output; real runs need a 300s timeout (verified: 217s against a
  live target for the full ~134-mutation default set)
- [x] Wrap `testssl.sh`: TLS weakness scanner — `run_testssl`, MEDIUM. `--ip one` avoids
  per-resolved-IP multiplication; `-S` only (full protocol+cipher sweep takes several minutes)
- [x] Wrap `wpscan`: WordPress vuln scanner (conditional on tech detection) — `run_wpscan`,
  MEDIUM. Installed via `gem install --user-install` (no sudo) — needed a new binary-resolution
  fallback in `tools/base.py` for Ruby gem bin dirs

### tools/vuln_specific.py — all built session 4, see MEMORY.md "Session 4 summary"

- [x] Wrap `dalfox`: XSS detection on param list — `run_dalfox`, MEDIUM. Blind-fire mode
  deliberately not enabled (that's the HIGH tier per agent/risk.py's own comment)
- [x] Wrap `kxss`: reflected XSS parameter finder — `run_kxss`, MEDIUM. Takes a URL list via
  stdin like run_gf
- [x] Wrap `XSStrike`: advanced XSS with payload generation — `run_xsstrike`, MEDIUM. Two real
  gotchas: `--json` means "POST data as JSON" not "JSON output" (no JSON mode exists at all),
  and it crashes with `EOFError` on its own interactive "continue scanning?" prompt unless fed
  `stdin_input`
- [x] Wrap `sqlmap`: SQL injection detect + exploit — `run_sqlmap`, **HIGH**, detection-only:
  hardcoded `--batch --level 1 --risk 1`, no passthrough, NEVER `--dump`/`--os-shell`/any
  exfiltration or shell-access flag
- [x] Wrap `ghauri`: advanced SQLi for modern apps — `run_ghauri`, **HIGH**, same detect-only
  boundary as run_sqlmap; shares its output parser
- [x] Wrap `subjack` + `subzy`: subdomain takeover detection — `run_subjack`/`run_subzy`, both
  MEDIUM, read-only fingerprint checks

### tools/secrets.py + tools/cloud.py + tools/api.py — all built session 4, see MEMORY.md "Session 4 summary"

- [x] Wrap `trufflehog`: scan git repos, S3, URLs for secrets — `run_trufflehog`, MEDIUM.
  Always `--no-verification` (verification = actively authenticating with a found credential
  against a real API, deliberately not automated)
- [x] Wrap `gitleaks`: git repository secret scanning — `run_gitleaks`, **LOW** (zero network —
  scans an already-local repo path, doesn't clone; complements run_trufflehog rather than
  duplicating it)
- [x] Wrap `SecretFinder`: API keys in JS files — `run_secretfinder`, MEDIUM
- [x] Wrap `s3scanner` + `cloud_enum`: cloud asset enumeration — `run_s3scanner` (MEDIUM, never
  `--dangerous`) + `run_cloud_enum` (MEDIUM; fixed a real packaging bug — its pip-editable
  install breaks its own default mutation-file path resolution; ships a small ~38-word default
  mutation list instead of the vendored 306-word one, which was confirmed live to exceed 300s
  even with 2 of 3 clouds disabled — `thorough=True` opts into the full list)
- [x] Wrap `kiterunner`: API endpoint brute-force (40k+ routes, really 364k on the installed
  wordlist) — `run_kiterunner`, **HIGH** — no rate-limit flag exists at all (confirmed live:
  ramps to 7,000-8,000 req/s), a structural conflict with this project's 10 req/s policy that no
  other wrapper has
- [x] Wrap `arjun` + `ffuf`: parameter and directory discovery — `run_arjun` + `run_ffuf`, both
  MEDIUM; run_ffuf defaults to SecLists' `common.txt` (installed via snap, not apt)
- [x] Start `interactsh-client` as always-on background service → capture OOB interactions
  (blind SSRF/XSS/XXE) [CRITICAL] — `interactsh_start`/`interactsh_poll`/`interactsh_stop` in
  `tools/api.py`, all LOW. Architecturally different from every other Phase 2 wrapper: launches
  a DETACHED long-running process (not a bounded `run_tool()` call), persists its PID + log
  path under `sessions/_interactsh/<id>.json`, and exposes start/poll/stop as three separate
  tool calls rather than one function — this is the only way to model "start now, keep
  listening while other tools run, check back later" within this codebase's one-shot
  tool-call architecture

**Deliverable:** All tools callable as `await run_subfinder(domain)`-style async functions. LLM
can read and reason over structured output. **Phase 2 complete as of session 4 (2026-07-19)** —
37/37 checklist items done, 51 tools total registered in `ALL_TOOLS`. The only genuinely
unbuilt wrapper from the original 40+-tool list is `run_gowitness`, tracked separately above
since it's blocked on a missing Chrome/Chromium binary (needs the user to run
`scripts/phase0_setup.sh`), not unwritten code.

## Phase 3: Skills, Payloads & Safety Prompts

**Timeline:** Day 10 – 12

**Goal:** LLM-callable skills layered on top of the tool contract — scope enforcement, payload intelligence, chaining, PoC generation, bypass, fingerprinting


> **Prereq:**  Phase 2 complete — `ToolResult`/`Finding` contract exists. Skills reuse that same contract and register alongside tool wrappers.


**Build order:**

1. **Scope parser + orchestrator rules** — Safety — never test out-of-scope assets
2. **HITL risk rules in prompt** — Core behavior (done in Phase 1)
3. **Payload library** — Quality of vuln detection
4. **Chain analyzer** — Biggest impact on payout value
5. **PoC builder** — Required for good reports
6. **WAF bypass** — Needed when hits get blocked
7. **Tech stack analyzer** — Better scan targeting


### Scaffolding

- [x] Create `config/skills/` and `config/payloads/` with `__init__.py` stubs — **deviation**:
  skills live at top-level `skills/` instead (documented repo-wide, e.g. `agent/orchestrator.py`
  imports from `skills.*`); `config/payloads/` was followed as written
- [ ] Every skill returns the same `ToolResult`-shaped structure as tool wrappers, so the LLM calls skills and tools identically

### Tier 1 — Must Have

- [x] `config/skills/scope_parser.py`: parse a program's scope page/text (HackerOne/Bugcrowd) → `ScopePolicy(allowed_domains, forbidden_domains, allowed_vuln_types, max_severity)` [SKILL] [CRITICAL]
- [x] Wire scope check as a mandatory pre-flight gate: every target is checked against `ScopePolicy` before any tool call fires — no exceptions [CRITICAL]
- [x] Build `config/payloads/xss.yaml`: reflected, stored, DOM, polyglot payload sets [SKILL]
- [x] Build `config/payloads/sqli.yaml`: error-based, blind, time-based, OOB payload sets [SKILL]
- [x] Build `config/payloads/ssrf.yaml`: cloud metadata endpoints, internal IP ranges, protocol wrappers (file://, gopher://, dict://) [SKILL]
- [x] Build `config/payloads/lfi.yaml`: path traversal depths, null-byte variants, PHP wrappers [SKILL]
- [x] Build `config/payloads/ssti.yaml`: Jinja2, Twig, Freemarker, Smarty template-injection probes [SKILL]
- [x] Build `config/payloads/open_redirect.yaml`: scheme-relative, double-encoded, whitelist-bypass redirect payloads [SKILL]
- [x] Write payload loader: context-aware selector picks a payload set by detected param type / reflection context, not a raw wordlist dump [SKILL]
- [x] `config/skills/chain_analyzer.py`: after each phase, reason over accumulated low/medium findings → `ChainSuggestion(findings_involved, chain_type, potential_severity, steps_to_prove)` [SKILL] [LLM]
- [x] `config/skills/poc_builder.py`: generate a working PoC from any confirmed `Finding` → `PoC(steps, code, curl_command, screenshot_path)` [SKILL]

### Tier 2 — High Value

- [x] `config/skills/bypass.py`: on a blocked payload + detected WAF signature, generate encoding/case-mutation/comment-insertion/method-switch/chunked-encoding variants to retry [SKILL]
- [x] `config/skills/tech_analyzer.py` — 2026-07-22: `skills/tech_analyzer.py`'s `analyze_tech`
  builds a `TechProfile(framework, language, cms, auth_mechanism, cloud_provider, api_type,
  evidence)` from headers, cookie names, HTML body, up to 3 linked JS files, and a
  deliberately-nonexistent-path error-page probe — each field cites the exact signal that
  produced it in `evidence`. **MEDIUM** in `agent/risk.py` (sends a handful of real GETs).
  Live-verified against a local test server (correctly detected framework/language/
  cloud-provider/auth-mechanism from planted signatures). `select_nuclei_tags` (same file) maps
  a `TechProfile` to a targeted `run_nuclei` tags value — closes the Tier 3 "nuclei template
  selector" item below too, kept in this file since it's a direct `TechProfile` consumer [SKILL]
- [x] `config/skills/graphql.py` — 2026-07-22: `skills/graphql_mapper.py`'s `introspect_graphql`
  runs schema introspection, flags introspection-enabled-in-prod as its own finding, and flags
  mutations matching a sensitive-action keyword list (delete/update/admin/password/transfer/
  grant/role/...). `check_graphql_idor` mirrors `auth_mapper.py`'s `check_idor` (numeric-ID
  mutation + differential-auth) applied to a GraphQL query body instead of a REST URL — same
  `tools/response_fingerprint.py` false-positive guards. **MEDIUM**/**HIGH** respectively in
  `agent/risk.py`. Live-verified against a local mock GraphQL server, including a negative
  control (nonexistent object ID produces zero findings) [SKILL]
- [x] `config/skills/auth_mapper.py` — 2026-07-22, now complete: `check_jwt_weaknesses`
  (weak-secret dictionary crack, alg=none forgery, RS256→HS256 algorithm-confusion via a
  dependency-free hand-rolled JWKS→PEM converter — `skills/jwt_toolkit.py`) and `check_idor`
  (numeric-ID mutation + differential-auth across two identities' tokens) were built first
  (2026-07-22 session 5), both live-verified against a local test server and registered
  **HIGH** in `agent/risk.py` — forging/replaying real auth material is an active bypass
  attempt, not passive inspection. The remaining piece — mapping a login → session/refresh-
  token → role-gated-endpoint → password-reset flow end-to-end — is now also built:
  `map_auth_flow`, pure LLM reasoning over a human-supplied request sequence, same shape and
  **LOW** risk as `map_business_logic`. Techniques reimplemented from scratch (no code copied —
  no LICENSE in the source repo) after reviewing a third-party OWASP-API scanner's approach; see
  MEMORY.md for the evaluation [SKILL]

### Tier 3 — Nice to Have

- [x] CVE lookup skill — 2026-07-22: `skills/cve_lookup.py`'s `lookup_cves` queries the real NVD
  API (`keywordSearch`) and cross-references CISA's KEV catalog, reporting a KEV-listed CVE as
  **critical** regardless of its own CVSS score. **LOW** in `agent/risk.py` — every request goes
  to NVD/CISA's own public infrastructure, never the actual target. Live-verified against both
  real endpoints; also caught and fixed a real bug where CVSSv2 entries (most pre-2016 CVEs)
  report `baseSeverity` as a sibling of `cvssData` rather than nested inside it like CVSSv3.x —
  the first version silently reported "unknown" severity for every one of them [SKILL]
- [x] Shodan/Censys query builder — 2026-07-22: `skills/recon_query_builder.py`'s
  `build_recon_queries`. Deliberately does NOT call either API (no credentials configured
  anywhere in `config/settings.py`, and both require a paid plan for real use) — builds
  ready-to-paste query strings in each platform's own syntax, matching the plan's own "query
  builder" wording. **LOW**, pure string construction, no network at all [SKILL]
- [x] Nuclei template selector — see `select_nuclei_tags` under `tech_analyzer.py` above [SKILL]
- [x] Duplicate checker — 2026-07-22, **reduced scope from the original wording**:
  `skills/hacktivity_checker.py`'s `build_hacktivity_search` returns a Hacktivity search link +
  keyword suggestions for a human to check manually, NOT an automated checker. Verified live
  first that an automated version isn't reliably buildable: `hackerone.com/hacktivity` is a
  client-rendered SPA shell with no report data in the raw response, and the GraphQL API it
  actually calls has introspection disabled in production (confirmed:
  `{__schema{...}}` → `"Field '__schema' doesn't exist on type 'Query'"`) — scraping it would
  mean reverse-engineering an undocumented, unstable private API with no way to verify it stays
  correct. **LOW**, no network call [SKILL]

### Tier 4 — Differentiators (why this agent isn't a generic scanner clone)

Added after a competitive review: payload fuzzing + nuclei templates are commodity — every
public bounty agent runs those. These six close real gaps, in build order.

- [x] `skills/policy_compliance.py`: `check_policy_compliance` — detects "no automated tools" /
  manual-testing-only language and prohibited techniques (DoS, social engineering, physical) in
  a program's policy text, independent of domain scope. Must run once per program, before
  `check_scope` runs per-target. [SKILL] [CRITICAL]
- [x] `skills/scope_parser.py` extended: `ScopePolicy.payout_tiers` — parses `"Critical: $5,000"`-
  style lines out of scope text so downstream prioritization has real numbers, not guesses. [SKILL]
- [x] `skills/diff_tracker.py`: `diff_against_last_scan` — snapshots assets + JS-content hashes per
  target under `sessions/<target>/snapshot.json`; ranks new/changed surface over re-scanning
  everything cold every session. [SKILL]
- [x] `skills/roi_prioritizer.py`: `prioritize_targets` — ranks (asset, vuln_type) candidates by
  expected value (base-rate prior × `ScopePolicy.payout_tiers`) so scan budget goes to what's
  likely to pay, not breadth-first across every vuln type. [SKILL]
- [x] `skills/business_logic_mapper.py`: `map_business_logic` — reasons over a named multi-step
  flow (checkout, invite, password reset) for sequence-only flaws (step-skipping, price/quantity
  tampering, coupon reuse, mid-flow IDOR, one-time-action races) that payload fuzzers structurally
  cannot find. Findings are never auto-confirmable, same as other business-logic rules. [SKILL] [LLM]
- [x] `skills/confidence_scorer.py`: `score_finding_confidence` — actually implements the
  `MIN_REPRO_COUNT` / `MIN_CONFIDENCE_TO_AUTOCONFIRM` settings that `config/prompts.py` already
  stated but nothing enforced; scores baseline-vs-trigger response deltas across repeat attempts. [SKILL]
- [x] `skills/hitl_batcher.py`: `group_for_batch_approval` + `explain_action` — batches repetitive
  low-risk approvals into one prompt instead of one-per-target, and attaches a one-line "why
  this is being asked" to every approval. **Not an LLM tool** — helper functions consumed by
  `agent/hitl.py` (built in Phase 1), deliberately excluded from `ALL_TOOLS`. [SKILL]

### Tier 5 — Eligibility & Payout Optimization

Added after reviewing why real-world bounty reports get rejected: most rejections aren't
"wrong," they're "not eligible" (won't-fix category, duplicate, VDP with no reward) or
"insufficiently proven" (no demonstrated impact). Technical vuln-finding quality alone doesn't
convert to payouts without these.

- [x] `skills/scope_parser.py` extended: `ScopePolicy.program_type` (`paid` / `vdp_no_reward` /
  `unknown`, detected from payout tiers + "swag only"/"hall of fame"/"points only" language) and
  `ScopePolicy.excluded_finding_categories` (self-XSS, clickjacking, missing headers, logout
  CSRF, rate-limiting, SPF/DKIM, autocomplete, TLS best-practice, version disclosure, HTTP
  OPTIONS/TRACE — detected from the program's own policy text). [SKILL]
- [x] `skills/policy_compliance.py` extended: `PolicyCompliance.safe_harbor_stated` and
  `disclosure_embargo_days` — parses "safe harbor" language and a stated disclosure embargo
  ("no public disclosure for 90 days after resolution") so early disclosure doesn't forfeit a
  bounty. [SKILL] [CRITICAL]
- [x] `skills/eligibility_filter.py`: `check_eligibility` — auto-rejects a finding matching a
  known low-value/excluded category unless `has_demonstrated_impact` is true (then flags for
  human review instead of auto-confirming or auto-killing). Runs right before `build_poc`. [SKILL]
- [x] `skills/eligibility_filter.py`: `queue_for_retest` + `get_retest_queue` — tracks resolved
  findings per target under `sessions/<target>/retest_queue.json` so patch-bypass retests (a
  fresh bounty, not a duplicate) don't get forgotten between sessions. [SKILL]

### Register with Orchestrator

- [x] In `agent/orchestrator.py`, import every skill into the same `tools` list as the tool wrappers: `[analyze_chains, parse_scope, run_subfinder, run_nuclei, ...]`
- [x] `check_policy_compliance` registered immediately after `check_scope` in `ALL_TOOLS`, per prompt rule 8
- [x] `check_eligibility` and `queue_for_retest` registered in `ALL_TOOLS`, immediately before the reporting skills (`build_poc`, `get_waf_bypasses`)
- [x] Confirm the LLM can call each skill exactly like a tool wrapper — same structured-return
  contract, same HITL gating rules where risk applies. **Done and verified live 2026-07-16**:
  `agent/orchestrator.py` imports/builds cleanly with all 13 tools registered (12 skills +
  `parse_scope_policy`, added this session), and a real command ran through the full
  plan→HITL→execute→plan loop against the live model, including a two-tool chain
  (`parse_scope_policy` → `check_scope`) and a single-tool call (`get_waf_bypasses`). See
  MEMORY.md "check_scope reliability" for the two bugs found and fixed along the way

**Deliverable:** Every target is scope-checked before any action. Fuzzing uses context-aware payload sets instead of raw wordlists. Findings can be chained and turned into a PoC on demand.

## Phase 4: Recon Pipeline

**Timeline:** Day 13 – 16

**Goal:** One command triggers full automated recon: subdomains → live hosts → ports → crawl → params → dirs → LLM summary


### Pipeline Orchestration

- [x] Wire recon pipeline stages in LangGraph — 2026-07-22: `agent/recon_pipeline.py`, a SEPARATE
  graph from `agent/graph.py`'s single-LLM-chosen-action loop (that one's `MAX_STEPS=6` can't fit
  an 8-stage sequence, and the sequence here is fixed by design, not something to re-derive via
  the LLM each time). Stage order: subfinder → httpx → naabu+nmap (`ports`) → katana+gau
  (`crawl`) → paramspider (`params`) → ffuf (`dirs`) → enrichment → LLM aggregate. Every stage
  goes through the same propose→gate→execute triad `agent/graph.py` already established, just
  generalized to a fixed stage list instead of one LLM-chosen action
- [x] Add HITL gate between each stage — approval happens BEFORE a stage runs (not after),
  matching `ORCHESTRATOR_SYSTEM_PROMPT` rule 2, using the exact same `request_approval()` gate
  and risk-level styling the single-action loop already uses. A reject stops the pipeline early
  with partial results checkpointed (see `resume`, below), not a hard failure
- [x] Run secrets + cloud + takeover agents in parallel — the `enrichment` stage runs
  `run_subzy` + `run_cloud_enum` + `run_s3scanner` + `run_secretfinder` (on JS files the `crawl`
  stage found) concurrently via `asyncio.gather`, behind ONE combined approval. **Scoped
  honestly, not literally**: "parallel" here means concurrent with each other, not literally
  overlapping the sequential main pipeline's wall-clock — this graph's nodes are synchronous
  state transitions, same execution model `agent/graph.py` already uses, so true
  background-while-other-stages-run concurrency would need a different execution model
  entirely. `run_trufflehog` deliberately excluded: needs a real git repo URL a domain-only
  recon pipeline has no way to discover
- [x] LLM aggregates all stage output → ranked target list — `_execute_aggregate` condenses
  every accumulated finding (grouped by type, capped per type, hard char budget) plus the
  scope-diff result into one prompt, run through `RECON_AGENT_PROMPT` as the system message.
  Live-verified: produced well-formed JSON matching the prompt's own requested shape (assets
  array with type/priority/details) [LLM]

### Recon Agent Prompt Rules — embed in `RECON_AGENT_PROMPT`

- [x] Rule: focus on breadth first, depth second — added 2026-07-22, was the only genuinely
  missing rule; every other rule below was already substantively present in the prompt text,
  just never checked off
- [x] Rule: flag subdomains that look like staging/dev/internal — already present
- [x] Rule: flag subdomains with a tech stack different from the main domain — already present
- [x] Rule: flag any domain with expired SSL, unusual open ports, or non-standard headers —
  already present
- [x] Rule: always note acquisition domains and recently-registered subdomains found via
  certificate-transparency logs — already present
- [x] Rule: on a previously-hunted target, call `diff_against_last_scan` first and bias priority
  toward `new_assets`/`changed_js` — freshly changed surface has a materially higher hit rate
  than re-treading unchanged production that's already been picked over
- [x] Rule: call `get_retest_queue` for this target — retesting a resolved finding for a patch
  bypass is worth as much as new surface, and nothing else in the pipeline remembers it

### Session & Memory

- [x] Write `agent/memory.py` — 2026-07-22: ChromaDB `PersistentClient` with its bundled default
  embedding model (no separate embedding-model config/API key needed). `save_findings_to_memory`
  (plain function, called automatically after the `aggregate` stage, not an LLM tool) and
  `query_similar_findings` (an LLM tool, LOW risk — reads this project's own local store only).
  **Real bug found and fixed via a live test, not just an import check**: the first version
  hashed each finding's memory ID from the pipeline's OUTER target string (constant across the
  whole batch) instead of the finding's OWN `target` field — two findings sharing a type+detail
  but different actual targets (e.g. two subdomains both httpx-fingerprinted identically)
  collapsed to the same ID and `chromadb`'s `upsert()` rejects a batch with any duplicate ID
  outright. Fixed to hash on the finding's own target; re-verified live
- [x] Save session checkpoint JSON after every stage — `node_execute` calls
  `agent/session.py`'s existing `save_checkpoint()` after every stage, not just per-command like
  `main.py`'s single-action loop already did
- [x] Implement `resume` command — `resume_recon_pipeline()` + `main.py`'s `"resume <target>"` /
  `"resume recon <target>"` command routing. **A second real bug found and fixed via a live
  test**: the node that runs when a stage gate gets rejected unconditionally set `stage="done"`
  regardless of WHY the pipeline stopped — this made `resume_recon_pipeline`'s "is this already
  finished" check treat a rejected-and-stopped run as complete, so resuming after a reject
  (exactly the scenario this feature exists for) silently did nothing. Fixed: `stage_index` is
  now the sole authoritative progress marker; `stage` is `"done"` only when every stage actually
  ran, `"rejected"` when stopped early by a human reject. Verified live: reject mid-pipeline →
  resume → confirms it continues from the next stage, keeps every finding collected before the
  interruption, and finishes; resuming an already-finished pipeline correctly returns `None`
  instead of silently restarting
- [x] Dedup logic — not new tracking logic: operationalizes `skills/diff_tracker.py`'s
  already-built `diff_against_last_scan` (Phase 3 Tier 4) inside the `subfinder` stage —
  `hosts_to_probe` for every subsequent stage is `new_assets` (plus the root target), not the
  full subdomain list, so an unchanged subdomain from a prior scan doesn't get re-probed

**Deliverable:** `"recon hackerone.com"` → complete recon report with LLM summary and ranked
targets. **Caveat on the 10–15 min figure**: not re-verified at full scale this session — several
stages (`naabu`/`nmap` at the mandated 10 req/s rate, `ffuf`'s default ~4,749-entry wordlist per
host) are individually slow enough that a real multi-host run could exceed that window; the
per-stage host caps (`_MAX_HOSTS_PORTS`/`_MAX_HOSTS_CRAWL`/`_MAX_HOSTS_DIRS` etc. in
`agent/recon_pipeline.py`) exist specifically to bound this, tune them if a real run runs long.

## Phase 5: Vulnerability Assessment

**Timeline:** Day 17 – 21

**Goal:** LLM reasons over recon data → prioritizes vuln classes by tech stack → targeted scanning → human-confirmed findings


### LLM Planner

- [x] Planner prompt: given tech stack from httpx → output prioritized vuln checklist (e.g. "WordPress detected → run wpscan + nuclei:wordpress") [LLM] — `agent/vuln_pipeline.py`'s `tech_profile` stage, `_build_vuln_checklist`
- [x] Map tech → tool: React app → XSS + CORS; PHP → SQLi + LFI; S3 present → cloud_enum; login form → auth bypass tests [LLM] — same planner call, verified live it grounds recommendations in actual `TechProfile` evidence rather than inventing tech
- [x] Business logic hint engine: LLM flags areas needing human manual testing (multi-step flows, privilege escalation, payment logic) [LLM] — `business_logic_hints` stage; deliberately a URL-pattern hint scan (WHERE to look), not a full step-sequence mapper — that's `map_business_logic`/`map_auth_flow`'s job once a human captures the real request sequence

### Scanning & False-Positive Reduction

- [x] Run nuclei with targeted template tags based on planner output (not all templates — reduces noise) — `targeted_scan` stage, tags come from `select_nuclei_tags` fed by the tech profile
- [x] LLM vuln assessor: reads raw scanner output → filters likely false positives → assigns confidence score [LLM] — new `skills/vuln_assessor.py` (`assess_findings`), batch-triages a whole stage's findings in one LLM pass; verified live it discriminates a concrete exposed-`.git/config` finding (confidence 9, real) from a generic tech-detect match (confidence 3, flagged false-positive) rather than scoring by severity label alone
- [x] HITL gate: human reviews each finding — approve (confirmed), reject (false positive), escalate (needs deeper test) [CRITICAL] — `gate` stage, per-finding via `request_batch_approval` (see `agent/vuln_pipeline.py`'s own docstring for why this ONE stage's HITL shape differs from every other stage's single approve/reject)
- [x] OOB monitor: check interactsh server for callbacks after each scan phase → attribute any hits to specific payloads — `tech_profile` starts a session, `finalize` polls + stops it; deliberately coarse (run-level, not payload-level) attribution since this fixed pipeline doesn't itself craft a payload embedding the domain — see the module docstring's "OOB (out-of-band) monitoring" paragraph for why
- [x] Store human-confirmed findings separately from scanner raw output in ChromaDB — `agent/memory.py`'s new `save_confirmed_findings_to_memory`, a distinct `confirmed_findings` collection from the raw `findings` one

### Vuln Assessment Agent Prompt Rules — embed in `VULN_AGENT_PROMPT`

- [x] Rule: never report a finding with confidence < 7/10 without human review — sourced from `score_finding_confidence`, not asserted [CRITICAL]
- [x] Rule: always attempt to determine business impact, not just technical severity
- [x] Rule: for each finding, ask "can this be chained with anything else found?" — via `analyze_chains`
- [x] Rule: for any multi-step flow, run `map_business_logic` on the request sequence — sequence-only flaws don't show up in single-request fuzzing
- [x] Rule: business logic flaws cannot be auto-confirmed — always flag for human [CRITICAL]
- [x] Rule: false-positive check — verify the finding is reproducible 3 times before marking confirmed
- [x] Rule: before `build_poc`, call `check_eligibility` on every confirmed finding — many
  technically-true findings (self-XSS, clickjacking on non-sensitive pages, missing headers
  alone, etc.) are auto-rejected by most programs and not worth a PoC/report without
  demonstrated impact
- [x] Rule: when a program marks a finding resolved, call `queue_for_retest` — a confirmed
  bypass of a patched fix is a fresh bounty, not a duplicate

### Wire Tier 1/2 Skills into the Assessment Loop

- [x] Route every accumulated finding set through `chain_analyzer.analyze_chains()` after each scan stage [SKILL] — `chain` stage, over the plausibly-real subset per the `assess` stage's own output
- [x] Generate a PoC via `poc_builder.py` for every human-confirmed finding [SKILL] — `finalize` stage, after `check_eligibility`; parameter/payload are best-effort (no per-parameter fuzz artifact survives to this stage — see that stage's own comment)
- [x] On any blocked/filtered payload response, invoke `bypass.py` to generate and retry variants [SKILL] — new `xss_probe` stage (`run_kxss` + `run_dalfox`) detects the concrete "blocked/filtered" signal (kxss confirms reflection, dalfox reports zero exploitable findings there — per `run_dalfox`'s own docstring that specifically does NOT mean confirmed-clean), then a new `skills/waf_bypass_prober.py` (`probe_waf_bypass`) actually retries `get_waf_bypasses`' variants via a real HTTP request. Verified live against a real local test server simulating a naive WAF filter — genuinely detected the block and found a working bypass variant
- [x] Feed the `tech_analyzer.py` fingerprint into the planner before selecting the nuclei template subset [SKILL] — `tech_profile` stage feeds `select_nuclei_tags` into `targeted_scan`
- [x] Run `graphql.py` introspection whenever a `/graphql` endpoint is discovered [SKILL] — `graphql_probe` stage, auto-discovers from `live_hosts`/accumulated finding targets
- [x] Run `auth_mapper.py` whenever the human supplies test credentials/tokens for the target [SKILL] — new `auth_probe` stage, gated on an optional `auth_token`/`auth_other_identity_token` (`run_vuln_pipeline(...)` params, or `"assess <target> token=... [other_token=...]"` in `main.py`): runs `check_idor` on live hosts, `check_jwt_weaknesses` once if the token looks JWT-shaped, and `map_auth_flow` always. A clean no-op with nothing supplied — never silently skipped without saying so (see that stage's own propose text)

**Deliverable:** Prioritized, confidence-rated, human-confirmed finding list per target, with chain suggestions and draft PoCs attached. Business logic hints surfaced for manual testing. **Fully delivered** via `agent/vuln_pipeline.py` (`"assess <target>"` / `"resume assess <target>"` in `main.py`) — all checklist items above are now done, including the WAF-bypass retry loop and credentialed auth-mapper wiring that were still open after the first pass.

## Phase 6: Web UI

**Timeline:** Day 22 – 25

**Goal:** Gradio web app at `http://<WSL-IP>:7860` — full hunt orchestration from Windows browser


### Gradio Layout

- [x] Build `ui/app.py` with Gradio Blocks: target input, start button, phase status indicator [UI] — three tabs (Automated Recon, Automated Vuln Assessment, Natural-Language Command), each with its own target/command input + Start/Resume buttons, sharing one status line below
- [x] Left panel: live streaming agent activity log (WebSocket-fed) [UI] — implemented as a single shared Activity Log textbox, fed by `graph.stream()` (not a hand-rolled WebSocket — see "WebSocket Bridge" note below) via a `gr.Timer` polling roughly once a second
- [x] Right panel: HITL approval gate — Approve / Reject / Modify buttons surface here instead of terminal [UI] — a shared Pending Approval panel + three buttons, live-tested via a real running Gradio server (not just unit-level) driving a full recon pipeline to completion through the actual HTTP API
- [x] Bottom panel: findings table (sortable by severity), notes field, generate report button [UI] — findings `gr.Dataframe`, a notes textbox (feeds reject/modify), and a Generate Report button — the button itself is a stub (Phase 8 isn't built yet), stated as such rather than silently doing nothing
- [x] Bind Gradio to `server_name="0.0.0.0", server_port=7860` so accessible from Windows at WSL IP [UI]

### WebSocket Bridge

- [x] Add FastAPI WebSocket endpoint in `main.py` → agent pushes events (stage start, tool output, HITL request, finding) — **deliberately NOT built as a hand-rolled endpoint**: Gradio (already a FastAPI/Starlette app underneath — `fastapi==0.139.2` already in `requirements.txt`) runs its own live component-update transport for exactly this need. A second, redundant WebSocket protocol alongside the one Gradio already runs internally would add real complexity (message schema, reconnect handling, session multiplexing) for no visible capability gain in a single-user local tool — see `agent/web_hitl.py`'s own module docstring for the full reasoning. `ui/app.py`'s `gr.Timer` polling plays this role instead.
- [x] Gradio frontend subscribes → renders streamed events in activity log in real-time — via the Timer poll above, backed by `agent.recon_pipeline`/`agent.vuln_pipeline`/`agent.graph`'s own `build_*graph()` + `.stream()` (confirmed live before writing any UI code: LangGraph's default stream mode already yields this project's full node-return-shape, no config tuning needed)
- [x] HITL approval from UI sends WebSocket message back → unblocks agent state machine — via `agent/web_hitl.py`'s `WebApprovalBackend` (a `threading.Event`-based backend, thread-local per hunt via `agent/hitl.py`'s new pluggable `ApprovalBackend`), not literally a WebSocket message, but delivering the same "browser click unblocks the pipeline" behavior
- [x] Test: trigger hunt from browser, approve stages in browser, see results in browser — no terminal needed — verified two ways: (1) function-level, driving `ui/app.py`'s own `_start_recon`/`_poll`/`_approve`/`_reject` directly through a full recon pipeline to completion AND a mid-pipeline reject; (2) a REAL Gradio server launched and driven via `gradio_client` over actual HTTP, from Start through repeated Poll/Approve to a finished pipeline — not literally a browser, but the same HTTP/session layer a browser would use

**Deliverable:** Full hunt operable from Windows Chrome at `http://localhost:7860`. Human approves/rejects via UI buttons. **Delivered**, with the WebSocket-bridge item intentionally reduced in scope as explained above — every other item is unreduced.

## Phase 7: Memory & Session Management

**Timeline:** Day 26 – 28

**Goal:** Agent remembers across restarts, resumes interrupted hunts, avoids re-reporting known findings

**Deliverable:** `"resume last session on target.com"` → agent loads state, skips already-found subdomains, continues where left off.

## Phase 8: Report Generator

**Timeline:** Day 29 – 31

**Goal:** One-click professional bug bounty report ready to paste into HackerOne / Bugcrowd


### Report Pipeline

- [x] Write Jinja2 template for Markdown report: Executive Summary, PoC Steps, Impact, CVSS Score, Remediation sections — `config/report_templates.py`, three platform variants (see the format-toggle item below), all sharing the same Executive Summary/Steps/Impact/CVSS/Remediation section set
- [x] LLM writes narrative from structured findings: converts raw tool output into plain-English impact statement [LLM] — `skills/report_generator.py`'s `generate_report_narrative()`, the ONE genuinely LLM-driven piece (CVSS and remediation are deliberately NOT LLM-guessed — see that module's own docstring for why). Verified live against real Ollama: given a JWT-weak-secret + BOLA + exposed-`.git/config` finding set, it wrote a specific, grounded summary/impact naming the actual findings, not generic boilerplate
- [x] Auto-calculate CVSS 3.1 score based on finding metadata (attack vector, complexity, privileges, impact) — `calculate_cvss()`, the official FIRST.org CVSS 3.1 formula implemented exactly and **verified against 4 independent, well-known reference vectors** before anything was built on top of it (a classic unauthenticated-RCE vector → 9.8, CVE-2021-44228 Log4Shell's own NVD vector → 10.0, a typical reflected-XSS vector → 6.1, a typical IDOR vector → 7.5 — all matched exactly). Per-finding metric VALUES come from `_CVSS_PROFILE_BY_FINDING_TYPE`/`_CVSS_PROFILE_BY_SEVERITY`, which ARE approximations (documented as such, human review expected) — only the arithmetic on top is exact
- [x] Human review + edit step in UI before export (textarea, not locked) — `ui/app.py`'s Report section: "Generate Report Draft" populates an editable `gr.Textbox`, a SEPARATE "Export" button writes whatever's in that box (edited or not) — generation and export are deliberately two different actions so nothing gets written to disk before a human can revise it
- [x] Export to `reports/<target>/<date>-report.md` and `.pdf` (reportlab) — `export_report()`. The `.pdf` path uses a deliberately scoped-down Markdown→reportlab renderer matching exactly what this module's own templates emit (headers/paragraphs/fenced code/`**bold**`), not a general markdown parser. Verified live: real `.md` and `.pdf` files written to disk, PDF confirmed to start with a genuine `%PDF-` header, not just a renamed text file
- [x] Platform-specific format toggles: HackerOne markdown vs Bugcrowd format vs Immunefi template — three distinct Jinja2 templates in `config/report_templates.py` (Bugcrowd's own P1–P5 priority scale computed from the CVSS severity tier). Each is a best-effort STRUCTURAL approximation of that platform's commonly-documented submission format, not a literal scrape of any program's live custom form — documented as such in that file's own module docstring, the same honesty precedent as the Shodan/Hacktivity items. Verified live that the three templates produce genuinely different section structure, not just a label swap (e.g. only Bugcrowd's output contains "Business Impact"/"Priority")

### Report Writing Agent Prompt Rules — embed in `REPORT_AGENT_PROMPT`

- [x] Rule: write from the triage engineer's perspective — they need to reproduce this in under 5 minutes
- [x] Rule: never use AI-sounding phrases ("certainly", "I found", "as an AI")
- [x] Rule: CVSS score must be justified line by line, not just stated — `calculate_cvss()`'s own `justification` field spells out every metric letter and why, attached to every finding in the rendered report
- [x] Rule: impact section must reference the specific business risk, not a generic "data breach possible"
- [x] Rule: steps to reproduce must be numbered, one action per step, no ambiguity
- [x] Rule: attach `poc_builder.py` output directly — request/response pair, screenshot, curl command [SKILL] — every rendered finding includes `build_poc`'s own steps/curl_command/code fields (all 6 rules above were ALREADY embedded in `REPORT_AGENT_PROMPT` in `config/prompts.py` from an earlier phase; this pass is what finally calls it)

**Deliverable:** Click "Generate Report" → Markdown + PDF ready. Human edits narrative, exports, submits directly to platform. **Delivered** — `main.py`'s `"report <target> [hackerone|bugcrowd|immunefi]"` command and `ui/app.py`'s Report section (Generate Draft → edit → Export) both call the same `skills/report_generator.py` machinery.

## Phase 9: CI / Polish

**Timeline:** Day 32 – 33

**Goal:** GitHub Actions linting, full README, stable deploy, project ready for ongoing use

**Deliverable:** Tagged v0.1.0 on GitHub. CI passing. Full hunt → report cycle works end-to-end on a real target.

### Checklist

- [x] GitHub Actions `lint` job — `ruff check .` (was the only job originally; kept as-is)
- [x] GitHub Actions `test` job — installs `requirements-dev.txt` (a minimal test-only
  dependency set, NOT the full CUDA/Gradio runtime stack) and runs `python -m pytest -q`.
  Rationale for the split deps lives in the `test` job's own comment in `ci.yml` and in
  `requirements-dev.txt`'s header.
- [x] Real pytest coverage in `tests/` (was an empty `__init__.py`). 67 tests covering the
  pure-logic, safety-critical contracts that don't need the LLM / network / external binaries:
  - `test_risk.py` — fixed risk table, fail-closed-to-HIGH default, SQLi tools always HIGH
  - `test_scope_parser.py` — the scope-fabrication gate (`looks_like_scope_text`), in/out-of-scope
    classification, prose-on-one-line splitting, forbidden-wins, payout-tier + VDP detection,
    wildcard `check_scope`
  - `test_eligibility_filter.py` — low-value auto-reject, demonstrated-impact → human review,
    program-specific exclusions, retest-queue roundtrip
  - `test_payload_loader.py` — every shipped `config/payloads/*.yaml` parses; missing-type safe path
  - `test_hitl_batcher.py` — approval grouping key (tool + risk) and the explain-action line
  - `test_tool_base.py` — `run_tool()`'s never-raise / always-set-`error` contract (success,
    missing binary, non-zero exit, timeout) against harmless local binaries, plus the
    `Finding`/`ToolResult` model defaults
- [x] Root `conftest.py` puts the repo root on `sys.path` so `tests/` import the project
  packages regardless of where pytest is invoked.
- [x] `[tool.pytest.ini_options]` in `pyproject.toml` pins test discovery to `tests/`.
- [x] README updated: Status now reads Phases 1–9 complete, with a "Tests & CI" section
  documenting how to run the suite and what the two CI jobs do.
- [ ] Tag `v0.1.0` on GitHub — deferred to the user (a release tag is a maintainer action, not
  something to cut automatically on their behalf).
- [ ] Full hunt → report cycle end-to-end on a real *authorized* target — requires a live
  Ollama host, the Phase 0 tool binaries installed, and a real in-scope program; can only be
  run by the user in their own environment, not from CI or this agent's sandbox.
