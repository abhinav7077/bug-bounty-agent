# Project Memory — Bug Bounty Agent

Last updated: 2026-07-24 (session 7, **Phase 8 built** — CVSS 3.1 calculator, report generator,
Markdown+PDF export, 3 platform templates; Phases 5 and 6 fully complete beforehand in the same
session).
Read this first in any new session before touching the code — it's the handoff summary. Full
task-level checklist: [docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md). Live version with
click-to-check progress tracking: https://claude.ai/code/artifact/1bcab525-024f-4bb5-bd8d-f70ea5c0ff20

## Session 7, continued a third time (2026-07-24) — Phase 8 built: CVSS calculator, `skills/report_generator.py`, `config/report_templates.py`

Right after Phase 6 finished (below), user said "continue with next phase" (and separately asked
how to run the UI — answered inline, not memory-worthy). Phase 8 (Report Generator) is now
built — `jinja2==3.1.6`/`reportlab==5.0.0` were already in `requirements.txt` and installed
(confirmed live before committing to the phase).

**Three genuinely different concerns, handled the way each actually deserves** (documented
explicitly in `skills/report_generator.py`'s own module docstring so a future session doesn't
"fix" this into one LLM call):
1. **CVSS 3.1 base score** — pure, deterministic arithmetic per the official FIRST.org formula,
   implemented in `calculate_cvss()`. **Verified against 4 independent, well-known reference
   vectors BEFORE writing anything on top of it** (a classic unauthenticated-RCE vector → 9.8, the
   actual published NVD vector for CVE-2021-44228 Log4Shell → 10.0, a typical reflected-XSS vector
   → 6.1, a typical IDOR vector → 7.5 — all four matched exactly). This is the same "verify a pure
   function against known-correct values" pattern as verifying live against a real server for
   anything network-facing — a calculation can still be live-verified even with no network
   involved. `_roundup()` implements CVSS's own specified rounding procedure (NOT Python's
   `round()` — smallest 1-decimal-place value >= x, defined via integer arithmetic specifically to
   dodge floating-point boundary errors).
2. **Narrative (executive summary, impact)** — the ONE piece that genuinely needs an LLM, via
   `generate_report_narrative()` using the ALREADY-EXISTING `REPORT_AGENT_PROMPT` (written in an
   earlier phase, never called until now). Verified live against real Ollama: given a JWT-weak-
   secret + BOLA-ID-mutation + exposed-`.git/config` finding set, it wrote a summary/impact
   naming the SPECIFIC findings (weak secret value, ID mutation 42→99, exposed repo metadata),
   not generic "data breach possible" boilerplate.
3. **Remediation** — a static lookup by finding type (`_REMEDIATION_BY_FINDING_TYPE`), not an LLM
   guess — a fix suggestion for "jwt_weak_secret" doesn't change per-run, and a wrong static
   suggestion is a one-time fix instead of a hallucination repeating across every future report.

**Per-finding CVSS metric VALUES fed into the exact calculator above ARE approximations**
(`_CVSS_PROFILE_BY_FINDING_TYPE`/`_CVSS_PROFILE_BY_SEVERITY`) — this codebase has no per-finding
attack-complexity/scope telemetry, so a finding TYPE maps to that vuln class's well-established,
commonly-published CVSS shape (e.g. JWT forgery → the 9.8-shape vector, reflected-XSS-style
findings → the 6.1-shape vector), with an honest fallback to the tool's own reported severity
tier for anything without a specific profile (mainly `nuclei_match`, since nuclei assigns its own
severity per template but no CVSS vector). Every finding's `justification` text names exactly
which path was used, satisfying `REPORT_AGENT_PROMPT`'s existing "CVSS score must be justified
line by line" rule (that prompt, and all its other rules, were ALREADY written in an earlier
phase — this pass is what finally calls it).

**New `config/report_templates.py`**: three Jinja2 template strings (HackerOne/Bugcrowd/Immunefi),
mirroring `config/prompts.py`'s own "config/ holds content, skills/ holds logic" split. Each is a
best-effort STRUCTURAL approximation of that platform's commonly-documented submission format
(section names/order), not a literal scrape of any program's live custom form — same
scope-honesty precedent as the Shodan/Hacktivity items, documented in the file's own docstring.
Verified live the three genuinely differ in structure (only Bugcrowd's output contains "Business
Impact"/a computed P1–P5 priority), not just a find-and-replace label swap.

**`agent/memory.py` gained `get_confirmed_findings(target)`** — an EXACT metadata-filtered
`collection.get(where=...)` fetch, deliberately not `query_similar_findings`'s top-k semantic
search, since report generation needs the COMPLETE confirmed set for one target, not an
approximate match. Required also storing `detail` as its own metadata field (previously only
embedded inside the `documents` string) so read-back is lossless — verified live that the exact
original detail text round-trips, not a re-parsed/truncated approximation.

**Human review + edit step, per the plan's own explicit requirement**: `ui/app.py`'s Report
section splits "Generate Report Draft" (writes nothing to disk, just fills an editable textbox)
from "Export" (a SEPARATE button that writes whatever's currently in that box) — so a human can
revise the LLM-written narrative before anything hits `reports/<target>/`. `main.py` also gained
a `"report <target> [hackerone|bugcrowd|immunefi]"` command for the same underlying
`skills/report_generator.py` machinery.

**Verified end-to-end, not just unit-level**: the full `generate_report` tool call (real Ollama,
not mocked) produced a real `.md` file AND a real, non-trivial `.pdf` file on disk — confirmed
the PDF starts with a genuine `%PDF-` header (not a renamed text file) via the deliberately
scoped-down Markdown→reportlab renderer (handles exactly what this module's own templates emit:
headers/paragraphs/fenced code/`**bold**` — not a general markdown parser nobody asked for).
Also verified the clean-error path (no confirmed findings for a target) and the UI wiring
functions (`_do_generate_report`/`_do_export_report`) directly. Ollama's Windows-side
`llama-server` crashed with the same known CUDA error mid-run again this session and came back
on its own again — this is now the THIRD time in one session; still don't assume it's reliable,
but a simple retry-after-a-moment has worked every time so far.

**No regressions**: re-ran the full Phase 4/5/6 test suite afterward. One OLD scratch test script
(`test_vuln_pipeline_resume.py`, written before the `xss_probe`/`auth_probe` stages existed)
appeared to fail — investigated rather than assumed-fine: it was the SCRIPT's own stale,
non-deterministic design (a global reject-counter that doesn't account for the pipeline now
having 10 stages instead of 8, combined with several newer stages it never mocked hitting real
Ollama/network calls), not an actual regression — confirmed by writing a clean, fully-mocked
resume test from scratch, which passed. Worth remembering: a scratch test failing doesn't
automatically mean new code broke something — check whether the TEST's own assumptions are still
valid for the current code shape before concluding a real regression.

## Session 7, continued again (2026-07-24) — Phase 6 built: `ui/app.py`, `agent/web_hitl.py`, `agent/hitl.py` refactored for pluggable backends

Right after Phase 5 finished (below), user said "continue next phase" — Phase 6 (Web UI) is now
built. `gradio==6.20.0`/`fastapi==0.139.2`/`uvicorn`/`websockets` were ALREADY in
`requirements.txt` and installed (confirmed live before committing to this phase), so nothing new
needed installing.

**Core architectural problem this phase had to solve**: every existing HITL gate
(`agent/graph.py`'s `node_awaiting_human`, `agent/recon_pipeline.py`/`agent/vuln_pipeline.py`'s
`node_gate`) calls `agent/hitl.py`'s `request_approval()`, which blocked on `console.input()` —
meaningless in a browser session where "the human" is a button click on a completely different
request/thread than the one running the pipeline. Fixed by making the approval I/O itself
pluggable rather than rewriting any of the three graphs:

- **`agent/hitl.py` refactored**: extracted the original stdin behavior unchanged into
  `ConsoleApprovalBackend`, added an `ApprovalBackend` interface, and made the active backend
  **thread-local** (`threading.local()`, not a plain module global) via
  `set_approval_backend()`/`get_approval_backend()`. `request_approval()`/`request_batch_approval()`
  are now thin wrappers delegating to whichever backend the CALLING thread opted into — every
  existing caller (`agent/graph.py`, `agent/recon_pipeline.py`, `agent/vuln_pipeline.py`) needed
  ZERO changes, since they only ever called the module-level functions, never a backend directly.
  Thread-local specifically because two concurrent hunts (two background threads, one per browser
  tab) must never resolve each other's pending approval — verified live, not just designed: a
  test ran two concurrent hunt threads with two different backends/sessions and confirmed
  resolving one never touched the other, AND that the main thread's own default
  `ConsoleApprovalBackend` was untouched by either.
- **New `agent/web_hitl.py`**: `HuntSession` (thread-safe shared state: activity log, findings,
  status, current pending approval) + `WebApprovalBackend` (blocks on a `threading.Event` instead
  of stdin — `request()` parks a `PendingApproval` in the session and waits; `resolve_pending()`,
  called from a UI button click on a DIFFERENT thread, sets the decision and signals the event).
- **New `ui/app.py`**: Gradio Blocks app, three tabs (Automated Recon, Automated Vuln Assessment,
  Natural-Language Command) sharing one status line / activity log / pending-approval panel /
  findings table below. Every "Start"/"Resume" button spawns a `threading.Thread` (returns
  immediately — a Gradio click handler that blocked for a whole pipeline run would freeze the
  buttons the human needs to click) that sets this thread's backend to a fresh
  `WebApprovalBackend`, then calls `build_recon_graph()`/`build_vuln_graph()`/`build_graph()`'s
  `.stream()` directly (NOT those modules' own `run_*()`/`resume_*()`, which call `.invoke()` and
  only return once the whole pipeline finishes) — `.stream()` yields `{node_name: full_state}`
  after every node, which is what actually lets the activity log update stage-by-stage. **Verified
  live before writing any UI code**: LangGraph's default stream mode already hands back this
  project's full node-return-shape (every node here returns `{**state, **delta}`, never a bare
  delta), so no stream-mode config tuning was needed. A `gr.Timer` polls the active
  `HuntSession` roughly once a second and renders it.
- **Deliberately reduced in scope from the plan's literal wording, documented rather than
  silent** (same "ship the honest, smaller version" precedent as session 5's Shodan/Hacktivity
  items): the plan describes a hand-rolled FastAPI WebSocket endpoint as the UI<->backend
  transport. Gradio is ALREADY a FastAPI/Starlette app underneath and already runs its own live
  component-update transport for exactly this need — a second, redundant WebSocket protocol
  would add real complexity (message schema, reconnect handling, session multiplexing) for no
  visible capability gain in a single-user local tool. `gr.Timer` polling plays that role
  instead. Also v1-scoped: ONE hunt at a time per browser tab (one shared `gr.State` across all
  three tabs), and `request_batch_approval` falls back to one prompt per action in the web
  backend rather than a dedicated batch-approval widget (slower, never less safe).
- **Verification, two passes**: (1) function-level — called `ui/app.py`'s own
  `_start_recon`/`_poll`/`_approve`/`_reject` directly (mocked tool wrappers + LLM) through a
  full recon pipeline to completion, AND a mid-pipeline reject, confirming the findings table and
  activity log update correctly; (2) a REAL Gradio server launched (`demo.launch(...,
  prevent_thread_lock=True)`) and driven via `gradio_client` over actual HTTP — Start, then
  repeated Poll/Approve calls through the real API — to a finished pipeline. Also confirmed the
  Vuln Assessment tab cleanly errors (not crashes) when no recon checkpoint exists yet, matching
  the CLI's own behavior.
- **No regressions**: re-ran every Phase 4/5 test (memory collision fix, resume-after-reject,
  full 10-stage vuln pipeline mocked + real-LLM, WAF-bypass real-local-server test) after the
  `agent/hitl.py` refactor landed — all still pass, confirming `ConsoleApprovalBackend` is
  byte-for-byte the original behavior for any thread that never opts into a different one (i.e.
  `main.py`'s CLI loop is completely unaffected by this refactor).

## Session 7, continued (2026-07-24) — closed Phase 5's two remaining gaps: WAF-bypass retry loop, credentialed auth-mapper wiring

Right after the first Phase 5 pass (below), user said "continue phase 5 now" to close the two
checklist items that pass had left genuinely open. Both are now done, adding two new stages to
`agent/vuln_pipeline.py` (`VULN_STAGES` grew from 8 to 10) and one new skill:

- **New `xss_probe` stage** (after `targeted_scan`, before `auth_probe`) — runs `run_kxss` then
  `run_dalfox` per live host. The concrete "blocked/filtered payload" signal this reacts to:
  `run_kxss` confirms a param reflects special characters at a URL, but `run_dalfox` returns
  ZERO findings there — per `run_dalfox`'s OWN docstring, that specific combination does NOT
  mean "confirmed clean" (dalfox's detection is documented as non-deterministic). When that
  combination fires, a new `skills/waf_bypass_prober.py` (`probe_waf_bypass`) actually retries
  `skills/bypass.py`'s `get_waf_bypasses` variants via a real HTTP request (`tools/http_client.py`'s
  `send_request`) — closing the loop `get_waf_bypasses` deliberately leaves open ("this function
  never sends a request itself").
- **`probe_waf_bypass` is HIGH risk**, and — important architectural note — it does NOT inherit
  `xss_probe`'s own MEDIUM stage-level approval. `node_execute` calls `request_approval` directly
  with its OWN explicit HIGH-risk action for each candidate before ever invoking it, so a human
  gets a real explicit "yes" prompt for the actual bypass attempt rather than it being smuggled in
  under the stage's baseline MEDIUM approval — the exact "don't fold a HIGH tool into a lower-risk
  stage's single approval" precedent MEMORY.md already flagged from Phase 4's `run_kiterunner`
  exclusion. Verified this actually happens, not just documented: a live test asserted exactly one
  nested HIGH-risk approval request fired, with the correct risk_level.
- **`probe_waf_bypass` verified against a REAL local HTTP server**, not mocked — a naive
  simulated WAF that blocks the literal substring `<script>` and reflects everything else
  unfiltered. It genuinely detected the block and found a working bypass variant
  (`%3Cscript%3Ealert(1)%3C/script%3E` — a URL-encoded variant the naive substring filter missed)
  entirely through the real HTTP stack (aiohttp client -> real socket -> http.server), the same
  "spin up two local servers and check the real access log" verification rigor this project's
  earlier scope-safety fixes used.
- **New `auth_probe` stage** (after `xss_probe`, before `graphql_probe`) — gated on an optional
  test credential (`run_vuln_pipeline(..., auth_token=..., auth_other_identity_token=...)`, or
  `main.py`'s new `"assess <target> token=... [other_token=...]"` command syntax). With a token
  supplied: runs `check_idor` on live hosts, `check_jwt_weaknesses` ONCE (against one
  representative host — repeating a real forged-token replay per host multiplies live bypass
  attempts for zero extra signal, since the token itself is what's being tested, not the host)
  if the token looks JWT-shaped (`token.count(".") == 2`), and `map_auth_flow` always. With no
  token: a clean no-op, `stage="LOW"`, and the stage's own propose text says exactly why nothing
  ran rather than silently skipping. Unlike `xss_probe`, this stage does NOT need a nested
  approval — when it runs at all, EVERYTHING inside it is inherently a HIGH-risk active
  auth-bypass attempt, so the whole stage proposes as HIGH and gates with one explicit "yes."
- **A real bug found and fixed via this round's live testing** (same "verify live, don't trust
  code that looks right" pattern every prior session has followed): `agent/memory.py`'s
  `_get_client()` cached its ChromaDB `PersistentClient` on `_client is None` alone, never
  checking whether `settings.SESSIONS_DIR` had actually changed since. Running the vuln pipeline
  twice in the same process against two different SESSIONS_DIR values (exactly what any future
  pytest suite with tmp_path-scoped fixtures would do) surfaced this as a "readonly database"
  error on the SECOND run — the client kept writing to the FIRST run's now-stale/deleted
  `_chroma` path. Fixed by tracking the path the cached client was built with and rebuilding if
  it no longer matches `settings.SESSIONS_DIR`; harmless no-op for the normal case (one
  SESSIONS_DIR per `main.py` process, never mutated).
- Full pipeline re-verified end-to-end after both stages landed: WITH a supplied JWT-shaped
  token, all three auth_probe tools' findings landed in `all_findings`; WITHOUT one, none did.
  No regressions in any of session 7's earlier tests (memory collision fix, resume-after-reject,
  the original 8-stage mocked + real-LLM passes).

## Session 7 summary (2026-07-24) — Phase 5 built: `agent/vuln_pipeline.py`, `skills/vuln_assessor.py`, confirmed-findings memory collection

Same-session start: first verified the two real bugs session 6 found (finding-ID hash collision
in `agent/memory.py`, resume-after-reject in `node_done`) were actually fixed and still working —
re-ran live tests against both (not just re-reading the code), both confirmed fixed. User then
said "continue next phase development," so Phase 5 (vulnerability assessment) is now built,
mirroring Phase 4's own dedicated-LangGraph-pipeline pattern:

- **`agent/vuln_pipeline.py`** (new) — a SEPARATE fixed-stage LangGraph, same propose→gate→execute
  triad as `agent/recon_pipeline.py`, 8 stages: `tech_profile` (runs `analyze_tech` across live
  hosts, feeds `select_nuclei_tags`, and an inline LLM call maps the fingerprinted stack to a
  prioritized vuln checklist — closes the "LLM Planner"/"map tech→tool" checklist items) →
  `targeted_scan` (nuclei with the tech-derived tags, not the broad default) → `graphql_probe`
  (auto-discovers `/graphql`-looking URLs from live_hosts/accumulated findings, runs
  `introspect_graphql` only if any exist) → `assess` (new `skills/vuln_assessor.py`'s
  `assess_findings` — see below) → `chain` (`analyze_chains` over the plausibly-real subset) →
  `business_logic_hints` (a NEW inline LLM call, deliberately just a URL-pattern hint scan for
  WHERE a human should manually walk a flow, not a full step-sequence mapper — that's still
  `map_business_logic`/`map_auth_flow`'s job once someone captures the real request sequence) →
  `gate` (see below — architecturally different from every other stage) → `finalize`
  (`check_eligibility` → `build_poc` for confirmed findings, interactsh poll/stop, persists
  confirmed findings via the new separate ChromaDB collection).
- **Input is a PRIOR recon run's output, not a bare domain** — `run_vuln_pipeline()` loads
  `live_hosts`/`js_urls`/`all_findings` from `agent/recon_pipeline.py`'s own checkpoint via
  `load_recon_surface()`; if `target` was never recon'd, it returns a clean error state telling
  the caller to run `"recon <target>"` first rather than operating on nothing. Checkpoints save
  under `"<target>__vuln"` — a distinct session key from the recon pipeline's own `<target>`, so
  resuming one pipeline can never collide with or shadow the other's checkpoint history.
- **The `gate` stage is architecturally different from every other stage in this file OR
  `agent/recon_pipeline.py`**: every other stage's HITL approval is a single "run this whole
  stage or not" decision. Phase 5's entire point is a PER-FINDING decision (approve/reject/
  escalate, per the plan's own wording), which can't collapse into one yes/no — so this stage's
  own propose/gate covers only "start the per-finding review session," and the real per-finding
  decisions happen inside `node_execute` via `agent/hitl.py`'s existing `request_batch_approval`
  (one prompt per tool/risk group, same batching used everywhere else in this codebase to avoid
  approval-fatigue rubber-stamping) — documented explicitly in the module docstring so this
  doesn't look like an accidental architecture violation to a future reader.
- **`skills/vuln_assessor.py`** (new) — `assess_findings`, an LLM batch false-positive/confidence
  triage over a whole stage's findings in one pass. Deliberately distinct from
  `skills/confidence_scorer.py`'s `score_finding_confidence`: that tool scores ONE finding from
  repeated baseline-vs-trigger `ResponseSignal` pairs (needs N actual repeated requests already
  in hand); nothing in this pipeline generates that data per-finding, so re-running everything N
  times before triage would multiply request volume for little benefit at recon-level severity.
  This is a coarser, cheaper first-pass triage on the finding's own text — not a replacement for
  `score_finding_confidence` on anything a human decides is worth the repeated-request cost.
  **Verified live against a real (not mocked) Ollama call**: given one concrete finding (an
  exposed `.git/config` with a real remote-origin URL) and one generic finding (a bare
  X-Powered-By tech-detect match), the assessor scored them 9/not-false-positive and
  3/false-positive respectively — it discriminates on evidence QUALITY, not the scanner's own
  severity label, which was the whole point of adding this stage rather than trusting nuclei's
  raw output directly.
- **`agent/memory.py` gained `save_confirmed_findings_to_memory`** — a SEPARATE ChromaDB
  collection (`confirmed_findings`) from the raw-scanner `findings` collection
  `save_findings_to_memory` already writes, closing the plan's own "Store human-confirmed
  findings separately from scanner raw output in ChromaDB" line. Only called for findings the
  `gate` stage marked "confirmed" AND `check_eligibility` didn't reject.
- **OOB monitoring is deliberately scoped down**, documented in the module docstring rather than
  overclaimed: this pipeline starts an interactsh session in `tech_profile` and polls/stops it in
  `finalize`, but never crafts a payload embedding that session's own domain into a request the
  way a human using the generic `agent/graph.py` path might (e.g. via `run_ffuf`/`run_dalfox`
  with a hand-chosen parameter) — nuclei's OWN built-in interactsh integration for oast-tagged
  templates is independent of this. So a captured callback can only be attributed to "happened
  sometime during this pipeline run," not to a specific finding/payload. Same scope-honesty
  precedent as session 5's Hacktivity checker and Shodan/Censys query builder.
- **Two Phase 5 checklist items remain genuinely open, not silently skipped** (see
  `docs/DEVELOPMENT_PLAN.md`'s own updated checkboxes): wiring `bypass.py`'s WAF-bypass retry
  loop into a blocked/filtered-response signal (this pipeline's scans are single-shot, no active
  fuzz-and-retry loop exists yet to hang that off of), and running `auth_mapper.py`'s
  credentialed checks (`check_idor`/`check_jwt_weaknesses`) automatically — this pipeline has no
  credential-input path yet, so those stay a job for the generic chat-driven path until one exists.
- **No new bugs found live-testing this phase** (unlike sessions 3-6, which each found at least
  one) — two-pass verification per Phase 4's own precedent: full pipeline mechanics (stage
  sequencing, index-alignment between findings/assessments, gate-decision mapping, mid-pipeline
  reject-then-resume, checkpoint-key separation from the recon pipeline) verified with every tool
  call AND the LLM mocked; then a second real-Ollama pass (tool calls still mocked, but
  `assess_findings`/`analyze_chains`/the tech-checklist planner/the business-logic-hints call all
  hit the actual live model) to confirm real LLM output round-trips through the JSON parsing
  correctly and the assessor's discrimination is genuine, not just well-typed. Ollama's
  Windows-side `llama-server` process crashed mid-session with a CUDA error on the first attempt
  (matches the known fragility already noted below) and came back on its own without a manual
  restart this time — don't assume that always resolves itself; the manual-restart fallback
  noted in "Environment quirks" below may still be needed some sessions.

## Session 6 summary (2026-07-22) — Phase 4 built: `agent/recon_pipeline.py`, `agent/memory.py`, resume support, two real bugs found via live tests

User said "continue with next phase now" right after Phase 3 finished (session 5, same day).
**Phase 4 is now built and live-verified** — every checklist item in
`docs/DEVELOPMENT_PLAN.md`'s Phase 4 section is `[x]`.

**Why this needed a whole new graph, not just more tools registered in `ALL_TOOLS`**:
`agent/graph.py`'s existing single-action loop lets the LLM freehand-chain tool calls, but caps
compound tasks at `MAX_STEPS=6` — Phase 4's own "Goal" line describes a FIXED 8-stage sequence
(subdomains → live hosts → ports → crawl → params → dirs → enrichment → LLM summary), which both
exceeds that bound and doesn't need an LLM re-deriving a sequence that's fixed by design. Built
`agent/recon_pipeline.py` as a separate LangGraph graph instead, reusing the exact same
propose → gate → execute triad `agent/graph.py` already established (approval BEFORE a stage
runs, per `ORCHESTRATOR_SYSTEM_PROMPT` rule 2), just generalized to a hardcoded stage list
(`RECON_STAGES`) instead of one LLM-chosen action per turn. Wired into `main.py` via two new
command patterns — `"recon <target>"` and `"resume <target>"` / `"resume recon <target>"` —
routed to this pipeline instead of the generic graph. **Known simplification, not a bug**: these
are strict regex matches on the whole command, not natural-language parsing — `"resume last
session on target.com"` (Phase 7's own example phrasing) won't match; only the two exact forms
above do.

**`agent/memory.py`** — new ChromaDB integration (`chromadb==1.5.9`, already in
`requirements.txt`, no install needed). Uses `PersistentClient` with its bundled default
embedding model (a small local ONNX sentence-transformer) — first call in a fresh environment
downloads it once (~80MB, confirmed live), every call after reuses the cache. `query_similar_findings`
is registered as an LLM tool (LOW risk, reads the local store only); `save_findings_to_memory` is
a plain function called automatically after the pipeline's final `aggregate` stage, the same way
`agent/session.py`'s `save_checkpoint()` is already called automatically rather than invoked by
the model.

**Real bug #1, found via a live mocked-pipeline test, not just an import check**: `agent/memory.py`'s
finding-ID hash used the pipeline's OUTER `target` string (constant for the whole batch) instead
of each finding's OWN `target` field. Two findings that happen to share a `type` + `detail` but
have different actual targets (confirmed live: two subfinder-discovered subdomains, both with the
placeholder detail text `"source=fake"` in the mocked test — but the identical-detail scenario is
completely realistic with real tools too, e.g. two hosts httpx-fingerprints identically) collapsed
to the same hash, and `chromadb`'s `upsert()` rejects a batch containing any duplicate ID outright
— the whole `aggregate` stage crashed. Fixed to hash on `f.get('target', target)` (the finding's
own target, falling back to the outer one only if a finding is somehow missing it).

**Real bug #2, found via a live resume test**: `node_done` (the node reached whenever the pipeline
stops, for ANY reason) unconditionally set `stage="done"` regardless of whether every stage
actually ran or a human rejected a stage gate partway through. This made
`resume_recon_pipeline`'s "is this checkpoint already finished, nothing to resume" check treat a
rejected-and-stopped run as fully complete — resuming after a reject (the exact scenario `resume`
exists for) would silently do nothing, always returning `None`. Fixed: `stage_index` (not the
`stage` string) is now the sole authoritative "is this finished" signal; `node_done` sets
`stage="done"` only when `stage_index >= len(RECON_STAGES)`, else `stage="rejected"`.

**Verified live, in this order**:
1. Full pipeline mechanics with every tool call mocked (fast, isolates the actually-new
   orchestration logic from the already-Phase-2-verified individual tool wrappers): all 8 stages
   ran in sequence, state threaded correctly between them (`live_hosts` from `httpx` feeding
   `ports`/`crawl`/`dirs`, `js_urls` from `crawl` feeding `enrichment`), checkpointing didn't
   crash, and the real (not mocked) LLM aggregation call produced well-formed JSON matching
   `RECON_AGENT_PROMPT`'s requested shape.
2. Resume flow: rejected a stage gate partway through (mocked auto-reject at the `crawl` gate),
   confirmed the pipeline stopped with `stage="rejected"` and partial findings preserved; called
   `resume_recon_pipeline()` with approval re-enabled, confirmed it continued from exactly the
   next stage (findings count went from 11 to the same 21 total the uninterrupted mocked run
   produced — not fewer, not duplicated) and finished; confirmed resuming an already-finished
   pipeline correctly returns `None` instead of silently restarting.
3. Real-target smoke test (not mocked) of the `subfinder` and `httpx` execute functions directly
   against `scanme.nmap.org` (the same intentionally-scannable test host prior sessions already
   used for `run_katana`/`run_hakrawler` scope-safety tests) — confirmed the real
   `diff_against_last_scan` integration and the `_final_url` regex extractor against REAL httpx
   JSON output (`status=200 title='Go ahead and ScanMe!' tech=['Apache HTTP Server:2.4.7',
   'Ubuntu']`), not just synthetic mock data. Did not run the full pipeline (`ports`/`crawl`/
   `dirs`/`enrichment`) against a real target this session — `naabu`/`nmap` at the mandated
   10 req/s rate and `ffuf`'s ~4,749-entry default wordlist per host are individually slow
   enough (see `tools/recon.py`'s own docstrings) that a full real run could take much longer
   than one verification pass justifies; the per-stage host caps in `agent/recon_pipeline.py`
   (`_MAX_HOSTS_PORTS=10`, `_MAX_HOSTS_CRAWL=5`, `_MAX_HOSTS_DIRS=5`, etc.) exist specifically to
   bound this in real use, not just in testing.

`agent/orchestrator.py` imports cleanly with **62 tools total** (was 61 — only
`query_similar_findings` is a new `ALL_TOOLS` entry this session; the rest of Phase 4's new code
is pipeline/memory plumbing, not new LLM-callable tools).

**Not built, deliberately out of scope for "Phase 4 complete"**: the `enrichment` stage's
"parallel" is concurrent-with-each-other via `asyncio.gather`, not literally overlapping the
sequential main pipeline's wall-clock — this graph's nodes are synchronous state transitions,
same execution model `agent/graph.py` already uses, so true background-while-other-stages-run
concurrency needs a different execution model entirely. Don't "fix" this into a bigger
architecture change without discussing it first; it was a deliberate, documented scope call, not
an oversight.

## Session 5 summary (2026-07-22) — evaluated 4 third-party security-agent repos, built `skills/auth_mapper.py` from reimplemented techniques

User asked whether four public repos could be used for this project:
`Cypharia/agentic-vuln-scanner`, `Cypharia/aion-redteam`, `0x4m4/hexstrike-ai`, and
`piratesshield/APIHarvester`. Verdict on the first three: none become a dependency.
`agentic-vuln-scanner`/`aion-redteam` test *other AI agents* against the OWASP Agentic Top 10 —
wrong target class entirely (they'd test THIS project's own LangGraph graph, not a bug-bounty
target), and both are early-stage prototypes. `hexstrike-ai` is a mature (10.4k★) MCP server
doing roughly the same job as this whole project, packaged as an opaque 150+-tool black box —
explicitly rejected as a tool-provider because calling into it would bypass every scope-safety
gate and per-tool risk classification this project has built up over 4 sessions; it's a
reference for tool-list ideas only, never a dependency.

`piratesshield/APIHarvester` (OWASP API Top 10 black-box scanner) was different: genuinely
relevant since it overlaps `docs/DEVELOPMENT_PLAN.md`'s still-open Phase 3 Tier 2
`auth_mapper.py` item. **No LICENSE file in that repo** — confirmed by cloning it — so the only
legitimate path was technique reuse, never code copy; user explicitly directed this ("use their
tools/idea and integrate into our product directly" rather than "we won't use it"). Cloned it to
a scratchpad dir and read every file under `apiharvester/attacks/`, `recon/`, `utils/` (not just
the README) to extract real algorithms, not marketing claims — findings sorted into three tiers:

- **Tier A (ported)**: response-fingerprint primitives (soft-404/similarity via difflib after
  stripping volatile JSON fields), a median-of-3 timing-confirmation gate, a dependency-free JWT
  toolkit (weak-secret HMAC crack, alg=none forgery, and a genuinely clever hand-rolled
  RSA-JWK→PEM DER encoder enabling RS256→HS256 algorithm-confusion with zero crypto libraries),
  BOLA differential-auth logic (bounded ID-mutation candidates + break-on-first-hit), and an
  entropy-gated secret-validation heuristic. Only the JWT toolkit + BOLA logic got built into a
  tool this session (see below) — the rest (soft-404 primitives beyond what auth_mapper needed,
  entropy-gated secrets, WAF-detector layering, Arjun-style stability pre-check, CORS/misconfig
  checks, tightened SSRF heuristic) are queued, not yet built.
- **Tier B (redesign before use)**: the source's mass-assignment/business-logic/BFLA modules do
  REAL persisting writes (PATCH role=admin, DELETE) against the live target with no rollback,
  and its injection module ships a literal `'; DROP TABLE test--` payload with no gate, and
  nothing in the source rate-limits itself by default. None of this was ported as-is — same
  rule this project already applies to sqlmap/ghauri (hardcoded detect-only despite the tool's
  own capability). Any future build-out of this tier must gate real mutations behind explicit
  HIGH-risk HITL approval and add a revert step the source never had.
- **Tier C (skipped)**: the source's own pure-Python recon fallbacks (subdomain/resolve/probe/
  crawl) just reimplement subfinder/dnsx/httpx/katana more weakly than this project's own
  already-verified Phase 2 wrappers — no value. `swagger_targeting.py`/`api_profiler.py` ideas
  are low-priority; the source itself never actually wired swagger-spec mining into any attack
  module despite writing the accessor layer for it.

**Built this session**: `tools/http_client.py` (new — a rate-limited, never-raising direct-HTTP
primitive for skills that speak HTTP themselves rather than shelling out to a CLI binary; this
is a genuinely new pattern, the first thing in this codebase that isn't either a subprocess
wrapper or a pure-reasoning skill). Its pacing state is a plain `list[float]`, deliberately NOT
an `asyncio.Lock` — `agent/graph.py` runs every tool via a fresh `asyncio.run()` per call (see
`tools/base.py`'s own docstring), and a Lock created once at import time binds to the first
event loop and raises on the next call; a bare float has no event-loop affinity.
`tools/response_fingerprint.py` (new — `similarity`/`responses_equivalent`/`is_distinct_object`/
`is_soft_404`/`confirm_timing`/`shannon_entropy`/`looks_like_real_secret`, all pure functions, no
network). `skills/jwt_toolkit.py` (new — dependency-free JWT parse/crack/forge, including the
hand-rolled ASN.1 DER encoder for the algorithm-confusion attack; no `pyjwt`/`cryptography`
needed). `skills/auth_mapper.py` (new — the actual `@tool` entrypoints, `check_jwt_weaknesses`
and `check_idor`, closing the Phase 3 Tier 2 checklist item — see
`docs/DEVELOPMENT_PLAN.md`'s own line for exactly what's covered vs still open). Both registered
**HIGH** in `agent/risk.py`, not MEDIUM — forging and replaying real auth material is an active
bypass attempt, the same reasoning that already keeps `run_sqlmap`/`run_ghauri` HIGH despite
being detect-only. Neither `tools/response_fingerprint.py` nor `skills/jwt_toolkit.py` is in
`ALL_TOOLS` — plain-function helper modules, same precedent as `skills/hitl_batcher.py`.

**Real bug found and fixed via the live test, not just an import check**: the first
`_looks_accepted()` heuristic (`status 2xx and body length > 50 bytes`) missed a genuine,
confirmed `alg=none` bypass against a local vulnerable test server because that specific
response body was exactly 50 bytes — an off-by-one — and a length-only threshold is fragile
generally anyway (a real rejection body like `{"error":"unauthorized"}` is already 24 bytes,
not obviously distinguishable from a small real object by length alone). Fixed by replacing the
magic-number threshold with a content-based check (reject empty/`{}`/`[]`/`null` bodies and
anything containing an explicit error/denial phrase, accept everything else) — same class of
"verify live before trusting a heuristic" lesson this project has hit repeatedly (see
`run_katana`/`run_hakrawler`'s scope-flag lessons below). **Verified live**: built a local
Python HTTP test server (`ThreadingHTTPServer`, one endpoint wrongly trusting `alg=none`, one
BOLA-vulnerable object endpoint with no ownership check) — confirmed `check_jwt_weaknesses`
correctly finds the weak secret (`password`, in the crack wordlist) AND the `alg=none` bypass
after the fix; confirmed `check_idor` correctly finds both the numeric-ID-mutation hit and the
differential-auth hit against the vulnerable object; confirmed a negative control (a
nonexistent object ID) produces zero findings, not a false positive. `agent/orchestrator.py`
imports cleanly with 53 tools total.

### Same-session continuation: user asked to "complete Phase 3 now" — all 4 remaining items built

Rest of Phase 3 Tier 2/3 built in the same session, right after the auth_mapper.py work above.
**Phase 3 is now 100% complete** — every checklist item in `docs/DEVELOPMENT_PLAN.md`'s Phase 3
section is `[x]`, `agent/orchestrator.py` imports cleanly with **61 tools total**.

- **`skills/tech_analyzer.py`** — `analyze_tech` (MEDIUM) builds a `TechProfile` from headers/
  cookies/HTML/up-to-3-JS-files/an error-page probe, with an `evidence` list citing exactly
  which signal produced each field (so a human can sanity-check a guess, not trust it blindly).
  `select_nuclei_tags` (LOW, no network) maps a `TechProfile` to a `run_nuclei` `tags` value —
  closes the Tier 3 "nuclei template selector" item too, kept in this file since it's a direct
  `TechProfile` consumer rather than living in its own module.
- **`skills/graphql_mapper.py`** — `introspect_graphql` (MEDIUM) runs schema introspection,
  reports introspection-enabled-in-prod as its own finding, and flags mutations matching a
  sensitive-action keyword list. `check_graphql_idor` (HIGH) mirrors `auth_mapper.py`'s
  `check_idor` applied to a GraphQL query body instead of a REST URL path — same
  `tools/response_fingerprint.py` guards, same reasoning for HIGH.
- **`skills/auth_mapper.py` extended** — added `map_auth_flow` (LOW, pure LLM reasoning, zero
  requests), same shape as `map_business_logic`. This was the genuinely-missing piece from
  earlier in this session (login → session/refresh-token → role-gated-endpoint →
  password-reset-flow mapping) — `auth_mapper.py` is now fully done, not partial.
- **`skills/cve_lookup.py`** — `lookup_cves` (LOW — every request goes to NVD/CISA's own public
  infra, never the actual target) queries the real NVD API and cross-references CISA's KEV
  catalog, reporting a KEV-listed CVE as `critical` regardless of its own CVSS score.
- **`skills/recon_query_builder.py`** — `build_recon_queries` (LOW, zero network). Deliberately
  does NOT call Shodan/Censys APIs at all — no credentials exist anywhere in
  `config/settings.py` and both require a paid plan; the plan's own wording is "query builder,"
  not "run a scan," so this just returns ready-to-paste query strings in each platform's syntax.
- **`skills/hacktivity_checker.py`** — `build_hacktivity_search` (LOW, zero network) — **scoped
  down from the plan's literal wording on purpose**. Verified live BEFORE writing any code that
  an automated duplicate-checker isn't reliably buildable: `hackerone.com/hacktivity` is a
  client-rendered SPA shell (server response is ~1.6KB, no report data in it — everything loads
  via client-side JS), and the GraphQL API that page actually calls
  (`https://hackerone.com/graphql`) has introspection disabled in production (confirmed:
  `{__schema{...}}` → `"Field '__schema' doesn't exist on type 'Query'"`). Building a scraper
  against that undocumented, unstable private API with no way to verify it stays correct is
  exactly the kind of unverifiable behavior this project's own "never trust a tool's own docs"
  discipline argues against — so this returns a search LINK + keyword suggestions for a human to
  check manually instead of pretending to automate something that can't be reliably automated.
  Don't "upgrade" this to a scraper without re-verifying H1's frontend API is actually stable and
  documented by then — it wasn't as of 2026-07-22.

**Two more real bugs found via live tests, not just import checks** (on top of the
`_looks_accepted` off-by-one above):
1. `select_nuclei_tags`/`analyze_tech` test: no bug, but the live test against a synthetic page
   containing BOTH React (`data-reactroot`) and Nuxt (`__NUXT__`) signatures confirmed
   `_first_match`'s priority order is deterministic (checks signatures in a fixed list order,
   not by position in the page) — worth knowing before adding new signatures: order in
   `_FRAMEWORK_SIGNATURES` matters when a page could ever contain more than one framework's
   markers (unlikely on a real site, but the tuple order is the tiebreak if it happens).
2. `lookup_cves`'s `_extract_severity` initially reported `"unknown"` severity for EVERY single
   CVE. Root cause, confirmed by fetching a real NVD response directly: CVSSv3.x nests
   `baseSeverity` inside `cvssData`, but CVSSv2 (most pre-2016 CVEs) puts `baseSeverity` as a
   SIBLING of `cvssData`, not inside it — the first version only checked the v3.x location.
   Fixed by checking both locations; re-verified against a real CISA-KEV-listed CVE
   (CVE-2026-60137) that the fix produces the right severity AND the KEV cross-reference
   correctly overrides it to `critical` despite the CVE's own CVSS being only `MEDIUM`.

## Session 4 summary (2026-07-19) — `run_hakrawler` + `run_gf` built, a second scope-safety bug found and fixed, a gf-patterns blocker fixed directly

Continued Phase 2's `tools/url_harvest.py` with `run_hakrawler` (fast web spider — hrefs, forms,
scripts) then `run_gf` (local pattern grep over an already-harvested URL list). `paramspider`
and Chrome/Chromium (blocking `run_gowitness`) are still not on PATH — those genuinely need
sudo or a dedicated venv the user has to run themselves, unchanged from session 3.

**`run_gf` blocker found and fixed directly, not deferred**: `gf`'s binary alone (installed via
`GOTOOLS`) does nothing — `gf -list` was empty and `gf xss` returned "no such pattern" (exit 0)
on this box, confirmed live. Unlike `run_gowitness`'s Chrome dependency, this needed no sudo,
just `git clone github.com/1ndianl33t/Gf-Patterns` into `~/.gf/*.json` (14 patterns), so it was
fixed in this session rather than added to the "needs the user" pile — also added to
`scripts/phase0_setup.sh` for future fresh installs. `run_gf(urls, pattern)` is genuinely
different from every other Phase 2 wrapper so far: it does zero network activity, it's a pure
local grep over a URL list some other tool already harvested (gau/waybackurls/katana/hakrawler),
classified `LOW` in `agent/risk.py` on that basis. Validates `pattern` against the installed set
and returns an explicit error for an unknown one, since gf's own "no such pattern" on stdout
with exit 0 would otherwise look identical to "ran fine, matched nothing." **Verified live**:
`xss`/`redirect` patterns against a 4-URL test list gave correct matches; unknown pattern
returns the expected error; `agent/orchestrator.py` imports cleanly with 25 tools, `run_gf`
classified `LOW`.

**Critical scope-safety bug found via a controlled local test, same class as session 3's katana
`-fs rdn` bug but with no equivalent flag documented anywhere in `hakrawler -h`.** Before writing
the parser, ran two local Python HTTP servers on different ports (one "target," one "external,"
simulating two unrelated hosts) with the target page linking to the external one, then crawled
the target with hakrawler's default flags. Confirmed via the external server's own access log
that hakrawler sent it a REAL GET request — not just extracting and reporting the link, actually
fetching it — despite it being a completely different host. Re-ran the identical test with `-i`
("only crawl inside path" per `-h`, which reads like a path-scope flag, not a host-scope one)
and confirmed zero requests reached the external server while a second same-host path still got
crawled correctly. `-i` is therefore passed unconditionally in `run_hakrawler`, never
caller-optional — this is the actual host-restriction mechanism, not what its help text implies.
`-subs` (include subdomains) is deliberately never passed either, same reasoning as katana's
`-fs fqdn`: an authorized host doesn't authorize its subdomains too.

Takes its URL via stdin (positional arg silently ignored, verified live) — same
`run_tool(stdin_input=...)` path as `run_waybackurls`. Registered in `ALL_TOOLS` right after
`run_katana`, classified `MEDIUM` in `agent/risk.py` (sends real HTTP requests to the target).
**Verified live**: `http://scanme.nmap.org`, depth 2 → 8 findings (href/script/form sources),
`error: null`, ~0.8s; `agent/orchestrator.py` imports cleanly with 24 tools total, `run_hakrawler`
correctly classified `MEDIUM` via `risk_level_for()`.

**Takeaway for whoever wraps `hakrawler`, `gf`, `paramspider`, or any other crawler/spider
next**: never trust a tool's own `-h` text to tell you which flag actually restricts request
scope to the target — verify with a controlled test (two local servers, one seed, one
"external," check the external one's access log) before shipping the wrapper, exactly like this
session and session 3's katana fix both did. A flag whose help text sounds like it's about
paths, output filtering, or something unrelated may be the actual scope gate.

## Session 3 summary (2026-07-18/19) — `run_httpx`/`run_naabu`/`run_nmap`/`run_dnsx`/`run_tlsx`/`run_gau`/`run_amass`/`run_waybackurls`/`run_katana` built, scope-fabrication gap closed, `run_tool()` timeout-discards-everything gap fixed, katana scope-safety bug found and fixed

User explicitly chose to continue Phase 2 tool wrappers over fixing the scope-fabrication gap
(the top item in session 2's "Immediate next steps") — that gap is still open, not fixed, just
deprioritized by the user's own choice. Don't assume it's been addressed.

Built `tools/recon.py`'s `run_httpx` (probe hosts for status/title/tech-stack), following the
same discipline as `run_subfinder`: confirmed real CLI flags and JSON output shape against the
installed binary live before writing the parser, then verified the async wrapper standalone
(hackerone.com, bugcrowd.com, and a non-resolving domain) before wiring it in. Classified
`MEDIUM` in `agent/risk.py` (first wrapper that sends real traffic to the target — everything
before this was LOW). Registered in `ALL_TOOLS` right after `run_subfinder`.

**Real bug found and fixed getting it working — a binary-name collision, not a logic bug.**
First live run returned `httpx exited 2: Usage: httpx [OPTIONS] URL / Error: No such option
'-s'` — the *Python* `httpx` package (an HTTP client, installed as a dependency, not anything
this project asked for directly) installs its own `httpx` console script into `.venv/bin/`.
Once the venv is active, `.venv/bin` sits earlier on PATH than `~/go/bin`, so
`shutil.which("httpx")` in `tools/base.py`'s `run_tool()` silently resolved to the wrong binary
entirely — not a flag mismatch, a completely different program. **Fixed at the shared
`run_tool()` level, not per-wrapper**: binary resolution now checks `~/go/bin/<tool>` first
(hardcoded — matches `scripts/phase0_setup.sh`'s own install location, used there for
trufflehog/gitleaks too, not just Go's default) before falling back to `shutil.which()`. Any
other Go-installed tool sharing a name with a Python/pip package would hit the identical
collision, so this needed to live in the shared helper, not be special-cased in `run_httpx`
alone. Verified: re-ran `run_httpx` live (correct binary, correct output this time),
regression-checked `run_subfinder` still returns real results (19 subdomains for
hackerone.com — matches session 2's baseline exactly), confirmed `agent/orchestrator.py`
imports cleanly with 15 tools registered and `agent/risk.py` classifies both `run_subfinder`
(LOW) and `run_httpx` (MEDIUM) correctly.

Also enforced `ORCHESTRATOR_SYSTEM_PROMPT` rule 4 (max 10 req/s) in code for the first time:
`run_httpx` passes `-rate-limit settings.MAX_REQ_PER_SEC` — httpx's own default is 150 req/s,
far above the stated cap. `run_httpx` also accepts a batch of domains in one call (`-u` repeated
per host, no stdin needed) rather than one call per host, so probing an entire `run_subfinder`
result stays under one HITL approval instead of turning into one prompt per subdomain — this is
exactly the kind of repetitive-approval problem `skills/hitl_batcher.py` exists for, worth
revisiting once `agent/hitl.py`'s batch path is exercised against a real multi-host result.

### Scope-fabrication gap — CLOSED 2026-07-18, verified live

Came back to this later the same session at the user's explicit direction ("complete it: first
scope-fabrication safety gap from session 2 is still open"). This was session 2's top-priority
open item: verified live back then that the model will invent a plausible-looking scope policy
from its own training knowledge — rather than asking the human — when asked about a well-known
program with no real scope text anywhere in the conversation. A prompt rule alone
(`ORCHESTRATOR_SYSTEM_PROMPT` rule 1) was tried in session 2 and confirmed NOT sufficient; this
needed the structural fix session 2 sketched but didn't build.

**Fix, exactly as session 2 sketched it:** `skills/scope_parser.py` gained
`looks_like_scope_text(text) -> bool` — reuses the module's existing domain regex and in/out-
scope marker tuples, requires an explicit marker AND ≥2 distinct domain-shaped tokens (a real
policy page lists several domains under those markers; a short instruction naming one target
domain deliberately doesn't pass). `agent/graph.py`'s `node_plan()` now checks this against
every `HumanMessage` in the conversation (`_human_provided_scope_text()`) whenever the model's
next planned action is `parse_scope_policy`, `check_scope`, OR `check_policy_compliance` — all
three consume scope text or a policy the model could fabricate, not just the one the original
bug happened to surface. If no message anywhere looks like real scope-page content, `node_plan`
routes straight to `Stage.ERROR` with an explanatory message, **before the human ever sees an
HITL approval prompt for it** — showing one at all would imply the content is legitimate and
invite a rushed approve.

**One design correction from session 2's own sketch:** session 2 phrased the fix as "no
HumanMessage *other than the initial command*" needs checking — but the already-verified
session-2 compound command pastes real scope text inline as part of that very first message
("is www.example.com in scope, given this policy text: ..."). Excluding the first message would
have broken that legitimate, already-verified case. The actual check scans the WHOLE
conversation including message zero; `looks_like_scope_text`'s marker+domain-count heuristic is
what distinguishes a real paste from a bare command mentioning one domain, not message position.

**Verified live, three ways:**
1. Unit-level: `looks_like_scope_text()` returns `False` on the exact original fabrication
   trigger ("Check if api.hackerone.com is in scope for the HackerOne bug bounty program"),
   `True` on a real scope snippet, `True` on the session-2 compound-command phrasing.
2. Full graph, fabrication case: `run_command("Check if api.hackerone.com is in scope for the
   HackerOne bug bounty program")` now returns `Stage.ERROR` immediately with the refusal
   message — `plan` was never set, confirming the tool never ran.
3. Full graph, legitimate case (regression check): `run_command("is example.com in scope? In
   scope: example.com. Out of scope: internal.example.com.")` ran twice, both times completing
   `parse_scope_policy` → `check_scope` → `check_scope` end-to-end via live Ollama, LOW-risk
   auto-proceed at each step, reaching `Stage.IDLE` with no errors — identical behavior to
   session 2's original verified run, zero regressions from the new gate.

Separately noticed while testing (NOT part of this fix, not touched): the exact session-2 wording
("is www.example.com in scope, given this policy text: ...") reliably triggers this model's
malformed-pseudo-tool-call quirk on this phrasing specifically (3/3 attempts) — `PlanParseError`
fired correctly each time (the session-2 detection working as designed), it just means that
specific longer phrasing doesn't reliably reach a real tool call on this model/quantization.
Shorter phrasing of the same request went through cleanly. This is the same known intermittent
behavior documented in session 2's "Phase 2 kickoff," not a new issue and not something this fix
introduced.

### `run_naabu` built, verified live — Phase 2 continued after closing the scope-fabrication gap

Third `tools/recon.py` wrapper this session. Port scan via naabu, CONNECT mode (no raw-socket
privileges needed, unlike SYN scan). Confirmed real `-host`/`-top-ports`/`-json`/`-rate` flags
and JSON output shape (`host`, `ip`, `port`, `protocol`, `tls`) against the installed binary
before writing the parser, same discipline as `run_subfinder`/`run_httpx`. Classified `MEDIUM`
in `agent/risk.py` (sends real TCP connection attempts). Registered in `ALL_TOOLS` right after
`run_httpx`.

**Two environment-specific issues found and fixed, same discovery pattern as the `httpx`
binary collision — verify live, don't trust the plan's one-line description:**

1. **naabu's default host discovery hangs indefinitely in this sandbox.** First live test
   timed out with zero output. Confirmed raw TCP egress itself works fine
   (`bash -c 'echo > /dev/tcp/scanme.nmap.org/22'` succeeded immediately) — the problem is
   specifically naabu's default ICMP-based host-discovery pre-check, not general network
   restriction. Fixed: `run_naabu` passes `-Pn` (skip host discovery) unconditionally. A
   genuinely dead host still just returns no open ports either way, so this costs nothing
   correctness-wise.
2. **The safety-mandated rate cap makes port scanning much slower than `run_httpx`, to the
   point of blowing past `run_tool()`'s 120s default timeout on a 2-host batch.** `run_httpx`
   only sends one request per host regardless of rate limit, so a 10 req/s cap barely matters
   there. naabu inherently sends one probe per port per host, and its default `-retries 3`
   re-scans every port again per retry round rather than just non-responsive ones — measured
   live: ONE host, top-ports 100, rate 10, default retries → ~62s; the exact same 2-host batch
   that surfaced this issue → timed out at exactly 120s (matches ~62s × 2 almost exactly).
   Fixed: `run_naabu` passes `-retries 1` instead (~23s/host measured — one retry still catches
   most transient packet loss, three does not scale under a 10 pps cap) AND overrides
   `run_tool()`'s default timeout to `timeout_s=300` for this wrapper specifically. `run_tool()`
   already supported a `timeout_s` override from the start (see `tools/base.py`) — this is the
   first wrapper to actually need it, not a new capability added this session.

Also confirmed naabu still reports the same open `(host, port)` more than once even at
`-retries 1` (each confirming attempt re-emits a JSON line) — deduped in the wrapper before
building findings, raw duplicate lines still preserved in `raw_output`.

**Verified live, final run:** 2 real hosts (`scanme.nmap.org`, `hackerone.com`), top-ports 100,
completed in ~43s with `error: null`, 12 raw JSON lines correctly deduped down to 6 unique
open-port findings. Regression-checked: `agent/orchestrator.py` imports cleanly with 16 tools
registered, `agent/risk.py` classifies `run_subfinder` (LOW), `run_httpx` (MEDIUM), and
`run_naabu` (MEDIUM) correctly.

### `run_nmap` built, verified live — fourth `tools/recon.py` wrapper this session

Service/version detection on ports `run_naabu` already found open — deliberately scoped, not a
blind sweep, since nmap's `-sV` version probing is far more expensive per port than naabu's
plain connect check. Confirmed real `-sT`/`-sV`/`-Pn`/`-p`/`--max-rate`/`-oX -` flags and XML
output shape against the installed binary before writing the parser. Parses with stdlib
`xml.etree.ElementTree` — no new dependency needed. Classified `MEDIUM` in `agent/risk.py`.
Registered in `ALL_TOOLS` right after `run_naabu`.

Two things confirmed live before trusting any assumption, following the same discipline as
`run_naabu`'s `-Pn`/rate-vs-timeout lessons:
- **No root/raw-socket access** (`id` shows no CAP_NET_RAW) → uses `-sT` (TCP connect scan),
  never `-sS` (SYN scan), which would need it.
- **nmap's own default host-discovery does NOT hang here**, unlike naabu's — tested explicitly
  rather than assumed, since the `-Pn` fix for naabu doesn't necessarily generalize. nmap falls
  back to a TCP-based discovery probe (not pure ICMP) when unprivileged, so it just works
  without `-Pn`. `run_nmap` still passes `-Pn` — but as a pure speed optimization (the caller
  already knows the host is alive from a prior `run_naabu`/`run_httpx`), not a hang workaround.
  **Lesson for the next wrapper**: don't assume every tool needs the same fix naabu did — verify
  each one's actual behavior in this sandbox independently.

**One real bug found and fixed during verification, same category as the `httpx` binary
collision — a live test catching something the code review alone would have missed:** the
first parser version built `Finding.target` from nmap's own resolved `<address addr="...">`
XML element, which returned the target's *IP* (`45.33.32.156`) rather than the hostname passed
in (`scanme.nmap.org`). Every other wrapper's convention is `target` = the caller's own
identifier, never something the tool resolved on its own — `run_subfinder`/`run_httpx`/
`run_naabu` all already followed this. An IP-valued `target` would have silently broken
hostname-keyed correlation downstream (`diff_tracker`'s snapshot diffing, `check_scope`'s
domain matching) the first time this ran inside the real pipeline, not obviously at build time.
Fixed: use the `host` parameter directly instead of the XML's resolved address.

**Verified live, final run** (after the fix): `scanme.nmap.org`, ports `22,80` → completed in
~9.9s, `error: null`, both services correctly parsed (`ssh`/OpenSSH/6.6.1p1 on 22,
`http`/Apache httpd/2.4.7 on 80) with `target: "scanme.nmap.org"` this time. Regression-checked:
`agent/orchestrator.py` imports cleanly with 17 tools registered, `agent/risk.py` classifies
all four recon wrappers correctly (`run_subfinder` LOW; `run_httpx`/`run_naabu`/`run_nmap`
MEDIUM).

### `run_dnsx` built, verified live — fifth `tools/recon.py` wrapper this session

DNS record enumeration (A, AAAA, CNAME, NS, MX, TXT). Confirmed real `-l`/`-a`/`-aaaa`/`-cname`/
`-ns`/`-mx`/`-txt`/`-json` flags and JSON output shape (`host`, `resolver`, per-record-type
arrays, `status_code`) against the installed binary before writing the parser. Classified `LOW`
in `agent/risk.py` — dnsx queries public third-party resolvers (Cloudflare/Google/Quad9/etc.,
visible in each result's own `resolver` field), never the target's own infrastructure, same
rationale as `run_subfinder`. Registered in `ALL_TOOLS` right after `run_nmap`.

No new bug this time — first attempt worked. Two things confirmed rather than assumed, in
keeping with the pattern from the last three wrappers:
- `-l` accepts a comma-separated string directly (verified live) — no stdin or file needed, so
  a whole domain batch stays one call, same batching reasoning as `run_httpx`'s repeated `-u`.
- dnsx has no `-rate`/rate-limit flag at all (only `-threads` for concurrency) — confirmed via
  `-h`, not assumed absent. `ORCHESTRATOR_SYSTEM_PROMPT` rule 4 is about target-facing traffic;
  resolving through public resolvers isn't that, so there's nothing to enforce here the way
  `run_httpx`/`run_naabu` needed to.

**Verified live:** 3-domain batch (`hackerone.com`, `bugcrowd.com`, and a non-resolving domain)
→ 80 findings across both real domains' A/AAAA/MX/NS/TXT records, `error: null`, completed in
~2.3s; the non-resolving domain correctly produced zero findings and no crash (confirmed only
`hackerone.com`/`bugcrowd.com` appear as `target` values). Regression-checked:
`agent/orchestrator.py` imports cleanly with 18 tools registered, `agent/risk.py` classifies
all five recon wrappers correctly (`run_subfinder`/`run_dnsx` LOW;
`run_httpx`/`run_naabu`/`run_nmap` MEDIUM).

### `amass` is NOT installed — skipped, blocked, not forgotten (superseded later this session — see below)

Checked before starting the next wrapper: `which amass` and `~/go/bin/amass` both come up empty.
Every other tool used so far (`subfinder`, `httpx`, `naabu`, `nmap`, `dnsx`, `tlsx`) was
confirmed on PATH first; `amass` is the first one that genuinely isn't there, unlike the earlier
`httpx` situation which was a binary-name collision, not a missing install. `scripts/
phase0_setup.sh` may need a fix or a rerun for this specific tool — not investigated this
session, don't assume it's a quick add. Skipped in favor of `run_tlsx`, built next instead.

### `run_tlsx` built, verified live — sixth `tools/recon.py` wrapper this session

TLS certificate analysis — expiry, SANs, issuer, cipher. Confirmed real `-u` (comma-separated,
same batching as `run_httpx`)/`-json`/`-silent` flags and JSON output shape (`host`,
`tls_version`, `cipher`, `not_before`, `not_after`, `subject_cn`, `subject_an`, `issuer_cn`,
`wildcard_certificate`, ...) against the installed binary before writing the parser. Classified
`MEDIUM` in `agent/risk.py` — unlike `run_dnsx`, this opens a real TLS connection directly to
the target on port 443, the same "one lightweight request per host" profile as `run_httpx`, not
`run_naabu`'s per-port volume (confirmed via `-h`: no rate-limit flag exists here either, only a
per-connection `-timeout`). Registered in `ALL_TOOLS` right after `run_dnsx`.

**A flag ambiguity investigated and deliberately avoided, not just assumed safe:** tlsx has
`-expired`/`-self-signed`/`-wildcard-cert`/`-mismatched` flags whose `-h` wording ("display host
with X certificate") reads like a text-mode display filter. Tested live: passing `-expired
-self-signed -wildcard-cert` alongside `-json` didn't change which hosts appeared or add any
distinct boolean fields — `wildcard_certificate` was already present (and `true`) for
`bugcrowd.com` in a run that passed NONE of these flags at all. Rather than trust ambiguous,
seemingly-inert flags that might filter a JSON batch down to only matching hosts in some
untested combination, `run_tlsx` doesn't pass any of them — expiry is computed directly from
the certificate's own `not_after` field instead (unambiguous, and ties directly into
`RECON_AGENT_PROMPT`'s existing rule to flag expired SSL certs — `Finding.severity` is set to
`"low"` specifically when the certificate has actually expired, everything else stays `"info"`
like every other recon wrapper's asset-discovery findings).

**Verified live:** `hackerone.com`, `bugcrowd.com`, `scanme.nmap.org` (no HTTPS listener) → 2
findings (only the two real HTTPS hosts), `error: null`, ~3.6s, expiry correctly computed
(`expires in 244d` / `expires in 247d`), `scanme.nmap.org` silently and correctly omitted — same
non-error-for-a-non-applicable-host pattern as `run_httpx`/`run_naabu`. Regression-checked:
`agent/orchestrator.py` imports cleanly with 19 tools registered, `agent/risk.py` classifies all
six recon wrappers correctly (`run_subfinder`/`run_dnsx` LOW;
`run_httpx`/`run_naabu`/`run_nmap`/`run_tlsx` MEDIUM).

### `run_gau` built, verified live — new `tools/url_harvest.py` file, first wrapper in it

Historical URL harvesting from Wayback Machine + AlienVault OTX. Classified `LOW` in
`agent/risk.py` — queries third-party archives, never the target. Confirmed real `--json`/
`--providers`/`--blacklist`/`--from` flags and JSON output shape (`{"url": "..."}`) against the
installed binary first, same discipline as every wrapper before it.

Single domain per call, not a batch — tested passing two domains as positional args and it
didn't behave like `run_httpx`'s repeated `-u` (didn't finish inside 25s where one domain
reliably does); rather than guess at undocumented multi-arg semantics, `run_gau` follows
`run_nmap`'s single-target precedent instead.

**A real scale problem found via live testing, not assumed:** gau has no result-count limit
flag. Querying ALL 4 default providers for `hackerone.com` got killed at a 60s cap having
produced only 139 URLs (commoncrawl/urlscan are slow to even start responding); restricting to
`--providers wayback,otx` was WORSE in a sense — 47,000+ URLs and still not done after 60s,
because wayback alone streams enormous volume for a decade-old, high-profile domain. A smaller,
newer domain (`scanme.nmap.org`) finished in ~19s with 42 URLs — confirming `hackerone.com` is
a genuine outlier, not gau being broadly slow. Since `tools/base.py`'s `run_tool()` discards
stdout entirely on a timeout (no partial results survive), hitting the timeout on an outlier
domain would return zero URLs, not a truncated-but-useful list. Added an optional `from_date`
(YYYYMM) parameter as the only available escape hatch — gau has no `--limit`, only date-range
narrowing via `--from`/`--to`.

**Verified live:** `scanme.nmap.org` → 59 findings, `error: null`, ~7s. Registered in
`ALL_TOOLS` right after `run_tlsx`.

### `amass`: root cause found, fixed, and wrapped — supersedes the "skipped" note above

Came back to `amass` later this session rather than leaving it as a permanent gap. Reading
`scripts/phase0_setup.sh` directly (not just checking `which amass`) found the real reason it's
missing: its `GOTOOLS` array simply never lists it. Not a failed install — never attempted. It's
OWASP Amass, a separate project from the ProjectDiscovery tools that make up most of that list,
easy to have overlooked when the script was originally written. Fixed the script (added
`github.com/owasp-amass/amass/v4/cmd/amass@latest` to `GOTOOLS`, for future setup runs) AND
realized `go install` itself needs no sudo (installs to `~/go/bin`, unlike the apt/docker/
Go-toolchain steps elsewhere in that script that genuinely do need the user to run them) — so
installed it directly this session instead of leaving it fully blocked on the user. Confirmed:
`amass -version` → v4.2.0, on PATH.

**Two real discoveries getting `run_amass` working, both structurally different from every
wrapper before it, found only through live testing:**

1. **amass v4 produces NO stdout output at all when run non-interactively.** Tested with and
   without `-silent`, both against a domain with zero subdomains for it to find
   (`scanme.nmap.org`) and one with plenty (`hackerone.com`, where `run_subfinder` already found
   19 real ones) — completely empty stdout/stderr either way, even mid-run. amass v4's terminal
   UI appears designed only for a real TTY. The only way to get results is its `-oA` file output
   (a text relationship graph: `subject (FQDN) --> relation_type --> object (FQDN)` per line,
   confirmed by reading the actual file after a run that used `-oA /tmp/.../h1` directly outside
   the wrapper). `run_amass` writes to a `tempfile.TemporaryDirectory()`, reads
   `<prefix>.txt` back after `run_tool()` returns, parses it with a regex, and lets the
   `TemporaryDirectory` context manager clean up — every other wrapper here relies on stdout
   alone; this is the first one that doesn't.
2. **Runtime is markedly slower than every other recon tool, AND unpredictably so.** Three live
   runs against the IDENTICAL target (`hackerone.com`): ~95s, then timed out past 150s with
   zero results, then ~137s. No way to predict which up front — depends on however long amass's
   own upstream OSINT sources take to respond that particular run. This matters more here than
   anywhere else in this codebase: a run that hits `run_tool()`'s outer timeout gets SIGKILLed
   before it can flush its `-oA` file, so timing out means TOTAL loss of results, not a partial
   list — every JSON-over-stdout wrapper at least has SOME partial-output story even if
   `run_tool()` doesn't currently expose it; amass has none at all. Bumped `timeout_s` to 180s
   for headroom (confirmed working: 29 findings, `error: null`, ~137s) — but documented this as
   a "usually enough" margin, not a guarantee, directly in the wrapper's own docstring so a
   future session doesn't mistake an occasional timeout for a bug.

Classified `LOW` in `agent/risk.py` (`-passive` flag only — `-active` mode, which attempts zone
transfers and cert grabs directly against the target's nameservers, was deliberately not used
and would need its own MEDIUM wrapper if ever added). Registered in `ALL_TOOLS` right after
`run_subfinder`. Regression-checked after all this: `agent/orchestrator.py` imports cleanly with
21 tools registered, `agent/risk.py` classifies all 8 recon/harvest wrappers correctly, and
`run_subfinder` itself still works unchanged (24 subdomains for `hackerone.com` on a fresh run).

### `run_gowitness` — blocked on a missing Chrome/Chromium binary, root cause found

Next after `amass`, per the plan's `tools/recon.py` order. `gowitness` itself is installed and
runs fine (`go install` succeeded, on PATH) — but verified live that it fails at the actual
screenshot step: `failed to initialize chrome context: exec: "google-chrome": executable file
not found in $PATH`. Checked before assuming this was fixable in-session: no browser binary
exists anywhere in this environment (`which chromium chromium-browser google-chrome` all
empty; `apt-cache policy chromium-browser` shows only a snap-transitional candidate, nothing
actually installed). Unlike `amass`, this genuinely needs `sudo apt install -y chromium-browser`
— real sudo, not a plain `go install` — so it can't be unblocked the same way this session.
Added `sudo apt install -y chromium-browser` to `scripts/phase0_setup.sh`'s step 1, with a
comment explaining exactly why it's there (gowitness specifically, nothing else in this project
needs a browser). Left as the one remaining gap in `tools/recon.py` until the user runs that
script.

### `run_tool()` gained an optional `stdin_input` parameter — first new `tools/url_harvest.py` wrapper needed it

Moved to `tools/url_harvest.py`'s next tool per the plan order: `waybackurls`. Verified live it
ignores a domain passed as a positional arg entirely (hangs indefinitely) — unlike every
ProjectDiscovery tool wrapped so far, it ONLY reads its target from stdin. `tools/base.py`'s
`run_tool()` had no way to pipe input to a subprocess at all, so added `stdin_input: str | None
= None` to it directly (passed to `proc.communicate(input=...)`, stdin only set to `PIPE` when
provided) rather than special-casing this per-wrapper — several other classic tomnomnom-style
tools (`gf`, `qsreplace`, `anew`) follow the same stdin-only convention and will need this too.
Backward compatible: defaults to `None`, which reproduces the exact previous behavior
(`stdin=None`, i.e. inherit) — regression-checked `run_subfinder` still works unchanged after
this change (0 findings for `scanme.nmap.org`, `error: null`, matching its known small
footprint, no crash).

### `run_waybackurls` built, verified live — genuinely worse reliability than `run_amass`'s timing variance

Wayback Machine URL extraction, classified `LOW` (third-party archive, same as `run_gau`).
Confirmed real behavior (no flags needed, stdin-only input) before writing the parser.

**Found something more concerning than any prior wrapper's caveat, via three live runs against
the IDENTICAL domain (`hackerone.com`)**: 1189 URLs when the process was killed at 60s, 0 URLs
when it exited 0 ("success") at ~61s, then 302 URLs when killed at 90s. The Wayback CDX API this
tool queries appears to intermittently return partial or empty result sets with NO error
surfaced anywhere — not by waybackurls itself, not by this wrapper. This is a materially
different (and worse) failure mode than `run_amass`'s: amass's variance is at least always
visible as an explicit `error` when it times out; `run_waybackurls` can complete "successfully"
with zero results and there is no way to tell that apart from a domain that genuinely has no
Wayback history. Documented this explicitly and prominently in the wrapper's own docstring —
an error-free empty result from this specific tool should NOT be trusted the way it would be
from every other wrapper in this codebase; the caller should retry rather than conclude "nothing
found" when a real result is expected.

**Verified live, end-to-end through the wrapper** (not just the raw binary): `scanme.nmap.org` →
84 findings, `error: null`, ~37s (itself notably slower than the ~2s a raw manual test took
earlier for the same domain — more evidence of the same underlying variance, just on the
"still works, just slower" side of it this time). Registered in `ALL_TOOLS` right after
`run_gau`. Regression-checked: `agent/orchestrator.py` imports cleanly with 22 tools registered,
`agent/risk.py` classifies both `run_gau` and `run_waybackurls` as `LOW`.

### `run_tool()` fixed to preserve partial output on timeout — the architectural gap flagged repeatedly this session, now actually closed

Came back to this at the user's explicit direction ("fix the architectural gap then continue")
after flagging it as an unresolved limitation across the `run_gau`, `run_amass`, and
`run_waybackurls` writeups above without ever fixing it. The gap: `run_tool()` used
`proc.communicate()` inside `asyncio.wait_for(..., timeout=timeout_s)` — `communicate()` only
hands back its buffered stdout/stderr on clean completion, so killing the process on timeout
(the only path available) discarded EVERYTHING read so far, even when a slow tool had produced
real, useful partial output before running out of time.

**Fix:** rewrote `run_tool()` to drain `stdout`/`stderr` incrementally via a background
`_drain_stream()` reader task per stream, accumulating into byte-chunk lists as the process
runs, rather than waiting for `communicate()`'s one-shot return. A kill now only stops FUTURE
output from being captured — everything already read survives. Also switched from a bare
`proc.kill()` (SIGKILL) to `proc.terminate()` (SIGTERM) first, with a 3s grace period before
falling back to `SIGKILL` — gives a well-behaved tool a chance to exit and flush cleanly rather
than being cut off mid-write. `error` is still always set on a timeout, partial data or not — a
timeout must never look like a clean, complete success to a caller.

**This required touching every existing wrapper, not just `run_tool()` itself**: each one's
`raw_output=stdout if not error else stderr` line and `if not error:` findings-parsing gate
would have kept discarding the newly-available partial data even after the `run_tool()` fix,
since `error` is still set on every timeout by design. Changed both patterns uniformly
(`raw_output=stdout or stderr`, `if stdout:`) across `run_subfinder`, `run_httpx`, `run_naabu`,
`run_dnsx`, `run_tlsx`, `run_gau`, and `run_waybackurls`. `run_nmap` and `run_amass` were left
alone: `run_nmap`'s XML output doesn't parse safely when truncated (an incomplete `-oX`
document just fails `ET.fromstring` cleanly, falls back to zero findings — safe, but doesn't
recover partial data, and fixing that would need a real streaming XML parser, out of scope
here); `run_amass`'s results live in a file via `-oA`, not stdout, so this fix doesn't reach it
at all — noted explicitly in its docstring that whether amass flushes `-oA` on `SIGTERM` rather
than `SIGKILL` is still unverified.

**Verified live, three ways:**
1. Direct `run_tool()` test: a `bash -c` script printing two lines then sleeping past a 2s
   timeout returned `'line1\nline2\n'` with `error` set — previously would have returned `''`.
2. Real-world confirmation: re-ran `run_gau` against `hackerone.com` (the known outlier domain
   from earlier in this session) — now returns 24 real findings AND
   `error: "gau timed out after 120s (partial output below, if any)"`, where it previously
   returned zero findings for the identical scenario.
3. Full regression sweep against `scanme.nmap.org`/a small live target: all 8 existing wrappers
   (`run_subfinder`, `run_httpx`, `run_naabu`, `run_nmap`, `run_dnsx`, `run_tlsx`, `run_gau`,
   `run_waybackurls`) still return their expected result counts with `error: null` — the fix
   didn't change behavior for the success path, only the timeout path. `agent/orchestrator.py`
   still imports cleanly with all 22 tools registered.

Every stale docstring claim about the old "discards everything on timeout" behavior was updated
to reflect the fix — `run_gau`'s and `run_waybackurls`' docstrings previously said the timeout
case came back with nothing; both now describe the accurate partial-output behavior, and
`run_waybackurls`' docstring specifically distinguishes the (now improved) timeout case from
its OTHER, still-unresolved caveat (a clean exit-0 with zero results, which isn't a timeout at
all and isn't touched by this fix).

### `run_katana` built — and a real scope-safety bug found and fixed via live testing

Moved to `tools/url_harvest.py`'s next tool: `katana`, active JS-aware crawling to find
endpoints/forms/APIs. This is the first Phase 2 wrapper where the standard "confirm real CLI
flags and output shape live" discipline surfaced a genuine SAFETY bug, not just a reliability
or convenience one.

**The bug**: crawling `http://scanme.nmap.org` with katana's documented defaults sent a REAL
HTTP request — confirmed via a populated `response` field with a real `status_code` in the
JSONL output — to `nmap.org` itself, a completely different host than the one passed in. Root
cause: katana's default `-fs rdn` ("root domain name") scope treats anything sharing the same
*registrable* root domain as in-scope, and `scanme.nmap.org`'s root domain is `nmap.org`. In a
real bug-bounty program, being authorized to test one subdomain does NOT imply the root domain
is authorized too — this would have been a genuine, real scope violation the very first time
this wrapper touched a real program, silently, since nothing about the call would have looked
wrong (no error, a normal-looking crawl result). This is exactly the class of mistake
`check_scope`/`check_policy_compliance`/the scope-fabrication gate exist to prevent, just
arriving through a different door (a tool's own default behavior instead of the model
fabricating scope).

**How it was caught**: didn't just eyeball the discovered-URL list (which included `nmap.org`,
`npcap.com`, `facebook.com`, `github.com`, `twitter.com`, etc., and looked alarming at first
glance) — wrote a small script to check the JSONL output for which hosts actually had a
`response` field (meaning a request was genuinely sent and answered) versus which were just
extracted `href`/`src` references from a crawled page's HTML (normal, safe crawler behavior,
never fetched). Only `nmap.org` (besides the target itself) had a real `response` — everything
else was link-list noise. That distinction is what separates "a real scope violation" from "a
crawler doing its job," and it wasn't visible without checking.

**Fix**: pass `-fs fqdn` (exact fully-qualified-hostname match) instead of the default. Verified
live, re-running the identical crawl: only `scanme.nmap.org` ever has a populated `response`
field afterward — confirmed via the same host-extraction script.

Also passes `-omit-raw -omit-body` — katana's default JSONL embeds the ENTIRE HTML/CSS/JS
response body inline per line, which bloats every result for no benefit `parsed` findings
actually need (endpoint, method, tag, status code only). `-rate-limit` set from
`settings.MAX_REQ_PER_SEC`, same policy as every other target-facing wrapper. Single URL per
call, matching `run_nmap`/`run_gau`'s single-target precedent — no multi-URL behavior assumed
or tested.

Classified `MEDIUM` in `agent/risk.py` (sends real requests directly to the target while
crawling). Registered in `ALL_TOOLS` right after `run_waybackurls`.

**Verified live, final run** (with the `-fs fqdn` fix applied): `http://scanme.nmap.org`, depth
2 → 6 findings, `error: null`, ~14s, confirmed programmatically that `scanme.nmap.org` is the
ONLY host appearing across every finding's URL. Regression-checked: `agent/orchestrator.py`
imports cleanly with 23 tools registered, `agent/risk.py` classifies `run_katana` as `MEDIUM`.

## Session 2 summary (2026-07-16) — Phase 0 partial + Phase 1 built and smoke-tested

**Hard constraint discovered this session:** Claude's Bash tool has no TTY. `sudo` fails
outright with "a terminal is required to authenticate" — not just non-interactive, genuinely
impossible from this tool, even one command at a time. Every sudo-gated Phase 0 step (apt
packages, docker group, Ollama's own install script) had to be written to
`scripts/phase0_setup.sh` and `scripts/install_ollama.sh` for the user to run themselves in
their own WSL terminal, rather than run directly. If a future session is tempted to retry
`sudo` directly — don't; this has been verified impossible in this environment, not just risky.

**What the user explicitly chose this session** (asked via AskUserQuestion, don't re-ask):
- Sudo-gated installs: user will run them manually (see scripts/ above) — **done**, all critical
  tools verified on PATH (`subfinder`, `httpx`, `nuclei`, `ffuf`, `nmap`, `sqlmap`, `dalfox`, `go`)
- Ollama: user already had it running on Windows with a model loaded, and chose to reuse that
  rather than a redundant ~18GB re-download inside WSL2. **This is now working end-to-end** —
  see "Live Ollama setup" below for exactly how, and the caveats that come with it.
- Git/GitHub: **explicitly skipped for this session** — repo is still not a git repo. Don't
  push for this next session either unless the user brings it up; they chose to defer it, not
  forgot about it.

## Live Ollama setup (reused existing Windows install, not `scripts/install_ollama.sh`)

WSL2 uses default NAT networking (no `.wslconfig` mirrored mode) — Windows' `127.0.0.1` and
WSL2's `127.0.0.1` are different network namespaces, and Ollama binds to `127.0.0.1` only by
default, so a Windows-hosted Ollama is structurally unreachable from WSL2 out of the box. To fix
it without a duplicate model download:
1. On Windows: killed the running Ollama process, then relaunched it with
   `$env:OLLAMA_HOST="0.0.0.0:11434"; ollama serve` run inline in a PowerShell window (left
   running in the foreground). **Setting `OLLAMA_HOST` as a persisted System/User env var and
   restarting the app did NOT work** — Explorer-launched processes don't pick up new env vars
   without a full logoff/login, a Windows quirk unrelated to Ollama itself. The inline-env-var
   approach sidesteps that entirely.
2. Windows Firewall: `New-NetFirewallRule -DisplayName "Ollama (WSL2)" -Direction Inbound -LocalPort 11434 -Protocol TCP -Action Allow` (run as Administrator).
3. `.env` created (wasn't there before, only `.env.example`) with
   `OLLAMA_BASE_URL=http://172.22.208.1:11434` (the WSL2 default-gateway IP —
   **not stable across WSL2/Windows restarts**; re-derive with
   `ip route | grep default | awk '{print $3}'` if a future session finds Ollama unreachable
   again) and `OLLAMA_MODEL=huihui_ai/qwen3-coder-abliterated:30b-a3b-instruct-q3_K_M` (the
   plan/`.env.example` assumed `qwen3-coder:30b`, which isn't what's actually pulled on this
   machine — always check `curl http://<gateway>:11434/api/tags` for the real registered name
   rather than trusting the default).
- `scripts/install_ollama.sh` (self-contained WSL2 install) is still there as a fallback, with
  a `zstd` prerequisite fix added after a first failed run — just wasn't the path taken.

## `check_scope` reliability — fixed 2026-07-16, verified live

Was broken (see history below), now fixed and verified end-to-end against the live model. Two
separate bugs, fixed together:

**Bug 1 — model couldn't freehand a `ScopePolicy`.** `check_scope` takes a nested `ScopePolicy`
object (`allowed_domains`, `forbidden_domains`, etc.), and even with `bind_tools` the model
reliably got the nested keys wrong (e.g. `allowed`/`forbidden` instead of
`allowed_domains`/`forbidden_domains`). Because every `ScopePolicy` field has a default,
Pydantic silently dropped the unrecognized keys and built an empty-list `ScopePolicy`, so
`check_scope` ran without crashing but returned `requires_human_confirm: True` regardless of the
real answer — fails safe, but non-functional. **Fix:** `skills/scope_parser.py`'s
`parse_scope(scope_text) -> ScopePolicy` (deterministic heuristic, no LLM involved) is now also
exposed as an `@tool` — `parse_scope_policy` — registered in `ALL_TOOLS` right before
`check_scope`. This alone wasn't enough on its own, though — it needed:

**A second architecture change — multi-step tool calling.** The original `agent/graph.py` only
ever asked the model for ONE tool call per command (`plan → awaiting_human → execute → report`,
straight line, no loop). That can't use two chained tools in one command at all. Rewrote the
graph to loop `plan → awaiting_human → execute → plan → ...`, with each iteration individually
HITL-gated. `plan_step()` returning no tool call (agent/planner.py) means "final answer,"
routing to REPORTING. Bounded by `MAX_STEPS = 6` in `agent/graph.py` so a runaway/looping model
can't burn through approval prompts indefinitely. `HuntState` gained `messages` (running
LangChain message history for the command) and `step_count`.

**Bug 2 — found only once the chain actually ran**: `parse_scope()`'s own heuristic
misclassified domains when "In scope"/"Out of scope" markers appeared in the same
line/sentence (prose-style policy text, not bulleted) — it only tracks section state
per-physical-line via `splitlines()`, so the LAST marker on a line retroactively reclassified
every earlier domain on it too. Fixed by forcing every marker onto its own line
(`_force_markers_onto_own_lines()`) before the existing per-line logic runs — verified against
both the broken prose case and the original bulleted multi-line case (no regression).

**Verified live, 2026-07-16:** a compound command ("is www.example.com in scope, given this
policy text") correctly ran `parse_scope_policy` then `check_scope` with its exact output,
both auto-approved as LOW risk, correct final in-scope answer, correct reasoning shown to the
user. Regression-checked: single-tool commands (`get_waf_bypasses`) and the LOW/MEDIUM/HIGH
HITL gate still behave identically to before this change.

**What got built and verified (see docs/DEVELOPMENT_PLAN.md for the checkbox-level detail):**
- Python venv (`python3.14`, since this box is Ubuntu 26.04 "Resolute" — no `python3.11`
  package exists here, contra the plan's assumption). `pip install -r requirements.txt`
  succeeded clean — 150 packages, including langgraph 1.2.9, langchain 1.3.14, torch 2.13.0 —
  despite Python 3.14 being very new, no wheel-compatibility issues were hit. Took ~10 minutes,
  mostly network-bound (torch alone is ~1.5GB of CUDA wheels).
- Fixed a real bug in `agent/orchestrator.py`: `create_react_agent(state_modifier=...)` — that
  kwarg is gone in langgraph 1.2.9 (renamed to `prompt=` several versions back). Would have
  hard-crashed on first import once deps were installed.
- Rest of Phase 1 built: `agent/state.py` (Stage enum + HuntState/ActionPlan TypedDicts),
  `agent/planner.py` (initially free-hand JSON prompting, later rewritten twice more — see
  "check_scope reliability" below for the final `bind_tools` + multi-step design),
  `agent/hitl.py` (approve/reject/modify gate, LOW/MEDIUM/HIGH coloring, batch approval via
  hitl_batcher), `agent/graph.py` (the LangGraph StateGraph — final form loops
  plan → awaiting_human → execute → plan → ... with an error sink and a modify-loops-back-to-plan
  edge), `agent/session.py` (JSON checkpoint save/load), `main.py` (terminal loop, pings Ollama
  first with a clean error exit if unreachable).
- **Verified without needing a live LLM**: orchestrator imports cleanly, all 12 skills register
  as tools, the LangGraph graph compiles, and — most importantly — the full
  awaiting_human → execute → report path was driven directly with a scripted plan dict (bypassing
  the LLM planner node) for all three risk levels: LOW auto-approved `check_scope` correctly,
  MEDIUM correctly asked and honored a reject, HIGH correctly required literal "yes".
  **Then verified fully live**: real Ollama, real command through `main.py` end-to-end —
  "Agent ready" printed, command → `bind_tools`-based planner → real tool call
  (`get_waf_bypasses`) → LOW-risk auto-approve shown → executed → checkpoint saved → status
  table rendered. First time any part of this project has run against a live LLM.

**What's still not built:** same Phase 2–9 gap as before (tool wrappers, tech_analyzer/graphql/
auth_mapper, recon pipeline, Gradio UI, ChromaDB memory, report generator, CI) — see
docs/DEVELOPMENT_PLAN.md for the current per-item state. The "Where we actually are" section
below is from session 1 and is now partially superseded — Phase 0 is no longer 100% undone,
Phase 1 is no longer 0% done — but is kept for the parts still accurate (Phase 2+ gap).

## Phase 2 kickoff — `run_subfinder`, and three real bugs found building it

Built `tools/base.py` (`ToolResult`/`Finding` contract + async `run_tool()` subprocess helper)
and `tools/recon.py`'s `run_subfinder` — the first Phase 2 tool wrapper. Confirmed subfinder's
real CLI flags (`-d`, `-silent`, `-json`/`-oJ`, `-timeout`) and JSON output shape
(`{"host": "...", "input": "...", "source": "..."}`) directly against the installed binary
before writing the parser, then verified the async wrapper standalone (19 real subdomains for
`hackerone.com`) before ever touching the LLM. Registered in `ALL_TOOLS`, classified `LOW` in
`agent/risk.py` (passive — queries public sources, never touches the target).

Getting it working through the actual live-LLM HITL graph surfaced three separate real bugs,
each fixed and verified:

1. **Async tools couldn't execute at all.** `agent/graph.py`'s `node_execute` called
   `tool.invoke()` synchronously — fine for every sync `@tool` skill so far, but `run_subfinder`
   is `async def`-only, and LangChain raises `"StructuredTool does not support sync invocation"`
   rather than silently handling it. Fixed by switching to
   `asyncio.run(tool.ainvoke(plan.get("args", {})))`, which works uniformly for both sync tools
   (LangChain runs them in a thread executor) and async ones (awaited directly). Any future
   async tool wrapper needs no special-casing because of this.
2. **Ollama's runtime context window was too small.** Even though this model reports
   `context_length: 262144` in `/api/tags`, Ollama's actual allocated KV-cache size at runtime
   (`num_ctx`) defaults small (hit a 4096 cap with just the system prompt + 13 tool schemas +
   one modest tool result — 5877 tokens). Fixed by adding `OLLAMA_NUM_CTX` (default 8192) to
   `config/settings.py` and passing `num_ctx=settings.OLLAMA_NUM_CTX` to **every** `ChatOllama`
   instantiation (`agent/planner.py`, `agent/orchestrator.py`, `skills/chain_analyzer.py`,
   `skills/business_logic_mapper.py`) — the latter two call the LLM directly too and would hit
   the same wall on a large findings list, not just the planner.
3. **The model doesn't always use the native tool-calling API.** Sometimes it emits a
   pseudo-function-call as plain text instead —
   `"<function=parse_scope_policy>\n<parameter=scope_text>...`. `response.tool_calls` comes
   back empty either way, so `agent/planner.py`'s `plan_step()` was silently treating a FAILED
   tool-call attempt as "the model is done, final answer" — the intended action just silently
   never happened, a worse failure mode than a crash. Fixed: `plan_step()` now checks
   `response.content` for markers of a malformed attempt
   (`_MALFORMED_TOOL_CALL_MARKERS = ("<function=", "<tool_call>", "<|tool_call|>", "[TOOL_CALL]")`)
   and raises `PlanParseError` (routes to the ERROR stage, visible to the human) instead of
   silently completing.

**A fourth issue found, NOT fixed — flag for follow-up, safety-relevant:** asked the model
(with no scope text provided) "Check if api.hackerone.com is in scope for the HackerOne bug
bounty program" — it fabricated a plausible-looking HackerOne scope policy from its own
training knowledge and called `parse_scope_policy`/`check_scope` with the fabricated text,
rather than asking the human for the real policy. Added an explicit rule to
`ORCHESTRATOR_SYSTEM_PROMPT` (rule 1) forbidding this — **re-tested after the prompt fix and
the model still fabricated scope text** (this is what surfaced bug 3 above — the fabrication
attempt happened to also be malformed). Prompting alone is not reliably fixing this on this
model/quantization. This is a real, open safety gap: rule 1 ("never test out-of-scope assets")
is only as good as the scope data it's checked against, and a hallucinated policy could as
easily fabricate an "allowed" domain that isn't really in scope as it could wrongly exclude
one. Needs a structural fix, not just a prompt rule — e.g. the graph refusing to run
`parse_scope_policy`/`check_scope` at all until the human has pasted scope text into the
conversation this session (detectable: no HumanMessage other than the initial command has
scope-page-shaped content), rather than trusting the model's self-restraint.

Also fixed while diagnosing this session's Ollama connectivity: the Windows-hosted `ollama
serve` (started in a foreground PowerShell window per "Live Ollama setup" above) died mid-session
— likely the window got closed or the machine idled — and needed a manual restart. This is the
inherent fragility of that setup, not a one-time fluke; expect to need to restart it again in
future sessions the same way.

## Immediate next steps for whoever picks this up

1. ~~Fix the scope-fabrication gap~~ — **CLOSED 2026-07-18**, see "Scope-fabrication gap —
   CLOSED" under "Session 3 summary" above for the fix and its live verification. Don't
   re-litigate this; the remaining Phase 2/3 work below is the actual next priority now.
2. **Phase 2 is COMPLETE as of session 4 (2026-07-19)** — all 37 checklist items done, 51 tools
   registered and live-verified. Don't re-litigate this or re-check individual wrappers'
   plumbing; see "Session 4 summary" for the full bug/quirk list if something in `tools/*.py`
   seems off. The only remaining Phase 2 item is `run_gowitness`
   (`tools/recon.py`), blocked on a missing Chrome/Chromium binary — needs the user to run
   `scripts/phase0_setup.sh` (which now includes `sudo apt install -y chromium-browser`).
   **Phase 3 is now ALSO COMPLETE as of session 5 (2026-07-22)** — every checklist item done, 61
   tools registered and live-verified; see "Same-session continuation" under "Session 5 summary"
   above for the full list and the two real bugs found shipping it.
   **Phase 4 is now ALSO COMPLETE as of session 6 (2026-07-22)** — `agent/recon_pipeline.py` (a
   dedicated LangGraph pipeline, separate from `agent/graph.py`'s single-action loop),
   `agent/memory.py` (ChromaDB), and resume support, all live-verified including two real bugs
   found and fixed along the way — see "Session 6 summary" above for the full account.
   **Phase 5 is now FULLY COMPLETE as of session 7 (2026-07-24)** — `agent/vuln_pipeline.py` (a
   third dedicated LangGraph pipeline, consuming a prior recon run's surface, now 10 stages), the
   LLM tech→checklist planner, `skills/vuln_assessor.py`'s false-positive/confidence triage, the
   per-finding HITL gate, `check_eligibility`→`build_poc`→confirmed-findings-memory wiring, the
   `xss_probe`/`skills/waf_bypass_prober.py` WAF-bypass retry loop, and the credentialed
   `auth_probe` stage are ALL live-verified (real Ollama calls and a real local test server, not
   just mocked) — see "Session 7 summary" and "Session 7, continued" above.
   **Phase 6 is now ALSO COMPLETE as of session 7 (2026-07-24)** — `ui/app.py` (Gradio Blocks,
   three tabs), `agent/web_hitl.py` (`HuntSession`/`WebApprovalBackend`), and `agent/hitl.py`
   refactored for a pluggable, thread-local `ApprovalBackend` (zero behavior change for
   `main.py`'s CLI path) — all live-verified including a real Gradio server driven end-to-end via
   `gradio_client` over actual HTTP, not just function-level — see "Session 7, continued again"
   above. The WebSocket-bridge checklist item was deliberately reduced in scope (Gradio's own
   live-update transport used instead of a hand-rolled second one) and documented as such, not
   silently skipped.
   **Phase 8 is now ALSO COMPLETE as of session 7 (2026-07-24)** — `skills/report_generator.py`
   (CVSS 3.1 calculator verified against 4 known reference vectors, LLM narrative via the
   already-existing `REPORT_AGENT_PROMPT`, static remediation lookup), `config/report_templates.py`
   (3 platform-specific Jinja2 templates), `agent/memory.py`'s `get_confirmed_findings()`, and
   both `main.py`'s `"report <target> [platform]"` command and `ui/app.py`'s Report section
   (generate-draft → human-editable textbox → separate Export button) — all live-verified
   including real `.md`+`.pdf` file output (PDF header confirmed genuine) — see "Session 7,
   continued a third time" above. Don't re-litigate Phases 2-8 — **next priority is Phase 9** (CI
   / polish — see docs/DEVELOPMENT_PLAN.md; Phase 7's own scope was already mostly delivered by
   Phase 4). One open design tension
   still unresolved, relevant whenever a future pipeline stage adds more tools (Phase 4's own
   `dirs` stage uses only `run_ffuf`, `run_kiterunner` was deliberately NOT included in it for
   this exact reason): `run_kiterunner` has no rate-limit flag at all and cannot honor
   `ORCHESTRATOR_SYSTEM_PROMPT` rule 4 the way every other active wrapper does — classified HIGH
   specifically so a human always approves it explicitly. Any future pipeline stage that wants to
   include it should treat it as a special case (e.g. never auto-chain it) rather than assume
   every HIGH-risk tool behaves the same way as sqlmap/ghauri (which DO respect a request cap,
   just via a stricter human-approval bar, not a rate mismatch).
3. Whenever the user wants version control back: git init, GitHub repo, first commit — was
   explicitly deferred, not forgotten.
4. If Ollama becomes unreachable in a future session: re-check the WSL2 gateway IP
   (`ip route | grep default | awk '{print $3}'`) against what's in `.env`, and remember the
   Windows-side `ollama serve` itself may need restarting too (see "Phase 2 kickoff" above —
   this happened mid-session, not just once at setup time; session 7 saw it crash with a CUDA
   error mid-run and come back on its own without a manual restart, but don't assume that always
   resolves itself). This is not guaranteed stable.
5. `check_scope` reliability (the OLD top blocker), the async/num_ctx/malformed-tool-call bugs,
   and the scope-fabrication gap are ALL fixed and verified live as of 2026-07-18. Don't
   re-litigate any of these — there is no known open safety gap in the scope-checking path as
   of this writing. The next open items are Phase 2/3 build-out (see #2/#3 above), not safety.

## Differentiation strategy

There are already public "bug bounty agent" projects that run nuclei + a fuzzer + an LLM
summary. That's commodity and not worth building again. This project's edge is meant to be:
(1) skills that reason about *sequence and state* (business logic), not just parameters, and
(2) an economically-aware hunter (ROI prioritization, hunt memory) instead of a breadth-first
scanner, layered under an HITL flow that stays pleasant to use at scale (batched approvals,
explained risk) instead of turning into permission-prompt spam. Six skills below exist
specifically to deliver on that, not just to pad the tool count — see each one's docstring
for the "why," not just the "what."

## Eligibility & payout optimization

A separate, later pass added rules aimed specifically at *converting* technically-real findings
into paid, accepted reports — a different problem from finding vulns at all. Most bounty-report
rejections aren't "wrong," they're "not eligible": a program's own won't-fix list (self-XSS,
clickjacking on non-sensitive pages, missing headers, logout CSRF, rate-limiting nits, SPF/DKIM,
autocomplete, TLS best-practice, version disclosure), a VDP program with no monetary reward at
all, or a disclosed-too-early bounty forfeited over a stated embargo. `scope_parser.py` and
`policy_compliance.py` now extract this (`program_type`, `excluded_finding_categories`,
`safe_harbor_stated`, `disclosure_embargo_days`), and `eligibility_filter.py` is the new skill
that actually enforces it — killing low-value findings before report-writing time, and queuing
resolved findings for bypass retests (a fresh bounty, not a duplicate). See prompt rules 9–10 in
`ORCHESTRATOR_SYSTEM_PROMPT` and the eligibility/retest rules in `VULN_AGENT_PROMPT`.

## Where we actually are

Phase 0 and Phase 1 are both done and verified as of 2026-07-16 (session 2), including a real
end-to-end run against a live LLM. Phase 2 is 13/37 checklist items done as of 2026-07-19
(session 3) — `run_subfinder`, `run_amass`, `run_httpx`, `run_naabu`, `run_nmap`, `run_dnsx`,
`run_tlsx` (all in `tools/recon.py`), and `run_gau` + `run_waybackurls` + `run_katana` (new
`tools/url_harvest.py`) are all built, registered, and verified live (see "Phase 2 kickoff" and
"Session 3 summary" above for the real bugs found and fixed getting each working, including a
genuine scope-safety bug in katana's default crawl scope). `tools/recon.py` only needs
`run_gowitness` left, blocked on a missing Chrome/Chromium binary (fixed in
`scripts/phase0_setup.sh`, needs the user to run it); `tools/url_harvest.py` needs `hakrawler`/
`gf`/`paramspider`; `tools/scanner.py`/`tools/vuln_specific.py`/`tools/secrets.py`+`cloud.py`+
`api.py` are untouched.
Phase 3's skills layer (built session 1) is no longer entirely ahead of Phase 2, just mostly
ahead. The scope-fabrication safety gap (open since session 2) is now closed and verified live —
see "Scope-fabrication gap — CLOSED" under "Session 3 summary" above. There is no known open
safety gap as of this writing.

**Environment (Phase 0) — done as of 2026-07-16 (session 2):**
- `/home/singh/bug-bounty-agent` is **still not a git repo** — explicitly deferred by the user
  this session, not an oversight
- `.venv` exists, `pip install -r requirements.txt` succeeded (Python 3.14, since this Ubuntu
  26.04 box has no `python3.11` package) — see session 2 summary above
- Security tools: **on PATH and verified** — `subfinder`, `httpx`, `nuclei`, `ffuf`, `nmap`,
  `sqlmap`, `dalfox`, `go` confirmed via `which`; the rest of `scripts/phase0_setup.sh`'s ~23
  Go tools + pipx tools + git-cloned tools ran too (a couple of pipx package-name mismatches —
  `paramspider`/`corsy`/`cloud_enum` aren't real PyPI packages — got fixed mid-script and moved
  to the git-clone section instead)
- Ollama: **reachable and verified live** — reused the user's existing Windows install rather
  than installing a fresh copy in WSL2. See "Live Ollama setup" above for exactly how, including
  the gateway-IP fragility caveat
- The Python package skeleton from session 1 (folders, `__init__.py`s, `.env.example`,
  `.gitignore`, `requirements.txt`) is unchanged, now with Phase 1's `agent/*.py` and `main.py`
  filled in on top of it

**What that means:** the code below marked "verified" in the per-file table has actually been
run and checked this session. Anything still marked "unverified" genuinely hasn't — most
commonly because it needs a live Ollama, which isn't up yet.

## What's actually built (code)

| File | Status | Notes |
|---|---|---|
| `config/settings.py` | done | Pydantic `Settings`, loads `.env`, sane defaults. `OLLAMA_NUM_CTX` (default 8192) added this session — see "Phase 2 kickoff" |
| `config/prompts.py` | done | All 4 prompts: Orchestrator (11 rules now — scope, policy, safe-harbor/embargo, VDP-warning, confidence-scoring pointers, plus a new no-fabricated-scope rule this session that testing showed doesn't fully work yet, see "Phase 2 kickoff"), Recon (freshness/retest-queue bias), Vuln (business-logic + eligibility + retest pointers), Report |
| `skills/scope_parser.py` | done | `ScopePolicy` (+ `payout_tiers`, `program_type`, `excluded_finding_categories`) + `parse_scope()` (heuristic HackerOne/Bugcrowd text, payout, program-type, and won't-fix-category parser, fixed for same-line marker misclassification — see "check_scope reliability" above) + `check_scope` tool + `parse_scope_policy` tool (exposes `parse_scope()` to the model directly) + `looks_like_scope_text()` (**new** session 3 — marker+domain-count heuristic that powers `agent/graph.py`'s scope-fabrication gate, see "Scope-fabrication gap — CLOSED") |
| `skills/policy_compliance.py` | done | `check_policy_compliance` tool — flags "no automated tools"/manual-only policies, prohibited techniques (DoS, social engineering, physical), `safe_harbor_stated`, and `disclosure_embargo_days`, all independent of domain scope |
| `skills/chain_analyzer.py` | done | `analyze_chains` tool, calls the LLM directly with a chain-pattern prompt, defensive JSON parsing. `num_ctx=settings.OLLAMA_NUM_CTX` added this session — it instantiates its own `ChatOllama` and would hit the same context-window wall on a large findings list |
| `skills/business_logic_mapper.py` | done | `map_business_logic` tool — reasons over a named multi-step flow (checkout/invite/reset) for sequence-only flaws (step-skip, param tampering across steps, coupon reuse, mid-flow IDOR, one-time-action races). Same `num_ctx` fix applied |
| `skills/poc_builder.py` | done | `build_poc` tool — templated PoCs for xss/sqli/ssrf, generic fallback for anything else |
| `skills/bypass.py` | done | `get_waf_bypasses` tool — encoding/case/comment/method-switch variants |
| `skills/payload_loader.py` | done | loads `config/payloads/*.yaml`, formats for prompt injection |
| `skills/diff_tracker.py` | done | `diff_against_last_scan` tool — snapshots assets + JS-content hashes per target under `sessions/<target>/snapshot.json`, surfaces only new/changed surface on repeat scans |
| `skills/confidence_scorer.py` | done | `score_finding_confidence` tool — actually implements `MIN_REPRO_COUNT`/`MIN_CONFIDENCE_TO_AUTOCONFIRM` from `settings.py`, which nothing enforced before this |
| `skills/roi_prioritizer.py` | done | `prioritize_targets` tool — ranks (asset, vuln_type) by expected value (base-rate prior × `ScopePolicy.payout_tiers`) |
| `skills/hitl_batcher.py` | done | `group_for_batch_approval` + `explain_action` — **not an LLM tool**, plain helpers consumed by `agent/hitl.py` |
| `skills/eligibility_filter.py` | done — **new** | `check_eligibility` — auto-rejects a finding matching a known won't-fix category unless `has_demonstrated_impact`; `queue_for_retest`/`get_retest_queue` — tracks resolved findings per target under `sessions/<target>/retest_queue.json` for bypass retests |
| `config/payloads/*.yaml` | done | all 6: xss, sqli, ssrf, lfi, ssti, open_redirect |
| `agent/orchestrator.py` | done | wires `ORCHESTRATOR_SYSTEM_PROMPT` + all 13 skills + all 37 Phase 2 tool wrappers into a LangGraph `create_react_agent` (`parse_scope_policy` → `check_scope` → `check_policy_compliance` first, `check_eligibility`/`queue_for_retest` right before the reporting skills). Fixed `state_modifier=` → `prompt=` (langgraph 1.2.9 renamed it), added `num_ctx`. **51 tools total as of session 4** (13 skills + 37 Phase 2 wrappers + `parse_scope_policy` etc. already counted in the 13) |
| `agent/state.py` | done — **new** | `Stage` enum + `HuntState`/`ActionPlan` TypedDicts, plus `messages`/`step_count` fields added for the multi-step planner rewrite — the state schema `agent/graph.py` and `agent/planner.py` share |
| `agent/planner.py` | done, **verified live** | `plan_step(messages)` — `llm.bind_tools(ALL_TOOLS)`, reads `response.tool_calls`, returns `(plan, ai_message)` or `(None, ai_message)` once the model has no more tool calls; raises `PlanParseError` if it detects a malformed pseudo-tool-call in plain text instead (added this round — see "Phase 2 kickoff"). Rewritten three times total this session: free-hand JSON → `bind_tools` → multi-step `plan_step()` → malformed-call detection |
| `agent/risk.py` | done | `risk_level_for(action_name)` — static per-tool risk table, deliberately not trusted to the LLM, every one of the 51 registered tools has an explicit entry (verified live — zero fall through to the HIGH default). Notably **HIGH**: `run_sqlmap`/`run_ghauri` (real SQLi testing, hardcoded detect-only but still HIGH) and `run_kiterunner` (no rate-limit flag exists at all, confirmed live ramping to 7-8k req/s — a structural conflict with this project's 10 req/s policy) |
| `agent/hitl.py` | done — **new**, verified | `request_approval()` (LOW auto/MEDIUM approve-reject-modify/HIGH explicit-yes, rich coloring) + `request_batch_approval()` (uses `skills/hitl_batcher.py`). Verified via direct node tests for all three risk levels. Phase 6 (session 7): refactored into a pluggable, **thread-local** `ApprovalBackend` (`ConsoleApprovalBackend` = the original behavior, extracted unchanged) via `set_approval_backend()`/`get_approval_backend()` — `request_approval`/`request_batch_approval` are now thin delegating wrappers. Verified live that concurrent threads never cross-resolve each other's pending approval, and that `main.py`'s CLI path is byte-for-byte unaffected |
| `agent/web_hitl.py` | done, **verified live** — **new** | Phase 6 (session 7): `HuntSession` (thread-safe shared state: activity log/findings/status/pending approval) + `WebApprovalBackend` (blocks on a `threading.Event` instead of stdin) + `resolve_pending()` (called from a UI button-click thread to unblock the pipeline thread). Verified live with real concurrent threads, including the two-session no-cross-talk guarantee |
| `ui/app.py` | done, **verified live** — **new** | Phase 6 (session 7): Gradio Blocks web console, three tabs (Recon/Vuln Assessment/NL Command) sharing one activity log/pending-approval panel/findings table, driven by a `gr.Timer` polling each hunt's `HuntSession`. Every Start/Resume button spawns a background thread calling `build_*graph().stream()` directly rather than the pipelines' own blocking `run_*()`/`resume_*()`. Verified two ways: function-level (mocked tools) through a full recon pipeline + a mid-run reject, and a REAL Gradio server driven via `gradio_client` over actual HTTP end-to-end. Phase 8 (session 7, continued): Report section wired for real — "Generate Report Draft" fills an editable textbox, a separate "Export" button writes it |
| `skills/report_generator.py` | done, **verified live** — **new** | Phase 8 (session 7, continued a third time): `calculate_cvss()` (official CVSS 3.1 formula, verified against 4 known-correct reference vectors before anything was built on it), `generate_report_narrative()` (the one LLM-driven piece, using the already-existing `REPORT_AGENT_PROMPT`), static remediation lookup, `render_report()`/`export_report()` (real `.md`+`.pdf` output, PDF via a deliberately scoped-down Markdown→reportlab renderer), and the `generate_report` tool |
| `config/report_templates.py` | done — **new** | Phase 8 (session 7, continued a third time): 3 Jinja2 template strings (HackerOne/Bugcrowd/Immunefi) — best-effort structural approximations of each platform's documented submission format, not a literal scrape of any live custom form (documented as such). Verified live they genuinely differ in section structure, not just labels |
| `agent/graph.py` | done, **verified live** | The LangGraph `StateGraph`: `plan → awaiting_human → execute → plan → ...`, `MAX_STEPS = 6` bound, `report`/`error` sinks, modify appends the human's note and loops back to `plan`. `node_execute` invokes tools via `asyncio.run(tool.ainvoke(...))` instead of `tool.invoke(...)` (async-only tools couldn't run at all before this fix). Verified live end-to-end with `run_subfinder` chained recursively across 6 steps to `MAX_STEPS`, plus the `parse_scope_policy` → `check_scope` chain, no regressions. `node_plan()` now also refuses to run `parse_scope_policy`/`check_scope`/`check_policy_compliance` at all unless `_human_provided_scope_text()` finds real scope-page content somewhere in the conversation (**new** session 3 — the scope-fabrication gate, routes straight to `Stage.ERROR` before any HITL prompt; see "Scope-fabrication gap — CLOSED") |
| `tools/base.py` | done, **verified live** | `ToolResult`/`Finding` (pydantic, not dataclass — matches every other structured return in this codebase) + async `run_tool()` subprocess helper: binary-not-on-PATH check, timeout with kill, non-zero-exit and launch-failure handling, all returned as an `error` string rather than raised. Binary resolution checks `~/go/bin/<tool>` before `shutil.which()` (fixes the `httpx` PyPI-vs-Go-binary collision at the shared level so every wrapper benefits). Gained an optional `stdin_input` parameter this session (needed by `run_waybackurls` — that tool ignores a positional/flag domain entirely and only reads stdin); backward compatible, defaults to `None` (unchanged inherit behavior) |
| `tools/recon.py` | done, **verified live** | `run_subfinder` (session 2) + `run_amass` + `run_httpx` + `run_naabu` + `run_nmap` + `run_dnsx` + `run_tlsx` (session 3, **new**) — see "Phase 2 kickoff" and "Session 3 summary" above for the bugs found getting each working. Only `run_gowitness` left in this file, blocked on a missing Chrome/Chromium binary (fixed in `scripts/phase0_setup.sh`, needs the user to run it) |
| `tools/url_harvest.py` | **done**, verified live | `run_gau` + `run_waybackurls` + `run_katana` + `run_hakrawler` + `run_gf` + `run_paramspider` (**new** session 4, completes this file). See "Session 3 summary" for the gau timeout/partial-output lesson, waybackurls' worse-than-amass flaky-empty-result caveat, and katana's default-scope-too-permissive safety bug; "Session 4 summary" for hakrawler's own scope-safety fix (`-i`, not documented as a host-scope flag), gf's pattern-file blocker (fixed directly), and paramspider's `cwd=` quirk (writes a stray `results/` dir relative to cwd — `run_tool()` gained a `cwd` param for this) |
| `tools/scanner.py` | **done**, verified live — **new** | `run_nuclei`/`run_nikto`/`run_wapiti`/`run_corsy`/`run_smuggler`/`run_testssl`/`run_wpscan`, all MEDIUM. See "Session 4 summary" — wapiti's unsafe defaults, corsy's isatty hang, smuggler's 300s-for-a-real-run timing, wpscan's Ruby gem bin path |
| `tools/vuln_specific.py` | **done**, verified live — **new** | `run_dalfox`/`run_kxss`/`run_xsstrike`/`run_sqlmap`/`run_ghauri`/`run_subjack`/`run_subzy`. sqlmap/ghauri are **HIGH**, hardcoded to detect-only flags with no passthrough; the rest MEDIUM. XSStrike needed two real workarounds (`--json` means something else entirely; an interactive prompt crashes without `stdin_input`) |
| `tools/secrets.py` | **done**, verified live — **new** | `run_trufflehog` (MEDIUM, always `--no-verification`) + `run_gitleaks` (**LOW** — zero network, scans an already-local path) + `run_secretfinder` (MEDIUM). All three partially redact discovered secret values before putting them in `Finding.detail` — a deliberate policy not applied anywhere else in this codebase, see the module's own docstring for why |
| `tools/cloud.py` | **done**, verified live — **new** | `run_s3scanner` (MEDIUM, never `--dangerous`) + `run_cloud_enum` (MEDIUM; fixed a real packaging bug in its pip-editable install, ships a small default mutation list instead of the vendored one that exceeded 300s live) |
| `tools/api.py` | **done**, verified live — **new** | `run_kiterunner` (**HIGH** — no rate-limit flag at all) + `run_arjun` + `run_ffuf` (both MEDIUM) + `interactsh_start`/`interactsh_poll`/`interactsh_stop` (all LOW — the always-on OOB service, architecturally different from every bounded-call wrapper elsewhere: a detached background process plus a small `sessions/_interactsh/<id>.json` state file, not a single `ToolResult`-returning call) |
| `agent/session.py` | done | `save_checkpoint()`/`load_latest()`/`list_checkpoints()` — JSON under `sessions/<target>/`. Structurally verified via `main.py`'s import and live runs; not yet exercised for actual resume |
| `main.py` | done, **verified live** | Terminal entrypoint: pings Ollama first (clean exit if down, verified both ways), prints "Agent ready", command loop → `graph.invoke()` → status table → checkpoint save. Ran a full real command end-to-end against the live model |
| `scripts/phase0_setup.sh` | done, **run successfully** | Manual (non-sudo-for-Claude) install script: apt base packages, Go, all `go install` tool wrappers, trufflehog/gitleaks installers, nuclei templates, pipx tools, no-package git clones. Fixed mid-run: `seclists` isn't an apt package (moved to snap), `paramspider`/`corsy`/`cloud_enum` aren't real PyPI packages (moved to git-clone + a dedicated `~/tools/.venv-scripts` venv, since Ubuntu 26.04 blocks bare `pip install` outside a venv) |
| `scripts/install_ollama.sh` | done, **not run** | Installs + starts Ollama inside WSL2 directly (fixed a missing-`zstd` prerequisite). Not the path actually taken — see "Live Ollama setup" above — kept as a fallback for a fully self-contained install |
| `agent/recon_pipeline.py` | done, **verified live** | Phase 4 (session 6): 8-stage fixed LangGraph (`subfinder`→`httpx`→`ports`→`crawl`→`params`→`dirs`→`enrichment`→`aggregate`), same propose→gate→execute triad as `agent/graph.py`. See "Session 6 summary" for the finding-ID/`node_done` bugs found and fixed |
| `agent/memory.py` | done, **verified live** | Phase 4 (session 6): ChromaDB `save_findings_to_memory`/`query_similar_findings` (raw `findings` collection). Session 7 added `save_confirmed_findings_to_memory` — a SEPARATE `confirmed_findings` collection for HITL-approved findings only, called from `agent/vuln_pipeline.py`'s `finalize` stage. Session 7 continued: fixed a real caching bug in `_get_client()` — it never noticed `settings.SESSIONS_DIR` changing within a process, so a second run against a different SESSIONS_DIR kept writing to the first run's stale path ("readonly database" error); now rebuilds when the path changes. Session 7 continued a third time (Phase 8): added `get_confirmed_findings()` (exact metadata-filtered fetch for report generation, not semantic search) and started storing `detail` as its own metadata field so it round-trips losslessly |
| `agent/vuln_pipeline.py` | done, **verified live** — **new** | Phase 5 (session 7): originally an 8-stage fixed LangGraph (`tech_profile`→`targeted_scan`→`graphql_probe`→`assess`→`chain`→`business_logic_hints`→`gate`→`finalize`), consuming a prior recon checkpoint's surface via `load_recon_surface()`. Session 7 continued: grew to 10 stages, inserting `xss_probe` (kxss+dalfox, conditionally retries WAF-bypass variants via its own NESTED HIGH-risk approval) and `auth_probe` (credentialed check_idor/check_jwt_weaknesses/map_auth_flow, a clean no-op without a supplied `auth_token`) between `targeted_scan` and `graphql_probe`. The `gate` stage is architecturally distinct from every other propose/gate/execute stage in this codebase (per-finding, not per-stage, approval) — see its own module docstring and "Session 7 summary"/"Session 7, continued" above |
| `skills/vuln_assessor.py` | done, **verified live** — **new** | Phase 5 (session 7): `assess_findings` — LLM batch false-positive/confidence triage, deliberately distinct from `skills/confidence_scorer.py`'s per-request statistical scorer (see that module's own docstring for the distinction). Verified against a real Ollama call, not just mocked |
| `skills/waf_bypass_prober.py` | done, **verified live** — **new** | Phase 5 (session 7, continued): `probe_waf_bypass` — actually SENDS `skills/bypass.py`'s `get_waf_bypasses` variants via `tools/http_client.py`'s `send_request`, closing the loop that skill deliberately leaves open. Verified against a REAL local HTTP server simulating a naive WAF filter, not mocked — genuinely detected a block and found a working bypass variant |

**Deviation from the plan:** the plan's Phase 3 section says skills live under `config/skills/`.
The actual code puts them at top-level `skills/` instead (`config/payloads/` did follow the
plan). Don't "fix" this without checking — `agent/orchestrator.py` already imports from
`skills.*`, so moving them is a real refactor, not a typo fix.

## What's not built yet

- **Phase 1:** fully done and verified live, including the LLM planner node.
- **Phase 2 (tool wrappers): COMPLETE as of session 4 (2026-07-19)** — 37/37 checklist items
  done, 51 tools total registered in `ALL_TOOLS`, every one live-verified and classified in
  `agent/risk.py`. The only unbuilt wrapper from the original list is `run_gowitness`
  (`tools/recon.py`), blocked on a missing Chrome/Chromium binary — needs the user to run
  `scripts/phase0_setup.sh` (see "`run_gowitness` — blocked" above); everything else across
  `tools/recon.py`, `tools/url_harvest.py`, `tools/scanner.py`, `tools/vuln_specific.py`,
  `tools/secrets.py`, `tools/cloud.py`, and `tools/api.py` is done. See "Session 4 summary" for
  the full list of real bugs/quirks found getting each one working — recurring lessons worth
  keeping in mind for Phase 3+ work that touches these tools:
  - **Never trust a tool's own `-h`/`--help` text, or even its documented "safe" bundle, to
    describe what it actually does** — confirmed repeatedly: `wapiti`'s `common` module bundle
    quietly includes `exec`/`upload`/an external OOB callback; `hakrawler`'s `-i` ("only crawl
    inside path") is actually the host-scope restriction; `cloud_enum`'s pip-editable install
    silently breaks its own documented default mutation-file path; `kiterunner`'s truncation
    syntax from its own `--help` text ("apiroutes-260227;20000") is rejected by the installed
    version. Verify live with a controlled test before trusting any of it, exactly like
    sessions 3-4 did for every wrapper.
  - **A tool CLI can be installed and runnable but still non-functional** without a step beyond
    the binary itself — `gf` needed pattern files (`~/.gf/*.json`) cloned separately; several
    git-cloned Python tools (XSStrike, Corsy, smuggler, SecretFinder, ghauri, paramspider,
    cloud_enum) needed their own `pip install` into a dedicated `~/tools/.venv-scripts` venv
    before they'd even import their own dependencies. Check for this before assuming a
    "not found" or crash means a code bug in the wrapper.
  - **A tool's own default safety posture is not this project's default safety posture.**
    sqlmap/ghauri (SQL injection) are hardcoded to `--batch --level 1 --risk 1` with NO
    passthrough for `--dump`/`--os-shell`/any exfiltration flag, classified HIGH regardless of
    "detect vs exploit mode" framing. `kiterunner` has no rate-limit flag at all — a genuine,
    unresolved structural conflict with `ORCHESTRATOR_SYSTEM_PROMPT` rule 4 that's flagged, not
    silently ignored, via a HIGH classification. Secret-scanning wrappers
    (`run_trufflehog`/`run_gitleaks`/`run_secretfinder`) partially redact discovered secret
    values before they land in `Finding.detail` — the only wrappers in this codebase that do,
    since those values get persisted into `sessions/<target>/*.json` checkpoints.
- **Phase 3: COMPLETE as of session 5 (2026-07-22)** — Tier 2 (`tech_analyzer.py`,
  `graphql.py`, `auth_mapper.py`) and Tier 3 (CVE lookup, Shodan/Censys query builder, nuclei
  template selector, Hacktivity duplicate checker) all built and live-verified; `agent/
  orchestrator.py` imports cleanly with 61 tools. Two items are deliberately reduced in scope
  from the plan's literal wording, not partial/broken — see "Same-session continuation" under
  "Session 5 summary" above for why: the Shodan/Censys builder never calls either API (no
  credentials configured, both need a paid plan — it only builds query strings), and the
  Hacktivity checker returns a search link for a human to check manually rather than an
  automated scraper (verified live that HackerOne's Hacktivity frontend can't be reliably
  scraped — client-rendered SPA, GraphQL introspection disabled in production).
- **Phase 4: COMPLETE as of session 6 (2026-07-22)** — `agent/recon_pipeline.py` (dedicated
  LangGraph pipeline, 8 fixed stages, propose→gate→execute per stage), `agent/memory.py`
  (ChromaDB), `main.py`'s `"recon <target>"`/`"resume <target>"` commands, and dedup via
  `diff_against_last_scan`, all live-verified including two real bugs found and fixed (a
  finding-ID hash collision in `agent/memory.py`, and a resume-after-reject bug in
  `node_done`) — see "Session 6 summary" above. `agent/orchestrator.py` imports cleanly with 62
  tools. Not literally full-scale live-tested (a real multi-host run through `naabu`/`ffuf` could
  take much longer than one verification pass justifies) — mechanics verified via a mocked run,
  real-tool integration verified via a `scanme.nmap.org` smoke test of the `subfinder`/`httpx`
  stages specifically, per that section's own account of what was and wasn't covered.
- **Phase 5: FULLY COMPLETE as of session 7 (2026-07-24)** — `agent/vuln_pipeline.py` (a third
  dedicated LangGraph pipeline, consuming a prior recon run's `live_hosts`/`js_urls`/
  `all_findings` rather than a bare domain, now 10 stages), the LLM tech→vuln-checklist planner,
  `skills/vuln_assessor.py` (`assess_findings` — false-positive/confidence triage), the
  per-finding HITL `gate` stage, `check_eligibility`→`build_poc`→confirmed-findings-memory
  wiring in `finalize`, `main.py`'s `"assess <target>"`/`"resume assess <target>"` commands, the
  `xss_probe` stage + new `skills/waf_bypass_prober.py` (WAF-bypass retry loop), and the
  `auth_probe` stage (credentialed `check_idor`/`check_jwt_weaknesses`/`map_auth_flow`, gated on
  an optional `auth_token`) are ALL live-verified — see "Session 7 summary" and "Session 7,
  continued" above for the full account, including a real-Ollama pass that confirmed the
  assessor genuinely discriminates evidence quality, and a REAL local-HTTP-server test that
  confirmed `probe_waf_bypass` actually detects a filter and finds a working bypass variant.
  `agent/orchestrator.py` imports cleanly with 64 tools. Every Phase 5 checklist item in
  docs/DEVELOPMENT_PLAN.md is now checked off — nothing deliberately reduced in scope this time,
  unlike Phase 3's Shodan/Hacktivity items.
- **Phase 6: COMPLETE as of session 7 (2026-07-24)** — `ui/app.py` (Gradio Blocks, three tabs:
  Recon/Vuln Assessment/Natural-Language Command, sharing one activity log, pending-approval
  panel, and findings table), `agent/web_hitl.py` (`HuntSession` + `WebApprovalBackend`), and a
  refactor of `agent/hitl.py` for a pluggable, thread-local `ApprovalBackend` — all live-verified,
  including a REAL Gradio server driven end-to-end via `gradio_client` over actual HTTP (Start →
  repeated Poll/Approve → finished pipeline), not just function-level calls. The plan's literal
  "hand-rolled FastAPI WebSocket endpoint" item was deliberately reduced in scope (Gradio's own
  live-update transport used instead, `gr.Timer` polling plays that role) and documented as such
  in `docs/DEVELOPMENT_PLAN.md` — see "Session 7, continued again" above for the full account.
- **Phase 8: COMPLETE as of session 7 (2026-07-24)** — `skills/report_generator.py` (CVSS 3.1
  calculator verified against 4 known-correct reference vectors, LLM narrative via the
  already-existing `REPORT_AGENT_PROMPT`, static remediation lookup), `config/report_templates.py`
  (HackerOne/Bugcrowd/Immunefi Jinja2 templates, verified to genuinely differ in structure, not
  just labels), `agent/memory.py`'s new `get_confirmed_findings()` (exact metadata-filtered fetch,
  not semantic search — also fixed `detail` to round-trip losslessly via its own metadata field),
  `main.py`'s `"report <target> [platform]"` command, and `ui/app.py`'s Report section
  (generate-draft → human-editable textbox → separate Export button, satisfying the plan's
  explicit "human review + edit step... before export" requirement) — all live-verified,
  including real `.md`+`.pdf` file output with the PDF's `%PDF-` header confirmed genuine. See
  "Session 7, continued a third time" above.
- **Phase 7**'s own scope was already mostly delivered by Phase 4 (ChromaDB, resume, dedup) —
  nothing further currently planned there beyond what exists.
- **Phase 9 (CI / Polish):** not started.

See "Immediate next steps for whoever picks this up" near the top of this file for the ordered
next-actions list — kept in one place rather than duplicated here.

## Conventions to keep

- Every skill/tool wrapper returns the same structured shape (`ToolResult`/`Finding` per the
  plan) so the LLM calls skills and tool wrappers identically — already followed by every
  skill, keep doing it.
- Safety rules live only in `config/prompts.py` as constants — don't inline prompt text
  elsewhere.
- `parse_scope_policy`, then `check_scope`, then `check_policy_compliance` must stay first (in
  that order) in `ALL_TOOLS` in `agent/orchestrator.py` — they're the pre-flight gates every
  other action depends on. `parse_scope_policy` was added before `check_scope` this session
  specifically so the model calls it first and pipes its output straight into `check_scope`
  rather than freehanding a `ScopePolicy`.
- Every tool added to `ALL_TOOLS` needs an entry in `agent/risk.py`'s `_RISK_BY_TOOL` table too
  — an unclassified tool defaults to HIGH (fail closed), which will surprise whoever adds a new
  skill and finds it always demands an explicit "yes" until they add the entry.
- Not every file in `skills/` is an LLM tool. `skills/hitl_batcher.py` has no `@tool` functions
  on purpose — it's a plain-function helper consumed by `agent/hitl.py`, and must never be
  added to `ALL_TOOLS`. Check a new skill file's own docstring before assuming it belongs in
  that list.
- `agent/graph.py`'s `execute` node looks up tools by name in `ALL_TOOLS` (imported from
  `agent/orchestrator.py`) — a new skill/tool only becomes reachable from the terminal loop
  once it's added to `ALL_TOOLS`, registering it isn't enough on its own if `graph.py`'s import
  is ever changed to something more selective.
- `sudo` cannot be run by Claude in this environment — no TTY, confirmed by direct test this
  session (`sudo -v` → "a terminal is required to authenticate"). Any future sudo-gated step
  goes into a `scripts/*.sh` file for the user to run manually, never attempted directly.
- Any tool wrapper can be `async def` (Phase 2's `tools/*.py` all will be, since `run_tool()` is
  async) — `agent/graph.py`'s `node_execute` calls every tool via
  `asyncio.run(tool.ainvoke(...))`, which works for both sync and async tools uniformly. Don't
  "simplify" this back to `tool.invoke(...)` — that breaks every async-only tool with
  `"StructuredTool does not support sync invocation"`, confirmed live this session.
- Every `ChatOllama(...)` instantiation must pass `num_ctx=settings.OLLAMA_NUM_CTX`. Ollama's
  runtime context window defaults small regardless of what the model itself supports, and this
  bit a real live run (see "Phase 2 kickoff"). Four call sites exist as of this writing
  (`agent/planner.py`, `agent/orchestrator.py`, `skills/chain_analyzer.py`,
  `skills/business_logic_mapper.py`) — a fifth added later needs this too.
- Scope text must come from the human, never from the model's own training knowledge, even for
  a well-known program. This is now structurally enforced, NOT just a prompt rule (a prompt
  rule alone was tried in session 2 and confirmed insufficient) — `agent/graph.py`'s
  `node_plan()` refuses to run `parse_scope_policy`/`check_scope`/`check_policy_compliance` at
  all unless `skills/scope_parser.py`'s `looks_like_scope_text()` finds real scope-page content
  in the conversation. See "Scope-fabrication gap — CLOSED" under "Session 3 summary." Don't
  remove this gate to "simplify" the graph — it's the only thing standing between the model and
  silently fabricating scope for a target it thinks it recognizes.
- A security-tool binary can be shadowed by a same-named PyPI package's console script once the
  venv is active (`.venv/bin` beats `~/go/bin` on PATH) — confirmed live with `httpx` (see
  "Session 3 summary"). `tools/base.py`'s `run_tool()` now checks `~/go/bin/<tool>` first for
  this reason; don't bypass it with a raw `shutil.which()` call in a new wrapper. When adding a
  wrapper for a tool whose name might collide with something pip-installable, verify which
  binary actually gets picked up (`python3 -c "from tools.base import _resolve_binary; print(_resolve_binary('toolname'))"`)
  before trusting the output.
- Not every CLI tool takes its target as a flag or positional arg — `waybackurls` reads ONLY
  from stdin and hangs indefinitely if given a domain any other way (confirmed live). Use
  `run_tool(..., stdin_input=f"{domain}\n")` for tools like this rather than assuming the
  ProjectDiscovery flag/positional-arg convention every other wrapper so far has followed.
- Not every wrapper's "no error, empty `parsed`" result is trustworthy. `run_waybackurls`'s
  underlying data source (the Wayback CDX API) has been observed to intermittently return
  empty or partial results with no error surfaced anywhere — confirmed via three live runs
  against the identical domain returning wildly different counts. If a new wrapper's tool is
  known or found to behave this way, say so explicitly and prominently in its docstring; don't
  let it silently inherit the "empty means nothing there" assumption that holds for every other
  wrapper in this codebase.
- `run_tool()` now preserves partial `stdout`/`stderr` when a subprocess times out (fixed
  2026-07-19 — was returning empty strings before, discarding everything even when a slow tool
  had produced real output; see "`run_tool()` fixed to preserve partial output on timeout" under
  "Session 3 summary"). `error` is still always set on a timeout regardless — never treat a
  timeout as a clean success just because some data came back. Every wrapper MUST use
  `raw_output=stdout or stderr` (not `stdout if not error else stderr`) and gate findings-parsing
  on `if stdout:` (not `if not error:`), or the wrapper layer will keep throwing away the
  partial data `run_tool()` now makes available. This doesn't help tools whose results live in a
  file rather than stdout (`run_amass`'s `-oA`) — a kill still loses everything for those, since
  the fix only covers stream draining, not file flushing.
- A crawler's default scope restriction is not automatically as strict as it sounds. katana's
  default `-fs rdn` ("root domain name") sent a REAL request to `nmap.org` while crawling
  `scanme.nmap.org` — a genuine scope violation, since a real bug-bounty program authorizing one
  subdomain does not authorize its root domain too. Confirmed live: this was verified NOT a
  false alarm by checking each discovered host for a populated `response` field (a real fetch)
  versus a bare discovered link with no `response` (harmless, never fetched) — `run_katana`
  fixes this with `-fs fqdn` (exact host match). Any future wrapper for a tool that crawls or
  follows links (not just probes a fixed list of targets) needs this same check before being
  trusted: verify which hosts actually received traffic, don't assume the tool's own scope
  defaults match what "in scope" means for a bug-bounty program.
- A crawler's `-h`/`--help` text is not a reliable guide to which flag actually restricts
  request scope to the target host — confirmed with `hakrawler` (session 4): its `-i` flag is
  documented as "only crawl inside path," which reads like a URL-path filter, but a controlled
  test (two local HTTP servers, a seed/"target" page linking to an unrelated "external" one,
  then checking the external server's own access log) proved `-i` is actually what keeps every
  real request confined to the seed host — without it, hakrawler fetches any discovered link
  regardless of host, confirmed via a real GET landing on the unrelated server. `run_hakrawler`
  passes `-i` unconditionally, never caller-optional. Any future crawler/spider wrapper needs
  this same local-server test before trusting a flag's help text about scope, in either
  direction — a flag can sound stricter than it is (`run_katana`'s original `-fs rdn`) or sound
  unrelated to scope while actually being the scope gate (`run_hakrawler`'s `-i`).
