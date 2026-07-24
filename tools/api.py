"""API/parameter/route discovery tool wrappers, plus the interactsh OOB service — Phase 2.

Each wrapper returns the same ToolResult shape as every skills/*.py tool (see tools/base.py),
so the LLM calls tool wrappers and skills identically — EXCEPT the three `interactsh_*`
functions at the bottom of this file, which are a deliberately different shape (see their own
module-level explanation) because interactsh-client is not a bounded request/response tool like
everything else in Phase 2 — it's a long-running background process, exactly as
docs/DEVELOPMENT_PLAN.md's Phase 2 checklist describes it ("[CRITICAL]... always-on background
service").
"""
import asyncio
import json
import os
import re
import signal
import time
from pathlib import Path

from langchain_core.tools import tool

from config.settings import settings
from tools.base import Finding, ToolResult, run_tool

_DEFAULT_FFUF_WORDLIST = "/snap/seclists/1214/Discovery/Web-Content/common.txt"
_INTERACTSH_STATE_DIR = Path(settings.SESSIONS_DIR) / "_interactsh"


@tool
async def run_kiterunner(target: str) -> dict:
    """Brute-force discover API routes on a target using kiterunner's real-world route corpus.

    HIGH risk — two compounding reasons, not just one:
    (1) The route corpus (`apiroutes-260227`, ~364,000 entries, sourced from real HTTP Archive
    API traffic) includes routes associated with arbitrary HTTP methods per its kitebuilder
    schema, not just GET — unlike a plain wordlist-based fuzzer, some of what it tries could be
    state-changing if a matching route happens to exist and accept it.
    (2) **kiterunner has NO rate-limiting flag at all** — confirmed via `scan --help`, only
    `-x`/`--max-connection-per-host` (concurrency, not requests/sec) and
    `-j`/`--max-parallel-hosts` exist. This is a structural conflict with
    `ORCHESTRATOR_SYSTEM_PROMPT` rule 4's 10 req/s cap that every other active wrapper in this
    codebase enforces via a real flag — there is no way to make this tool honor that policy.
    Confirmed live: a full run against a trivial, instantly-responding local test server ramped
    up to 7,000-8,000 requests/SECOND within a few seconds. Classified HIGH specifically so this
    always requires explicit human approval, not silently treated like run_ffuf/run_arjun's
    MEDIUM tier — a human approving this action should understand they're approving a
    volume/rate profile fundamentally different from everything else in this file.

    `-x`/`max-connection-per-host` is still capped at a conservative 10 (not kiterunner's own
    default of 3, but nowhere near what it's capable of) as a partial mitigation — this bounds
    concurrency, not overall request rate, so it does not substitute for real rate limiting.

    Always uses `-A apiroutes-260227` (the only wordlist alias available in this environment —
    confirmed via `kiterunner wordlist list`). Its documented inline-truncation syntax
    (`apiroutes-260227;20000` to use only the first N routes) was tried live and rejected by
    this installed version ("invalid names") — no smaller built-in alias exists as an
    alternative, so a full run is always what this wrapper does; there's no narrower default to
    fall back to the way run_nuclei/run_cloud_enum could.

    **Verified live 2026-07-19** against a local test server (not a real remote target — this
    tool's own volume made that an easy call): confirmed real `-A`/`-x`/`-j`/`-o json` flags,
    the preflight-scan-then-full-scan behavior, and the final summary line shape
    (`{"results": N, "duration": ..., "message": "scan complete"}`). Got `results: 0` against
    that test server — expected, not a wrapper bug: kiterunner does response-similarity
    filtering to suppress generic catch-all responses (the same status/body for every path,
    which is exactly what the trivial test server returned), so its own docstring-worthy
    per-route hit shape (not independently confirmed live) is expected to include route/method/
    status/content-length fields based on kiterunner's documented output.
    """
    args = ["scan", target, "-A", "apiroutes-260227", "-x", "10", "-j", "1", "-o", "json"]
    stdout, stderr, returncode, duration_s, error = await run_tool("kiterunner", args, timeout_s=300)

    findings = []
    if stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "route" not in record and "url" not in record:
                continue  # progress/summary log lines, not a discovered-route record
            findings.append(Finding(
                type="api_route",
                target=target,
                detail=str(record),
                severity="info",
                tool_source="kiterunner",
            ))

    result = ToolResult(
        tool="kiterunner",
        command_run="kiterunner " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_arjun(url: str) -> dict:
    """Discover hidden GET/POST parameters on a single URL via arjun's differential analysis.

    MEDIUM risk — sends many real requests directly to the target (parameter-name chunks
    tested in batches), non-destructive (arjun's default probe values are its own
    placeholder-like strings, not attacker payloads). Call check_scope first.

    **Verified live 2026-07-19** against a local test server with a real `q` parameter:
    confirmed arjun's own chunked-testing approach (splits its parameter-name wordlist into
    chunks, narrows down via response-length diffing) correctly identified `q` as a real
    parameter. JSON output shape (`-o <file>`) is a dict keyed by URL:
    `{url: {"headers": {...}, "method": "GET", "params": [...]}}` — a flat params list, not
    per-parameter detail objects.
    """
    out_path = f"/tmp/arjun_{abs(hash(url))}.json"
    args = ["-u", url, "-o", out_path]
    stdout, stderr, returncode, duration_s, error = await run_tool("arjun", args, timeout_s=90)

    findings = []
    try:
        with open(out_path) as f:
            data = json.load(f)
        for found_url, info in data.items():
            for param in info.get("params", []):
                findings.append(Finding(
                    type="hidden_parameter",
                    target=found_url,
                    detail=f"param={param} method={info.get('method', 'GET')}",
                    severity="info",
                    tool_source="arjun",
                ))
    except (FileNotFoundError, json.JSONDecodeError):
        pass  # no file means arjun found no parameters — not an error condition

    result = ToolResult(
        tool="arjun",
        command_run="arjun " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_ffuf(url: str, wordlist_path: str = _DEFAULT_FFUF_WORDLIST) -> dict:
    """Fuzz a single URL's FUZZ keyword position (directory/file discovery by default).

    MEDIUM risk — sends one real request per wordlist entry directly to the target. Call
    check_scope first. `url` must contain the literal `FUZZ` keyword at the position to fuzz
    (e.g. `http://target.com/FUZZ` for directory discovery); ffuf itself defines this
    convention, not this wrapper.

    Defaults `wordlist_path` to SecLists' `Discovery/Web-Content/common.txt` (4,749 entries,
    confirmed present on this system at `/snap/seclists/1214/...` — installed via snap per
    `scripts/phase0_setup.sh`, apt has no `seclists` package). Override for parameter fuzzing,
    subdomain fuzzing (via a `Host: FUZZ` header instead — not this wrapper's concern, the
    caller controls that through `url`/headers), or any other wordlist.

    Uses ffuf's own default match-code set (`200-299,301,302,307,401,403,405,500`) rather than
    `-mc all` — deliberately, so a target that returns a real 404 page (the common case) doesn't
    get every wordlist entry reported as a hit.

    **Verified live 2026-07-19** against a local test server (which happens to return 200 for
    every path — an unusually permissive case, but still confirms the wrapper's plumbing):
    confirmed real `-u`/`-w`/`-of json`/`-o` flags and JSON output shape — top-level `results`
    is a list of `{input, position, status, length, words, lines, content-type, url, host,
    duration}` dicts.
    """
    out_path = f"/tmp/ffuf_{abs(hash(url))}.json"
    args = [
        "-u", url, "-w", wordlist_path, "-of", "json", "-o", out_path, "-s",
        "-rate", str(settings.MAX_REQ_PER_SEC),
    ]
    stdout, stderr, returncode, duration_s, error = await run_tool("ffuf", args, timeout_s=180)

    findings = []
    try:
        with open(out_path) as f:
            data = json.load(f)
        for record in data.get("results", []):
            findings.append(Finding(
                type="fuzz_hit",
                target=record.get("url", url),
                detail=(
                    f"input={record.get('input', {})} status={record.get('status', '?')} "
                    f"length={record.get('length', '?')}"
                ),
                severity="info",
                tool_source="ffuf",
            ))
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    result = ToolResult(
        tool="ffuf",
        command_run="ffuf " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


# ---------------------------------------------------------------------------
# interactsh-client — always-on OOB (out-of-band) interaction service.
#
# Every other tool in this file (and every tool wrapper in tools/*.py) is a bounded
# request/response call: run_tool() launches a subprocess, waits up to timeout_s, and returns
# once it's done. interactsh-client is architecturally different — per
# docs/DEVELOPMENT_PLAN.md's own Phase 2 checklist, it needs to run as an "always-on
# background service" for the DURATION of a hunt, continuously listening for out-of-band
# callbacks (blind SSRF/XSS/XXE — cases where a vulnerability doesn't reflect anything in the
# direct HTTP response, the only proof it fired is a separate, later callback to a listener
# like this one). A single bounded run_tool() call can't model "start now, keep listening while
# other tools run, check back later, stop when done."
#
# So these three functions don't return a ToolResult at all (there's no single "duration" for
# an open-ended listener) — they manage a small persisted session instead: `start` launches the
# process DETACHED (not awaited — run_tool() would either time it out or block the whole hunt),
# captures the registered payload domain from its startup banner, and writes the process's PID
# plus its `-o` log file path to sessions/_interactsh/<id>.json (matching agent/session.py's
# own sessions/<target>/ convention, under a leading-underscore name so it can't collide with a
# real target). `poll` just reads that log file — the background process keeps appending to it
# on its own. `stop` sends SIGTERM to the stored PID. Verified live 2026-07-19: the banner
# ("[INF] Listing N payload for OOB Testing" followed by N `<id>.oast.<tld>` domain lines)
# takes noticeably longer than a typical wrapper's response (confirmed needing ~10-15s to
# register with a remote interactsh server, not instant) and is written to stdout even under
# `-json` mode — only actual CAPTURED interactions go to the `-json`-formatted `-o` file.
# ---------------------------------------------------------------------------

_DOMAIN_PATTERN = re.compile(r"^([a-z0-9]+\.oast\.\w+)$")


@tool
async def interactsh_start(session_id: str) -> dict:
    """Start a persistent interactsh listener and return its unique OOB callback domain(s).

    LOW risk — interactsh-client itself never sends any request to the target; it only
    registers with a public interactsh server and listens. The domain it returns becomes
    genuinely risk-relevant only once embedded in an actual payload delivered by some OTHER
    tool (e.g. an SSRF parameter value passed to run_ffuf/run_dalfox) — that delivery step is
    covered by whichever wrapper sends it, not by this one.

    `session_id` is any caller-chosen label (e.g. the target name) — used only to name the
    on-disk state file under `sessions/_interactsh/`, letting multiple independent listeners
    run concurrently without colliding.

    Returns the generated `*.oast.<tld>` domain as a Finding's `detail` — embed this directly
    into an SSRF/XXE/blind-injection payload elsewhere, then call `interactsh_poll` later to
    check whether anything called back to it.
    """
    _INTERACTSH_STATE_DIR.mkdir(parents=True, exist_ok=True)
    log_path = _INTERACTSH_STATE_DIR / f"{session_id}.jsonl"
    state_path = _INTERACTSH_STATE_DIR / f"{session_id}.state.json"
    banner_path = _INTERACTSH_STATE_DIR / f"{session_id}.banner.log"

    proc = await asyncio.create_subprocess_exec(
        "interactsh-client", "-n", "1", "-json", "-o", str(log_path),
        stdout=open(banner_path, "wb"), stderr=asyncio.subprocess.STDOUT,
    )

    domain = None
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        await asyncio.sleep(1)
        if banner_path.exists():
            text = banner_path.read_text(errors="replace")
            for line in text.splitlines():
                clean = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
                clean = re.sub(r"^\[INF\]\s*", "", clean)
                if _DOMAIN_PATTERN.match(clean):
                    domain = clean
                    break
        if domain:
            break

    state_path.write_text(json.dumps({"pid": proc.pid, "log_path": str(log_path), "domain": domain}))

    if domain is None:
        return ToolResult(
            tool="interactsh-client",
            command_run=f"interactsh-client -n 1 -json -o {log_path}",
            raw_output=banner_path.read_text(errors="replace") if banner_path.exists() else "",
            parsed=[],
            duration_s=20.0,
            error="interactsh-client did not register a payload domain within 20s",
        ).model_dump()

    return ToolResult(
        tool="interactsh-client",
        command_run=f"interactsh-client -n 1 -json -o {log_path}",
        raw_output=f"registered domain: {domain}",
        parsed=[Finding(
            type="interactsh_session_started",
            target=domain,
            detail=f"session_id={session_id} domain={domain} pid={proc.pid}",
            severity="info",
            tool_source="interactsh-client",
        )],
        duration_s=20.0,
        error=None,
    ).model_dump()


@tool
async def interactsh_poll(session_id: str) -> dict:
    """Check a running interactsh session's log for any out-of-band interactions captured so far.

    LOW risk — read-only, just reads the listener's own accumulated log file; no request is
    sent anywhere by this call.

    Call this after embedding `interactsh_start`'s returned domain into a payload delivered by
    another tool and giving the target time to (maybe) call back — a blind SSRF/XXE/injection
    only proves itself via a LATER, asynchronous callback, not the immediate HTTP response.
    """
    state_path = _INTERACTSH_STATE_DIR / f"{session_id}.state.json"
    if not state_path.exists():
        return ToolResult(
            tool="interactsh-client",
            command_run=f"interactsh_poll({session_id})",
            raw_output="",
            parsed=[],
            duration_s=0.0,
            error=f"no interactsh session found for session_id={session_id!r} — call interactsh_start first",
        ).model_dump()

    state = json.loads(state_path.read_text())
    log_path = Path(state["log_path"])

    findings = []
    raw = ""
    if log_path.exists():
        raw = log_path.read_text(errors="replace")
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append(Finding(
                type="oob_interaction",
                target=state.get("domain", session_id),
                detail=(
                    f"protocol={record.get('protocol', 'unknown')} "
                    f"remote-address={record.get('remote-address', 'unknown')} "
                    f"raw-request={str(record.get('raw-request', ''))[:200]}"
                ),
                severity="critical",  # a callback firing at all confirms a real blind vulnerability
                tool_source="interactsh-client",
            ))

    result = ToolResult(
        tool="interactsh-client",
        command_run=f"interactsh_poll({session_id})",
        raw_output=raw,
        parsed=findings,
        duration_s=0.0,
        error=None,
    )
    return result.model_dump()


@tool
async def interactsh_stop(session_id: str) -> dict:
    """Stop a running interactsh session and clean up its state.

    LOW risk — sends SIGTERM to a local process this project itself started; no target-facing
    action at all.
    """
    state_path = _INTERACTSH_STATE_DIR / f"{session_id}.state.json"
    if not state_path.exists():
        return ToolResult(
            tool="interactsh-client",
            command_run=f"interactsh_stop({session_id})",
            raw_output="",
            parsed=[],
            duration_s=0.0,
            error=f"no interactsh session found for session_id={session_id!r}",
        ).model_dump()

    state = json.loads(state_path.read_text())
    pid = state.get("pid")
    error = None
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            error = f"process {pid} was already gone"

    result = ToolResult(
        tool="interactsh-client",
        command_run=f"interactsh_stop({session_id})",
        raw_output=f"stopped pid={pid}",
        parsed=[],
        duration_s=0.0,
        error=error,
    )
    return result.model_dump()
