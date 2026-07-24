"""Uniform contract every Phase 2 tool wrapper returns.

Same shape as every skills/*.py tool's return value (see MEMORY.md
"Conventions to keep") so the LLM calls tool wrappers and skills identically.
Deviation from docs/DEVELOPMENT_PLAN.md: the plan calls these "dataclasses",
but every other structured return in this codebase (ScopePolicy, PoC,
ConfidenceScore, ...) is a pydantic BaseModel, not a stdlib dataclass — kept
that convention here instead of introducing a second one.
"""
import asyncio
import glob
import os
import shutil
import time
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field

DEFAULT_TIMEOUT_S = 120

# All of Phase 0's Go-installed security tools land in ~/go/bin (see
# scripts/phase0_setup.sh — hardcoded there for trufflehog/gitleaks too, not
# just Go's own default). Checked BEFORE shutil.which()'s normal PATH search
# because a same-named Python package can install a CLI script into
# .venv/bin, which sits earlier on PATH than ~/go/bin once the venv is
# active — verified live 2026-07-18: the `httpx` PyPI package (an HTTP
# client, pulled in as a dependency) installs its own `httpx` console
# script, which silently shadowed ProjectDiscovery's httpx and made
# run_httpx call the wrong binary entirely (wrong CLI, wrong flags, exit 2).
# Any other Go tool sharing a name with a Python package would hit the same
# collision, so this resolves at the shared run_tool() level, not per-wrapper.
_GO_BIN_DIR = Path(os.environ.get("GOBIN") or (Path.home() / "go" / "bin"))

# `gem install --user-install` (used for wpscan, session 4 — no sudo needed)
# puts binaries in a Ruby-version-specific directory, not on PATH and not
# predictable ahead of time (confirmed live: ruby 3.3.0 here landed it at
# ~/.local/share/gem/ruby/3.3.0/bin, but the version segment isn't something
# to hardcode). Globbed the same way as _GO_BIN_DIR is checked, so any future
# gem-installed tool benefits without a per-wrapper special case.
_RUBY_GEM_USER_BIN_GLOB = str(Path.home() / ".local" / "share" / "gem" / "ruby" / "*" / "bin")

# Shared location for git-cloned Python security tools with no console-script
# entry point (XSStrike, Corsy, smuggler, SecretFinder — see
# scripts/phase0_setup.sh's git-clone step). Each such tool's wrapper calls
# run_tool(PY_SCRIPTS_PYTHON, [str(PY_SCRIPTS_DIR / "<Tool>" / "<script>.py"), ...]).
# A bare `python3 script.py` invocation still finds each tool's own db/*.json
# files correctly even though cwd is this project's root, not the tool's own
# directory — verified live these scripts locate their data files via
# sys.path[0] (the directory of the script argument, which Python sets
# regardless of the caller's cwd), not the process's current working
# directory, so no cwd= plumbing was needed in run_tool() for this.
PY_SCRIPTS_PYTHON = str(Path.home() / "tools" / ".venv-scripts" / "bin" / "python3")
PY_SCRIPTS_DIR = Path.home() / "tools"


def _resolve_binary(tool: str) -> str | None:
    # Session 4: several Phase 2 tools are git-cloned Python scripts (XSStrike,
    # Corsy, smuggler, SecretFinder, ghauri's CLI, ...) run via a dedicated
    # interpreter (~/tools/.venv-scripts/bin/python3) rather than a bare command
    # name. A wrapper passes that interpreter's absolute path as `tool` directly
    # in that case — resolve it as-is rather than searching PATH for it.
    if os.path.isabs(tool) and os.path.isfile(tool) and os.access(tool, os.X_OK):
        return tool
    go_installed = _GO_BIN_DIR / tool
    if go_installed.is_file() and os.access(go_installed, os.X_OK):
        return str(go_installed)
    for gem_bin_dir in glob.glob(_RUBY_GEM_USER_BIN_GLOB):
        candidate = Path(gem_bin_dir) / tool
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return shutil.which(tool)


_TERMINATE_GRACE_S = 3  # seconds to let a tool exit cleanly after SIGTERM before SIGKILL


async def _drain_stream(stream: asyncio.StreamReader | None, chunks: list[bytes]) -> None:
    """Read a subprocess stream to EOF, accumulating into chunks as data arrives.

    Unlike proc.communicate() (which only hands back its buffered result on
    clean completion), this lets run_tool() keep whatever was read so far
    even if the process gets killed for running past timeout_s.
    """
    if stream is None:
        return
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        chunks.append(chunk)


class Finding(BaseModel):
    type: str
    target: str
    detail: str
    severity: str = "info"
    tool_source: str
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


class ToolResult(BaseModel):
    tool: str
    command_run: str
    raw_output: str
    parsed: list[Finding] = Field(default_factory=list)
    duration_s: float
    error: str | None = None


async def run_tool(
    tool: str, args: list[str], timeout_s: int = DEFAULT_TIMEOUT_S, stdin_input: str | None = None,
    cwd: str | None = None,
) -> tuple[str, str, int, float, str | None]:
    """Run a security-tool binary as a subprocess. Never raises.

    Returns (stdout, stderr, returncode, duration_s, error). error is set
    when the binary isn't on PATH, fails to launch, times out, or exits
    non-zero — callers build a ToolResult with that error rather than
    letting an exception propagate up into the HITL-gated graph
    (agent/graph.py's node_execute also catches exceptions defensively, but
    tool wrappers shouldn't rely on that as the only safety net).

    On a timeout, stdout/stderr are whatever was actually captured before
    the process was stopped, NOT empty strings — fixed 2026-07-19 (see
    MEMORY.md "run_tool() gained partial-output-on-timeout"). The previous
    implementation used proc.communicate(), which only returns its buffered
    result on clean completion; killing the process on timeout discarded
    everything read so far, even when run_gau/run_amass/run_waybackurls had
    real partial output sitting in the pipe. Streams are now drained
    incrementally as the process runs (see _drain_stream), so stopping the
    process only cuts off FUTURE output, not what's already been captured.
    `error` is still always set on a timeout, even when partial data comes
    back — a timeout is never silently treated as a clean, complete result;
    callers should treat timed-out stdout as possibly-truncated, not final.

    Tries SIGTERM (proc.terminate()) first, with a grace period before
    SIGKILL — gives a well-behaved tool the chance to flush any file-based
    output on its own terms rather than being cut off mid-write. (Not
    verified to actually help run_amass's -oA output specifically — that
    would need amass to handle SIGTERM by flushing, which hasn't been
    confirmed — but costs nothing for tools that don't.)

    stdin_input: passed to the process's stdin, then stdin is closed. Added
    for tools/url_harvest.py's run_waybackurls — verified live that
    waybackurls ignores a domain passed as a positional arg entirely and
    just hangs waiting on stdin instead, unlike every ProjectDiscovery tool
    wrapped so far (subfinder/httpx/naabu/etc. all take a flag or positional
    arg directly). Several other classic tomnomnom-style tools follow the
    same stdin-only convention (gf, qsreplace, anew), so this lives in the
    shared helper rather than being special-cased per wrapper.

    cwd: added for tools/url_harvest.py's run_paramspider — verified live it
    writes a `results/<domain>.txt` file relative to the process's current
    working directory (unlike XSStrike/Corsy, which locate their own db/*.json
    files via `sys.path[0]`, the script's own directory, regardless of cwd).
    Without this, every run_paramspider call would litter a `results/` folder
    into wherever this project's process happens to be running from. Pass a
    tempfile.TemporaryDirectory() and read the file back after, same pattern
    run_amass already uses for its `-oA` file output.
    """
    binary_path = _resolve_binary(tool)
    if binary_path is None:
        return "", "", -1, 0.0, f"{tool!r} not found on PATH — is Phase 0's tool install done?"

    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            binary_path, *args,
            stdin=asyncio.subprocess.PIPE if stdin_input is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
    except OSError as exc:
        return "", "", -1, time.monotonic() - start, f"{tool} failed to launch: {exc}"

    if stdin_input is not None:
        proc.stdin.write(stdin_input.encode())
        await proc.stdin.drain()
        proc.stdin.close()

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_task = asyncio.ensure_future(_drain_stream(proc.stdout, stdout_chunks))
    stderr_task = asyncio.ensure_future(_drain_stream(proc.stderr, stderr_chunks))

    error = None
    try:
        await asyncio.wait_for(
            asyncio.gather(proc.wait(), stdout_task, stderr_task), timeout=timeout_s
        )
    except asyncio.TimeoutError:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=_TERMINATE_GRACE_S)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
        # Drain whatever's left in the now-closed pipes before giving up on them.
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        error = f"{tool} timed out after {timeout_s}s (partial output below, if any)"

    duration_s = time.monotonic() - start
    stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
    stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")

    if error is None and proc.returncode != 0:
        error = f"{tool} exited {proc.returncode}: {stderr.strip()[:500]}"

    return stdout, stderr, proc.returncode, duration_s, error
