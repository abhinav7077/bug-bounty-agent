"""Subprocess-runner + result-contract tests (tools/base.py).

run_tool() is the shared primitive under every external-tool wrapper and its
docstring makes hard promises: it NEVER raises, always sets `error` on
not-found / non-zero exit / timeout, and returns whatever was captured rather
than throwing. These run against harmless local binaries (echo/false/sleep) —
no network, no target — so they're safe and deterministic in CI.
"""
import asyncio
import shutil

from tools.base import Finding, ToolResult, _resolve_binary, run_tool


def _run(*args, **kwargs):
    return asyncio.run(run_tool(*args, **kwargs))


def test_successful_command_returns_output_and_no_error():
    stdout, stderr, rc, duration, error = _run("echo", ["hello-world"])
    assert "hello-world" in stdout
    assert rc == 0
    assert error is None
    assert duration >= 0.0


def test_missing_binary_sets_error_never_raises():
    stdout, stderr, rc, duration, error = _run("definitely_not_a_real_binary_xyz", [])
    assert error is not None
    assert "not found" in error
    assert rc == -1


def test_nonzero_exit_sets_error():
    # `false` exits 1 with no output.
    stdout, stderr, rc, duration, error = _run("false", [])
    assert rc != 0
    assert error is not None
    assert "exited" in error


def test_timeout_sets_error_and_returns():
    stdout, stderr, rc, duration, error = _run("sleep", ["5"], timeout_s=1)
    assert error is not None
    assert "timed out" in error
    # Must have actually stopped near the timeout, not waited the full 5s.
    assert duration < 4.0


def test_resolve_binary_accepts_absolute_executable_path():
    echo_path = shutil.which("echo")
    assert echo_path is not None
    assert _resolve_binary(echo_path) == echo_path


def test_resolve_binary_returns_none_for_unknown():
    assert _resolve_binary("definitely_not_a_real_binary_xyz") is None


# --- result-model contract ---------------------------------------------------

def test_finding_defaults():
    f = Finding(type="xss", target="example.com", detail="reflected", tool_source="run_dalfox")
    assert f.severity == "info"          # default
    assert isinstance(f.timestamp, str)  # auto-populated
    assert f.timestamp


def test_tool_result_defaults_to_empty_findings():
    r = ToolResult(tool="run_subfinder", command_run="subfinder -d example.com",
                   raw_output="", duration_s=0.1)
    assert r.parsed == []
    assert r.error is None
