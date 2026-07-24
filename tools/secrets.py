"""Secret-scanning tool wrappers — Phase 2.

Each wrapper returns the same ToolResult shape as every skills/*.py tool (see tools/base.py),
so the LLM calls tool wrappers and skills identically.

**Deliberate redaction policy, not present elsewhere in this codebase**: every Finding built
here partially masks the actual secret value it discovered (keeps a few leading/trailing
characters, masks the middle) rather than embedding it in full. Every other wrapper in this
project (dalfox/xsstrike payloads, sqlmap injection strings, ...) shows its full value because
those are payloads THIS project crafted, not sensitive material belonging to the target or a
third party. A discovered AWS key or private key is different — ToolResult/Finding objects get
persisted into `sessions/<target>/*.json` checkpoint files (see agent/session.py), and there's
no reason to keep a live credential sitting in full plaintext on disk any longer than the scan
itself needs it. trufflehog already provides its own `Redacted` field for exactly this purpose,
used directly; gitleaks/SecretFinder don't, so a small shared `_redact()` helper does the same
thing for their output.
"""
import json
import re

from langchain_core.tools import tool

from tools.base import PY_SCRIPTS_DIR, PY_SCRIPTS_PYTHON, Finding, ToolResult, run_tool

_SECRETFINDER_SCRIPT = str(PY_SCRIPTS_DIR / "SecretFinder" / "SecretFinder.py")


def _redact(secret: str, keep: int = 4) -> str:
    if len(secret) <= keep * 2:
        return "*" * len(secret)
    return secret[:keep] + "*" * (len(secret) - keep * 2) + secret[-keep:]


@tool
async def run_trufflehog(git_url: str) -> dict:
    """Scan a git repository (by URL — trufflehog clones it itself) for exposed credentials.

    MEDIUM risk — trufflehog clones the repository over the network itself, a real request to
    wherever it's hosted; in a bug bounty context that's typically the target's own source
    repo (an in-scope asset), not a passive third-party lookup. Call check_scope first.

    Always passes `--no-verification` — trufflehog can optionally make LIVE authentication
    attempts against the credential's actual service (e.g. a real AWS API call) to confirm a
    found key is still active. That's a materially more sensitive action than pattern-matching
    text in a git history — actually using a discovered credential, even just to check
    validity — so it's never enabled by default here; a human explicitly wanting verified
    results is a separate, deliberate decision this wrapper doesn't make on its own.

    **Verified live 2026-07-19** against a small, intentionally-public credential-testing repo
    (github.com/trufflesecurity/test_keys — literally exists for this purpose, canary AWS keys
    with no real access): confirmed real `git <uri> --json --no-verification` flags and
    JSON-lines output shape — `DetectorName`, `Raw`/`Redacted`/`RawV2`, `SourceMetadata.Data.Git`
    (`commit`, `file`, `email`, `timestamp`, `line`). Uses the `Redacted` field trufflehog
    already provides rather than `Raw` — see this module's docstring for why.
    """
    args = ["git", git_url, "--json", "--no-verification"]
    stdout, stderr, returncode, duration_s, error = await run_tool("trufflehog", args, timeout_s=180)

    findings = []
    if stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue  # trufflehog's own trailing summary line isn't a finding record
            if "DetectorName" not in record:
                continue  # skip the final {"level":..., "msg":"finished scanning", ...} log line
            git_meta = record.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
            findings.append(Finding(
                type="exposed_secret",
                target=git_url,
                detail=(
                    f"detector={record.get('DetectorName', 'unknown')} "
                    f"file={git_meta.get('file', 'unknown')} commit={git_meta.get('commit', 'unknown')} "
                    f"secret={record.get('Redacted', '[redacted]')}"
                ),
                severity="critical" if record.get("Verified") else "high",
                tool_source="trufflehog",
            ))

    result = ToolResult(
        tool="trufflehog",
        command_run=f"trufflehog git {git_url} --json --no-verification",
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_gitleaks(repo_path: str) -> dict:
    """Scan an already-cloned local git repository's full history for exposed credentials.

    LOW risk — zero network activity at all. Purely local scanning of git history/files
    already on disk, same rationale as run_gf. Complements run_trufflehog rather than
    duplicating it: this wrapper deliberately does NOT clone anything itself — `repo_path` must
    already exist locally (a human or an earlier step is responsible for getting the repo onto
    disk first). Confirmed via `gitleaks detect --help` that `--source`/`-s` takes a path, not
    a URL — there is no gitleaks flag that fetches a remote repo on its own.

    **Verified live 2026-07-19** against a local clone of the same intentionally-public
    credential-testing repo used to verify run_trufflehog: confirmed real
    `detect --source --report-format json --report-path` flags and JSON array output shape —
    `RuleID`, `Description`, `File`, `StartLine`, `Commit`, `Secret`/`Match` (redacted here via
    this module's `_redact()`, same reasoning as run_trufflehog's use of trufflehog's own
    `Redacted` field), `Author`, `Email`, `Date`.
    """
    report_path = f"/tmp/gitleaks_{abs(hash(repo_path))}.json"
    args = ["detect", "--source", repo_path, "--report-format", "json",
            "--report-path", report_path, "--no-banner", "--exit-code", "0"]
    stdout, stderr, returncode, duration_s, error = await run_tool("gitleaks", args, timeout_s=120)

    findings = []
    try:
        with open(report_path) as f:
            records = json.load(f)
        for record in records or []:
            secret = record.get("Secret", "")
            findings.append(Finding(
                type="exposed_secret",
                target=repo_path,
                detail=(
                    f"rule={record.get('RuleID', 'unknown')} file={record.get('File', 'unknown')}"
                    f":{record.get('StartLine', '?')} commit={record.get('Commit', 'unknown')} "
                    f"secret={_redact(secret) if secret else '[none captured]'}"
                ),
                severity="high",
                tool_source="gitleaks",
            ))
    except (FileNotFoundError, json.JSONDecodeError):
        pass  # no report file means no leaks found — gitleaks --exit-code 0 makes this a clean run, not an error

    result = ToolResult(
        tool="gitleaks",
        command_run="gitleaks " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_secretfinder(url: str) -> dict:
    """Scan a single JavaScript URL for hardcoded API keys/tokens/secrets via regex patterns.

    MEDIUM risk — fetches the JS file directly from the target. Call check_scope first.

    Git-cloned Python tool (github.com/m4ll0k/SecretFinder), run via
    `tools.base.PY_SCRIPTS_PYTHON`. Passes `-o cli` (confirmed via source read of
    `SecretFinder.py`'s `cli_output()` — prints directly to stdout as `<pattern_name>\\t->\\t
    <matched_value>` per line) rather than its default HTML-report mode, which this wrapper has
    no way to open/parse.

    **Verified live 2026-07-19** against a local test server serving a JS file with deliberately
    fake AWS/Google API key strings: confirmed real detection (`google_api`/
    `amazon_aws_access_key_id` pattern names, correct matched values) and the tab-separated
    output format. Matched values are partially redacted before being placed in `Finding.detail`
    — see this module's docstring.
    """
    args = [_SECRETFINDER_SCRIPT, "-i", url, "-o", "cli"]
    stdout, stderr, returncode, duration_s, error = await run_tool(
        PY_SCRIPTS_PYTHON, args, timeout_s=60
    )

    findings = []
    if stdout:
        pattern = re.compile(r"^(\S+)\t->\t(.+)$")
        for line in stdout.splitlines():
            match = pattern.match(line.strip())
            if not match:
                continue
            name, value = match.groups()
            findings.append(Finding(
                type="exposed_secret",
                target=url,
                detail=f"pattern={name} secret={_redact(value)}",
                severity="high",
                tool_source="secretfinder",
            ))

    result = ToolResult(
        tool="secretfinder",
        command_run=f"SecretFinder.py -i {url} -o cli",
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()
