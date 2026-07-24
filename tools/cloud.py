"""Cloud asset enumeration tool wrappers — Phase 2.

Each wrapper returns the same ToolResult shape as every skills/*.py tool (see tools/base.py),
so the LLM calls tool wrappers and skills identically.
"""
import json
import re
from pathlib import Path

from langchain_core.tools import tool

from tools.base import Finding, ToolResult, run_tool

# cloud_enum's own default mutation-file path resolution is broken under its pip-editable
# install (see run_cloud_enum's docstring) — hardcoded to the real source location instead.
_CLOUD_ENUM_FULL_MUTATIONS = str(Path.home() / "tools" / "cloud_enum" / "enum_tools" / "fuzz.txt")
# This project's own small default mutation list (~38 common env/purpose words) — the vendored
# tool's own fuzz.txt (306 lines) was confirmed live to make a full 3-cloud run exceed 300s even
# with 2 of 3 clouds disabled (see run_cloud_enum's docstring); this keeps the DEFAULT call fast,
# with `thorough=True` opting into the full list exactly like run_nuclei's tags default.
_CLOUD_ENUM_SMALL_MUTATIONS = str(
    Path(__file__).resolve().parent.parent / "config" / "wordlists" / "cloud_enum_default_mutations.txt"
)
_CLOUD_ENUM_BIN = str(Path.home() / "tools" / ".venv-scripts" / "bin" / "cloud_enum")


@tool
async def run_s3scanner(bucket_name: str) -> dict:
    """Check whether a single S3-style bucket name exists and audit its basic permissions.

    MEDIUM risk — sends real requests to AWS's S3 API (or a target-adjacent infra endpoint —
    a bucket name derived from an in-scope company/product name), read-only by default.

    **Safety-conscious default, not the tool's own default**: NEVER passes `--dangerous` —
    confirmed via `s3scanner scan --help` this flag "Include Write and WriteACP permissions
    checks (potentially destructive)": it would attempt to actually WRITE to the bucket to test
    write permissions. This wrapper only ever runs the default read-only permission check.

    **Verified live 2026-07-19**: confirmed real `scan --bucket` flag (not `--bucket-name`, and
    there is no `--json`/output-format flag at all — s3scanner only prints plain text, one line
    per bucket: `<name> | <status>`, e.g. `bucket_not_exist`). Also confirmed a real quirk, not
    a wrapper bug: a bucket hosted outside AWS's default us-east-1 region (tested against the
    well-known public bucket `flaws.cloud`) raises `PermanentRedirect` rather than reporting a
    clean status — s3scanner doesn't auto-follow the region-specific endpoint, so a redirect
    exception shows up as `error` rather than a definitive not-vulnerable result; don't treat
    that as "confirmed safe."
    """
    args = ["scan", "--bucket", bucket_name]
    stdout, stderr, returncode, duration_s, error = await run_tool("s3scanner", args, timeout_s=45)

    findings = []
    if stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if not line or "AWS credentials not configured" in line:
                continue
            if "|" not in line:
                continue
            name, _, status = line.partition("|")
            status = status.strip()
            if status == "bucket_not_exist":
                continue
            findings.append(Finding(
                type="s3_bucket_exposure",
                target=name.strip(),
                detail=f"status={status}",
                severity="high" if re.search(r"open|read|list", status, re.IGNORECASE) else "info",
                tool_source="s3scanner",
            ))

    result = ToolResult(
        tool="s3scanner",
        command_run="s3scanner " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_cloud_enum(keyword: str, disable_aws: bool = False, disable_azure: bool = False,
                          disable_gcp: bool = False, thorough: bool = False) -> dict:
    """Enumerate public cloud assets (S3/Azure/GCP) whose names are derived from a keyword.

    MEDIUM risk — sends real DNS/HTTP requests to AWS/Azure/GCP endpoints for every generated
    name mutation.

    **Real packaging bug found and worked around, not a code issue in this wrapper**:
    cloud_enum was pip-installed editable into `~/tools/.venv-scripts` with a real
    console_scripts entry point (unlike most git-cloned tools in this project, which have no
    entry point at all and are invoked via `PY_SCRIPTS_PYTHON <script>.py`). Its own default
    mutation-file path is computed from `sys.argv[0]`'s directory — under a console-script
    entry point, that resolves to `~/tools/.venv-scripts/bin/`, which doesn't contain
    `enum_tools/fuzz.txt` at all. Confirmed live: running with no `-m`/`-b` override fails
    immediately with `Cannot access mutations file`. Every call here always passes explicit
    `-m`/`-b` paths for this reason, never the tool's own (broken) default.

    **Safety/practicality-conscious default, not the tool's own default**: `thorough=False`
    (the default) uses this project's own small ~38-word mutation list
    (`config/wordlists/cloud_enum_default_mutations.txt`) instead of cloud_enum's real one —
    confirmed live that the vendored `enum_tools/fuzz.txt` (306 base patterns before per-cloud
    template expansion) made a full run exceed 300s even with 2 of 3 clouds disabled, no
    findings recovered from the timeout. `thorough=True` switches to the full vendored list for
    a caller who deliberately wants broader coverage and is prepared for a much longer run —
    same "narrow safe default, explicit broader opt-in" pattern as run_nuclei's `tags` param.

    **Verified live 2026-07-19**: confirmed real `-k`/`-m`/`-b`/`-l`/`-f json`/`--disable-{aws,
    azure,gcp}` flags and JSON-lines-in-a-file output shape — `{"platform", "msg", "target",
    "access"}`. **Known false-positive-prone area, not filtered out**: AWS WorkMail/AppStream-
    style `*.awsapps.com` results were found for EVERY mutation tried in testing, including ones
    with no real association to the keyword — these domains appear to resolve generically
    rather than confirming a genuine asset; treat `aws` "App Found" hits as lower-confidence
    than S3 bucket or Azure/GCP storage hits specifically.
    """
    mutations_file = _CLOUD_ENUM_FULL_MUTATIONS if thorough else _CLOUD_ENUM_SMALL_MUTATIONS
    report_path = f"/tmp/cloud_enum_{abs(hash(keyword))}.json"
    args = ["-k", keyword, "-m", mutations_file, "-b", mutations_file,
            "-l", report_path, "-f", "json"]
    if disable_aws:
        args.append("--disable-aws")
    if disable_azure:
        args.append("--disable-azure")
    if disable_gcp:
        args.append("--disable-gcp")

    stdout, stderr, returncode, duration_s, error = await run_tool(
        _CLOUD_ENUM_BIN, args, timeout_s=300 if thorough else 90
    )

    findings = []
    try:
        with open(report_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                findings.append(Finding(
                    type="cloud_asset",
                    target=record.get("target", keyword),
                    detail=f"platform={record.get('platform', 'unknown')} "
                           f"access={record.get('access', 'unknown')} msg={record.get('msg', '')}",
                    severity="info",
                    tool_source="cloud_enum",
                ))
    except FileNotFoundError:
        pass

    result = ToolResult(
        tool="cloud_enum",
        command_run="cloud_enum " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()
