"""Active web/network scanner tool wrappers — Phase 2.

Each wrapper returns the same ToolResult shape as every skills/*.py tool
(see tools/base.py), so the LLM calls tool wrappers and skills identically.

Every tool here sends real requests directly to the target (unlike
tools/url_harvest.py's third-party-archive wrappers) — classified MEDIUM in
agent/risk.py across the board, matching the precedent risk.py's own comment
block already sets for nuclei/nikto/ffuf. None of these fire actual exploit
payloads or write/modify target state; several (nikto, wapiti) ship with
broader, more invasive modes by default that this file deliberately does NOT
enable — see each wrapper's own docstring for what was excluded and why.
"""
import json
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from langchain_core.tools import tool

from config.settings import settings
from tools.base import PY_SCRIPTS_DIR, PY_SCRIPTS_PYTHON, Finding, ToolResult, run_tool

_TESTSSL_BIN = str(Path.home() / "tools" / "testssl.sh" / "testssl.sh")
_CORSY_SCRIPT = str(PY_SCRIPTS_DIR / "Corsy" / "corsy.py")
_SMUGGLER_SCRIPT = str(Path.home() / "tools" / "smuggler" / "smuggler.py")
_WPSCAN_BIN = "wpscan"  # resolved via tools/base.py's Ruby-gem-bin fallback, see that module


@tool
async def run_nuclei(target: str, tags: str = "cve,exposure,tech,misconfig,default-login") -> dict:
    """Run nuclei template-based scanning against a single target URL/host.

    MEDIUM risk — sends real HTTP requests matching whatever templates run. Call check_scope
    first, per ORCHESTRATOR_SYSTEM_PROMPT rule 1.

    **Safety-conscious default, not the tool's own default**: always passes
    `-etags dos,fuzz` (confirmed live these tag categories exist in the installed template set —
    9 "dos"-tagged and 31 "fuzz"-tagged templates under ~/nuclei-templates/http/) — templates
    explicitly designed to test denial-of-service or send heavy fuzzing traffic are excluded
    unconditionally, never caller-optional. `tags` defaults to a conservative info-gathering set
    (cve/exposure/tech/misconfig/default-login); pass a broader value deliberately, not by
    accident — an unrestricted scan runs nuclei's full ~11,000-template library.

    **Verified live 2026-07-19** against scanme.nmap.org: confirmed real `-jsonl`/`-tags`/
    `-etags`/`-rate-limit`/`-timeout` flags and JSON-lines output shape (`template-id`,
    `info.name`/`info.severity`/`info.tags`, `matched-at`, `matcher-name`, `host`). One
    surprise worth knowing before tuning `tags` further: even the single tag `tech` alone
    matched 948 of ~1073 loaded templates against one host (tags heavily overlap across nuclei's
    template set — a template's own tag list is rarely just its primary category), so a request
    for "just tech fingerprinting" can still take well over a minute at the enforced rate limit.
    Default timeout here is generous (300s) for exactly this reason — don't assume a narrow-
    sounding tag list means a fast scan.
    """
    args = [
        "-u", target, "-jsonl", "-silent", "-tags", tags, "-etags", "dos,fuzz",
        "-rate-limit", str(settings.MAX_REQ_PER_SEC), "-timeout", "10",
    ]
    stdout, stderr, returncode, duration_s, error = await run_tool("nuclei", args, timeout_s=300)

    findings = []
    if stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip a malformed line rather than losing the whole batch
            info = record.get("info", {})
            findings.append(Finding(
                type="nuclei_match",
                target=target,
                detail=(
                    f"template={record.get('template-id', 'unknown')} "
                    f"name={info.get('name', 'unknown')} matched-at={record.get('matched-at', target)}"
                ),
                severity=info.get("severity", "info"),
                tool_source="nuclei",
            ))

    result = ToolResult(
        tool="nuclei",
        command_run="nuclei " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_nikto(host: str, max_time_s: int = 90) -> dict:
    """Run nikto's web server misconfiguration/interesting-file scan against a single host.

    MEDIUM risk — sends many real HTTP requests directly to the target. Call check_scope first.

    **Safety-conscious default, not the tool's own default**: passes `-Tuning x6809` — reverse-
    tuning syntax that runs every check category EXCEPT 6 (Denial of Service), 8 (Command
    Execution / Remote Shell), 0 (File Upload), and 9 (SQL Injection). Confirmed live via
    `nikto -Help` that these categories exist and are nikto's own explicit taxonomy for its more
    invasive checks; excluding them is a deliberate default, not an oversight — a caller wanting
    the full check set can still request it, but it's never silently on by default here.

    **Real gotcha found live, not assumed**: this nikto build (2.1.5, apt-installed) has NO
    JSON output option at all (`-Format json` errors "Invalid output format" — only csv/htm/
    msf/nbe/txt/xml are supported). CSV output on this same build also has a live-confirmed Perl
    stringification bug (`"45.33.32.156SCALAR(0x...)"` embedded directly in a field, not a
    parsing artifact on this wrapper's side). XML (`-Format xml -o -`, confirmed live it accepts
    `-` for stdout rather than requiring a real file path) is clean and parsed here with stdlib
    `xml.etree.ElementTree`, matching run_nmap's precedent for XML-only tools.
    """
    args = ["-h", host, "-Format", "xml", "-o", "-", "-maxtime", f"{max_time_s}s", "-Tuning", "x6809"]
    stdout, stderr, returncode, duration_s, error = await run_tool("nikto", args, timeout_s=max_time_s + 30)

    findings = []
    if stdout:
        try:
            root = ET.fromstring(stdout)
            for item in root.iter("item"):
                description = item.findtext("description", default="").strip()
                uri = item.findtext("uri", default="").strip()
                findings.append(Finding(
                    type="nikto_finding",
                    target=host,
                    detail=f"uri={uri} method={item.get('method', 'GET')} desc={description}",
                    severity="info",
                    tool_source="nikto",
                ))
        except ET.ParseError:
            pass  # a killed/partial scan can leave unclosed XML — treat as zero findings, not a crash

    result = ToolResult(
        tool="nikto",
        command_run="nikto " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_wapiti(url: str, modules: str = "backup,xss,sql,redirect,crlf,csrf,htaccess,htp,cms") -> dict:
    """Run wapiti's active web vulnerability scan against a single URL, scoped to that URL only.

    MEDIUM risk — sends real, varied HTTP requests directly to the target. Call check_scope
    first.

    **Critical safety finding from a live test, not assumed safe — wapiti's OWN defaults are
    NOT conservative**: run with no `-m` at all, wapiti defaults to the `exec` (command/code
    execution detection — sends real command-injection-style payloads) and `file` modules.
    Passing `-m common` (looked like the "sane default" bundle) was WORSE — confirmed live it
    actually launches `xss, file, exec, ssrf, upload, redirect, ssl, permanentxss`, including
    `upload` (attempts real file uploads to the target) and `ssrf` (which pinged an external
    third-party OOB callback service, `wapiti3.ovh`, not under this project's control, to detect
    blind SSRF). `permanentxss` specifically tests for STORED XSS by attempting to persist a
    payload — a real risk of leaving a live payload sitting in the target's own data if it
    actually succeeds. None of `exec`/`upload`/`permanentxss`/`brute_login_form`/`ssrf` are in
    this wrapper's default `modules` list, and that's deliberate, not an oversight — confirmed
    via `wapiti --list-modules` these are real, separately-invokable categories. `modules` is
    still caller-overridable for a human who explicitly wants broader coverage and has approved
    it, but the safe set is what runs by default.

    `--scope url` restricts the scan to exactly the URL passed in, not `page`/`folder`/`domain`
    (same "don't assume broader is safe" lesson session 3/4 already learned from crawlers) —
    the caller should feed in already-discovered endpoints if broader coverage is wanted, not
    rely on wapiti's own crawler to wander.

    **Verified live 2026-07-19** against scanme.nmap.org (safe default modules): confirmed real
    `-u`/`-m`/`-f json`/`-o`/`--scope`/`--max-scan-time` flags and JSON shape — top-level
    `vulnerabilities`/`anomalies`/`additionals` dicts, each keyed by vulnerability class name,
    each value a list of `{method, path, info, level, parameter, module}` dicts.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = str(Path(tmp_dir) / "wapiti_out.json")
        args = [
            "-u", url, "--scope", "url", "-m", modules, "-f", "json", "-o", out_path,
            "--max-scan-time", "120",
        ]
        stdout, stderr, returncode, duration_s, error = await run_tool("wapiti", args, timeout_s=150)

        findings = []
        try:
            with open(out_path) as f:
                data = json.load(f)
            for section in ("vulnerabilities", "anomalies", "additionals"):
                for vuln_class, entries in data.get(section, {}).items():
                    for entry in entries:
                        findings.append(Finding(
                            type=f"wapiti_{section}",
                            target=url,
                            detail=(
                                f"class={vuln_class} method={entry.get('method', 'GET')} "
                                f"path={entry.get('path', url)} info={entry.get('info', '')}"
                            ),
                            severity="info",
                            tool_source="wapiti",
                        ))
        except (FileNotFoundError, json.JSONDecodeError):
            pass  # no file at all means wapiti found nothing to report — not an error condition

    result = ToolResult(
        tool="wapiti",
        command_run="wapiti " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_corsy(url: str) -> dict:
    """Detect CORS misconfigurations (wildcard/reflected/null-origin ACAO) on a single URL.

    MEDIUM risk — sends several real HTTP requests directly to the target, one per Origin
    header variant tested. Call check_scope first.

    Git-cloned Python tool (github.com/s0md3v/Corsy), run via the dedicated
    ~/tools/.venv-scripts interpreter (tools/base.py's PY_SCRIPTS_PYTHON) — no console-script
    entry point, unlike run_paramspider's ParamSpider.

    **Real bug found and worked around, not a code issue in this wrapper**: Corsy's own
    `main` branches on `sys.stdin.isatty()` — in a non-interactive subprocess (this project's
    normal execution context), that's always False, so it goes down a path that calls
    `sys.stdin.read()` and blocks forever waiting for EOF that never arrives, even though `-u`
    was passed and would otherwise be enough on its own. Worked around with
    `run_tool(..., stdin_input="")` — an immediately-closed empty stdin pipe — which satisfies
    the `readlines()` call with zero lines and lets it proceed straight to testing the `-u`
    target. Confirmed live this fixes it (hung indefinitely without, completed in ~7s with).

    **Known reliability caveat, not a code bug here**: Corsy's own HTTP client
    (`core/requester.py`) calls `requests.get(url, ..., verify=False)` with NO `timeout=` at
    all — if the target is slow or a connection stalls, Corsy itself has no internal escape
    hatch, only this wrapper's own outer `run_tool()` timeout will ever end it, and there's no
    partial result possible if that happens (Corsy never streams progress to stdout, only a
    final "no misconfigurations" message or a results file). Not patched here — this project
    doesn't modify vendored third-party tool source — but worth knowing before assuming a
    timeout means "target is unreachable" rather than "target is just slow."

    **Verified live 2026-07-19** against scanme.nmap.org: clean run, "No misconfigurations
    found" (expected — a static site with no CORS headers at all), confirming the isatty
    workaround and the overall pipeline. A real finding's shape (`class`/`description`/
    `severity`/`exploitation`/`acao header`/`acac header`, keyed by URL) was confirmed by
    reading Corsy's own `core/tests.py`/`db/details.json`, not fired live — no CORS-
    misconfigured test target was available in this session.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = str(Path(tmp_dir) / "corsy_out.json")
        args = [_CORSY_SCRIPT, "-u", url, "-o", out_path, "-q"]
        stdout, stderr, returncode, duration_s, error = await run_tool(
            PY_SCRIPTS_PYTHON, args, stdin_input="", timeout_s=45
        )

        findings = []
        try:
            with open(out_path) as f:
                data = json.load(f)
            for finding_url, info in data.items():
                findings.append(Finding(
                    type="cors_misconfig",
                    target=finding_url,
                    detail=(
                        f"class={info.get('class', 'unknown')} "
                        f"acao={info.get('acao header', '')} acac={info.get('acac header', '')}"
                    ),
                    severity=info.get("severity", "info").lower(),
                    tool_source="corsy",
                ))
        except (FileNotFoundError, json.JSONDecodeError):
            pass  # no file at all means Corsy found no misconfiguration — not an error condition

    result = ToolResult(
        tool="corsy",
        command_run=f"corsy.py -u {url}",
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_smuggler(url: str, method: str = "GET") -> dict:
    """Detect HTTP request smuggling (TE.CL / CL.TE desync) on a single URL/endpoint.

    MEDIUM risk — sends real, deliberately malformed Transfer-Encoding/Content-Length framed
    requests directly to the target (~134 mutation variants at the tool's default config).
    Call check_scope first — this is a more unusual traffic shape than any other wrapper in
    this file, worth flagging explicitly before firing at a real target.

    Git-cloned Python tool (github.com/defparam/smuggler), run via `tools.base.PY_SCRIPTS_PYTHON`.
    Unlike run_corsy, its `-u` path never touches stdin at all (confirmed by reading
    `smuggler.py`'s own arg handling — the isatty/stdin-read branch is only reachable when `-u`
    is omitted), so no stdin workaround was needed here.

    **Output format note**: smuggler has no JSON/CSV option, only a `-l <logfile>` plus ANSI-
    colored, carriage-return-overwritten progress on stdout that isn't practical to parse
    reliably. Passing `-q` (quiet — per its own `-h` text, "will only log issues found") plus
    `-l <tempfile>` means the log file contains ONLY the run header (URL/method/endpoint/
    configfile/timeout) when nothing is found, or a header plus explicit
    `"Potential CLTE/TECL Issue Found"` lines when it is — this wrapper parses for that literal
    phrase, confirmed via `smuggler.py`'s own source (grep for "Potential.*Found").

    **Verified live 2026-07-19**: against a local test HTTP server (not scanme.nmap.org for
    this specific check — this project made heavy repeated use of that shared public test box
    already this session, and its own homepage explicitly asks not to be hammered), confirmed
    the log-file-only-has-real-findings behavior and that passing `-u` alone (no stdin)
    completes in well under a second against a trivial local server. Separately confirmed
    against scanme.nmap.org directly that the full default ~134-mutation sweep over a real
    network round-trip takes noticeably longer than a typical wrapper call in this codebase —
    a first attempt at a 180s timeout was insufficient (killed mid-run with zero findings
    recovered); `timeout_s` here is set to 300s for this reason, closer to run_amass's "several
    minutes, no way to predict up front" precedent than to run_httpx's few-seconds norm. No
    actual smuggling-vulnerable target was available to confirm the positive-finding path.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        log_path = str(Path(tmp_dir) / "smuggler.log")
        args = [_SMUGGLER_SCRIPT, "-u", url, "-m", method, "-q", "-l", log_path, "-t", "5"]
        stdout, stderr, returncode, duration_s, error = await run_tool(
            PY_SCRIPTS_PYTHON, args, timeout_s=300
        )

        findings = []
        try:
            with open(log_path) as f:
                log_text = f.read()
            for line in log_text.splitlines():
                if "Potential" in line and "Found" in line:
                    clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
                    findings.append(Finding(
                        type="request_smuggling",
                        target=url,
                        detail=clean_line,
                        severity="high",
                        tool_source="smuggler",
                    ))
        except FileNotFoundError:
            pass

    result = ToolResult(
        tool="smuggler",
        command_run=f"smuggler.py -u {url} -m {method}",
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_testssl(host: str, port: int = 443) -> dict:
    """Analyze TLS/SSL configuration on a single host:port via testssl.sh (protocols, ciphers, cert).

    MEDIUM risk — opens real TLS connections directly to the target, same rationale as
    run_tlsx. Call check_scope first.

    Different depth than run_tlsx (which does one quick handshake to pull cert fields):
    testssl.sh actually enumerates supported protocol versions, cipher suites, and known
    TLS-level vulnerabilities (e.g. Heartbleed-class checks) — a real second opinion, not a
    duplicate.

    Restricted to `-S` (server defaults / certificate info) rather than a full run — confirmed
    live a full protocol+cipher enumeration takes several minutes per host; `-S` alone still
    took ~55s against a single IP. Always passes `--ip one` (confirmed via `--help`: "one"
    means test just the first DNS-returned IP) — without it, testssl.sh tests EVERY resolved IP
    for the host serially, multiplying runtime unpredictably for any host with multiple A
    records. Never passes the deprecated `--fast` flag — confirmed live it prints its own
    "not recommended to use anymore" warning.

    **Verified live 2026-07-19** against example.com:443: confirmed real `-S`/`--ip`/
    `--jsonfile-pretty`/`--quiet`/`--color 0` flags and JSON shape — top-level `scanResult` is a
    flat list of `{id, severity, finding}` dicts (not nested by category).
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = str(Path(tmp_dir) / "testssl_out.json")
        args = [
            "--quiet", "--color", "0", "--ip", "one", "--jsonfile-pretty", out_path,
            "-S", f"{host}:{port}",
        ]
        stdout, stderr, returncode, duration_s, error = await run_tool(_TESTSSL_BIN, args, timeout_s=150)

        findings = []
        try:
            with open(out_path) as f:
                data = json.load(f)
            for entry in data.get("scanResult", []):
                findings.append(Finding(
                    type="tls_finding",
                    target=f"{host}:{port}",
                    detail=f"{entry.get('id', 'unknown')}: {entry.get('finding', '')}",
                    severity=str(entry.get("severity", "info")).lower(),
                    tool_source="testssl",
                ))
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    result = ToolResult(
        tool="testssl",
        command_run=f"testssl.sh -S {host}:{port}",
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_wpscan(url: str) -> dict:
    """Enumerate a WordPress site's version, plugins, themes, and known vulnerabilities.

    MEDIUM risk — sends real HTTP requests directly to the target. Call check_scope first.

    **Environment note**: wpscan was installed via `gem install --user-install` (session 4,
    no sudo needed — Ruby/gem were already present) rather than a `go install`/apt package like
    every other tool in this file; its binary landed in a Ruby-version-specific gem bin
    directory, not on PATH. `tools/base.py`'s `_resolve_binary()` gained a generic fallback for
    this (globs `~/.local/share/gem/ruby/*/bin/`), so `run_tool("wpscan", ...)` here resolves
    the same way any other tool name would.

    Passes `--random-user-agent` and `--request-timeout` from a fixed conservative value;
    deliberately does NOT pass `-e` (enumerate plugins/themes/users) by default — confirmed via
    `--help` this triggers a much larger request volume (per-plugin/theme version-detection
    probing) than a plain scan, left as a caller decision rather than a silent default.

    **Verified live 2026-07-19** against scanme.nmap.org (a non-WordPress site, deliberately —
    avoids firing a real enumeration scan at a live WordPress install with no test target
    available this session): confirmed real `--url`/`-f json`/`-o`/`--random-user-agent`/
    `--request-timeout` flags. Output for a non-WordPress target is `{"scan_aborted": "...",
    "target_url": ...}` with no `vulnerabilities` key at all — this wrapper's parser handles
    that shape explicitly rather than assuming `vulnerabilities` is always present. **Also
    confirmed live**: every invocation, not just the first, updates wpscan's own vulnerability
    database at the start of the run (no `--no-update`/`--update` flag exists in this installed
    version to control it) — expect the first real call from a fresh environment to take
    noticeably longer than later ones.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = str(Path(tmp_dir) / "wpscan_out.json")
        args = [
            "--url", url, "-f", "json", "-o", out_path, "--random-user-agent",
            "--request-timeout", "15",
        ]
        stdout, stderr, returncode, duration_s, error = await run_tool(_WPSCAN_BIN, args, timeout_s=180)

        findings = []
        try:
            with open(out_path) as f:
                data = json.load(f)
            if data.get("scan_aborted"):
                findings.append(Finding(
                    type="wpscan_not_wordpress",
                    target=url,
                    detail=str(data["scan_aborted"]),
                    severity="info",
                    tool_source="wpscan",
                ))
            else:
                version_info = data.get("version") or {}
                if version_info.get("number"):
                    findings.append(Finding(
                        type="wordpress_version",
                        target=url,
                        detail=f"WordPress {version_info['number']}",
                        severity="info",
                        tool_source="wpscan",
                    ))
                for vuln in version_info.get("vulnerabilities", []):
                    findings.append(Finding(
                        type="wordpress_vulnerability",
                        target=url,
                        detail=vuln.get("title", "unknown vulnerability"),
                        severity="high",
                        tool_source="wpscan",
                    ))
                for plugin_slug, plugin_info in (data.get("plugins") or {}).items():
                    findings.append(Finding(
                        type="wordpress_plugin",
                        target=url,
                        detail=f"plugin={plugin_slug} version={plugin_info.get('version', {}).get('number', 'unknown')}",
                        severity="info",
                        tool_source="wpscan",
                    ))
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    result = ToolResult(
        tool="wpscan",
        command_run=f"wpscan --url {url}",
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()
