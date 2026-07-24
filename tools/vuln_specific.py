"""Vulnerability-class-specific tool wrappers (XSS, SQLi, subdomain takeover) — Phase 2.

Each wrapper returns the same ToolResult shape as every skills/*.py tool
(see tools/base.py), so the LLM calls tool wrappers and skills identically.

run_sqlmap/run_ghauri are the most sensitive wrappers in this codebase to date — real SQL
injection testing tools. Both are hardcoded to a hardcoded, conservative flag set (`--batch
--level 1 --risk 1`, NEVER `--dump`/`--dump-all`/`--os-shell`/`--os-pwn` or any other
data-exfiltration/shell-access flag) with no passthrough for arbitrary caller-supplied flags —
this wrapper only ever runs detection, never exploitation, and classifies both HIGH regardless
in agent/risk.py, deliberately more conservative than risk.py's own comment ("sqlmap in exploit
mode") might suggest is required for detect-only use, because even confirming SQL injection
exists sends attacker-controlled input into a live query.
"""
import glob
import json
import re
from pathlib import Path

from langchain_core.tools import tool

from tools.base import PY_SCRIPTS_DIR, PY_SCRIPTS_PYTHON, Finding, ToolResult, run_tool

_XSSTRIKE_SCRIPT = str(PY_SCRIPTS_DIR / "XSStrike" / "xsstrike.py")

# ghauri got a real console_scripts entry point (pip install -e), but into the dedicated
# ~/tools/.venv-scripts venv, not this project's own .venv — same PATH gap run_paramspider hit.
# Reference by absolute path (tools/base.py's _resolve_binary passes an already-absolute,
# executable path through as-is) rather than a bare "ghauri" that only resolves by accident if
# someone happens to activate the other venv first.
_GHAURI_BIN = str(PY_SCRIPTS_DIR / ".venv-scripts" / "bin" / "ghauri")


def _find_subjack_fingerprints() -> str | None:
    # subjack ships its CNAME-fingerprint database alongside its own source in the Go module
    # cache, not somewhere stable to hardcode — the module path is version-pinned
    # (.../subjack@v0.0.0-<hash>/...) and that version segment changes on every `go install`
    # upgrade. Globbed at call time rather than hardcoded so a future re-install doesn't
    # silently break this wrapper.
    matches = glob.glob(str(Path.home() / "go" / "pkg" / "mod" / "github.com" / "haccer" /
                            "subjack@*" / "subjack" / "fingerprints.json"))
    return matches[0] if matches else None


@tool
async def run_dalfox(url: str) -> dict:
    """Scan a single URL for reflected/DOM XSS via dalfox (payload generation + verification).

    MEDIUM risk — sends real, non-destructive XSS probe payloads directly to the target's
    parameters (reflected display only, no persistence attempt). Call check_scope first.

    Deliberately does NOT enable dalfox's blind-XSS-fire mode (an out-of-band callback workflow
    requiring a listener like interactsh) — agent/risk.py's own comment reserves HIGH
    specifically for "dalfox in blind-XSS-fire mode"; this wrapper only ever does the MEDIUM-
    tier standard scan.

    **Verified live 2026-07-19** against a local test server with a deliberately-reflected `q`
    parameter (not scanme.nmap.org — needed a real reflection to confirm detection actually
    fires, and scanme.nmap.org has no injectable-looking parameters): confirmed real `url`
    subcommand, `--format json`/`--silence` flags, and JSON-lines-in-an-array output shape —
    each element has `type` ("R"=reflected, "V"=verified-vulnerable), `param`, `payload`,
    `evidence`, `cwe`, `severity`, `message_str`. **A real quirk, not a parsing bug**: the JSON
    array's last element is consistently an empty `{}` — skipped here rather than emitted as a
    junk Finding.

    **A reliability caveat found during a later re-verification pass, not on the first live
    check**: dalfox's own detection is non-deterministic against the identical, confirmed-
    vulnerable target — four consecutive runs against the same URL returned 0, 1, 1, and 2
    findings respectively, with no `error` set on any of them. This isn't a bug in this wrapper
    (the JSON parsing is correct for whatever dalfox actually returns), but it does mean a
    single `findings: []` result should NOT be read as "confirmed not vulnerable" the way it can
    be for most other wrappers in this file — consider a retry (or run_xsstrike/run_kxss as a
    cross-check) before concluding a parameter is clean.
    """
    args = ["url", url, "--format", "json", "--silence", "--timeout", "10"]
    stdout, stderr, returncode, duration_s, error = await run_tool("dalfox", args, timeout_s=90)

    findings = []
    if stdout:
        try:
            records = json.loads(stdout)
        except json.JSONDecodeError:
            records = []
        for record in records:
            if not record:
                continue  # dalfox's own trailing {} in the JSON array
            findings.append(Finding(
                type="xss_finding",
                target=url,
                detail=(
                    f"param={record.get('param', 'unknown')} type={record.get('type', '?')} "
                    f"payload={record.get('payload', '')} msg={record.get('message_str', '')}"
                ),
                severity=str(record.get("severity", "info")).lower(),
                tool_source="dalfox",
            ))

    result = ToolResult(
        tool="dalfox",
        command_run="dalfox " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_kxss(urls: list[str]) -> dict:
    """Check a list of URLs for parameters that reflect special characters unescaped.

    MEDIUM risk — sends real requests directly to each host in the URL list (one request per
    parameter tested, injecting `"'><` and checking what survives in the response). Cheaper,
    faster first-pass filter than run_dalfox — meant to narrow down which URLs are worth a full
    dalfox scan, not a replacement for one (kxss only confirms reflection, not exploitability).

    Takes a URL list via stdin (same stdin-only convention as run_gf/run_waybackurls) —
    confirmed live it has no `-h`/flags at all, just reads lines from stdin.

    **Verified live 2026-07-19** against a local test server with a deliberately-reflected `q`
    parameter: confirmed real plain-text output shape —
    `param {name} is reflected and allows {chars} on {url}`, one line per surviving character
    class. Parsed with a regex rather than assuming a fixed character list, since the exact set
    of characters reported varies by what the target actually reflects unescaped.
    """
    stdin_input = "\n".join(urls) + "\n"
    stdout, stderr, returncode, duration_s, error = await run_tool(
        "kxss", [], stdin_input=stdin_input, timeout_s=60
    )

    findings = []
    if stdout:
        pattern = re.compile(r"param (\S+) is reflected and allows (.+?) on (\S+)")
        for line in stdout.splitlines():
            match = pattern.match(line.strip())
            if not match:
                continue
            param, chars, found_url = match.groups()
            findings.append(Finding(
                type="reflected_param",
                target=found_url,
                detail=f"param={param} allows={chars}",
                severity="info",
                tool_source="kxss",
            ))

    result = ToolResult(
        tool="kxss",
        command_run=f"kxss (stdin: {len(urls)} urls)",
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_xsstrike(url: str) -> dict:
    """Scan a single URL for XSS via XSStrike (context-aware payload generation, WAF detection).

    MEDIUM risk — sends real, non-destructive XSS probe payloads directly to the target's
    parameters. Call check_scope first.

    Git-cloned Python tool (github.com/s0md3v/XSStrike), run via `tools.base.PY_SCRIPTS_PYTHON`.
    Always passes `--skip-dom` — XSStrike's DOM-based checks need a real headless browser, and
    this environment has none installed (the same missing-Chrome/Chromium gap that blocks
    run_gowitness; see docs/DEVELOPMENT_PLAN.md). Reflected/parameter-based XSS detection
    (this wrapper's actual scope) doesn't need one.

    **Two real gotchas found live, not assumed**: (1) XSStrike's own `--json` flag does NOT mean
    "output JSON" — confirmed via its `-h` text and by testing it — it means "treat POST data as
    JSON" (a request-body format flag). Passing it with no POST data active caused detection to
    silently fail (0 reflections found on a parameter independently confirmed reflected by both
    run_dalfox and run_kxss against the identical target) — never pass it here. XSStrike has NO
    structured output mode at all; this wrapper parses its plain colored-text stdout instead.
    (2) After finding a working payload for a parameter, XSStrike interactively prompts
    "Would you like to continue scanning? [y/N]" — in a non-interactive subprocess with no
    stdin, this crashes with an unhandled `EOFError` rather than defaulting sanely. Worked
    around with `run_tool(..., stdin_input="n\\n" * 50)` (confirmed live this answers every such
    prompt with the safe default without crashing; 50 is a generous margin, not a measured
    exact count of how many times it can ask).

    **Verified live 2026-07-19** against a local test server with a deliberately-reflected `q`
    parameter: found a real working payload (`<A/+/OnMoUseoveR%0d=%0dconfirm()%0dx>...`,
    Efficiency 100, Confidence 10) and completed cleanly rather than hanging on the prompt.
    """
    args = [_XSSTRIKE_SCRIPT, "-u", url, "--skip-dom"]
    stdout, stderr, returncode, duration_s, error = await run_tool(
        PY_SCRIPTS_PYTHON, args, stdin_input="n\n" * 50, timeout_s=120
    )

    findings = []
    if stdout:
        clean_stdout = re.sub(r"\x1b\[[0-9;]*m", "", stdout)
        payload_pattern = re.compile(r"Payload:\s*(.+)")
        confidence_pattern = re.compile(r"Confidence:\s*(\d+)")
        payloads = payload_pattern.findall(clean_stdout)
        confidences = confidence_pattern.findall(clean_stdout)
        for i, payload in enumerate(payloads):
            confidence = confidences[i] if i < len(confidences) else "unknown"
            findings.append(Finding(
                type="xss_finding",
                target=url,
                detail=f"payload={payload.strip()} confidence={confidence}",
                severity="high" if confidence != "unknown" and int(confidence) >= 7 else "medium",
                tool_source="xsstrike",
            ))

    result = ToolResult(
        tool="xsstrike",
        command_run=f"xsstrike.py -u {url} --skip-dom",
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


def _parse_sqlmap_style_output(stdout: str, tool_name: str, url: str) -> list[Finding]:
    """Shared parser for sqlmap/ghauri — both use the same 'Parameter: ... Type: ... Payload:
    ...' summary block convention on a positive result, and the same 'does not seem to be
    injectable' / 'do not appear to be injectable' phrasing on a negative one. Neither tool has
    a structured (JSON/CSV) output mode.
    """
    findings = []
    if "does not seem to be injectable" in stdout or "do not appear to be injectable" in stdout:
        return findings
    param_blocks = re.split(r"\nParameter:\s*", stdout)[1:]
    for block in param_blocks:
        first_line = block.splitlines()[0] if block.splitlines() else block
        type_match = re.search(r"Type:\s*(.+)", block)
        payload_match = re.search(r"Payload:\s*(.+)", block)
        findings.append(Finding(
            type="sql_injection",
            target=url,
            detail=(
                f"parameter={first_line.strip()} "
                f"type={type_match.group(1).strip() if type_match else 'unknown'} "
                f"payload={payload_match.group(1).strip() if payload_match else 'unknown'}"
            ),
            severity="critical",
            tool_source=tool_name,
        ))
    return findings


@tool
async def run_sqlmap(url: str) -> dict:
    """Test a single URL's parameters for SQL injection via sqlmap — DETECTION ONLY.

    HIGH risk — real SQL injection testing sends attacker-controlled input into a live
    database query. Classified HIGH regardless of sqlmap's own "exploit mode" framing (see
    agent/risk.py's comment) — even confirming injection exists carries real risk against a
    live target, so this always requires explicit HITL approval, not just when data
    exfiltration is requested.

    **Hardcoded, non-negotiable safety boundary**: only ever runs with `--batch --level 1
    --risk 1` (never-ask-for-input, lowest test intensity/risk). NEVER passes `--dump`,
    `--dump-all`, `--os-shell`, `--os-pwn`, `--sql-shell`, or any other data-exfiltration or
    shell-access flag — there is no parameter on this function that can reach those, by design,
    not merely by convention. A human wanting an actual data dump after a confirmed
    vulnerability needs a separate, explicitly-approved action outside this wrapper.

    **Verified live 2026-07-19** against a local test server's non-SQL-backed reflected
    parameter (confirms the wrapper's plumbing/parsing, not a real positive-injection case —
    no live SQL-injectable target was available or appropriate to test against this session):
    confirmed `--batch` suppresses every interactive prompt, and the negative-result phrasing
    ("does not seem to be injectable... all tested parameters do not appear to be injectable")
    that `_parse_sqlmap_style_output` treats as zero findings. A positive result's format
    (`Parameter: <name> (<place>)` / `Type: ...` / `Payload: ...` block) is sqlmap's own
    long-documented, stable output convention, not verified against a live positive case this
    session.
    """
    args = ["-u", url, "--batch", "--level", "1", "--risk", "1"]
    stdout, stderr, returncode, duration_s, error = await run_tool("sqlmap", args, timeout_s=120)

    findings = _parse_sqlmap_style_output(stdout or "", "sqlmap", url)

    result = ToolResult(
        tool="sqlmap",
        command_run="sqlmap " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_ghauri(url: str) -> dict:
    """Test a single URL's parameters for SQL injection via ghauri — DETECTION ONLY.

    HIGH risk — same rationale as run_sqlmap: real injection testing against a live target,
    classified HIGH unconditionally regardless of framing.

    A different engine than sqlmap (per docs/DEVELOPMENT_PLAN.md: "advanced SQLi for modern
    apps") — worth running alongside run_sqlmap for a second opinion, not as a replacement.

    **Hardcoded, non-negotiable safety boundary**, identical to run_sqlmap: only ever `--batch
    --level 1`, never `--dump`/any exfiltration or shell-access flag, no passthrough for
    arbitrary caller-supplied args.

    Like run_paramspider, ghauri's console-script entry point landed in the dedicated
    `~/tools/.venv-scripts` venv (pip installed there, editable), not this project's own
    `.venv` — referenced by absolute path (`_GHAURI_BIN`) rather than a bare `"ghauri"` that
    would only resolve by accident.

    **Verified live 2026-07-19** against the same local test server as run_sqlmap: confirmed
    `--batch`/`--level` flags, `--batch` suppresses prompts, and the same
    "does not seem to be injectable"/"do not appear to be injectable" negative phrasing sqlmap
    uses — ghauri is close enough to sqlmap's own CLI conventions that
    `_parse_sqlmap_style_output` is shared between both wrappers rather than duplicated.
    """
    args = ["-u", url, "--batch", "--level", "1"]
    stdout, stderr, returncode, duration_s, error = await run_tool(_GHAURI_BIN, args, timeout_s=120)

    findings = _parse_sqlmap_style_output(stdout or "", "ghauri", url)

    result = ToolResult(
        tool="ghauri",
        command_run="ghauri " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_subjack(domain: str) -> dict:
    """Check a single domain for subdomain takeover via a known-vulnerable CNAME fingerprint.

    MEDIUM risk — sends a real HTTP(S) request to the domain to check its response against a
    fingerprint database (e.g. an unclaimed GitHub Pages/Heroku/S3 CNAME target) — read-only,
    non-destructive.

    Uses `-a` (check every URL, not just those with an identified CNAME — confirmed via `-h`
    this is needed for reliable detection rather than depending on subjack's own CNAME
    pre-filter) and `-ssl` (HTTPS, confirmed via `-h` this "may increase accuracy"). The
    fingerprints file ships inside subjack's own Go module cache at a version-pinned path
    (`.../subjack@v0.0.0-<hash>/subjack/fingerprints.json`) — resolved via `glob` at call time
    rather than hardcoded, since a future `go install` upgrade changes that hash. Returns an
    explicit error if no fingerprints file is found rather than silently running with none.

    **Verified live 2026-07-19** against scanme.nmap.org (not vulnerable, as expected):
    confirmed real `-d`/`-w`/`-a`/`-ssl`/`-o` flags and JSON output shape —
    `[{"subdomain": ..., "vulnerable": bool}]`, with additional `service`/fingerprint fields
    expected (per subjack's documented behavior, not independently confirmed live) when
    `vulnerable` is true.
    """
    fingerprints_path = _find_subjack_fingerprints()
    if fingerprints_path is None:
        return ToolResult(
            tool="subjack",
            command_run=f"subjack -d {domain}",
            raw_output="",
            parsed=[],
            duration_s=0.0,
            error="subjack fingerprints.json not found under ~/go/pkg/mod — is Phase 0's tool install done?",
        ).model_dump()

    with_tempfile_suffix = f"/tmp/subjack_{domain.replace('.', '_')}.json"
    args = ["-d", domain, "-w", fingerprints_path, "-a", "-ssl", "-o", with_tempfile_suffix]
    stdout, stderr, returncode, duration_s, error = await run_tool("subjack", args, timeout_s=45)

    findings = []
    try:
        with open(with_tempfile_suffix) as f:
            records = json.load(f)
        for record in records or []:
            if record.get("vulnerable"):
                findings.append(Finding(
                    type="subdomain_takeover",
                    target=record.get("subdomain", domain),
                    detail=f"service={record.get('service', 'unknown')}",
                    severity="high",
                    tool_source="subjack",
                ))
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    result = ToolResult(
        tool="subjack",
        command_run="subjack " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_subzy(domains: list[str]) -> dict:
    """Check a list of domains for subdomain takeover (a second engine/fingerprint set than run_subjack).

    MEDIUM risk — sends a real HTTP(S) request per domain, read-only/non-destructive, same
    rationale as run_subjack.

    Accepts a batch (`--target` takes a comma-separated list, confirmed via `-h`) rather than
    one call per domain — same one-HITL-approval-per-batch reasoning as run_httpx.

    **A real quirk found live, not assumed**: with no vulnerable result, subzy's own
    `--output` file contains the literal JSON value `null`, not an empty array — this wrapper's
    parser checks for that explicitly rather than assuming a list is always what gets loaded.

    **Verified live 2026-07-19** against scanme.nmap.org (not vulnerable, as expected):
    confirmed real `--target`/`--output`/`--hide_fails` flags and the `null`-on-clean-result
    file content. A positive result's shape wasn't independently confirmed live (no known-
    vulnerable takeover target was available this session) — expected to be a JSON array of
    per-domain result objects based on subzy's own documented behavior.
    """
    with_tempfile_suffix = f"/tmp/subzy_{abs(hash(tuple(domains)))}.json"
    args = ["run", "--target", ",".join(domains), "--output", with_tempfile_suffix, "--hide_fails"]
    stdout, stderr, returncode, duration_s, error = await run_tool("subzy", args, timeout_s=60)

    findings = []
    try:
        with open(with_tempfile_suffix) as f:
            records = json.load(f)
        for record in records or []:
            findings.append(Finding(
                type="subdomain_takeover",
                target=record.get("subdomain", record.get("target", "unknown")),
                detail=str(record),
                severity="high",
                tool_source="subzy",
            ))
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    result = ToolResult(
        tool="subzy",
        command_run="subzy " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()
