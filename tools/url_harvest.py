"""URL harvesting tool wrappers — Phase 2.

Each wrapper returns the same ToolResult shape as every skills/*.py tool
(see tools/base.py), so the LLM calls tool wrappers and skills identically.
"""
import json
import tempfile
from pathlib import Path

from langchain_core.tools import tool

from config.settings import settings
from tools.base import Finding, ToolResult, run_tool

# paramspider (and cloud_enum, wrapped in tools/cloud.py) were pip-installed with a real
# console_scripts entry point, but into the dedicated ~/tools/.venv-scripts venv (session 3's
# scripts/phase0_setup.sh), not this project's own .venv — shutil.which() inside THIS process
# never finds them. Referencing by absolute path works: tools/base.py's _resolve_binary()
# passes through an already-absolute, executable path as-is.
_PARAMSPIDER_BIN = str(Path.home() / "tools" / ".venv-scripts" / "bin" / "paramspider")

# Installed 2026-07-19 (session 4) via scripts/phase0_setup.sh's gf-patterns step —
# github.com/1ndianl33t/Gf-Patterns, copied to ~/.gf/*.json. gf's own binary does nothing
# without these; `gf -list` against the live install is the source of truth if this ever
# needs updating, not this codebase's own memory of what was installed.
_GF_PATTERNS = {
    "debug_logic", "idor", "img-traversal", "interestingEXT", "interestingparams",
    "interestingsubs", "jsvar", "lfi", "rce", "redirect", "sqli", "ssrf", "ssti", "xss",
}


@tool
async def run_gau(domain: str, from_date: str = "") -> dict:
    """Pull historical URLs for a domain from Wayback Machine + AlienVault OTX.

    LOW risk — same classification as run_subfinder/run_dnsx: gau queries
    third-party archives, never sends a request to the target itself. Still
    call check_scope first per ORCHESTRATOR_SYSTEM_PROMPT rule 1.

    One domain per call, not a batch — verified live that passing two
    domains as positional args did not behave like run_httpx's repeated
    -u (a 2-domain call didn't finish inside 25s where a 1-domain call
    reliably does), so this mirrors run_nmap's single-target precedent
    instead of guessing at undocumented multi-arg behavior.

    Deliberately uses --providers wayback,otx, skipping commoncrawl and
    urlscan — verified live that a request for wayback+otx across ALL of a
    long-lived, high-profile domain's history can return 47,000+ URLs and
    still not finish inside 60s (hackerone.com specifically; a smaller,
    newer domain like scanme.nmap.org finished in ~19s with 42 URLs). This
    is normal gau behavior for that kind of target, not a bug. A run that
    hits the timeout now comes back with error SET but whatever URLs were
    captured before the cutoff still in parsed (tools/base.py's run_tool()
    was fixed 2026-07-19 to drain stdout incrementally rather than discard
    it on timeout) — still treat that as a possibly-incomplete list, not a
    reason to assume nothing more exists. If a domain is a known outlier
    like hackerone.com, pass from_date (format YYYYMM) to narrow the query
    to recent history up front instead of relying on a partial result —
    gau has no result-count limit flag, date narrowing is the only other
    lever available.
    """
    args = [domain, "--json", "--threads", "5", "--providers", "wayback,otx",
             "--blacklist", "png,jpg,gif,css,svg,woff,woff2,ttf,ico"]
    if from_date:
        args += ["--from", from_date]
    stdout, stderr, returncode, duration_s, error = await run_tool("gau", args)

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
            url = record.get("url", "")
            if not url:
                continue
            findings.append(Finding(
                type="historical_url",
                target=domain,
                detail=url,
                severity="info",
                tool_source="gau",
            ))

    result = ToolResult(
        tool="gau",
        command_run="gau " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_waybackurls(domain: str) -> dict:
    """Pull historical URLs for a domain from the Wayback Machine specifically.

    LOW risk — same classification as run_gau: queries a third-party
    archive, never the target itself.

    Unlike every ProjectDiscovery tool wrapped so far, waybackurls takes NO
    domain flag or positional argument at all — verified live it ignores
    one entirely and just hangs waiting on stdin. Uses
    tools/base.py's run_tool(stdin_input=...) for this (added this session
    specifically for this tool — see that function's docstring).

    **Known reliability caveat, worse than run_amass's timing variance —
    document this, don't paper over it**: three live runs against the
    IDENTICAL domain (hackerone.com) returned wildly different results —
    1189 URLs (process killed at 60s), 0 URLs (process exited 0, "success,"
    at ~61s), then 302 URLs (killed at 90s). Only the killed-at-N-seconds
    cases are timeouts, and those now come back with error SET plus
    whatever was captured before the cutoff (tools/base.py's run_tool() was
    fixed 2026-07-19 to drain output incrementally rather than discard it) —
    those are no longer silent. The 0-URLs/exit-0 case is NOT a timeout at
    all, and that fix does nothing for it: the Wayback CDX API this tool
    queries appears to intermittently return a genuinely empty result set
    on a clean exit, with no error surfaced by waybackurls or by this
    wrapper. A clean `error: null` with an empty `parsed` list STILL does
    NOT reliably mean "this domain has no Wayback history," unlike every
    other wrapper in this codebase where an error-free empty result is
    trustworthy — this part of the caveat is about the underlying tool/API,
    not something a code change here can fix. If a target is expected to
    have real history and this comes back empty, retry before concluding
    there's nothing there.
    """
    args = []
    stdout, stderr, returncode, duration_s, error = await run_tool(
        "waybackurls", args, stdin_input=f"{domain}\n"
    )

    findings = []
    if stdout:
        for line in stdout.splitlines():
            url = line.strip()
            if not url:
                continue
            findings.append(Finding(
                type="historical_url",
                target=domain,
                detail=url,
                severity="info",
                tool_source="waybackurls",
            ))

    result = ToolResult(
        tool="waybackurls",
        command_run=f"echo {domain} | waybackurls",
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_hakrawler(url: str, depth: int = 2) -> dict:
    """Fast web spider over a single URL via hakrawler — finds hrefs, forms, scripts.

    MEDIUM risk — sends real HTTP requests directly to the target as it
    crawls. Call check_scope on the host before this, per
    ORCHESTRATOR_SYSTEM_PROMPT rule 1.

    **Critical scope-safety fix, found via a controlled local test, not
    assumed safe — same class of bug as run_katana's default `-fs rdn`
    issue**: hakrawler has NO host-restriction flag equivalent to katana's
    `-fs`. Its `-i` flag ("only crawl inside path") sounds like a path
    restriction, but verified live it is actually what keeps the crawl
    confined to the seed host at all. Without `-i`, a controlled test
    (a local seed page linking to a completely unrelated second local
    server on a different port) proved hakrawler follows and actually
    FETCHES every discovered link regardless of host — confirmed via a real
    GET request landing in the unrelated server's access log, not just the
    link being extracted and reported. With `-i` passed, the identical test
    made zero requests to the unrelated server while still correctly
    crawling a second same-host path. `-i` is therefore passed
    unconditionally here, never left as caller-optional — omitting it would
    silently turn any crawl into a potential scope violation against
    whatever hosts the target happens to link to. `-subs` (include
    subdomains) is deliberately never passed either, matching run_katana's
    `-fs fqdn` choice: an authorized host does not imply its subdomains are
    authorized too.

    Takes a URL via stdin, not a flag or positional arg — verified live it
    ignores a positional URL entirely, same stdin-only convention as
    run_waybackurls. `-s -w` requested so each finding's Source and Where
    (the page a link was discovered on) are available for `detail`.
    """
    args = ["-json", "-d", str(depth), "-t", "8", "-timeout", "20", "-i", "-s", "-w"]
    stdout, stderr, returncode, duration_s, error = await run_tool(
        "hakrawler", args, stdin_input=f"{url}\n", timeout_s=60
    )

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
            found_url = record.get("URL", "")
            if not found_url:
                continue
            findings.append(Finding(
                type="endpoint",
                target=url,
                detail=(
                    f"url={found_url} source={record.get('Source', 'unknown')} "
                    f"where={record.get('Where', 'unknown')}"
                ),
                severity="info",
                tool_source="hakrawler",
            ))

    result = ToolResult(
        tool="hakrawler",
        command_run=f"echo {url} | hakrawler " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_gf(urls: list[str], pattern: str) -> dict:
    """Filter an already-harvested list of URLs against a gf pattern (xss/sqli/ssrf/lfi/etc).

    LOW risk — genuinely different from every other wrapper in this file: gf does no network
    activity at all. It's a local grep over a URL list you already collected (e.g. from
    run_gau/run_waybackurls/run_katana/run_hakrawler), matching each URL's query-string/path
    shape against a known vulnerability-pattern regex. Call this AFTER a harvesting tool, not
    instead of one — it has nothing to filter without a urls list.

    Valid pattern names (confirmed via `gf -list` against the live install): debug_logic, idor,
    img-traversal, interestingEXT, interestingparams, interestingsubs, jsvar, lfi, rce, redirect,
    sqli, ssrf, ssti, xss. An unknown pattern name returns an explicit error rather than a
    silent empty match list — gf itself only errors with "no such pattern" printed to stdout
    (exit 0), which would otherwise look identical to "ran fine, matched nothing."

    **Environment note**: gf's own binary is non-functional out of the box — a fresh install
    has no patterns in ~/.gf/ at all (`gf -list` empty, every pattern name errors "no such
    pattern", confirmed live 2026-07-19). scripts/phase0_setup.sh's GOTOOLS list only installs
    the binary; the actual pattern JSON files (github.com/1ndianl33t/Gf-Patterns) needed a
    separate step, added to that script this session. If this ever starts returning "unknown
    gf pattern" for everything, ~/.gf/ likely needs repopulating, not a code fix here.
    """
    if pattern not in _GF_PATTERNS:
        return ToolResult(
            tool="gf",
            command_run=f"gf {pattern}",
            raw_output="",
            parsed=[],
            duration_s=0.0,
            error=f"unknown gf pattern {pattern!r} — valid: {sorted(_GF_PATTERNS)}",
        ).model_dump()

    stdin_input = "\n".join(urls) + "\n"
    stdout, stderr, returncode, duration_s, error = await run_tool(
        "gf", [pattern], stdin_input=stdin_input, timeout_s=30
    )

    findings = []
    if stdout:
        for line in stdout.splitlines():
            matched_url = line.strip()
            if not matched_url:
                continue
            findings.append(Finding(
                type=f"gf_{pattern}_match",
                target=matched_url,
                detail=f"matched gf pattern={pattern}",
                severity="info",
                tool_source="gf",
            ))

    result = ToolResult(
        tool="gf",
        command_run=f"gf {pattern} (stdin: {len(urls)} urls)",
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_katana(url: str, depth: int = 2) -> dict:
    """Active JS-aware crawl of a single URL via katana — finds endpoints, forms, APIs.

    MEDIUM risk — unlike run_gau/run_waybackurls, this sends real HTTP
    requests directly to the target as it crawls. Call check_scope on the
    host before this, per ORCHESTRATOR_SYSTEM_PROMPT rule 1, and expect the
    HITL gate to show a plan first (rule 3).

    **Critical scope-safety fix, found via live testing, not assumed
    safe**: katana's default `-fs rdn` (root-domain-name) scope is far more
    permissive than it sounds. Crawling `http://scanme.nmap.org` with
    defaults sent a REAL request (confirmed via a populated `response`
    field in JSONL output) to `nmap.org` itself — a different host than the
    one passed in, just sharing its root/registrable domain. In a real
    bug-bounty program, an authorized subdomain does NOT imply the root
    domain is authorized too; sending traffic to the wrong host is exactly
    the scope violation this whole codebase's check_scope/
    check_policy_compliance/scope-fabrication-gate machinery exists to
    prevent. Every OTHER discovered link (facebook.com, github.com,
    npcap.com, etc., confirmed via the same JSONL inspection) had no
    `response` field at all — those are just extracted href/src references,
    never actually fetched, which is normal, safe crawler behavior. Fixed
    by passing `-fs fqdn` (exact host match) instead of the default —
    verified live this restricts every actual HTTP request to precisely
    the host passed in, nothing broader.

    Passes `-omit-raw -omit-body` to keep output lean (default JSONL embeds
    full request/response bodies, including entire HTML/CSS/JS payloads —
    verified live this bloats every single line unnecessarily; `parsed`
    findings only need the endpoint, method, tag, and status). `-rate-limit`
    set from settings.MAX_REQ_PER_SEC, same policy as every other
    target-facing wrapper. Single URL per call, not a batch — matches
    run_nmap/run_gau's single-target precedent.

    Not every discovered endpoint actually gets requested at the crawl's
    depth boundary — those entries have no `response` field/status_code
    either (same shape as the intentionally-unfetched external links
    above), so status_code shows as `unfetched` rather than a number.
    """
    args = ["-u", url, "-jsonl", "-silent", "-depth", str(depth), "-fs", "fqdn",
             "-omit-raw", "-omit-body", "-rate-limit", str(settings.MAX_REQ_PER_SEC),
             "-timeout", "10"]
    stdout, stderr, returncode, duration_s, error = await run_tool("katana", args, timeout_s=90)

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
            request = record.get("request", {})
            endpoint = request.get("endpoint", "")
            if not endpoint:
                continue
            response = record.get("response", {})
            findings.append(Finding(
                type="endpoint",
                target=url,
                detail=(
                    f"url={endpoint} method={request.get('method', 'GET')} "
                    f"tag={request.get('tag', 'seed')} "
                    f"status={response.get('status_code', 'unfetched')}"
                ),
                severity="info",
                tool_source="katana",
            ))

    result = ToolResult(
        tool="katana",
        command_run="katana " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_paramspider(domain: str) -> dict:
    """Mine historical URLs with query parameters for a domain from the Wayback Machine.

    LOW risk — same classification as run_gau/run_waybackurls: queries the Wayback Machine's
    CDX API directly (web.archive.org), never the target itself.

    Different value than run_gau/run_waybackurls despite the overlapping data source: this
    tool specifically extracts and normalizes the QUERY PARAMETERS from historical URLs
    (replacing each value with a placeholder, default "FUZZ") — useful as direct input to
    run_gf (pattern matching against likely-vulnerable params) or a future fuzzer, rather than
    a flat URL list.

    **Verified live 2026-07-19**: confirmed real `-d`/`-s` flags. Passes `-s` (stream to
    stdout) unconditionally — without it, paramspider writes ONLY to a file with no stdout
    output until the very end, which this wrapper has no way to read otherwise.

    **A real quirk found and worked around, not a code bug in this wrapper**: paramspider
    writes a `results/<domain>.txt` file relative to the process's CURRENT WORKING DIRECTORY —
    unlike XSStrike/Corsy (git-cloned Python tools elsewhere in this codebase), which locate
    their own data files via `sys.path[0]` regardless of cwd. Left alone, every call would
    litter a `results/` folder into wherever this project's process runs from. Worked around
    with `run_tool(..., cwd=<tempfile.TemporaryDirectory()>)` — same pattern run_amass already
    uses for its own file-based (`-oA`) output — so the stray file lands somewhere disposable
    and is cleaned up automatically when the wrapper returns.

    **Known upstream data-quality issue, not filtered out**: the Wayback CDX archive itself
    occasionally contains malformed concatenated-URL garbage (confirmed live: one result for
    `scanme.nmap.org` was literally `http://scanme.nmap.org/http://blog.taddong.com/...`, an
    archive artifact, not a real endpoint on the target). Findings are passed through as-is;
    a caller feeding these into run_gf or a fuzzer should expect the occasional garbage entry,
    same as any other Wayback-sourced wrapper here.
    """
    with tempfile.TemporaryDirectory() as tmp_cwd:
        stdout, stderr, returncode, duration_s, error = await run_tool(
            _PARAMSPIDER_BIN, ["-d", domain, "-s"], timeout_s=90, cwd=tmp_cwd
        )

    findings = []
    if stdout:
        for line in stdout.splitlines():
            url = line.strip()
            if not url or url.startswith(("[", "_", "/", "\\")) or "with <3" in url:
                continue  # skip paramspider's own banner/log lines, not a URL
            if "?" not in url:
                continue
            findings.append(Finding(
                type="historical_param_url",
                target=domain,
                detail=url,
                severity="info",
                tool_source="paramspider",
            ))

    result = ToolResult(
        tool="paramspider",
        command_run=f"paramspider -d {domain} -s",
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()
