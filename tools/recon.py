"""Recon tool wrappers — Phase 2.

Each wrapper returns the same ToolResult shape as every skills/*.py tool
(see tools/base.py), so the LLM calls tool wrappers and skills identically.
"""
import json
import re
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from langchain_core.tools import tool

from config.settings import settings
from tools.base import Finding, ToolResult, run_tool


@tool
async def run_subfinder(domain: str) -> dict:
    """Passive subdomain enumeration via subfinder.

    LOW risk — subfinder only queries public certificate-transparency/OSINT
    sources, it never sends a request to the target domain itself. Call
    check_scope on the domain before this, per ORCHESTRATOR_SYSTEM_PROMPT
    rule 1, even though this specific tool is passive.

    Passes -timeout 20 (per-source, subfinder's own flag) rather than
    relying only on tools/base.py's outer process timeout — verified live
    that with many default sources enabled, a couple of slow/unresponsive
    ones can otherwise drag total wall-clock past 90s before any output
    appears at all, which is a bad experience inside an interactive HITL loop.
    """
    args = ["-d", domain, "-silent", "-json", "-timeout", "20"]
    stdout, stderr, returncode, duration_s, error = await run_tool("subfinder", args)

    findings = []
    if stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                subdomain = record.get("host", "")
            except json.JSONDecodeError:
                subdomain = line  # plain-text fallback if -json output shape changes
            if subdomain:
                findings.append(Finding(
                    type="subdomain",
                    target=subdomain,
                    detail=f"discovered via subfinder for {domain}",
                    severity="info",
                    tool_source="subfinder",
                ))

    result = ToolResult(
        tool="subfinder",
        command_run="subfinder " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


_AMASS_LINE_RE = re.compile(r"^(.+?) \(FQDN\) --> (\w+) --> (.+?) \(FQDN\)$")


@tool
async def run_amass(domain: str) -> dict:
    """OSINT subdomain enumeration via amass — different data sources than run_subfinder.

    LOW risk — passes -passive, which only queries third-party OSINT
    sources, same rationale as run_subfinder. (amass also has an -active
    mode that attempts zone transfers and certificate grabs directly
    against the target's own nameservers — deliberately not used here;
    that would need its own MEDIUM-classified wrapper if ever added.)

    Unlike every other Phase 2 wrapper so far, amass v4 produces NO stdout
    output at all when run non-interactively — verified live, twice, with
    and without -silent: its terminal UI is apparently designed only for a
    real TTY and emits nothing when piped/redirected, not even a banner.
    Results only ever land in a file via -oA (a text relationship graph:
    "subject (FQDN) --> relation_type --> object (FQDN)" per line) — this
    wrapper writes that to a temp directory, reads it back after run_tool()
    returns, and cleans up, rather than relying on stdout like every other
    wrapper here does.

    Also markedly slower than run_subfinder, AND unpredictably so — three
    live runs against the identical target (hackerone.com) took ~95s, then
    timed out past 150s with zero results, then finished at ~137s. Runtime
    depends on however long amass's own upstream OSINT sources take to
    respond, which varies run to run; there's no way to predict it up
    front. This matters more here than for any other wrapper: results only
    exist in the -oA FILE, not stdout, so run_tool()'s 2026-07-19
    partial-output-on-timeout fix (which drains stdout/stderr incrementally
    and tries SIGTERM before SIGKILL) doesn't directly help here the way it
    does for run_gau/run_waybackurls — whether amass flushes -oA on SIGTERM
    rather than SIGKILL is NOT verified, so a run that times out should
    still be assumed to have lost its results until that's confirmed live.
    Passes -timeout 2 (amass's own flag, in MINUTES, not seconds like every
    other tool wrapped so far) and overrides run_tool()'s default subprocess
    timeout to 180s for headroom — even that is a "usually enough" margin,
    not a guarantee.
    """
    findings = []
    with tempfile.TemporaryDirectory() as tmpdir:
        out_prefix = str(Path(tmpdir) / "amass_out")
        args = ["enum", "-passive", "-d", domain, "-timeout", "2", "-silent", "-oA", out_prefix]
        stdout, stderr, returncode, duration_s, error = await run_tool("amass", args, timeout_s=180)

        out_file = Path(f"{out_prefix}.txt")
        if not error and out_file.exists():
            raw_output = out_file.read_text()
            seen = set()
            for line in raw_output.splitlines():
                match = _AMASS_LINE_RE.match(line.strip())
                if not match:
                    continue
                subject, relation, obj = match.groups()
                for fqdn in (subject, obj):
                    fqdn = fqdn.lower().rstrip(".")
                    if fqdn in seen or fqdn == domain.lower():
                        continue
                    seen.add(fqdn)
                    findings.append(Finding(
                        type="subdomain",
                        target=fqdn,
                        detail=f"discovered via amass for {domain} ({relation})",
                        severity="info",
                        tool_source="amass",
                    ))
        else:
            raw_output = stdout

    result = ToolResult(
        tool="amass",
        command_run="amass " + " ".join(args),
        raw_output=raw_output or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_httpx(domains: list[str]) -> dict:
    """Probe hosts for liveness, status, title, and tech stack via httpx.

    MEDIUM risk — unlike run_subfinder, this sends a real HTTP request to
    every domain passed in. Call check_scope on each domain before this, per
    ORCHESTRATOR_SYSTEM_PROMPT rule 1, and expect the HITL gate to show a
    plan before this runs (rule 3).

    Pass every domain from a run_subfinder result (or any other source) in
    one call via -u repeated per-host, rather than one call per domain —
    verified live that httpx accepts -u multiple times with no stdin needed,
    and this keeps the whole batch under one HITL approval instead of one
    per host. -rate-limit is set from settings.MAX_REQ_PER_SEC (httpx
    defaults to 150 req/s, far above ORCHESTRATOR_SYSTEM_PROMPT rule 4's
    10 req/s cap) — this is the first tool wrapper that actually sends
    traffic, so it's also the first place that rule is enforced in code
    rather than just stated in the prompt, matching the precedent set by
    skills/confidence_scorer.py for the repro-count rule.

    A host that doesn't resolve or respond is silently omitted by httpx
    (-silent), not returned as an error — verified live against a
    non-resolving domain (exit 0, empty stdout). Dead hosts just don't
    appear in parsed, they aren't a wrapper-level failure.
    """
    args = ["-json", "-silent", "-status-code", "-title", "-tech-detect", "-follow-redirects",
             "-timeout", "10", "-rate-limit", str(settings.MAX_REQ_PER_SEC)]
    for domain in domains:
        args += ["-u", domain]
    stdout, stderr, returncode, duration_s, error = await run_tool("httpx", args)

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
            host = record.get("input", record.get("host", ""))
            if not host:
                continue
            detail = (
                f"status={record.get('status_code', '?')} "
                f"title={record.get('title', '')!r} "
                f"tech={record.get('tech', [])} "
                f"final_url={record.get('final_url', record.get('url', ''))}"
            )
            findings.append(Finding(
                type="live_host",
                target=host,
                detail=detail,
                severity="info",
                tool_source="httpx",
            ))

    result = ToolResult(
        tool="httpx",
        command_run="httpx " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_naabu(hosts: list[str], top_ports: str = "100") -> dict:
    """Port scan via naabu (CONNECT scan — no raw-socket privileges needed).

    MEDIUM risk — sends a real TCP connection attempt to every port probed
    on every host. Call check_scope on each host before this, per
    ORCHESTRATOR_SYSTEM_PROMPT rule 1, and expect the HITL gate to show a
    plan first (rule 3). top_ports must be one of naabu's own presets —
    "100", "1000", or "full" — NOT an arbitrary integer; verified live that
    e.g. "20" is rejected outright ("could not parse ports: invalid top
    ports option").

    Passes -Pn (skip host discovery) unconditionally — verified live in this
    environment that naabu's default ICMP-based host-discovery probe hangs
    indefinitely (raw TCP connects work fine, confirmed separately with
    `/dev/tcp`; ICMP specifically does not), so every scan without -Pn timed
    out with zero output. A dead host just returns no open ports either way,
    so skipping discovery costs nothing correctness-wise, only the
    already-broken speed optimization.

    -rate is set from settings.MAX_REQ_PER_SEC, same as run_httpx's
    -rate-limit — naabu defaults to 1000 packets/s, far above
    ORCHESTRATOR_SYSTEM_PROMPT rule 4's 10/s cap. This makes port scanning
    inherently slow (unlike run_httpx, which only sends one request per
    host regardless of rate limit): measured live at rate=10, top-ports=100,
    naabu's default -retries 3 took ~62s for ONE host, since a "retry" here
    re-scans every port again rather than just non-responsive ones. Passes
    -retries 1 instead (~23s/host measured) as a deliberate speed/reliability
    tradeoff — one retry still catches most transient packet loss, three
    does not scale under a mandated 10 pps cap. tools/base.py's default 120s
    subprocess timeout is overridden to 300s here to accommodate a several-
    host batch at this rate; still finite, so don't pass dozens of hosts in
    one call — split into smaller batches instead.

    naabu still reports the same open (host, port) more than once even at
    -retries 1 (verified live — each confirming attempt re-emits a JSON
    line), so results are deduped here before building findings; the raw
    duplicate lines are still preserved in raw_output for anyone who wants
    the unfiltered view.
    """
    args = ["-json", "-silent", "-top-ports", top_ports, "-Pn", "-retries", "1",
             "-rate", str(settings.MAX_REQ_PER_SEC), "-host", ",".join(hosts)]
    stdout, stderr, returncode, duration_s, error = await run_tool("naabu", args, timeout_s=300)

    findings = []
    seen = set()
    if stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip a malformed line rather than losing the whole batch
            host = record.get("host", "")
            port = record.get("port")
            if not host or port is None:
                continue
            key = (host, port)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                type="open_port",
                target=host,
                detail=f"port={port} protocol={record.get('protocol', 'tcp')} tls={record.get('tls', False)}",
                severity="info",
                tool_source="naabu",
            ))

    result = ToolResult(
        tool="naabu",
        command_run="naabu " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_nmap(host: str, ports: str) -> dict:
    """Service/version detection via nmap, on ports already found open by run_naabu.

    MEDIUM risk — sends real TCP connections plus service/version probes to
    the target. Call check_scope on the host before this, per
    ORCHESTRATOR_SYSTEM_PROMPT rule 1, and expect the HITL gate to show a
    plan first (rule 3).

    Deliberately scoped, not a blind sweep: `ports` is nmap's own -p syntax
    (e.g. "22,80,443" or "1-1024") and is meant to be the open-port list
    run_naabu already found for this host — nmap's -sV version probing is
    far more expensive per port than naabu's plain connect check, so
    narrowing to known-open ports first (naabu) then depth-probing them
    (nmap) is much cheaper than nmap scanning a wide range blind.

    Uses -sT (TCP connect scan), not -sS (SYN scan) — verified live this
    machine has no root/setcap access for raw sockets (confirmed via `id`:
    no CAP_NET_RAW), and -sT needs neither. Passes -Pn: verified live,
    unlike run_naabu's naabu binary, nmap's own default host-discovery here
    does NOT hang (it falls back to a TCP-based probe rather than pure ICMP
    when unprivileged) — -Pn is used purely as a speed optimization since
    the caller already knows the host is alive from a prior
    run_naabu/run_httpx call, not a hang workaround like naabu needed.
    --max-rate is set from settings.MAX_REQ_PER_SEC, same policy as
    run_httpx/run_naabu.

    Parses nmap's XML output (-oX -) with the stdlib xml.etree.ElementTree —
    no new dependency needed. A host nmap can't reach still returns
    normally with zero open ports in `parsed`, not a wrapper-level error.
    """
    args = ["-sT", "-sV", "-Pn", "-p", ports, "--max-rate", str(settings.MAX_REQ_PER_SEC),
             "-oX", "-", host]
    stdout, stderr, returncode, duration_s, error = await run_tool("nmap", args, timeout_s=180)

    findings = []
    if not error and stdout.strip():
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError:
            root = None
        if root is not None:
            for host_el in root.findall("host"):
                # `host` (the caller's own input), not nmap's resolved address/PTR name —
                # every other wrapper's Finding.target is the identifier the caller asked
                # about, verified live this returned an IP here otherwise, which broke that
                # convention and would confuse downstream correlation (diff_tracker,
                # check_scope, etc. all key off hostnames, not resolved IPs).
                for port_el in host_el.findall("ports/port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    port_id = port_el.get("portid")
                    service_el = port_el.find("service")
                    service = service_el.get("name", "") if service_el is not None else ""
                    product = service_el.get("product", "") if service_el is not None else ""
                    version = service_el.get("version", "") if service_el is not None else ""
                    extrainfo = service_el.get("extrainfo", "") if service_el is not None else ""
                    findings.append(Finding(
                        type="service",
                        target=host,
                        detail=(
                            f"port={port_id} service={service} product={product} "
                            f"version={version} extrainfo={extrainfo}"
                        ).strip(),
                        severity="info",
                        tool_source="nmap",
                    ))

    result = ToolResult(
        tool="nmap",
        command_run="nmap " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_dnsx(domains: list[str]) -> dict:
    """DNS record enumeration (A, AAAA, CNAME, NS, MX, TXT) via dnsx.

    LOW risk — same classification rationale as run_subfinder: dnsx queries
    public third-party DNS resolvers (Cloudflare/Google/Quad9/etc., visible
    in each result's "resolver" field), not the target's own infrastructure.
    Still call check_scope first per ORCHESTRATOR_SYSTEM_PROMPT rule 1 —
    LOW just means it auto-proceeds rather than waiting for approval, not
    that scope doesn't apply.

    Pass every domain to resolve in one call via -l with a comma-separated
    string (verified live that dnsx accepts this directly, no stdin or file
    needed) rather than one call per domain, same batching reasoning as
    run_httpx's -u. No rate-limit flag applies here (dnsx has no -rate
    option, only -threads for concurrency) — DNS resolution through public
    resolvers isn't the kind of target-facing traffic
    ORCHESTRATOR_SYSTEM_PROMPT rule 4 is about.

    TXT records are returned verbatim, including SPF/domain-verification
    strings — useful for policy_compliance's SPF/DKIM checks and for
    spotting which third-party services (Google, Slack, Stripe, ...) a
    target has verified ownership with.
    """
    args = ["-l", ",".join(domains), "-a", "-aaaa", "-cname", "-ns", "-mx", "-txt",
             "-json", "-silent"]
    stdout, stderr, returncode, duration_s, error = await run_tool("dnsx", args)

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
            host = record.get("host", "")
            if not host:
                continue
            for record_type in ("a", "aaaa", "cname", "ns", "mx", "txt"):
                for value in record.get(record_type, []) or []:
                    findings.append(Finding(
                        type="dns_record",
                        target=host,
                        detail=f"type={record_type.upper()} value={value}",
                        severity="info",
                        tool_source="dnsx",
                    ))

    result = ToolResult(
        tool="dnsx",
        command_run="dnsx " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()


@tool
async def run_tlsx(hosts: list[str]) -> dict:
    """TLS certificate analysis via tlsx — expiry, SANs, issuer, cipher.

    MEDIUM risk — unlike run_dnsx, this opens a real TLS connection directly
    to the target on port 443 (a TCP handshake plus a TLS handshake, not a
    third-party lookup). Call check_scope on each host before this, per
    ORCHESTRATOR_SYSTEM_PROMPT rule 1, and expect the HITL gate to show a
    plan first (rule 3).

    Pass every host in one call via -u with a comma-separated string
    (verified live, same as run_httpx's batching reasoning). No rate-limit
    flag applies — tlsx has no -rate option (confirmed via -h, only a
    per-connection -timeout), and one handshake per host is the same
    lightweight profile as run_httpx, not run_naabu's per-port volume.

    Deliberately does NOT pass -expired/-self-signed/-wildcard-cert/
    -mismatched: verified live these didn't change which hosts appeared or
    add distinct fields when combined with -json (e.g. wildcard_certificate
    was already present when true with no flag at all) — their documented
    wording ("display host with X certificate") reads like a text-mode
    display filter, and passing them speculatively risked silently
    dropping non-matching hosts from a JSON batch. Expiry is computed here
    instead, directly from the certificate's own not_after field, which is
    unambiguous.

    A host that doesn't serve TLS on port 443 is silently omitted (verified
    live against scanme.nmap.org, which has no HTTPS listener — it simply
    never appears in the output), same non-error-for-a-dead-target pattern
    as run_httpx/run_naabu.
    """
    args = ["-u", ",".join(hosts), "-json", "-silent"]
    stdout, stderr, returncode, duration_s, error = await run_tool("tlsx", args)

    findings = []
    if stdout:
        now = datetime.now(timezone.utc)
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip a malformed line rather than losing the whole batch
            host = record.get("host", "")
            if not host:
                continue

            not_after = record.get("not_after", "")
            expiry_note = "unknown"
            severity = "info"
            try:
                expires_at = datetime.fromisoformat(not_after)
                days_left = (expires_at - now).days
                expiry_note = f"expires in {days_left}d" if days_left >= 0 else f"EXPIRED {-days_left}d ago"
                if days_left < 0:
                    severity = "low"  # per RECON_AGENT_PROMPT's own rule to flag expired certs
            except (ValueError, TypeError):
                pass  # not_after missing/unparseable — leave expiry_note as "unknown"

            findings.append(Finding(
                type="tls_cert",
                target=host,
                detail=(
                    f"cn={record.get('subject_cn', '')} san={record.get('subject_an', [])} "
                    f"issuer={record.get('issuer_cn', '')} tls_version={record.get('tls_version', '')} "
                    f"wildcard={record.get('wildcard_certificate', False)} {expiry_note}"
                ),
                severity=severity,
                tool_source="tlsx",
            ))

    result = ToolResult(
        tool="tlsx",
        command_run="tlsx " + " ".join(args),
        raw_output=stdout or stderr,
        parsed=findings,
        duration_s=duration_s,
        error=error,
    )
    return result.model_dump()
