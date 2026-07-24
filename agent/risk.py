"""Static risk classification for every registered tool — deliberately NOT trusted to the LLM.

Verified live against Ollama on 2026-07-16: the model reliably picks the right
tool and target, but regularly invents args that don't match a tool's real
pydantic schema (e.g. a `scope_policy` key with a `disallowed_domains` field
when `check_scope` actually needs `domain` + `policy.forbidden_domains`) — see
agent/planner.py's docstring. A model that gets tool args wrong on a routine
basis can't be trusted to self-assess something safety-critical like risk
level either, so risk_level is looked up here, never read from the model's
own output.

Every tool registered in ALL_TOOLS must have an explicit entry. Unknown tools
default to HIGH — fail closed, never fail open, per ORCHESTRATOR_SYSTEM_PROMPT
rule 6 ("when unsure, ask the human, never assume").
"""

# The 13 skills were all pure reasoning / local-file / LLM calls — none of
# them send a single request to the actual target, so all were LOW under the
# plan's own definition ("LOW = passive recon, no requests sent to the
# target"). Phase 2's tool wrappers are the first ones that actually touch
# real infrastructure — classify each on arrival, per-tool, based on what it
# actually does, not by copying the previous entry:
#   - LOW: passive recon that queries third-party sources (subfinder, gau,
#     waybackurls, etc.) — no request ever reaches the target itself.
#   - MEDIUM: active scanning that DOES send requests to the target (httpx,
#     naabu, nuclei, nikto, ffuf, etc.) — per ORCHESTRATOR_SYSTEM_PROMPT rule 3.
#   - HIGH: exploit attempts, data modification, or submission (sqlmap in
#     exploit mode, dalfox in blind-XSS-fire mode, anything that writes to
#     the target) — same rule.
_RISK_BY_TOOL = {
    "parse_scope_policy": "LOW",
    "check_scope": "LOW",
    "check_policy_compliance": "LOW",
    "diff_against_last_scan": "LOW",
    "get_retest_queue": "LOW",
    "prioritize_targets": "LOW",
    "analyze_chains": "LOW",
    "map_business_logic": "LOW",
    "score_finding_confidence": "LOW",
    "assess_findings": "LOW",  # pure LLM reasoning over already-collected findings, no requests sent
    # skills/waf_bypass_prober.py — HIGH, not MEDIUM: actively crafts and
    # sends filter-evasion payload variants, same reasoning as check_idor/
    # check_jwt_weaknesses (an active bypass attempt, not passive inspection).
    "probe_waf_bypass": "HIGH",
    # skills/report_generator.py — LOW: reads this project's own local
    # ChromaDB store and writes to reports/<target>/ locally; the LLM call
    # is for narrative text only, no request reaches the actual target.
    "generate_report": "LOW",
    "check_eligibility": "LOW",
    "queue_for_retest": "LOW",
    "build_poc": "LOW",
    "get_waf_bypasses": "LOW",
    # Phase 2 tool wrappers
    "run_subfinder": "LOW",  # passive: queries public CT-log/OSINT sources only, never the target
    "run_httpx": "MEDIUM",  # active: sends a real HTTP request to every domain passed in
    "run_naabu": "MEDIUM",  # active: sends real TCP connection attempts to every port probed
    "run_nmap": "MEDIUM",  # active: sends real TCP connections + service/version probes
    "run_dnsx": "LOW",  # passive: queries public DNS resolvers, never the target's own infra
    "run_tlsx": "MEDIUM",  # active: opens a real TLS connection directly to the target
    "run_gau": "LOW",  # passive: queries Wayback Machine/OTX archives, never the target itself
    "run_waybackurls": "LOW",  # passive: queries the Wayback Machine CDX API, never the target
    "run_katana": "MEDIUM",  # active: crawls and sends real HTTP requests directly to the target
    "run_amass": "LOW",  # passive: queries third-party OSINT sources only (-passive flag)
    "run_hakrawler": "MEDIUM",  # active: crawls and sends real HTTP requests directly to the target
    "run_gf": "LOW",  # no network activity at all: local grep over an already-harvested URL list
    "run_paramspider": "LOW",  # passive: queries the Wayback Machine CDX API, never the target
    "run_nuclei": "MEDIUM",  # active: sends real requests per matched template
    "run_nikto": "MEDIUM",  # active: sends many real requests directly to the target
    "run_wapiti": "MEDIUM",  # active: sends real requests; default modules kept detection-only
    "run_corsy": "MEDIUM",  # active: sends real requests, one per Origin header variant tested
    "run_smuggler": "MEDIUM",  # active: sends real, deliberately malformed framed requests
    "run_testssl": "MEDIUM",  # active: opens real TLS connections directly to the target
    "run_wpscan": "MEDIUM",  # active: sends real requests directly to the target
    "run_dalfox": "MEDIUM",  # active: reflected/DOM XSS probes only, no blind-fire mode enabled
    "run_kxss": "MEDIUM",  # active: sends a real request per parameter to check reflection
    "run_xsstrike": "MEDIUM",  # active: reflected XSS probes only, DOM/headless checks disabled
    "run_sqlmap": "HIGH",  # active SQL injection testing — hardcoded detect-only, still HIGH
    "run_ghauri": "HIGH",  # active SQL injection testing — hardcoded detect-only, still HIGH
    "run_subjack": "MEDIUM",  # active: real HTTP(S) request per domain, read-only fingerprint check
    "run_subzy": "MEDIUM",  # active: real HTTP(S) request per domain, read-only fingerprint check
    "run_trufflehog": "MEDIUM",  # active: clones the target's own git repo over the network
    "run_gitleaks": "LOW",  # no network activity: scans an already-local git repo/directory
    "run_secretfinder": "MEDIUM",  # active: fetches the JS file directly from the target
    "run_s3scanner": "MEDIUM",  # active: real requests to AWS S3, read-only (--dangerous never passed)
    "run_cloud_enum": "MEDIUM",  # active: real DNS/HTTP requests per generated name mutation
    "run_kiterunner": "HIGH",  # active: no rate-limit flag exists, 364k routes incl. non-GET methods
    "run_arjun": "MEDIUM",  # active: sends real requests directly to the target
    "run_ffuf": "MEDIUM",  # active: sends real requests directly to the target
    "interactsh_start": "LOW",  # no target-facing traffic at all — just registers an OOB listener
    "interactsh_poll": "LOW",  # read-only: reads the listener's own local log file
    "interactsh_stop": "LOW",  # local process teardown only, no target-facing action
    # skills/auth_mapper.py — HIGH, not MEDIUM: both forge and replay real auth
    # material against the target to attempt an actual bypass, same reasoning
    # that keeps run_sqlmap/run_ghauri HIGH despite being detect-only.
    "check_jwt_weaknesses": "HIGH",
    "check_idor": "HIGH",
    "map_auth_flow": "LOW",  # pure LLM reasoning over a human-supplied sequence, no requests sent
    # skills/tech_analyzer.py
    "analyze_tech": "MEDIUM",  # active: a handful of real GETs (page + JS files + one probe path)
    "select_nuclei_tags": "LOW",  # pure local lookup, no network at all
    # skills/graphql_mapper.py
    "introspect_graphql": "MEDIUM",  # active: one real POST, but read-only schema introspection
    "check_graphql_idor": "HIGH",  # same reasoning as check_idor — active bypass attempt
    # skills/cve_lookup.py — LOW: every request goes to NVD/CISA's own public
    # infrastructure, never the actual bug-bounty target.
    "lookup_cves": "LOW",
    "build_recon_queries": "LOW",  # pure string building, no network at all
    "build_hacktivity_search": "LOW",  # pure string building, no network at all
    # agent/memory.py — LOW: reads this project's own local ChromaDB store only.
    "query_similar_findings": "LOW",
}

_DEFAULT_RISK = "HIGH"


def risk_level_for(action_name: str) -> str:
    """Look up the fixed risk level for a tool by name. Unclassified -> HIGH."""
    return _RISK_BY_TOOL.get(action_name, _DEFAULT_RISK)
