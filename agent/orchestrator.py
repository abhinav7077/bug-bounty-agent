"""Wires prompts (Type 1), payload knowledge (Type 2), and callable skills
(Type 3) into a single LangGraph agent.

Tool wrappers from tools/*.py (run_subfinder, run_nuclei, etc.) land here as
Phase 2 progresses — run_subfinder is the first one; the rest are still
commented-out imports below, added one at a time as each gets built.

`agent` below is a raw create_react_agent — useful for free-form multi-tool
reasoning, but it has no per-step HITL gate. The actual terminal entrypoint
(main.py) drives agent/graph.py instead, which calls agent/planner.py for a
single structured plan, gates it through agent/hitl.py, and only then
executes one tool from ALL_TOOLS by name — that's what enforces the
approve/reject/modify pause the plan calls for. ALL_TOOLS is imported by
agent/graph.py for that lookup.
"""
from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent

from config.prompts import ORCHESTRATOR_SYSTEM_PROMPT
from config.settings import settings

# -- Callable skills (Type 3) --
from skills.scope_parser import check_scope, parse_scope_policy
from skills.policy_compliance import check_policy_compliance
from skills.chain_analyzer import analyze_chains
from skills.business_logic_mapper import map_business_logic
from skills.poc_builder import build_poc
from skills.bypass import get_waf_bypasses
from skills.diff_tracker import diff_against_last_scan
from skills.confidence_scorer import score_finding_confidence
from skills.roi_prioritizer import prioritize_targets
from skills.eligibility_filter import check_eligibility, queue_for_retest, get_retest_queue
from skills.auth_mapper import check_jwt_weaknesses, check_idor, map_auth_flow
from skills.tech_analyzer import analyze_tech, select_nuclei_tags
from skills.graphql_mapper import introspect_graphql, check_graphql_idor
from skills.cve_lookup import lookup_cves
from skills.recon_query_builder import build_recon_queries
from skills.hacktivity_checker import build_hacktivity_search
from skills.vuln_assessor import assess_findings
from skills.waf_bypass_prober import probe_waf_bypass
from skills.report_generator import generate_report
from agent.memory import query_similar_findings

# skills.jwt_toolkit and tools.response_fingerprint are deliberately NOT
# imported here either — plain-function helper modules with no @tool
# functions, consumed by skills.auth_mapper only. See their own docstrings.
# skills.hitl_batcher is deliberately NOT imported here — it has no @tool
# functions. It's a plain-function helper for agent/hitl.py's approval UX,
# not something the model calls.

# -- Tool wrappers (Phase 2) --
from tools.recon import run_subfinder, run_amass, run_httpx, run_naabu, run_nmap, run_dnsx, run_tlsx
from tools.url_harvest import run_gau, run_waybackurls, run_katana, run_hakrawler, run_gf, run_paramspider
from tools.scanner import run_nuclei, run_nikto, run_wapiti, run_corsy, run_smuggler, run_testssl, run_wpscan
from tools.vuln_specific import (
    run_dalfox, run_kxss, run_xsstrike, run_sqlmap, run_ghauri, run_subjack, run_subzy,
)
from tools.secrets import run_trufflehog, run_gitleaks, run_secretfinder
from tools.cloud import run_s3scanner, run_cloud_enum
from tools.api import (
    run_kiterunner, run_arjun, run_ffuf, interactsh_start, interactsh_poll, interactsh_stop,
)

ALL_TOOLS = [
    # Scope & policy — always checked first, per ORCHESTRATOR_SYSTEM_PROMPT rules 1 & 8.
    # parse_scope_policy runs before check_scope: it turns raw scope text into the exact
    # ScopePolicy dict check_scope needs, so the model passes that dict straight through
    # instead of freehanding one from memory (see skills/scope_parser.py's docstring — models
    # reliably get ScopePolicy's nested field names wrong when asked to construct it directly).
    parse_scope_policy,
    check_scope,
    check_policy_compliance,
    # Recon prioritization
    diff_against_last_scan,
    get_retest_queue,
    prioritize_targets,
    # Recon tool wrappers (Phase 2)
    run_subfinder,
    run_amass,
    run_httpx,
    run_naabu,
    run_nmap,
    run_dnsx,
    run_tlsx,
    run_gau,
    run_waybackurls,
    run_katana,
    run_hakrawler,
    run_gf,
    run_paramspider,
    # Active scanners (Phase 2)
    run_nuclei,
    run_nikto,
    run_wapiti,
    run_corsy,
    run_smuggler,
    run_testssl,
    run_wpscan,
    run_dalfox,
    run_kxss,
    run_xsstrike,
    run_sqlmap,
    run_ghauri,
    run_subjack,
    run_subzy,
    run_trufflehog,
    run_gitleaks,
    run_secretfinder,
    run_s3scanner,
    run_cloud_enum,
    run_kiterunner,
    run_arjun,
    run_ffuf,
    interactsh_start,
    interactsh_poll,
    interactsh_stop,
    # Vuln assessment skills
    analyze_chains,
    map_business_logic,
    score_finding_confidence,
    assess_findings,
    probe_waf_bypass,
    generate_report,
    check_jwt_weaknesses,
    check_idor,
    map_auth_flow,
    analyze_tech,
    select_nuclei_tags,
    introspect_graphql,
    check_graphql_idor,
    lookup_cves,
    build_recon_queries,
    build_hacktivity_search,
    query_similar_findings,
    # Eligibility & payout optimization — run before reporting, not after
    check_eligibility,
    queue_for_retest,
    # Reporting skills
    build_poc,
    get_waf_bypasses,
    # More tool wrappers get appended here as Phase 2 continues:
    # run_nuclei, run_nikto, run_dalfox, run_sqlmap,
]

llm = ChatOllama(
    base_url=settings.OLLAMA_BASE_URL,
    model=settings.OLLAMA_MODEL,
    temperature=settings.LLM_TEMPERATURE,
    num_ctx=settings.OLLAMA_NUM_CTX,
)

agent = create_react_agent(
    model=llm,
    tools=ALL_TOOLS,
    prompt=ORCHESTRATOR_SYSTEM_PROMPT,
)
