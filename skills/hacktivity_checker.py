"""Hacktivity duplicate-check helper — closes docs/DEVELOPMENT_PLAN.md's
Phase 3 Tier 3 "duplicate checker" item, at reduced scope from what the
plan's wording implies.

**Verified live 2026-07-22, before writing this, that an automated scraper
isn't reliably buildable**: `https://hackerone.com/hacktivity` is a
client-rendered SPA shell (confirmed — the server response is ~1.6KB with no
report data in it, everything loads via client-side JS after the fact), and
`https://hackerone.com/graphql` — the API that page actually calls — has
introspection disabled in production (confirmed: `{__schema{...}}` returns
`"Field '__schema' doesn't exist on type 'Query'"`). Building a scraper
against that GraphQL API's real query shape would mean reverse-engineering
an undocumented, unstable, frequently-changing private frontend API with no
way to verify it stays correct — the exact kind of unverifiable behavior
this project's own convention says not to ship silently (see MEMORY.md's
"never trust a tool's own docs/defaults" pattern, same principle applied to
an undocumented private API instead of a CLI tool's --help text).

So this builds a search LINK + keyword list for a human to check manually,
not an automated duplicate-checker — an honest, smaller, always-correct tool
beats a scraper that looks automated but silently breaks the next time
HackerOne changes their frontend.
"""
from urllib.parse import quote

from langchain_core.tools import tool

_HACKTIVITY_SEARCH_URL = "https://hackerone.com/hacktivity/overview?queryString={query}"


@tool
def build_hacktivity_search(vuln_type: str, target_name: str) -> dict:
    """Build a HackerOne Hacktivity search link + keyword suggestions to manually
    check for a prior public disclosure of the same bug pattern before submitting.

    LOW risk — no network call; returns a URL for a human to open. NOT an
    automated duplicate checker (see this module's docstring for why one
    isn't reliably buildable against HackerOne's actual frontend API right
    now) — always have a human actually check the link before assuming no
    duplicate exists.
    """
    keywords = [target_name, vuln_type, f"{target_name} {vuln_type}"]
    query = f"{target_name} {vuln_type}".strip()
    return {
        "search_url": _HACKTIVITY_SEARCH_URL.format(query=quote(query)),
        "suggested_keywords": keywords,
        "note": (
            "This is a search link, not an automated check — HackerOne's Hacktivity page "
            "is client-rendered and its GraphQL API has introspection disabled, so there's "
            "no reliable way to scrape it automatically. Open the link and look yourself."
        ),
    }
