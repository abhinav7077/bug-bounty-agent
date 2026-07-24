"""Shodan/Censys query STRING builder — closes docs/DEVELOPMENT_PLAN.md's
Phase 3 Tier 3 "Shodan/Censys query builder" item.

Deliberately does not call either service's API: the plan's own wording is
"query builder", not "run a Shodan scan", and neither API is free (both
require a paid plan for meaningful query volume) — this project has no
Shodan/Censys credentials configured anywhere in config/settings.py, and
adding a hard dependency on paid third-party credentials for a Tier 3 "nice
to have" item isn't justified. Returns ready-to-paste query strings in each
platform's own syntax; the human runs them through whichever service/plan
they actually have.
"""
from langchain_core.tools import tool


@tool
def build_recon_queries(org_name: str = "", asn: str = "", domain: str = "", product: str = "") -> dict:
    """Build Shodan and Censys query strings scoped to a target's org/ASN/domain.

    LOW risk — pure string construction, no network call at all, nothing
    sent anywhere. Pass whatever subset of org_name/asn/domain/product is
    known (e.g. from a WHOIS/ASN lookup or analyze_tech's output); each
    provided field ANDs into both query strings. `asn` should be the bare
    number or the full "ASxxxx" form — both are normalized.
    """
    asn_number = asn.upper().removeprefix("AS").strip() if asn else ""

    shodan_parts = []
    censys_parts = []
    if org_name:
        shodan_parts.append(f'org:"{org_name}"')
        censys_parts.append(f'autonomous_system.organization="{org_name}"')
    if asn_number:
        shodan_parts.append(f"asn:AS{asn_number}")
        censys_parts.append(f"autonomous_system.asn={asn_number}")
    if domain:
        shodan_parts.append(f'hostname:"{domain}"')
        censys_parts.append(f'dns.names="{domain}"')
    if product:
        shodan_parts.append(f'product:"{product}"')
        censys_parts.append(f'services.software.product="{product}"')

    return {
        "shodan_query": " ".join(shodan_parts),
        "censys_query": " and ".join(censys_parts),
        "note": (
            "Query strings only — this project has no Shodan/Censys API credentials "
            "configured, run these through whichever plan/UI the human has access to."
        ) if shodan_parts or censys_parts else "No fields provided — nothing to build a query from.",
    }
