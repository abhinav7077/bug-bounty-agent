"""CVE lookup against NVD (description/CVSS) cross-referenced with CISA's
Known Exploited Vulnerabilities (KEV) catalog. Closes
docs/DEVELOPMENT_PLAN.md's Phase 3 Tier 3 "CVE lookup skill" item.

LOW risk — every request goes to NVD/CISA's own public infrastructure, never
the actual bug-bounty target, same reasoning that keeps run_subfinder/run_gau
LOW despite being "active" HTTP requests. Uses tools/http_client.send_request
for convenience/consistency, not because NVD/CISA needs the same rate-limit
policy as a hunted target — NVD's own public (no-API-key) rate limit is
roughly 5 requests/30s, well under what one lookup call here ever needs.

**Verified live 2026-07-22** against both real endpoints: NVD's
`keywordSearch` param and response shape (`vulnerabilities[].cve.{id,
descriptions, metrics.cvssMetricV31/V2}`), and CISA's KEV JSON feed shape
(`vulnerabilities[].{cveID, vendorProject, product, vulnerabilityName,
dateAdded, shortDescription}`) — confirmed against `keywordSearch=wordpress`
and the live KEV catalog (1651 entries as of this writing).
"""
import json

from langchain_core.tools import tool

from tools.base import Finding, ToolResult
from tools.http_client import send_request

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_MAX_RESULTS = 15


def _extract_severity(cve: dict) -> tuple[float | None, str]:
    metrics = cve.get("metrics", {})
    # Prefer the newest CVSS version present; older CVEs often only have v2.
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            entry = entries[0]
            # v3.x nests baseSeverity inside cvssData; v2 puts it as a sibling of
            # cvssData instead (confirmed live 2026-07-22 against a real NVD
            # response — the first version of this function only checked the
            # v3.x location and silently reported "unknown" for every CVSSv2-only
            # CVE, which is most pre-2016 entries).
            data = entry["cvssData"]
            severity = data.get("baseSeverity") or entry.get("baseSeverity", "unknown")
            return data.get("baseScore"), severity
    return None, "unknown"


@tool
async def lookup_cves(product: str, version: str = "") -> dict:
    """Look up known CVEs for a detected product/version against NVD, flagging any
    that CISA's KEV catalog lists as actively exploited in the wild.

    LOW risk — queries NVD and CISA's own public feeds, never the actual
    target. Pass fields from analyze_tech's TechProfile (cms/framework) as
    `product`, and any version string observed in headers/banners/error
    pages as `version`. A KEV-listed CVE is reported CRITICAL regardless of
    its own CVSS score — active in-the-wild exploitation is a stronger
    real-world signal than a static severity number.
    """
    query = f"{product} {version}".strip()
    resp = await send_request(
        "GET", _NVD_URL, params={"keywordSearch": query, "resultsPerPage": str(_MAX_RESULTS)},
        timeout_s=30,
    )
    if resp.error or resp.status != 200:
        return ToolResult(
            tool="lookup_cves", command_run=f"lookup_cves({query!r})", raw_output=resp.body[:500],
            parsed=[], duration_s=resp.elapsed_ms / 1000,
            error=resp.error or f"NVD returned status {resp.status}",
        ).model_dump()

    try:
        nvd_data = json.loads(resp.body)
    except ValueError:
        nvd_data = {}

    kev_resp = await send_request("GET", _KEV_URL, timeout_s=30)
    kev_by_id: dict[str, dict] = {}
    if not kev_resp.error and kev_resp.status == 200:
        try:
            kev_by_id = {v["cveID"]: v for v in json.loads(kev_resp.body).get("vulnerabilities", [])}
        except (ValueError, KeyError):
            pass

    findings: list[Finding] = []
    for entry in nvd_data.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "unknown")
        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
        )
        score, severity = _extract_severity(cve)
        kev_entry = kev_by_id.get(cve_id)

        if kev_entry:
            findings.append(Finding(
                type="cve_actively_exploited", target=product, detail=(
                    f"{cve_id} (CVSS {score}/{severity}) — ACTIVELY EXPLOITED per CISA KEV, "
                    f"added {kev_entry.get('dateAdded')}: {kev_entry.get('vulnerabilityName')}. "
                    f"{description[:300]}"
                ),
                severity="critical", tool_source="cve_lookup",
            ))
        else:
            findings.append(Finding(
                type="cve_candidate", target=product,
                detail=f"{cve_id} (CVSS {score}/{severity}): {description[:300]}",
                severity=(severity or "unknown").lower(), tool_source="cve_lookup",
            ))

    return ToolResult(
        tool="lookup_cves", command_run=f"lookup_cves({query!r})",
        raw_output=resp.body[:2000], parsed=findings,
        duration_s=resp.elapsed_ms / 1000, error=None,
    ).model_dump()
