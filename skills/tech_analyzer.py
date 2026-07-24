"""Deeper technology fingerprinting than httpx's own tech-detect: reads
headers, cookies, HTML source, and a handful of linked JS files, plus one
deliberately-nonexistent-path probe for a language/framework error-page
signature. Closes docs/DEVELOPMENT_PLAN.md's Phase 3 Tier 2 `tech_analyzer.py`
item. `select_nuclei_tags` in this same file also closes the Tier 3 "nuclei
template selector" item — it's a direct consumer of `TechProfile`, kept next
to it rather than in its own file.
"""
import re

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from tools.base import Finding, ToolResult
from tools.http_client import send_request

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_MAX_JS_FILES = 3

# (signature substring found in headers/body/JS, TechProfile field, value) —
# checked in order, first match per field wins. Deliberately simple substring
# matching, not a scoring system: this is meant to be a cheap, explainable
# second opinion alongside httpx's own tech-detect, not a replacement for it.
_CMS_SIGNATURES = (
    ("wp-content", "wordpress"), ("wp-includes", "wordpress"),
    ("Drupal.settings", "drupal"), ("/sites/default/files", "drupal"),
    ("Joomla!", "joomla"), ("/media/jui/", "joomla"),
    ("Shopify.theme", "shopify"), ("cdn.shopify.com", "shopify"),
    ("magento", "magento"), ("ghost-url", "ghost"),
)
_FRAMEWORK_SIGNATURES = (
    ("__NEXT_DATA__", "next.js"), ("_next/static", "next.js"),
    ("__NUXT__", "nuxt"), ("data-n-head", "nuxt"),
    ("ng-version", "angular"), ("data-reactroot", "react"), ("react-dom", "react"),
    ("id=\"app\"", "vue"), ("v-cloak", "vue"),
    ("csrf-token", "rails"), ("__RAILS_", "rails"),
    ("django", "django"), ("csrfmiddlewaretoken", "django"),
    ("laravel_session", "laravel"), ("<?php", "php"),
)
_LANGUAGE_HEADER_HINTS = (
    ("PHPSESSID", "php"), ("JSESSIONID", "java"), ("ASP.NET_SessionId", "asp.net"),
    ("connect.sid", "node.js"), ("laravel_session", "php"), ("_django_session", "python"),
    (".eclipse.jetty.server.SessionID", "java"),
)
_CLOUD_HEADER_HINTS = (
    ("cf-ray", "cloudflare"), ("x-amz-cf-id", "aws"), ("x-amz-request-id", "aws"),
    ("x-azure-ref", "azure"), ("x-ms-request-id", "azure"),
    ("x-goog-", "gcp"), ("x-served-by", "fastly"),
)
# Language-specific stack-trace fragments on a deliberately-broken path — same
# idea as a real error page giving away the runtime, not an exploit attempt.
_ERROR_LANGUAGE_RE = (
    (re.compile(r"Traceback \(most recent call last\)"), "python"),
    (re.compile(r"at [\w.$]+\([\w.]+\.java:\d+\)"), "java"),
    (re.compile(r"System\.\w+Exception"), ".net"),
    (re.compile(r"Warning:.*in .*\.php on line \d+|Fatal error:.*\.php"), "php"),
    (re.compile(r"/gems/[\w.-]+-\d"), "ruby"),
)
_AUTH_HEADER_RE = re.compile(r"^(Bearer|Basic|Digest|OAuth)\b", re.IGNORECASE)


class TechProfile(BaseModel):
    framework: str = ""
    language: str = ""
    cms: str = ""
    auth_mechanism: str = ""
    cloud_provider: str = ""
    api_type: str = ""
    evidence: list[str] = Field(default_factory=list)


def _first_match(haystack: str, signatures: tuple[tuple[str, str], ...]) -> tuple[str, str] | None:
    for needle, value in signatures:
        if needle.lower() in haystack.lower():
            return needle, value
    return None


@tool
async def analyze_tech(url: str) -> dict:
    """Fingerprint a target's framework/language/CMS/auth/cloud-provider/api-type.

    MEDIUM risk — sends a handful of real GETs (main page, up to 3 linked JS
    files, one deliberately-nonexistent path for an error-page signature).
    Purely observational, nothing destructive. Call check_scope first.

    Deeper than httpx's own tech-detect: reads cookie names, linked JS file
    contents, and an error page's stack-trace shape, not just the Server
    header. Returns a TechProfile plus an `evidence` list explaining exactly
    which signal produced each field, so a human can sanity-check a guess
    rather than trust it blindly.
    """
    profile = TechProfile()
    baseline = await send_request("GET", url)
    if baseline.error:
        return ToolResult(
            tool="analyze_tech", command_run=f"analyze_tech({url})", raw_output="",
            parsed=[], duration_s=baseline.elapsed_ms / 1000, error=baseline.error,
        ).model_dump()

    corpus = baseline.body
    js_bodies: list[str] = []
    for src in _SCRIPT_SRC_RE.findall(baseline.body)[:_MAX_JS_FILES]:
        js_url = src if src.startswith("http") else re.sub(r"/[^/]*$", "", url) + "/" + src.lstrip("/")
        js_resp = await send_request("GET", js_url)
        if not js_resp.error and js_resp.body:
            js_bodies.append(js_resp.body)
    corpus += "\n".join(js_bodies)

    if cms_hit := _first_match(corpus, _CMS_SIGNATURES):
        profile.cms = cms_hit[1]
        profile.evidence.append(f"cms={cms_hit[1]!r} via {cms_hit[0]!r} found in page/JS body")

    if fw_hit := _first_match(corpus, _FRAMEWORK_SIGNATURES):
        profile.framework = fw_hit[1]
        profile.evidence.append(f"framework={fw_hit[1]!r} via {fw_hit[0]!r} found in page/JS body")

    headers_blob = " ".join(f"{k}:{v}" for k, v in baseline.headers.items())
    set_cookie = baseline.headers.get("Set-Cookie", "") or baseline.headers.get("set-cookie", "")
    if lang_hit := _first_match(set_cookie or headers_blob, _LANGUAGE_HEADER_HINTS):
        profile.language = lang_hit[1]
        profile.evidence.append(f"language={lang_hit[1]!r} via cookie/header {lang_hit[0]!r}")

    if cloud_hit := _first_match(headers_blob, _CLOUD_HEADER_HINTS):
        profile.cloud_provider = cloud_hit[1]
        profile.evidence.append(f"cloud_provider={cloud_hit[1]!r} via header containing {cloud_hit[0]!r}")

    www_auth = baseline.headers.get("WWW-Authenticate", "") or baseline.headers.get("www-authenticate", "")
    if www_auth and (m := _AUTH_HEADER_RE.match(www_auth)):
        profile.auth_mechanism = m.group(1).lower()
        profile.evidence.append(f"auth_mechanism={m.group(1).lower()!r} via WWW-Authenticate header")
    elif set_cookie:
        profile.auth_mechanism = "session_cookie"
        profile.evidence.append("auth_mechanism='session_cookie' via Set-Cookie present, no WWW-Authenticate")

    content_type = baseline.headers.get("Content-Type", "") or baseline.headers.get("content-type", "")
    if "graphql" in url.lower() or ('"errors"' in corpus and '"data"' in corpus):
        profile.api_type = "graphql"
    elif "json" in content_type.lower():
        profile.api_type = "rest_json"
    elif "xml" in content_type.lower():
        profile.api_type = "xml_soap"
    if profile.api_type:
        profile.evidence.append(f"api_type={profile.api_type!r} via Content-Type/body shape")

    if not profile.language:
        probe = await send_request("GET", url.rstrip("/") + "/__nonexistent_a9f3x__")
        for pattern, lang in _ERROR_LANGUAGE_RE:
            if pattern.search(probe.body):
                profile.language = lang
                profile.evidence.append(f"language={lang!r} via error-page stack-trace signature")
                break

    finding = Finding(
        type="tech_profile", target=url, detail=profile.model_dump_json(),
        severity="info", tool_source="tech_analyzer",
    )
    return ToolResult(
        tool="analyze_tech", command_run=f"analyze_tech({url})",
        raw_output=baseline.body[:2000], parsed=[finding],
        duration_s=baseline.elapsed_ms / 1000, error=None,
    ).model_dump()


# TechProfile field -> nuclei tag(s). Deliberately conservative: only fires a
# tag when a field gives a real, specific signal — no generic catch-all tags
# added here beyond what run_nuclei's own default already covers.
_NUCLEI_TAG_MAP = {
    "cms": {
        "wordpress": ["wordpress", "wp-plugin"], "drupal": ["drupal"], "joomla": ["joomla"],
        "magento": ["magento"], "shopify": ["shopify"], "ghost": ["ghost"],
    },
    "framework": {
        "next.js": ["nodejs"], "nuxt": ["nodejs"], "angular": ["angular"],
        "react": ["react"], "vue": ["vue"], "rails": ["rails"], "django": ["django"],
        "laravel": ["laravel"], "php": ["php"],
    },
    "cloud_provider": {
        "aws": ["aws", "cloud"], "azure": ["azure", "cloud"], "gcp": ["gcp", "cloud"],
        "cloudflare": ["cloudflare"], "fastly": ["cdn"],
    },
    "language": {
        "php": ["php"], "java": ["java"], ".net": ["dotnet"], "python": ["python"], "ruby": ["ruby"],
    },
}


@tool
def select_nuclei_tags(cms: str = "", framework: str = "", cloud_provider: str = "", language: str = "") -> list[str]:
    """Map an analyze_tech TechProfile's fields to a targeted nuclei -tags value.

    LOW risk — pure local lookup, no network at all. Pass analyze_tech's own
    output fields (cms/framework/cloud_provider/language) straight through.
    Always includes run_nuclei's own baseline tags (cve/exposure/misconfig)
    so this narrows the *additional* targeted tags rather than replacing the
    safe default — pass the combined, deduplicated list to run_nuclei's
    `tags` argument instead of its default when this returns anything beyond
    the baseline.
    """
    tags = {"cve", "exposure", "misconfig"}
    for field_value, group in ((cms, "cms"), (framework, "framework"),
                                (cloud_provider, "cloud_provider"), (language, "language")):
        tags.update(_NUCLEI_TAG_MAP.get(group, {}).get(field_value.lower(), []))
    return sorted(tags)
