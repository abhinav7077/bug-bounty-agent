"""Per-target hunt memory — diff this scan against the last one.

Re-scanning a program cold every session wastes LLM/tool time rediscovering
assets that haven't changed. This stores a lightweight snapshot per target
under sessions/<target>/snapshot.json and diffs the current pass against it,
so new/changed surface gets prioritized instead of re-treading old ground.
"""
import hashlib
import json
from pathlib import Path

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from config.settings import settings


class DiffResult(BaseModel):
    new_assets: list[str] = Field(default_factory=list)
    removed_assets: list[str] = Field(default_factory=list)
    changed_js: list[str] = Field(default_factory=list)
    unchanged_count: int = 0
    is_first_scan: bool = False


def _snapshot_path(target: str) -> Path:
    return Path(settings.SESSIONS_DIR) / target / "snapshot.json"


def _hash_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()


@tool
def diff_against_last_scan(target: str, current_assets: list[str], js_contents: dict | None = None) -> dict:
    """Compare this scan's asset list against the last stored snapshot for this target.

    Call this once recon has produced a subdomain/endpoint list, before
    deciding what to prioritize. js_contents is an optional {url: raw_js_text}
    map — JS bundles get content-hashed so a redeploy under the same URL still
    shows up as changed_js. Always call this before running the full tool
    suite on a previously-seen target; spend time on new_assets and
    changed_js first, not the whole list again.
    """
    js_contents = js_contents or {}
    path = _snapshot_path(target)
    current_set = set(current_assets)
    current_js_hashes = {url: _hash_content(content) for url, content in js_contents.items()}

    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"assets": sorted(current_set), "js_hashes": current_js_hashes}, indent=2))
        return DiffResult(new_assets=sorted(current_set), is_first_scan=True).model_dump()

    previous = json.loads(path.read_text())
    previous_set = set(previous.get("assets", []))
    previous_js_hashes = previous.get("js_hashes", {})

    new_assets = sorted(current_set - previous_set)
    removed_assets = sorted(previous_set - current_set)
    changed_js = sorted(
        url for url, h in current_js_hashes.items()
        if url in previous_js_hashes and previous_js_hashes[url] != h
    )
    unchanged_count = len(current_set & previous_set)

    path.write_text(json.dumps({"assets": sorted(current_set), "js_hashes": current_js_hashes}, indent=2))

    return DiffResult(
        new_assets=new_assets,
        removed_assets=removed_assets,
        changed_js=changed_js,
        unchanged_count=unchanged_count,
    ).model_dump()
