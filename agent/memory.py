"""Long-term cross-session finding memory via ChromaDB — Phase 4's "Session &
Memory" ChromaDB item.

Distinct from agent/session.py's JSON checkpoints and skills/diff_tracker.py's
asset-list diffing: those two answer "what's changed since last time" via
exact string comparison. This answers "have I seen something LIKE this
before" via semantic embedding search — e.g. a new finding's description can
surface a similar one from a different session or even a different-but-
related target, which an exact-match diff can never do.

Uses chromadb's PersistentClient with its bundled default embedding function
(a small local ONNX sentence-transformer, all-MiniLM-L6-v2) — no separate
embedding-model download/config needed, no external API key. First call in a
fresh environment downloads that model (~80MB) once; every call after reuses
the cached one.
"""
import hashlib
from pathlib import Path

import chromadb
from langchain_core.tools import tool

from config.settings import settings

_COLLECTION_NAME = "findings"
_CONFIRMED_COLLECTION_NAME = "confirmed_findings"
_client = None
_client_path = None


def _get_client():
    """Return the cached PersistentClient, rebuilding it if settings.SESSIONS_DIR changed.

    Confirmed live 2026-07-24: caching only on `_client is None` (the
    original version) meant this module never noticed settings.SESSIONS_DIR
    changing within the same process — a second run against a different
    SESSIONS_DIR kept writing to the FIRST run's now-stale (possibly
    deleted) `_chroma` path, surfacing as a "readonly database" error rather
    than picking up the new path. Doesn't matter for a single main.py
    invocation (SESSIONS_DIR is loaded once and never mutated), but bites
    immediately in-process whenever multiple isolated runs share one
    process — exactly the shape any future pytest suite over this file
    would take (tmp_path-scoped fixtures, same process).
    """
    global _client, _client_path
    current_path = str(Path(settings.SESSIONS_DIR) / "_chroma")
    if _client is None or _client_path != current_path:
        _client = chromadb.PersistentClient(path=current_path)
        _client_path = current_path
    return _client


def _get_collection():
    return _get_client().get_or_create_collection(_COLLECTION_NAME)


def save_findings_to_memory(target: str, findings: list[dict]) -> int:
    """Embed and upsert a batch of Finding-shaped dicts for a target. Returns count saved.

    Not an LLM tool — called automatically by agent/recon_pipeline.py after
    each stage, the same way agent/session.py's save_checkpoint() is called
    automatically rather than invoked by the model. IDs are a content hash
    of (finding's own target, type, detail) — NOT the outer `target` param,
    which is the same pipeline-wide domain for every finding in the batch —
    so re-saving an identical finding from a later re-scan upserts in place
    instead of accumulating duplicates, while two DIFFERENT findings that
    merely share a type+detail (e.g. two subdomains both httpx-fingerprinted
    as "status=200 title='' tech=[]") still get distinct IDs. Confirmed live
    2026-07-22: hashing on the outer `target` instead of `f['target']` made
    exactly that collision happen (two subfinder findings, same type,
    identical placeholder detail, different hosts) and chromadb's upsert()
    rejects a batch with any duplicate ID outright.
    """
    return _upsert_findings(_get_collection(), target, findings)


def _upsert_findings(collection, target: str, findings: list[dict]) -> int:
    findings = [f for f in findings if f.get("detail")]
    if not findings:
        return 0

    ids = [
        hashlib.sha256(f"{f.get('target', target)}:{f.get('type', '')}:{f['detail']}".encode()).hexdigest()
        for f in findings
    ]
    documents = [f"{f.get('type', 'finding')} on {target}: {f['detail']}" for f in findings]
    metadatas = [
        {
            "target": target,
            "type": f.get("type", ""),
            "detail": f["detail"],  # kept as its own field (not just embedded in `documents`
            # above) so a lossless read-back is possible — see get_confirmed_findings(), the
            # first caller that needs the exact original detail text back out, not just for
            # semantic search.
            "severity": f.get("severity", "info"),
            "tool_source": f.get("tool_source", ""),
            "timestamp": str(f.get("timestamp", "")),
        }
        for f in findings
    ]
    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
    return len(ids)


def save_confirmed_findings_to_memory(target: str, findings: list[dict]) -> int:
    """Persist human-confirmed findings to a SEPARATE ChromaDB collection from raw scanner output.

    Closes docs/DEVELOPMENT_PLAN.md's Phase 5 "Store human-confirmed findings
    separately from scanner raw output in ChromaDB" item. Called by
    agent/vuln_pipeline.py's finalize stage for every finding the HITL gate
    marked "approve" — NOT called for the full raw finding set the way
    save_findings_to_memory is, since mixing an unfiltered scanner firehose
    into the same collection as vetted, human-approved findings would make
    query_similar_findings' results untrustworthy for "has a REAL bug like
    this shown up before" (the whole point of a separate collection). Uses
    the same content-hash-on-the-finding's-own-target ID scheme as
    save_findings_to_memory for the same reason (see that function's
    docstring) — re-confirming the same finding across sessions upserts in
    place rather than accumulating duplicates.
    """
    collection = _get_client().get_or_create_collection(_CONFIRMED_COLLECTION_NAME)
    return _upsert_findings(collection, target, findings)


def get_confirmed_findings(target: str) -> list[dict]:
    """Fetch every human-confirmed finding on record for `target`, exactly (not semantic search).

    Not an LLM tool — called by skills/report_generator.py's generate_report,
    which needs the complete, exact confirmed-finding set for one target, not
    a top-k similarity match the way query_similar_findings gives. Uses
    ChromaDB's own metadata-filtered .get() rather than .query() for that
    reason. Returns [] if nothing's been confirmed for this target yet.
    """
    collection = _get_client().get_or_create_collection(_CONFIRMED_COLLECTION_NAME)
    if collection.count() == 0:
        return []
    result = collection.get(where={"target": target})
    return [
        {
            "type": meta.get("type", ""), "target": meta.get("target", target),
            "detail": meta.get("detail", ""), "severity": meta.get("severity", "info"),
            "tool_source": meta.get("tool_source", ""), "timestamp": meta.get("timestamp", ""),
        }
        for meta in (result.get("metadatas") or [])
    ]


@tool
def query_similar_findings(target: str, query_text: str, n_results: int = 5) -> list[dict]:
    """Semantic search over this target's previously-saved findings for anything similar to query_text.

    LOW risk — reads this project's own local ChromaDB store only, no
    network/target-facing request at all. Useful before deep-diving a new
    lead: "has something like this shown up on this target before" can
    surface a related finding from a different session that an exact-match
    diff (diff_against_last_scan) would never catch, since it compares
    embeddings, not literal strings.
    """
    collection = _get_collection()
    if collection.count() == 0:
        return []
    result = collection.query(query_texts=[query_text], n_results=n_results, where={"target": target})
    docs = (result.get("documents") or [[]])[0]
    metas = (result.get("metadatas") or [[]])[0]
    distances = (result.get("distances") or [[]])[0]
    return [
        {"document": doc, "metadata": meta, "distance": dist}
        for doc, meta, dist in zip(docs, metas, distances)
    ]
