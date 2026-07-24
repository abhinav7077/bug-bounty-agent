"""Session state persistence — save/load HuntState so an interrupted hunt is resumable.

Phase 1 scope: save a checkpoint after every stage transition. Phase 4 adds
the full `resume` command (dedup against prior findings, ChromaDB memory);
this module only owns the on-disk JSON checkpoint itself.
"""
import json
from datetime import datetime
from pathlib import Path

from config.settings import settings


def _session_dir(target: str) -> Path:
    safe_target = target.strip().strip("/") or "unknown-target"
    return Path(settings.SESSIONS_DIR) / safe_target


def save_checkpoint(target: str, state: dict, timestamp: str | None = None) -> Path:
    """Write the current HuntState to sessions/<target>/<timestamp>.json.

    Also refreshes sessions/<target>/latest.json so load_latest() doesn't
    need to list/sort the directory.
    """
    timestamp = timestamp or datetime.now().strftime("%Y%m%dT%H%M%S")
    directory = _session_dir(target)
    directory.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(state, indent=2, default=str)
    checkpoint_path = directory / f"{timestamp}.json"
    checkpoint_path.write_text(payload)
    (directory / "latest.json").write_text(payload)
    return checkpoint_path


def load_latest(target: str) -> dict | None:
    """Load the most recent checkpoint for a target, or None if never hunted before."""
    latest_path = _session_dir(target) / "latest.json"
    if not latest_path.exists():
        return None
    return json.loads(latest_path.read_text())


def list_checkpoints(target: str) -> list[str]:
    """List all checkpoint timestamps on disk for a target, oldest first."""
    directory = _session_dir(target)
    if not directory.exists():
        return []
    return sorted(p.stem for p in directory.glob("*.json") if p.stem != "latest")
