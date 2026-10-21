"""Make the repo root importable so `from agent...`, `from skills...`, `from tools...`
work under pytest regardless of where it's invoked from. Kept at the repo root (not
inside tests/) so it applies before test collection starts.
"""
import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
