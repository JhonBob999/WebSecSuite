# core/paths.py
from __future__ import annotations

from pathlib import Path


def project_root() -> Path:
    """Repository root, resolved from this file's location (not CWD)."""
    return Path(__file__).resolve().parent.parent
