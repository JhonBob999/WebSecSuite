from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


SESSION_SCHEMA = "websecsuite.scraper.session"
SESSION_VERSION = 1
APP_NAME = "WebSecSuite"


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_scraper_session(
    *,
    tasks: Sequence[Mapping[str, Any]],
    selected_task_id: str | None = None,
    current_row: int = -1,
    saved_at: str | None = None,
) -> dict[str, Any]:
    return {
        "schema": SESSION_SCHEMA,
        "version": SESSION_VERSION,
        "saved_at": saved_at or utc_timestamp(),
        "app": APP_NAME,
        "workspace": {
            "selected_task_id": selected_task_id or None,
            "current_row": int(current_row) if current_row is not None else -1,
        },
        "tasks": [_safe_json(task) for task in tasks],
    }


def save_session(path: str | Path, data: Mapping[str, Any]) -> None:
    target = Path(path)
    if target.parent:
        target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as fh:
        json.dump(_safe_json(data), fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def _safe_json(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(k): _safe_json(v) for k, v in value.items()}
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_safe_json(item) for item in value]
    return str(value)
