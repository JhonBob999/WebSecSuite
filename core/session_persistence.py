from __future__ import annotations

import json
import math
import os
import tempfile
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from core.metadata import AnnotationStore


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
    annotation_store: AnnotationStore | None = None,
) -> dict[str, Any]:
    session = {
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
    if annotation_store is not None:
        session["metadata"] = _safe_json(annotation_store.to_dict())
    return session


def extract_annotation_store(session_data: Any) -> AnnotationStore:
    """Return session annotations, or an empty store for missing/malformed metadata."""
    if not isinstance(session_data, Mapping):
        return AnnotationStore()
    try:
        return AnnotationStore.from_dict(session_data.get("metadata"))
    except (TypeError, ValueError):
        return AnnotationStore()


def save_session(path: str | Path, data: Mapping[str, Any]) -> None:
    target = Path(path)
    if target.parent:
        target.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=target.parent,
            prefix=f".{target.name}.", suffix=".tmp", delete=False,
        ) as fh:
            temporary = Path(fh.name)
            json.dump(_safe_json(data), fh, ensure_ascii=False, indent=2)
            fh.write("\n")
            fh.flush()
            if hasattr(os, "fsync"):
                os.fsync(fh.fileno())
        # Close first: Windows cannot replace an open temporary file.
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def load_session(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    try:
        with target.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid session JSON: {exc.msg}") from exc
    except OSError as exc:
        raise ValueError(f"Could not read session file: {exc}") from exc
    return validate_session_data(data)


def validate_session_data(data: Any) -> dict[str, Any]:
    if not isinstance(data, Mapping):
        raise ValueError("Invalid session file: root value must be an object.")
    if data.get("schema") != SESSION_SCHEMA:
        raise ValueError(f"Invalid session schema. Expected {SESSION_SCHEMA}.")
    if data.get("version") != SESSION_VERSION:
        raise ValueError(f"Unsupported session version. Expected {SESSION_VERSION}.")

    tasks = data.get("tasks")
    if not isinstance(tasks, list):
        raise ValueError("Invalid session file: tasks must be a list.")

    seen_ids = set()
    for index, entry in enumerate(tasks, start=1):
        label = f"Invalid session task {index}"
        if not isinstance(entry, dict):
            raise ValueError(f"{label}: must be an object.")
        for key in ("id", "url"):
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                raise ValueError(f"{label}: {key} must be a nonempty string.")
        task_id = entry["id"].strip()
        if task_id in seen_ids:
            raise ValueError(f"{label}: duplicate task id.")
        seen_ids.add(task_id)
        _validate_task_params(entry.get("params", {}), label)
        result = entry.get("result")
        if result is not None and not isinstance(result, dict):
            raise ValueError(f"{label}: result must be an object or null.")
        if isinstance(result, dict):
            timings = result.get("timings")
            if timings is not None and not isinstance(timings, dict):
                raise ValueError(f"{label}: result.timings must be an object or null.")
            request_ms = (timings or {}).get("request_ms")
            if isinstance(request_ms, float) and not math.isfinite(request_ms):
                raise ValueError(f"{label}: result.timings.request_ms must be finite.")
            chain = result.get("redirect_chain")
            if chain is not None and not isinstance(chain, list):
                raise ValueError(f"{label}: result.redirect_chain must be a list or null.")

    workspace = data.get("workspace")
    if not isinstance(workspace, Mapping):
        workspace = {}

    return {
        **dict(data),
        "workspace": {
            "selected_task_id": workspace.get("selected_task_id") or None,
            "current_row": _safe_int(workspace.get("current_row"), -1),
        },
        "tasks": tasks,
    }


def _validate_task_params(params: Any, label: str) -> None:
    if not isinstance(params, dict):
        raise ValueError(f"{label}: params must be an object.")
    headers = params.get("headers", {})
    if not isinstance(headers, dict) or any(not isinstance(k, str) for k in headers):
        raise ValueError(f"{label}: params.headers must be an object with string keys.")
    for key in ("method", "user_agent", "proxy", "cookie_mode", "cookies_source", "cookie_file"):
        value = params.get(key)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{label}: params.{key} must be a string or null.")
    try:
        int(params.get("cookies_count") or 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{label}: params.cookies_count must be an integer.") from exc


def session_contains_sensitive_data(data: Mapping[str, Any]) -> bool:
    """Check common credential fields without returning or logging their values."""
    def contains(value):
        if isinstance(value, Mapping):
            for key, nested in value.items():
                name = str(key).lower().replace("-", "").replace("_", "")
                sensitive = name in {"cookie", "cookies", "setcookie"} or any(
                    marker in name for marker in (
                        "auth", "apikey", "token", "secret", "password",
                        "passwd", "credential", "sessionid",
                    )
                )
                if sensitive and nested:
                    return True
                if name in {"proxy", "url", "finalurl"} and isinstance(nested, str) and "@" in nested:
                    return True
                if contains(nested):
                    return True
        elif isinstance(value, (list, tuple)):
            return any(contains(item) for item in value)
        return False

    return contains(data.get("tasks", []))


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


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
