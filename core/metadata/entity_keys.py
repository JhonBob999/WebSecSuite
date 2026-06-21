"""Stable entity key builders for shared annotation metadata."""

from __future__ import annotations

from typing import Any


def normalize_entity_key_part(value: Any) -> str:
    """Convert an entity key part to a stripped, deterministic string."""
    if value is None:
        return ""
    return str(value).strip()


def build_task_entity_key(task_id: str) -> str:
    """Build the stable annotation key for a task."""
    normalized_task_id = normalize_entity_key_part(task_id)
    if not normalized_task_id:
        raise ValueError("task_id must not be empty")
    return f"task:{normalized_task_id}"


def build_preview_record_entity_key(
    task_id: str,
    record_key: str | None = None,
) -> str:
    """Build a stable key for a Data Preview record."""
    normalized_task_id = normalize_entity_key_part(task_id)
    if not normalized_task_id:
        raise ValueError("task_id must not be empty")
    normalized_record_key = normalize_entity_key_part(
        task_id if record_key is None else record_key
    )
    return f"preview-record:{normalized_task_id}:{normalized_record_key}"


def build_preview_field_entity_key(
    task_id: str,
    column_key: str,
    record_key: str | None = None,
) -> str:
    """Build a stable key for a Data Preview record field."""
    normalized_task_id = normalize_entity_key_part(task_id)
    if not normalized_task_id:
        raise ValueError("task_id must not be empty")
    normalized_column_key = normalize_entity_key_part(column_key)
    if not normalized_column_key:
        raise ValueError("column_key must not be empty")
    normalized_record_key = normalize_entity_key_part(
        task_id if record_key is None else record_key
    )
    return (
        f"preview-field:{normalized_task_id}:"
        f"{normalized_record_key}:{normalized_column_key}"
    )


__all__ = [
    "build_preview_field_entity_key",
    "build_preview_record_entity_key",
    "build_task_entity_key",
    "normalize_entity_key_part",
]
