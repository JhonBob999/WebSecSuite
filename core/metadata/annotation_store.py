"""UI-independent storage for annotations attached to stable entity keys."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Sequence

from .entity_keys import build_task_entity_key


ANNOTATION_STORE_VERSION = 1


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _normalize_timestamp(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _normalize_tags(tags: Sequence[str]) -> list[str]:
    if isinstance(tags, (str, bytes)):
        raise TypeError("tags must be a sequence of strings")

    normalized = []
    seen = set()
    for tag in tags:
        if not isinstance(tag, str):
            raise TypeError("tags must contain only strings")
        tag = tag.strip()
        if tag and tag not in seen:
            normalized.append(tag)
            seen.add(tag)
    return normalized


class AnnotationStore:
    """Versioned in-memory annotation store with serialization helpers."""

    def __init__(self) -> None:
        self._annotations: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _validate_entity_key(entity_key: str) -> str:
        if not isinstance(entity_key, str):
            raise TypeError("entity_key must be a string")
        entity_key = entity_key.strip()
        if not entity_key:
            raise ValueError("entity_key must not be empty")
        return entity_key

    def get_annotation(self, entity_key: str) -> Optional[Dict[str, Any]]:
        """Return a detached annotation dictionary, or None when absent."""
        entity_key = self._validate_entity_key(entity_key)
        annotation = self._annotations.get(entity_key)
        if annotation is None:
            return None
        return {"entity_key": entity_key, **deepcopy(annotation)}

    def upsert_annotation(
        self,
        entity_key: str,
        bookmark: Optional[bool] = None,
        note: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Create or update an annotation; remove it when all values are empty."""
        entity_key = self._validate_entity_key(entity_key)
        if bookmark is not None and not isinstance(bookmark, bool):
            raise TypeError("bookmark must be a bool or None")
        if note is not None and not isinstance(note, str):
            raise TypeError("note must be a string or None")

        existing = self._annotations.get(entity_key)
        now = _utc_now()
        annotation = deepcopy(existing) if existing is not None else {
            "bookmark": False,
            "note": "",
            "tags": [],
            "created_at": now,
            "updated_at": now,
        }

        if bookmark is not None:
            annotation["bookmark"] = bookmark
        if note is not None:
            annotation["note"] = note.strip()
        if tags is not None:
            annotation["tags"] = _normalize_tags(tags)

        if not annotation["bookmark"] and not annotation["note"] and not annotation["tags"]:
            self._annotations.pop(entity_key, None)
            return None

        annotation["updated_at"] = now
        self._annotations[entity_key] = annotation
        return self.get_annotation(entity_key)

    def remove_annotation(self, entity_key: str) -> bool:
        """Remove an annotation and report whether one existed."""
        entity_key = self._validate_entity_key(entity_key)
        return self._annotations.pop(entity_key, None) is not None

    def has_annotation(self, entity_key: str) -> bool:
        entity_key = self._validate_entity_key(entity_key)
        return entity_key in self._annotations

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the store to its stable versioned dictionary form."""
        return {
            "version": ANNOTATION_STORE_VERSION,
            "annotations": deepcopy(self._annotations),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "AnnotationStore":
        """Load valid annotations from a dictionary, ignoring malformed data."""
        store = cls()
        if not isinstance(data, Mapping):
            return store
        if data.get("version", ANNOTATION_STORE_VERSION) != ANNOTATION_STORE_VERSION:
            return store

        annotations = data.get("annotations")
        if not isinstance(annotations, Mapping):
            return store

        for entity_key, raw in annotations.items():
            if not isinstance(entity_key, str) or not entity_key.strip():
                continue
            if not isinstance(raw, Mapping):
                continue

            bookmark = raw.get("bookmark", False)
            note = raw.get("note", "")
            tags = raw.get("tags", [])
            if not isinstance(bookmark, bool) or not isinstance(note, str):
                continue
            try:
                normalized_tags = _normalize_tags(tags)
            except (TypeError, ValueError):
                continue
            note = note.strip()
            if not bookmark and not note and not normalized_tags:
                continue

            created_at = _normalize_timestamp(raw.get("created_at"))
            updated_at = _normalize_timestamp(raw.get("updated_at"))
            now = _utc_now()
            if created_at is None:
                created_at = now
            if updated_at is None:
                updated_at = created_at

            store._annotations[entity_key.strip()] = {
                "bookmark": bookmark,
                "note": note,
                "tags": normalized_tags,
                "created_at": created_at,
                "updated_at": updated_at,
            }

        return store


__all__ = ["ANNOTATION_STORE_VERSION", "AnnotationStore", "build_task_entity_key"]
