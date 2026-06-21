"""Stable entity key builders for shared annotation metadata."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit


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


def canonicalize_discovery_url(value: str) -> str:
    """Return the minimally normalized absolute HTTP(S) discovery URL."""
    raw_url = str(value).strip()
    if not raw_url:
        raise ValueError("url must not be empty")

    try:
        parsed = urlsplit(raw_url)
        # Accessing port validates malformed/non-numeric and out-of-range ports.
        parsed.port
    except (TypeError, ValueError) as exc:
        raise ValueError("url must be a valid absolute HTTP or HTTPS URL") from exc

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname
    if scheme not in {"http", "https"} or not parsed.netloc or not hostname:
        raise ValueError("url must be an absolute HTTP or HTTPS URL")
    if any(character.isspace() for character in hostname):
        raise ValueError("url hostname must not contain whitespace")

    userinfo, separator, host_port = parsed.netloc.rpartition("@")
    prefix = f"{userinfo}{separator}" if separator else ""
    if host_port.startswith("["):
        closing_bracket = host_port.find("]")
        if closing_bracket < 0:
            raise ValueError("url must contain a valid hostname")
        normalized_host_port = (
            f"[{hostname.lower()}]" + host_port[closing_bracket + 1 :]
        )
    else:
        port_suffix = host_port[len(hostname) :]
        normalized_host_port = hostname.lower() + port_suffix

    return urlunsplit(
        (
            scheme,
            prefix + normalized_host_port,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )


def build_discovery_url_entity_key(task_id: str, url: str) -> str:
    """Build a stable annotation key for a discovered URL."""
    normalized_task_id = normalize_entity_key_part(task_id)
    if not normalized_task_id:
        raise ValueError("task_id must not be empty")
    return f"discovery-url:{normalized_task_id}:{canonicalize_discovery_url(url)}"


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
    "build_discovery_url_entity_key",
    "build_preview_field_entity_key",
    "build_preview_record_entity_key",
    "build_task_entity_key",
    "canonicalize_discovery_url",
    "normalize_entity_key_part",
]
