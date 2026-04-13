from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

_ALLOWED_SCHEMES = {"http", "https"}
_ALLOWED_TARGET_SOURCES = (
    "candidate_url",
    "final_url",
    "request_url",
    "discovery_base_url",
    "unknown",
)


def _clean_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def is_absolute_http_url(value: Any) -> bool:
    clean = _clean_str(value)
    if not clean:
        return False
    try:
        parsed = urlparse(clean)
    except Exception:
        return False
    return parsed.scheme.lower() in _ALLOWED_SCHEMES and bool(parsed.netloc)


def resolve_precise_target(
    *,
    candidate_url: Any = "",
    final_url: Any = "",
    request_url: Any = "",
    discovery_base_url: Any = "",
) -> tuple[str, str]:
    candidates = (
        ("candidate_url", candidate_url),
        ("final_url", final_url),
        ("request_url", request_url),
        ("discovery_base_url", discovery_base_url),
    )
    for source, value in candidates:
        clean = _clean_str(value)
        if is_absolute_http_url(clean):
            return clean, source
    return "", "unknown"


def normalize_target_source(value: Any) -> str:
    clean = _clean_str(value)
    if clean in _ALLOWED_TARGET_SOURCES:
        return clean
    return "unknown"
