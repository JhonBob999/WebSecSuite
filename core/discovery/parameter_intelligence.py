from __future__ import annotations

from typing import Iterable


_NAME_RULES: list[tuple[set[str], str, list[str], float]] = [
    (
        {"id", "user_id", "uid", "item_id", "account_id", "profile_id", "post_id"},
        "id",
        ["sqli", "idor"],
        0.95,
    ),
    (
        {"file", "path", "page", "template", "filepath", "filename"},
        "file",
        ["lfi", "rfi"],
        0.95,
    ),
    (
        {"url", "redirect", "next", "return", "dest", "destination", "callback", "continue"},
        "url",
        ["ssrf", "open_redirect"],
        0.95,
    ),
    (
        {"q", "query", "search", "term", "keyword"},
        "search",
        ["xss"],
        0.9,
    ),
    (
        {"token", "access_token", "auth_token", "refresh_token", "api_token"},
        "token",
        [],
        0.9,
    ),
    (
        {"auth", "authorization", "password", "passwd", "session", "session_id"},
        "auth",
        [],
        0.85,
    ),
    (
        {"lang", "locale", "language"},
        "lang",
        [],
        0.95,
    ),
    (
        {"sort", "order", "filter", "orderby", "direction"},
        "sort_filter",
        [],
        0.9,
    ),
]


def _normalize_name(name: str | None) -> str:
    return (name or "").strip().lower()


def classify_param_name(name: str) -> dict:
    """
    Basic parameter intelligence classifier by parameter name only.
    """
    normalized = _normalize_name(name)
    if not normalized:
        return {
            "name": name or "",
            "category": "unknown",
            "risk_tags": [],
            "confidence": 0.1,
        }

    for variants, category, risk_tags, confidence in _NAME_RULES:
        if normalized in variants:
            return {
                "name": name,
                "category": category,
                "risk_tags": list(risk_tags),
                "confidence": confidence,
            }

    return {
        "name": name,
        "category": "unknown",
        "risk_tags": [],
        "confidence": 0.4,
    }


def _iter_param_names(params) -> Iterable[str]:
    if isinstance(params, dict):
        for key in params.keys():
            if key is None:
                continue
            yield str(key)
        return

    if isinstance(params, (list, tuple, set)):
        for item in params:
            if item is None:
                continue
            if isinstance(item, dict):
                name = item.get("name")
                if name:
                    yield str(name)
                continue
            yield str(item)


def analyze_query_params(params) -> list[dict]:
    """
    Build per-parameter intelligence records based on parameter names.
    Returns empty list for empty/unsupported input.
    """
    if not params:
        return []

    seen: set[str] = set()
    output: list[dict] = []

    for name in _iter_param_names(params):
        normalized = _normalize_name(name)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        output.append(classify_param_name(name))

    output.sort(key=lambda item: ((item.get("category") or "unknown"), (item.get("name") or "")))
    return output
