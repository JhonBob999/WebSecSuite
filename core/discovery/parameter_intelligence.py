from __future__ import annotations

from typing import Iterable


PARAM_ALIASES = {
    "id": {"id", "user_id", "uid", "item_id", "product_id"},
    "file": {"file", "path", "page", "template", "include"},
    "url": {"url", "redirect", "next", "return", "dest", "callback"},
    "search": {"q", "query", "search", "term", "keyword"},
    "token": {"token", "auth_token", "access_token", "csrf_token"},
    "auth": {"username", "user", "login", "email", "password"},
    "lang": {"lang", "locale", "language"},
    "sort_filter": {"sort", "order", "filter", "direction"}
}


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

    normalized_name = ""
    for category, aliases in PARAM_ALIASES.items():
        if normalized in aliases:
            normalized_name = category
            break

    if normalized_name:
        risk_tags: list[str] = []
        for _, category, candidate_risk_tags, _ in _NAME_RULES:
            if category == normalized_name:
                risk_tags = list(candidate_risk_tags)
                break

        return {
            "name": name,
            "category": normalized_name,
            "risk_tags": risk_tags,
            "confidence": 0.95,
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


def analyze_query_params(params) -> dict:
    """
    Build per-parameter intelligence records based on parameter names.
    Returns params + summary with deduplication by normalized parameter name.
    """
    if not params:
        return {
            "params": [],
            "summary": {
                "total": 0,
                "by_category": {},
                "high_risk": 0,
            },
        }

    seen: set[str] = set()
    output: list[dict] = []

    for name in _iter_param_names(params):
        normalized = _normalize_name(name)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        entry = classify_param_name(normalized)
        entry["name"] = normalized
        output.append(entry)

    output.sort(key=lambda item: ((item.get("category") or "unknown"), (item.get("name") or "")))

    by_category: dict[str, int] = {}
    high_risk = 0
    for item in output:
        category = item.get("category") or "unknown"
        by_category[category] = by_category.get(category, 0) + 1
        if item.get("risk_tags"):
            high_risk += 1

    return {
        "params": output,
        "summary": {
            "total": len(output),
            "by_category": by_category,
            "high_risk": high_risk,
        },
    }
