from __future__ import annotations

from collections.abc import Iterable


def _normalize_confidence(value) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        confidence = 0.1
    if confidence < 0.0:
        return 0.0
    if confidence > 1.0:
        return 1.0
    return confidence


def _normalize_type(value: str | None) -> str:
    normalized = (value or "unknown").strip().lower()
    return normalized or "unknown"


def _normalize_url(value: str | None, fallback: str) -> str:
    normalized = (value or "").strip()
    if normalized:
        return normalized
    return (fallback or "").strip()


def _normalize_param(value: str | None) -> str:
    return (value or "").strip().lower()


def _iter_scope_urls(classified_urls_by_scope: dict | None) -> Iterable[tuple[str, str]]:
    if not isinstance(classified_urls_by_scope, dict):
        return

    for scope, urls in classified_urls_by_scope.items():
        scope_name = str(scope or "unknown").strip().lower() or "unknown"

        if isinstance(urls, dict):
            nested_urls = urls.get("urls")
            if isinstance(nested_urls, (list, tuple, set)):
                for item in nested_urls:
                    if item is None:
                        continue
                    if isinstance(item, dict):
                        url_value = item.get("url")
                        if url_value:
                            yield scope_name, str(url_value)
                        continue
                    yield scope_name, str(item)
            continue

        if isinstance(urls, (list, tuple, set)):
            for item in urls:
                if item is None:
                    continue
                if isinstance(item, dict):
                    url_value = item.get("url")
                    if url_value:
                        yield scope_name, str(url_value)
                    continue
                yield scope_name, str(item)


def _iter_parameter_entries(parameter_intelligence: dict | list | None) -> Iterable[dict]:
    if isinstance(parameter_intelligence, dict):
        params = parameter_intelligence.get("params")
        if not isinstance(params, list):
            return
        for item in params:
            if isinstance(item, dict):
                yield item
        return

    if isinstance(parameter_intelligence, list):
        for item in parameter_intelligence:
            if isinstance(item, dict):
                yield item


def _safe_add_candidate(
    candidates: list[dict],
    seen: set[tuple[str, str, str]],
    *,
    fallback_url: str,
    candidate_type: str | None,
    url: str | None,
    param: str | None = None,
    confidence=None,
    evidence: dict | None = None,
):
    normalized_type = _normalize_type(candidate_type)
    normalized_url = _normalize_url(url, fallback=fallback_url)
    normalized_param = _normalize_param(param)
    normalized_confidence = _normalize_confidence(confidence)

    if not normalized_url:
        return

    dedup_key = (normalized_type, normalized_url, normalized_param)
    if dedup_key in seen:
        return

    seen.add(dedup_key)
    candidates.append(
        {
            "type": normalized_type,
            "url": normalized_url,
            "param": normalized_param,
            "confidence": normalized_confidence,
            "evidence": evidence or {},
        }
    )


def generate_candidates(
    final_url: str,
    classified_urls_by_scope: dict | None = None,
    parameter_intelligence: dict | list | None = None,
) -> dict:
    """
    Build a baseline list of vulnerability candidates.

    This is intentionally conservative and provides a stable, deduplicated
    foundation for future rule-based candidate generation.
    """
    normalized_final_url = (final_url or "").strip()
    candidates: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    _safe_add_candidate(
        candidates,
        seen,
        fallback_url=normalized_final_url,
        candidate_type="baseline",
        url=normalized_final_url,
        confidence=0.1,
        evidence={"source": "final_url"},
    )

    for scope, scope_url in _iter_scope_urls(classified_urls_by_scope):
        _safe_add_candidate(
            candidates,
            seen,
            fallback_url=normalized_final_url,
            candidate_type="endpoint_probe",
            url=scope_url,
            confidence=0.2,
            evidence={"source": "classified_urls_by_scope", "scope": scope},
        )

    for param_entry in _iter_parameter_entries(parameter_intelligence):
        param_name = _normalize_param(param_entry.get("name"))
        if not param_name:
            continue

        param_confidence = _normalize_confidence(param_entry.get("confidence"))
        _safe_add_candidate(
            candidates,
            seen,
            fallback_url=normalized_final_url,
            candidate_type="parameter_probe",
            url=normalized_final_url,
            param=param_name,
            confidence=param_confidence,
            evidence={"source": "parameter_intelligence", "category": param_entry.get("category", "unknown")},
        )

    candidates.sort(
        key=lambda item: (
            str(item.get("type") or ""),
            str(item.get("url") or ""),
            str(item.get("param") or ""),
        )
    )

    by_type: dict[str, int] = {}
    for candidate in candidates:
        candidate_type = candidate.get("type") or "unknown"
        by_type[candidate_type] = by_type.get(candidate_type, 0) + 1

    return {
        "final_url": normalized_final_url,
        "candidates": candidates,
        "summary": {
            "total": len(candidates),
            "by_type": by_type,
        },
    }
