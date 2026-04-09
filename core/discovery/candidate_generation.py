from __future__ import annotations

_ALLOWED_TYPES = {
    "xss_candidate",
    "sqli_candidate",
    "lfi_candidate",
    "ssrf_candidate",
}
_ALLOWED_CONFIDENCE = {"low", "medium", "high"}

_CATEGORY_TO_CANDIDATE_TYPE = {
    "id": "sqli_candidate",
    "id_like": "sqli_candidate",
    "file": "lfi_candidate",
    "file_like": "lfi_candidate",
    "path": "lfi_candidate",
    "path_like": "lfi_candidate",
    "template": "lfi_candidate",
    "template_like": "lfi_candidate",
    "page": "lfi_candidate",
    "page_like": "lfi_candidate",
    "url": "ssrf_candidate",
    "url_like": "ssrf_candidate",
    "redirect": "ssrf_candidate",
    "redirect_like": "ssrf_candidate",
    "next": "ssrf_candidate",
    "next_like": "ssrf_candidate",
    "return": "ssrf_candidate",
    "return_like": "ssrf_candidate",
    "search": "xss_candidate",
    "search_like": "xss_candidate",
    "query": "xss_candidate",
    "query_like": "xss_candidate",
    "q": "xss_candidate",
    "q_like": "xss_candidate",
    "term": "xss_candidate",
    "term_like": "xss_candidate",
}


def _normalize_confidence(confidence: str | None) -> str:
    normalized = str(confidence or "").strip().lower()
    if normalized in _ALLOWED_CONFIDENCE:
        return normalized
    return "low"


def _normalize_category(category: str | None) -> str | None:
    normalized = str(category or "").strip().lower()
    if normalized in _CATEGORY_TO_CANDIDATE_TYPE:
        return normalized
    return None


def _extract_parameter_entries(parameter_intelligence: dict | list | None) -> list[dict]:
    if isinstance(parameter_intelligence, dict):
        entries = parameter_intelligence.get("params")
        if isinstance(entries, list):
            return [item for item in entries if isinstance(item, dict)]
        return []

    if isinstance(parameter_intelligence, list):
        return [item for item in parameter_intelligence if isinstance(item, dict)]

    return []


def _add_candidate(
    candidates,
    candidate_type,
    url,
    param=None,
    confidence="low",
    reasons=None,
    endpoint_type=None,
    score=None,
    priority=None,
):
    """Add candidate with strict contract, including strict deduplication key.

    Deduplication key: (type, url, param, endpoint_type)
    """
    normalized_url = str(url or "").strip()
    if not normalized_url:
        return

    if candidate_type not in _ALLOWED_TYPES:
        return

    normalized_reasons = reasons if isinstance(reasons, list) else []
    normalized_confidence = _normalize_confidence(confidence)

    dedupe_key = (candidate_type, normalized_url, param, endpoint_type)
    for existing in candidates:
        existing_key = (
            existing.get("type"),
            existing.get("url"),
            existing.get("param"),
            existing.get("endpoint_type"),
        )
        if existing_key == dedupe_key:
            return

    candidates.append(
        {
            "type": candidate_type,
            "url": normalized_url,
            "param": param,
            "confidence": normalized_confidence,
            "reasons": normalized_reasons,
            "endpoint_type": endpoint_type,
            "score": score,
            "priority": priority,
        }
    )


def generate_candidates(
    final_url: str,
    classified_urls_by_scope: dict | None = None,
    parameter_intelligence: dict | None = None,
) -> dict:
    """Generate strict-contract candidate payload.

    This step intentionally generates candidates only from parameter_intelligence.
    """
    # TODO: add future endpoint-driven candidates.
    _ = classified_urls_by_scope

    # TODO: add future score-driven prioritization.

    all_candidates: list[dict] = []
    parameter_entries = _extract_parameter_entries(parameter_intelligence)

    for param_entry in parameter_entries:
        param_name = param_entry.get("name")
        if not isinstance(param_name, str) or not param_name.strip():
            continue
        param_name = param_name.strip()

        normalized_category = _normalize_category(param_entry.get("category"))
        if not normalized_category:
            continue

        candidate_type = _CATEGORY_TO_CANDIDATE_TYPE.get(normalized_category)
        if not candidate_type:
            continue

        candidate_url = param_entry.get("url")
        if not isinstance(candidate_url, str) or not candidate_url.strip():
            candidate_url = final_url

        endpoint_type = param_entry.get("endpoint_type")
        score = param_entry.get("score")
        priority = param_entry.get("priority")

        _add_candidate(
            candidates=all_candidates,
            candidate_type=candidate_type,
            url=candidate_url,
            param=param_name,
            confidence=param_entry.get("confidence"),
            reasons=[
                "parameter_intelligence",
                f"parameter_category:{normalized_category}",
            ],
            endpoint_type=endpoint_type,
            score=score,
            priority=priority,
        )

    by_type = {
        "xss_candidate": [],
        "sqli_candidate": [],
        "lfi_candidate": [],
        "ssrf_candidate": [],
    }

    for candidate in all_candidates:
        candidate_type = candidate.get("type")
        if candidate_type in by_type:
            by_type[candidate_type].append(candidate)

    return {
        "all": all_candidates,
        "by_type": by_type,
        "summary": {
            "total": len(all_candidates),
            "by_type": {
                "xss_candidate": len(by_type["xss_candidate"]),
                "sqli_candidate": len(by_type["sqli_candidate"]),
                "lfi_candidate": len(by_type["lfi_candidate"]),
                "ssrf_candidate": len(by_type["ssrf_candidate"]),
            },
        },
    }
