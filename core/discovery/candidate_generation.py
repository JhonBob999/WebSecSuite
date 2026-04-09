from __future__ import annotations

_ALLOWED_TYPES = {
    "xss_candidate",
    "sqli_candidate",
    "lfi_candidate",
    "ssrf_candidate",
}
_ALLOWED_CONFIDENCE = {"low", "medium", "high"}


def _normalize_confidence(confidence: str | None) -> str:
    normalized = str(confidence or "").strip().lower()
    if normalized in _ALLOWED_CONFIDENCE:
        return normalized
    return "low"


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

    NOTE: This step intentionally returns baseline empty structure.
    TODO: Add strict rule-based XSS/SQLi/LFI/SSRF generation in later steps.
    """
    _ = final_url
    _ = classified_urls_by_scope
    _ = parameter_intelligence

    all_candidates: list[dict] = []

    by_type = {
        "xss_candidate": [],
        "sqli_candidate": [],
        "lfi_candidate": [],
        "ssrf_candidate": [],
    }

    return {
        "all": all_candidates,
        "by_type": by_type,
        "summary": {
            "total": 0,
            "by_type": {
                "xss_candidate": 0,
                "sqli_candidate": 0,
                "lfi_candidate": 0,
                "ssrf_candidate": 0,
            },
        },
    }
