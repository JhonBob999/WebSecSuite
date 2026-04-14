from __future__ import annotations

from urllib.parse import urlparse

_ALLOWED_TYPES = {
    "xss_candidate",
    "sqli_candidate",
    "lfi_candidate",
    "ssrf_candidate",
}
_ALLOWED_CONFIDENCE = {"low", "medium", "high"}
_ALLOWED_PRIORITY = {"low", "medium", "high"}
_CONFIDENCE_LEVELS = ("low", "medium", "high")
_TRACKING_PARAM_PREFIXES = (
    "utm_",
    "ga_",
    "pk_",
)
_TRACKING_PARAM_NAMES = {
    "fbclid",
    "gclid",
    "dclid",
    "msclkid",
    "mc_eid",
    "mc_cid",
    "ref",
    "ref_src",
    "source",
}
_ASSET_EXTENSIONS = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".mp4",
    ".mp3",
    ".webp",
    ".pdf",
    ".zip",
)

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

_ENDPOINT_TYPE_TO_CANDIDATE_TYPES = {
    "admin": ["xss_candidate", "sqli_candidate"],
    "auth": ["xss_candidate", "sqli_candidate"],
    "api": ["sqli_candidate"],
    "upload": ["lfi_candidate"],
}

_ENDPOINT_TYPE_BASE_CONFIDENCE = {
    "admin": "medium",
    "auth": "low",
    "api": "low",
    "upload": "medium",
}

_IGNORED_ENDPOINT_TYPES = {"asset", "unknown"}


def _normalize_confidence(confidence: str | None) -> str:
    if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
        numeric = float(confidence)
        if numeric >= 0.9:
            return "high"
        if numeric >= 0.65:
            return "medium"
        return "low"
    normalized = str(confidence or "").strip().lower()
    if normalized in _ALLOWED_CONFIDENCE:
        return normalized
    return "low"


def _is_tracking_param(param_name: str | None) -> bool:
    normalized = str(param_name or "").strip().lower()
    if not normalized:
        return False
    if normalized in _TRACKING_PARAM_NAMES:
        return True
    return any(normalized.startswith(prefix) for prefix in _TRACKING_PARAM_PREFIXES)


def _is_asset_like_url(url: str | None) -> bool:
    raw = str(url or "").strip()
    if not raw:
        return False
    try:
        parsed = urlparse(raw)
        path = (parsed.path or "").lower()
    except Exception:
        path = raw.lower().split("?", 1)[0].split("#", 1)[0]
    return any(path.endswith(ext) for ext in _ASSET_EXTENSIONS)


def _has_meaningful_target_context(url: str, endpoint_type: str | None, param_name: str | None) -> bool:
    normalized_endpoint_type = str(endpoint_type or "").strip().lower()
    if normalized_endpoint_type in _IGNORED_ENDPOINT_TYPES:
        return False
    if _is_asset_like_url(url):
        return False
    if str(param_name or "").strip():
        return True
    return normalized_endpoint_type in {"admin", "auth", "api", "upload"}


def _confidence_from_signal_weights(strong_signals: int, medium_signals: int, weak_signals: int) -> str:
    if strong_signals >= 2 or (strong_signals >= 1 and medium_signals >= 2):
        return "high"
    if strong_signals >= 1 or medium_signals >= 2:
        return "medium"
    if medium_signals == 1 and weak_signals >= 1:
        return "medium"
    return "low"


def _normalize_priority(priority: str | None) -> str | None:
    normalized = str(priority or "").strip().lower()
    if normalized in _ALLOWED_PRIORITY:
        return normalized
    return None


def _normalize_score(score) -> int | None:
    if score is None or isinstance(score, bool):
        return None
    if isinstance(score, int):
        return score
    if isinstance(score, float):
        return int(score) if score.is_integer() else None
    if isinstance(score, str):
        normalized = score.strip()
        if not normalized:
            return None
        if normalized.startswith(("+", "-")):
            sign = normalized[0]
            payload = normalized[1:]
            if payload.isdigit():
                return int(f"{sign}{payload}")
            return None
        if normalized.isdigit():
            return int(normalized)
    return None


def _refine_candidate_confidence(candidate: dict) -> dict:
    refined_candidate = dict(candidate or {})
    confidence = _normalize_confidence(refined_candidate.get("confidence"))
    normalized_priority = _normalize_priority(refined_candidate.get("priority"))
    normalized_score = _normalize_score(refined_candidate.get("score"))
    reasons = refined_candidate.get("reasons")
    normalized_reasons = list(reasons) if isinstance(reasons, list) else []

    confidence_level_index = _CONFIDENCE_LEVELS.index(confidence)
    boost = 0
    used_priority = False
    used_score = False

    if normalized_priority == "high":
        boost += 1
        used_priority = True
    if normalized_score is not None and normalized_score >= 8:
        boost += 1
        used_score = True
    if (
        boost == 0
        and normalized_priority == "medium"
        and normalized_score is not None
        and normalized_score >= 5
    ):
        boost = 1
        used_priority = True
        used_score = True

    matched_signals = refined_candidate.get("matched_signals")
    normalized_signals = [str(item).strip().lower() for item in matched_signals] if isinstance(matched_signals, list) else []
    strong_signals = sum(
        1
        for token in normalized_signals
        if token.startswith(("parameter_category:", "endpoint_type:", "form_context", "js_context"))
    )
    medium_signals = sum(
        1
        for token in normalized_signals
        if token.startswith(("source_area:", "priority:", "score:"))
    )
    weak_signals = sum(1 for token in normalized_signals if token)
    derived_confidence = _confidence_from_signal_weights(strong_signals, medium_signals, weak_signals)
    derived_index = _CONFIDENCE_LEVELS.index(derived_confidence)

    boost = min(boost, 1)
    refined_index = min(confidence_level_index + boost, len(_CONFIDENCE_LEVELS) - 1)
    refined_index = min(refined_index, derived_index) if normalized_signals else refined_index
    refined_confidence = _CONFIDENCE_LEVELS[refined_index]

    refined_candidate["confidence"] = refined_confidence
    refined_candidate["priority"] = normalized_priority
    refined_candidate["score"] = normalized_score

    if refined_index > confidence_level_index:
        for reason in ("confidence_refined",):
            if reason not in normalized_reasons:
                normalized_reasons.append(reason)
        if used_priority and normalized_priority:
            priority_reason = f"priority:{normalized_priority}"
            if priority_reason not in normalized_reasons:
                normalized_reasons.append(priority_reason)
        if used_score and normalized_score is not None:
            score_reason = f"score:{normalized_score}"
            if score_reason not in normalized_reasons:
                normalized_reasons.append(score_reason)

    if normalized_signals:
        derivation_reason = f"derived_confidence:{derived_confidence}"
        if derivation_reason not in normalized_reasons:
            normalized_reasons.append(derivation_reason)

    refined_candidate["reasons"] = normalized_reasons
    return refined_candidate


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


def _extract_internal_endpoint_records(classified_urls_by_scope: dict | None) -> list[dict]:
    if not isinstance(classified_urls_by_scope, dict):
        return []

    def _extract_scope_records(scope_value) -> list[dict]:
        if isinstance(scope_value, dict):
            nested_urls = scope_value.get("urls")
            if isinstance(nested_urls, (list, tuple, set)):
                return [item for item in nested_urls if isinstance(item, dict)]
            return []
        if isinstance(scope_value, (list, tuple, set)):
            return [item for item in scope_value if isinstance(item, dict)]
        return []

    internal_records = _extract_scope_records(classified_urls_by_scope.get("internal"))
    if internal_records:
        return internal_records

    return _extract_scope_records(classified_urls_by_scope.get("all"))


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
    source_area="",
    source_ref="",
    matched_signals=None,
    explanation="",
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
    normalized_source_area = str(source_area or "").strip().lower()
    normalized_source_ref = str(source_ref or "").strip()
    normalized_signals = [str(signal).strip() for signal in matched_signals] if isinstance(matched_signals, list) else []
    normalized_explanation = str(explanation or "").strip()

    dedupe_key = (candidate_type, normalized_url, param, endpoint_type, normalized_source_area, normalized_source_ref)
    for existing in candidates:
        existing_key = (
            existing.get("type"),
            existing.get("url"),
            existing.get("param"),
            existing.get("endpoint_type"),
            existing.get("source_area"),
            existing.get("source_ref"),
        )
        if existing_key == dedupe_key:
            return

    candidates.append(
        {
            "type": candidate_type,
            "url": normalized_url,
            "target_url": normalized_url,
            "param": param,
            "param_name": param,
            "confidence": normalized_confidence,
            "reasons": normalized_reasons,
            "endpoint_type": endpoint_type,
            "score": score,
            "priority": priority,
            "source_area": normalized_source_area,
            "source_ref": normalized_source_ref,
            "matched_signals": normalized_signals,
            "evidence_sources": list(normalized_signals),
            "explanation": normalized_explanation,
        }
    )


def generate_candidates(
    final_url: str,
    classified_urls_by_scope: dict | None = None,
    parameter_intelligence: dict | None = None,
) -> dict:
    """Generate strict-contract candidate payload.

    This step generates candidates from parameter_intelligence and endpoint records.
    """
    # TODO: future SSRF candidate rules from richer endpoint hints.
    # TODO: add future score-driven prioritization.
    # TODO: future finding confidence model.
    # TODO: future evidence weighting.

    all_candidates: list[dict] = []
    parameter_entries = _extract_parameter_entries(parameter_intelligence)
    endpoint_records = _extract_internal_endpoint_records(classified_urls_by_scope)

    for param_entry in parameter_entries:
        param_name = param_entry.get("name")
        if not isinstance(param_name, str) or not param_name.strip():
            continue
        param_name = param_name.strip()
        if _is_tracking_param(param_name):
            continue

        normalized_category = _normalize_category(param_entry.get("category"))
        if not normalized_category:
            continue

        candidate_type = _CATEGORY_TO_CANDIDATE_TYPE.get(normalized_category)
        if not candidate_type:
            continue

        candidate_url = param_entry.get("url")
        if not isinstance(candidate_url, str) or not candidate_url.strip():
            candidate_url = final_url
        if not _has_meaningful_target_context(candidate_url, param_entry.get("endpoint_type"), param_name):
            continue

        endpoint_type = param_entry.get("endpoint_type")
        score = param_entry.get("score")
        priority = param_entry.get("priority")

        matched_signals = [
            f"source_area:query_param",
            f"parameter_category:{normalized_category}",
            f"source_ref:{param_name}",
        ]
        if endpoint_type:
            matched_signals.append(f"endpoint_type:{endpoint_type}")
        if priority:
            matched_signals.append(f"priority:{priority}")
        if score is not None:
            matched_signals.append(f"score:{score}")

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
            source_area="query_param",
            source_ref=param_name,
            matched_signals=matched_signals,
            explanation=f"Parameter '{param_name}' matched category '{normalized_category}' for {candidate_type}.",
        )

    for endpoint_record in endpoint_records:
        endpoint_url = endpoint_record.get("url")
        if not isinstance(endpoint_url, str) or not endpoint_url.strip():
            continue
        if _is_asset_like_url(endpoint_url):
            continue

        endpoint_type = str(endpoint_record.get("endpoint_type") or "").strip().lower()
        if not endpoint_type or endpoint_type in _IGNORED_ENDPOINT_TYPES:
            continue

        candidate_types = _ENDPOINT_TYPE_TO_CANDIDATE_TYPES.get(endpoint_type, [])
        if not candidate_types:
            continue

        priority = endpoint_record.get("priority")
        base_confidence = _ENDPOINT_TYPE_BASE_CONFIDENCE.get(endpoint_type, "low")
        effective_confidence = base_confidence
        reasons = [
            "endpoint_intelligence",
            f"endpoint_type:{endpoint_type}",
        ]
        matched_signals = [
            "source_area:path",
            f"endpoint_type:{endpoint_type}",
            f"source_ref:{endpoint_url}",
        ]
        if str(priority or "").strip().lower() == "high" and base_confidence == "low":
            effective_confidence = "medium"
            reasons.append(f"priority:{priority}")
        if priority:
            matched_signals.append(f"priority:{priority}")
        if endpoint_record.get("score") is not None:
            matched_signals.append(f"score:{endpoint_record.get('score')}")

        for candidate_type in candidate_types:
            _add_candidate(
                candidates=all_candidates,
                candidate_type=candidate_type,
                url=endpoint_url,
                param=None,
                confidence=effective_confidence,
                reasons=reasons,
                endpoint_type=endpoint_type,
                score=endpoint_record.get("score"),
                priority=priority,
                source_area="path",
                source_ref=endpoint_url,
                matched_signals=matched_signals,
                explanation=f"Endpoint '{endpoint_url}' classified as '{endpoint_type}' suggests {candidate_type}.",
            )

    all_candidates = [_refine_candidate_confidence(candidate) for candidate in all_candidates]
    all_candidates.sort(
        key=lambda item: (
            str(item.get("type") or ""),
            str(item.get("url") or ""),
            str(item.get("param") or ""),
            str(item.get("endpoint_type") or ""),
            str(item.get("source_area") or ""),
            str(item.get("source_ref") or ""),
        )
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

    max_confidence = ""
    for level in _CONFIDENCE_LEVELS[::-1]:
        if any(str(candidate.get("confidence") or "").strip().lower() == level for candidate in all_candidates):
            max_confidence = level
            break

    types_present = [candidate_type for candidate_type in sorted(by_type.keys()) if by_type[candidate_type]]

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
            "types_breakdown": {
                "xss_candidate": len(by_type["xss_candidate"]),
                "sqli_candidate": len(by_type["sqli_candidate"]),
                "lfi_candidate": len(by_type["lfi_candidate"]),
                "ssrf_candidate": len(by_type["ssrf_candidate"]),
            },
            "max_confidence": max_confidence,
            "types_present": types_present,
        },
    }
