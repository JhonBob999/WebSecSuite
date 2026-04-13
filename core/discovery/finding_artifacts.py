from __future__ import annotations

from typing import Any, Mapping

_ARTIFACT_TYPES = (
    "xss_candidate",
    "sqli_candidate",
    "lfi_candidate",
    "ssrf_candidate",
)
_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}
_PRIORITY_ALLOWED = {"low", "medium", "high"}


def _empty_contract() -> dict[str, Any]:
    by_type = {artifact_type: [] for artifact_type in _ARTIFACT_TYPES}
    return {
        "all": [],
        "by_type": by_type,
        "summary": {
            "total": 0,
            "by_type": {artifact_type: 0 for artifact_type in _ARTIFACT_TYPES},
            "max_confidence": "",
            "max_priority": "",
            "with_baseline_hash": 0,
            "with_request_context": 0,
            "with_response_context": 0,
            "with_primary_evidence": 0,
            "confirmed_total": 0,
            "types_present": [],
            "priorities_present": [],
        },
    }


def _normalized_confidence(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in _CONFIDENCE_RANK else ""


def _normalized_priority(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in _PRIORITY_ALLOWED else ""


def _to_status_code(value: Any) -> int:
    try:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str) and value.strip():
            return int(value.strip())
    except Exception:
        pass
    return 0


def _to_clean_string(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _to_reason_sources(reasons: Any) -> list[str]:
    if not isinstance(reasons, list):
        return []
    out: list[str] = []
    for reason in reasons:
        reason_value = _to_clean_string(reason)
        if reason_value:
            out.append(f"reason:{reason_value}")
    return out


def _build_evidence_sources(
    *,
    endpoint_type: str,
    param: Any,
    reasons: Any,
    request_method: str,
    request_url: str,
    baseline_status_code: int,
    baseline_content_type: str,
    baseline_body_hash: str,
) -> list[str]:
    candidates: list[str] = [f"candidate:endpoint_type:{endpoint_type or 'unknown'}"]
    param_value = _to_clean_string(param)
    if param_value:
        candidates.append(f"candidate:param:{param_value}")

    candidates.extend(_to_reason_sources(reasons))

    if request_method:
        candidates.append(f"request:method:{request_method}")
    if request_url:
        candidates.append("request:url")

    if baseline_status_code > 0:
        candidates.append("response:status_code")
    if baseline_content_type:
        candidates.append("response:content_type")
    if baseline_body_hash:
        candidates.append("response:body_hash")

    deduped: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        if isinstance(item, str) and item and item not in seen:
            deduped.append(item)
            seen.add(item)
    return deduped


def _primary_evidence_from_sources(sources: list[str]) -> str:
    priority_prefixes = (
        "response:body_hash",
        "response:status_code",
        "response:content_type",
        "request:url",
        "request:method:",
        "candidate:param:",
        "candidate:endpoint_type:",
        "reason:",
    )
    for prefix in priority_prefixes:
        for source in sources:
            if source == prefix or source.startswith(prefix):
                return source
    return ""


def build_finding_artifacts(
    *,
    candidates: Mapping[str, Any] | None = None,
    request_recipe: Mapping[str, Any] | None = None,
    response_snapshot: Mapping[str, Any] | None = None,
    status_code: Any = None,
    final_url: Any = "",
) -> dict[str, Any]:
    payload = _empty_contract()
    all_candidates = candidates.get("all") if isinstance(candidates, Mapping) else None
    if not isinstance(all_candidates, list):
        return payload

    recipe = request_recipe if isinstance(request_recipe, Mapping) else {}
    snapshot = response_snapshot if isinstance(response_snapshot, Mapping) else {}

    request_url = str(recipe.get("url") or "").strip()
    request_method = str(recipe.get("method") or "").strip()
    baseline_timestamp = str(recipe.get("timestamp") or "").strip()
    fallback_final_url = str(final_url or "").strip()
    baseline_body_hash = str(snapshot.get("body_hash") or "").strip()
    baseline_content_type = str(snapshot.get("content_type") or "").strip()
    baseline_status_code = _to_status_code(snapshot.get("status_code"))
    if baseline_status_code == 0:
        baseline_status_code = _to_status_code(status_code)

    seen: set[tuple[Any, ...]] = set()
    artifacts: list[dict[str, Any]] = []

    for index, candidate in enumerate(all_candidates):
        if not isinstance(candidate, Mapping):
            continue

        candidate_type = str(candidate.get("type") or "").strip()
        if candidate_type not in _ARTIFACT_TYPES:
            continue

        candidate_url = str(candidate.get("url") or "").strip() or request_url or fallback_final_url
        param = candidate.get("param", None)
        endpoint_type = str(candidate.get("endpoint_type") or "").strip() or "unknown"
        reasons = candidate.get("reasons") if isinstance(candidate.get("reasons"), list) else []
        confidence = _normalized_confidence(candidate.get("confidence"))
        priority = _normalized_priority(candidate.get("priority"))
        evidence_sources = _build_evidence_sources(
            endpoint_type=endpoint_type,
            param=param,
            reasons=reasons,
            request_method=request_method,
            request_url=request_url,
            baseline_status_code=baseline_status_code,
            baseline_content_type=baseline_content_type,
            baseline_body_hash=baseline_body_hash,
        )
        has_request_context = bool(request_method or request_url)
        has_response_context = bool(
            baseline_status_code > 0 or baseline_content_type or baseline_body_hash
        )
        primary_evidence = _primary_evidence_from_sources(evidence_sources)

        dedupe_key = (candidate_type, candidate_url, param, endpoint_type, baseline_body_hash)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        artifacts.append(
            {
                "type": candidate_type,
                "url": candidate_url,
                "param": param,
                "endpoint_type": endpoint_type,
                "confidence": confidence,
                "priority": priority,
                "reasons": reasons,
                "request_method": request_method,
                "request_url": request_url,
                "baseline_status_code": baseline_status_code,
                "baseline_body_hash": baseline_body_hash,
                "baseline_content_type": baseline_content_type,
                "baseline_timestamp": baseline_timestamp,
                "confirmed": False,
                "confirmation_method": "",
                "mutated_body_hash": "",
                "evidence_sources": evidence_sources,
                "primary_evidence": primary_evidence,
                "has_request_context": has_request_context,
                "has_response_context": has_response_context,
                "_stable_index": index,
            }
        )

    artifacts.sort(
        key=lambda item: (
            -_CONFIDENCE_RANK.get(item.get("confidence"), 0),
            str(item.get("type") or ""),
            str(item.get("url") or ""),
            str(item.get("param")),
            str(item.get("endpoint_type") or ""),
            str(item.get("baseline_body_hash") or ""),
            int(item.get("_stable_index", 0)),
        )
    )

    for artifact in artifacts:
        artifact.pop("_stable_index", None)
        artifact_type = artifact.get("type")
        if artifact_type in payload["by_type"]:
            payload["by_type"][artifact_type].append(artifact)
        payload["all"].append(artifact)

    summary_by_type = {artifact_type: len(payload["by_type"][artifact_type]) for artifact_type in _ARTIFACT_TYPES}
    max_confidence = ""
    for confidence in ("high", "medium", "low"):
        if any(item.get("confidence") == confidence for item in payload["all"]):
            max_confidence = confidence
            break
    max_priority = ""
    for priority in ("high", "medium", "low"):
        if any(item.get("priority") == priority for item in payload["all"]):
            max_priority = priority
            break
    priorities_present: list[str] = []
    for priority in ("low", "medium", "high"):
        if any(item.get("priority") == priority for item in payload["all"]):
            priorities_present.append(priority)
    types_present: list[str] = [
        artifact_type for artifact_type in _ARTIFACT_TYPES if summary_by_type.get(artifact_type, 0) > 0
    ]

    payload["summary"] = {
        "total": len(payload["all"]),
        "by_type": summary_by_type,
        "max_confidence": max_confidence,
        "max_priority": max_priority,
        "with_baseline_hash": sum(1 for item in payload["all"] if str(item.get("baseline_body_hash") or "").strip()),
        "with_request_context": sum(1 for item in payload["all"] if bool(item.get("has_request_context"))),
        "with_response_context": sum(1 for item in payload["all"] if bool(item.get("has_response_context"))),
        "with_primary_evidence": sum(1 for item in payload["all"] if str(item.get("primary_evidence") or "").strip()),
        "confirmed_total": sum(1 for item in payload["all"] if item.get("confirmed") is True),
        "types_present": types_present,
        "priorities_present": priorities_present,
    }
    return payload
