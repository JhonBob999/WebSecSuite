from __future__ import annotations

import hashlib
from typing import Any, Mapping

from core.discovery.target_binding import resolve_precise_target

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
            "replay_ready_total": 0,
            "unique_replay_keys": 0,
            "unique_artifact_ids": 0,
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


def _safe_join(parts: list[Any], separator: str = "|") -> str:
    return separator.join(_to_clean_string(part) for part in parts)


def _build_replay_key(
    *,
    request_method: str,
    replay_target_url: str,
    candidate_type: str,
    endpoint_type: str,
    param: Any,
    source_area: str,
    source_ref: str,
) -> str:
    return _safe_join(
        [
            request_method,
            replay_target_url,
            candidate_type,
            endpoint_type,
            _to_clean_string(param),
            _to_clean_string(source_area).lower(),
            _to_clean_string(source_ref),
        ]
    )


def _build_artifact_id(
    *,
    candidate_type: str,
    candidate_url: str,
    param: Any,
    endpoint_type: str,
    baseline_body_hash: str,
    request_method: str,
    replay_target_url: str,
) -> str:
    raw = _safe_join(
        [
            candidate_type,
            candidate_url,
            _to_clean_string(param),
            endpoint_type,
            baseline_body_hash,
            request_method,
            replay_target_url,
        ]
    )
    if not raw:
        return ""
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _normalize_evidence_tokens(values: Any, prefix: str = "") -> list[str]:
    if not isinstance(values, list):
        return []
    out: list[str] = []
    for value in values:
        token = _to_clean_string(value).lower()
        if not token:
            continue
        out.append(f"{prefix}{token}" if prefix else token)
    return out


def _build_candidate_identity_key(
    *,
    candidate_type: str,
    candidate_url: str,
    param: Any,
    endpoint_type: str,
    source_area: str,
    source_ref: str,
) -> str:
    return _safe_join(
        [
            candidate_type,
            candidate_url,
            _to_clean_string(param),
            endpoint_type,
            _to_clean_string(source_area).lower(),
            _to_clean_string(source_ref),
        ]
    )


def _build_evidence_sources(
    *,
    endpoint_type: str,
    param: Any,
    reasons: Any,
    source_area: str,
    source_ref: str,
    candidate_primary_evidence: str,
    candidate_evidence_sources: Any,
    candidate_matched_signals: Any,
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

    source_area_value = _to_clean_string(source_area).lower()
    if source_area_value:
        candidates.append(f"candidate:source_area:{source_area_value}")
    source_ref_value = _to_clean_string(source_ref)
    if source_ref_value:
        candidates.append(f"candidate:source_ref:{source_ref_value}")

    candidate_primary = _to_clean_string(candidate_primary_evidence).lower()
    if candidate_primary:
        candidates.append(f"candidate:primary_evidence:{candidate_primary}")

    candidates.extend(_normalize_evidence_tokens(candidate_evidence_sources, prefix="candidate:signal:"))
    candidates.extend(_normalize_evidence_tokens(candidate_matched_signals, prefix="candidate:matched:"))
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
        "candidate:primary_evidence:",
        "candidate:param:",
        "candidate:endpoint_type:",
        "candidate:source_area:",
        "candidate:source_ref:",
        "candidate:signal:",
        "candidate:matched:",
        "reason:",
        "request:url",
        "request:method:",
        "response:status_code",
        "response:content_type",
        "response:body_hash",
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
    discovery: Mapping[str, Any] | None = None,
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
    discovery_base_url = str(discovery.get("base_url") or "").strip() if isinstance(discovery, Mapping) else ""
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

        candidate_original_url = str(candidate.get("target_url") or candidate.get("url") or "").strip()
        candidate_origin_url = (
            str(candidate.get("candidate_origin_url") or "").strip()
            or str(candidate.get("candidate_origin") or "").strip()
            or str(candidate.get("origin_url") or "").strip()
            or str(candidate.get("candidate-origin") or "").strip()
        )
        candidate_url = candidate_original_url or request_url or fallback_final_url
        param = candidate.get("param_name", candidate.get("param", None))
        endpoint_type = str(candidate.get("endpoint_type") or "").strip() or "unknown"
        reasons = candidate.get("reasons") if isinstance(candidate.get("reasons"), list) else []
        source_area = _to_clean_string(candidate.get("source_area")).lower()
        source_ref = _to_clean_string(candidate.get("source_ref"))
        confidence = _normalized_confidence(candidate.get("confidence"))
        priority = _normalized_priority(candidate.get("priority"))
        evidence_sources = _build_evidence_sources(
            endpoint_type=endpoint_type,
            param=param,
            reasons=reasons,
            source_area=source_area,
            source_ref=source_ref,
            candidate_primary_evidence=_to_clean_string(candidate.get("primary_evidence")),
            candidate_evidence_sources=candidate.get("evidence_sources"),
            candidate_matched_signals=candidate.get("matched_signals"),
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
        replay_target_url, replay_target_source = resolve_precise_target(
            candidate_url=candidate_original_url or candidate_origin_url,
            final_url=fallback_final_url,
            request_url=request_url,
            discovery_base_url=discovery_base_url,
        )
        replay_key = _build_replay_key(
            request_method=request_method,
            replay_target_url=replay_target_url,
            candidate_type=candidate_type,
            endpoint_type=endpoint_type,
            param=param,
            source_area=source_area,
            source_ref=source_ref,
        )
        has_replay_recipe = bool(request_method and replay_target_url)
        artifact_id = _build_artifact_id(
            candidate_type=candidate_type,
            candidate_url=candidate_url,
            param=param,
            endpoint_type=endpoint_type,
            baseline_body_hash=baseline_body_hash,
            request_method=request_method,
            replay_target_url=replay_target_url,
        )

        candidate_identity_key = _build_candidate_identity_key(
            candidate_type=candidate_type,
            candidate_url=candidate_url,
            param=param,
            endpoint_type=endpoint_type,
            source_area=source_area,
            source_ref=source_ref,
        )

        dedupe_key = (candidate_identity_key, baseline_body_hash)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        artifacts.append(
            {
                "type": candidate_type,
                "url": candidate_url,
                "target_url": candidate_url,
                "param": param,
                "param_name": param,
                "source_area": source_area,
                "source_ref": source_ref,
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
                "artifact_id": artifact_id,
                "candidate_identity_key": candidate_identity_key,
                "replay_key": replay_key,
                "replay_target_url": replay_target_url,
                "replay_target_source": replay_target_source,
                "has_replay_recipe": has_replay_recipe,
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
        "replay_ready_total": sum(1 for item in payload["all"] if bool(item.get("has_replay_recipe"))),
        "unique_replay_keys": len(
            {
                str(item.get("replay_key") or "").strip()
                for item in payload["all"]
                if str(item.get("replay_key") or "").strip()
            }
        ),
        "unique_artifact_ids": len(
            {
                str(item.get("artifact_id") or "").strip()
                for item in payload["all"]
                if str(item.get("artifact_id") or "").strip()
            }
        ),
    }
    return payload
