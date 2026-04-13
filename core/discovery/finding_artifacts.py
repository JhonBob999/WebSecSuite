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
            "with_baseline_hash": 0,
            "confirmed_total": 0,
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

    payload["summary"] = {
        "total": len(payload["all"]),
        "by_type": summary_by_type,
        "max_confidence": max_confidence,
        "with_baseline_hash": sum(1 for item in payload["all"] if str(item.get("baseline_body_hash") or "").strip()),
        "confirmed_total": sum(1 for item in payload["all"] if item.get("confirmed") is True),
    }
    return payload
