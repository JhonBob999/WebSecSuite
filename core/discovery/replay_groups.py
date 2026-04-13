from __future__ import annotations

from typing import Any, Mapping

_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}
_PRIORITY_RANK = {"high": 3, "medium": 2, "low": 1}


def _empty_contract() -> dict[str, Any]:
    return {
        "all": [],
        "summary": {
            "total": 0,
            "replay_ready_total": 0,
            "unique_targets": 0,
            "max_group_size": 0,
            "with_baseline_hash": 0,
            "types_present": [],
        },
    }


def _clean_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _stable_dedup(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in values:
        clean = _clean_str(item)
        if clean and clean not in seen:
            out.append(clean)
            seen.add(clean)
    return out


def _artifact_target_url(artifact: Mapping[str, Any], fallback_final_url: str) -> str:
    return (
        _clean_str(artifact.get("replay_target_url"))
        or _clean_str(artifact.get("request_url"))
        or _clean_str(artifact.get("url"))
        or fallback_final_url
        or ""
    )


def _artifact_method(artifact: Mapping[str, Any]) -> str:
    return _clean_str(artifact.get("request_method"))


def _artifact_group_key(artifact: Mapping[str, Any], fallback_final_url: str) -> str:
    replay_key = _clean_str(artifact.get("replay_key"))
    if replay_key:
        return replay_key
    request_method = _artifact_method(artifact)
    target_url = _artifact_target_url(artifact, fallback_final_url)
    return f"__no_replay__|{request_method}|{target_url}"


def _primary_artifact_id(artifacts: list[Mapping[str, Any]]) -> str:
    if not artifacts:
        return ""

    def _rank_key(item: Mapping[str, Any]) -> tuple[Any, ...]:
        confidence = _clean_str(item.get("confidence")).lower()
        priority = _clean_str(item.get("priority")).lower()
        return (
            -_CONFIDENCE_RANK.get(confidence, 0),
            -_PRIORITY_RANK.get(priority, 0),
            _clean_str(item.get("artifact_id")),
            _clean_str(item.get("type")),
            _clean_str(item.get("url")),
            _clean_str(item.get("param")),
            _clean_str(item.get("endpoint_type")),
            int(item.get("_stable_index", 0)),
        )

    best = sorted(artifacts, key=_rank_key)[0]
    return _clean_str(best.get("artifact_id"))


def build_replay_groups(
    *,
    finding_artifacts: Mapping[str, Any] | None = None,
    request_recipe: Mapping[str, Any] | None = None,
    response_snapshot: Mapping[str, Any] | None = None,
    final_url: Any = "",
) -> dict[str, Any]:
    payload = _empty_contract()

    del request_recipe
    del response_snapshot

    artifacts_all = finding_artifacts.get("all") if isinstance(finding_artifacts, Mapping) else None
    if not isinstance(artifacts_all, list):
        return payload

    fallback_final_url = _clean_str(final_url)

    groups_map: dict[str, list[Mapping[str, Any]]] = {}
    for index, raw in enumerate(artifacts_all):
        if not isinstance(raw, Mapping):
            continue
        artifact = dict(raw)
        artifact["_stable_index"] = index
        group_key = _artifact_group_key(artifact, fallback_final_url)
        groups_map.setdefault(group_key, []).append(artifact)

    groups: list[dict[str, Any]] = []
    for replay_key, members in groups_map.items():
        target_url = ""
        request_method = ""
        for item in members:
            if not target_url:
                target_url = _artifact_target_url(item, fallback_final_url)
            if not request_method:
                request_method = _artifact_method(item)

        artifact_ids = _stable_dedup([_clean_str(item.get("artifact_id")) for item in members])
        artifact_types = _stable_dedup([_clean_str(item.get("type")) for item in members])
        priorities_present = _stable_dedup(
            [
                _clean_str(item.get("priority")).lower()
                for item in members
                if _clean_str(item.get("priority")).lower() in {"low", "medium", "high"}
            ]
        )
        confidences_present = _stable_dedup(
            [
                _clean_str(item.get("confidence")).lower()
                for item in members
                if _clean_str(item.get("confidence")).lower() in {"low", "medium", "high"}
            ]
        )
        baseline_body_hashes = _stable_dedup([_clean_str(item.get("baseline_body_hash")) for item in members])
        has_replay_recipe = any(bool(item.get("has_replay_recipe")) for item in members)
        has_baseline_hash = bool(baseline_body_hashes)

        groups.append(
            {
                "replay_key": replay_key,
                "target_url": target_url,
                "request_method": request_method,
                "artifacts_total": len(members),
                "artifact_ids": artifact_ids,
                "artifact_types": artifact_types,
                "priorities_present": priorities_present,
                "confidences_present": confidences_present,
                "baseline_body_hashes": baseline_body_hashes,
                "primary_artifact_id": _primary_artifact_id(members),
                "has_replay_recipe": has_replay_recipe,
                "has_baseline_hash": has_baseline_hash,
            }
        )

    groups.sort(
        key=lambda item: (
            -int(bool(item.get("has_replay_recipe"))),
            -int(bool(item.get("has_baseline_hash"))),
            -int(item.get("artifacts_total") or 0),
            _clean_str(item.get("replay_key")),
            _clean_str(item.get("target_url")),
        )
    )

    payload["all"] = groups

    types_present: list[str] = []
    seen_types: set[str] = set()
    for group in groups:
        for artifact_type in group.get("artifact_types", []):
            clean_type = _clean_str(artifact_type)
            if clean_type and clean_type not in seen_types:
                types_present.append(clean_type)
                seen_types.add(clean_type)

    unique_targets = {
        _clean_str(group.get("target_url"))
        for group in groups
        if _clean_str(group.get("target_url"))
    }

    payload["summary"] = {
        "total": len(groups),
        "replay_ready_total": sum(1 for group in groups if bool(group.get("has_replay_recipe"))),
        "unique_targets": len(unique_targets),
        "max_group_size": max((int(group.get("artifacts_total") or 0) for group in groups), default=0),
        "with_baseline_hash": sum(1 for group in groups if bool(group.get("has_baseline_hash"))),
        "types_present": types_present,
    }
    return payload
