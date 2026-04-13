from __future__ import annotations

from typing import Any, Mapping

from core.discovery.target_binding import normalize_target_source, resolve_precise_target


def _empty_contract() -> dict[str, Any]:
    return {
        "all": [],
        "summary": {
            "total": 0,
            "ready_total": 0,
            "with_headers": 0,
            "with_cookie_path": 0,
            "with_timeout": 0,
            "with_baseline_hash": 0,
            "unique_targets": 0,
            "types_present": [],
        },
    }


def _clean_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _stable_dedup_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        clean = _clean_str(item)
        if clean and clean not in seen:
            out.append(clean)
            seen.add(clean)
    return out


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, bool):
            return int(value)
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _scalar_friendly(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    return _clean_str(value)


def build_replay_manifest(
    *,
    replay_groups: Mapping[str, Any] | None = None,
    finding_artifacts: Mapping[str, Any] | None = None,
    request_recipe: Mapping[str, Any] | None = None,
    response_snapshot: Mapping[str, Any] | None = None,
    final_url: Any = "",
    discovery: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    del finding_artifacts

    payload = _empty_contract()
    groups = replay_groups.get("all") if isinstance(replay_groups, Mapping) else None
    if not isinstance(groups, list):
        return payload

    recipe = request_recipe if isinstance(request_recipe, Mapping) else {}
    snapshot = response_snapshot if isinstance(response_snapshot, Mapping) else {}
    fallback_final_url = _clean_str(final_url)
    discovery_base_url = _clean_str(discovery.get("base_url")) if isinstance(discovery, Mapping) else ""

    recipe_url = _clean_str(recipe.get("url"))
    recipe_method = _clean_str(recipe.get("method"))
    headers_present = isinstance(recipe.get("headers"), Mapping) and bool(recipe.get("headers"))
    cookie_path_present = bool(_clean_str(recipe.get("cookie_path")))
    timeout_value = _scalar_friendly(recipe.get("timeout"))
    redirects_value = _safe_int(recipe.get("redirects"), 0)

    baseline_status_code = _safe_int(snapshot.get("status_code"), 0)
    baseline_body_hash = _clean_str(snapshot.get("body_hash"))
    baseline_content_type = _clean_str(snapshot.get("content_type"))

    manifest_items: list[dict[str, Any]] = []
    for raw_group in groups:
        if not isinstance(raw_group, Mapping):
            continue

        replay_key = _clean_str(raw_group.get("replay_key"))
        target_url, target_source = resolve_precise_target(
            candidate_url=_clean_str(raw_group.get("target_url")),
            final_url=fallback_final_url,
            request_url=recipe_url,
            discovery_base_url=discovery_base_url,
        )
        group_target_source = normalize_target_source(raw_group.get("target_source"))
        if target_source == "candidate_url" and group_target_source != "unknown":
            target_source = group_target_source
        method = _clean_str(raw_group.get("request_method")) or recipe_method or ""

        artifact_ids = _stable_dedup_str_list(raw_group.get("artifact_ids"))
        artifact_types = _stable_dedup_str_list(raw_group.get("artifact_types"))
        ready_for_validation = bool(method and target_url and bool(raw_group.get("has_replay_recipe")))

        manifest_items.append(
            {
                "replay_key": replay_key,
                "target_url": target_url,
                "target_source": target_source,
                "method": method,
                "headers_present": headers_present,
                "cookie_path_present": cookie_path_present,
                "timeout": timeout_value,
                "redirects": redirects_value,
                "artifact_ids": artifact_ids,
                "artifact_types": artifact_types,
                "baseline_status_code": baseline_status_code,
                "baseline_body_hash": baseline_body_hash,
                "baseline_content_type": baseline_content_type,
                "ready_for_validation": ready_for_validation,
            }
        )

    manifest_items.sort(
        key=lambda item: (
            -int(bool(item.get("ready_for_validation"))),
            -int(bool(_clean_str(item.get("baseline_body_hash")))),
            -len(item.get("artifact_ids") or []),
            _clean_str(item.get("replay_key")),
            _clean_str(item.get("target_url")),
        )
    )

    unique_targets = {
        _clean_str(item.get("target_url"))
        for item in manifest_items
        if _clean_str(item.get("target_url"))
    }

    types_present: list[str] = []
    seen_types: set[str] = set()
    for item in manifest_items:
        for artifact_type in item.get("artifact_types", []):
            clean_type = _clean_str(artifact_type)
            if clean_type and clean_type not in seen_types:
                types_present.append(clean_type)
                seen_types.add(clean_type)

    payload["all"] = manifest_items
    payload["summary"] = {
        "total": len(manifest_items),
        "ready_total": sum(1 for item in manifest_items if bool(item.get("ready_for_validation"))),
        "with_headers": sum(1 for item in manifest_items if bool(item.get("headers_present"))),
        "with_cookie_path": sum(1 for item in manifest_items if bool(item.get("cookie_path_present"))),
        "with_timeout": sum(1 for item in manifest_items if _clean_str(item.get("timeout"))),
        "with_baseline_hash": sum(1 for item in manifest_items if _clean_str(item.get("baseline_body_hash"))),
        "unique_targets": len(unique_targets),
        "types_present": types_present,
    }
    return payload
