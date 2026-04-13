from __future__ import annotations

from typing import Any, Mapping

from core.discovery.target_binding import normalize_target_source, resolve_precise_target

_CHECK_REFLECTION_DIFF = "reflection_diff"
_CHECK_ERROR_PATTERN_DIFF = "error_pattern_diff"
_CHECK_STATUS_DIFF = "status_diff"
_CHECK_ORDER = (
    _CHECK_REFLECTION_DIFF,
    _CHECK_ERROR_PATTERN_DIFF,
    _CHECK_STATUS_DIFF,
)
_CHECK_PAYLOAD_FAMILY = {
    _CHECK_REFLECTION_DIFF: "reflection_probe",
    _CHECK_ERROR_PATTERN_DIFF: "error_probe",
    _CHECK_STATUS_DIFF: "status_probe",
}
_CHECK_COMPARISON_CONTRACT = {
    _CHECK_REFLECTION_DIFF: {
        "compare_mode": "reflection_compare",
        "baseline_fields": ["body_preview", "body_hash"],
        "requires_body_preview": True,
        "requires_status_code": False,
        "requires_body_hash": True,
        "requires_content_type": False,
    },
    _CHECK_ERROR_PATTERN_DIFF: {
        "compare_mode": "error_pattern_compare",
        "baseline_fields": ["status_code", "body_preview", "content_type"],
        "requires_body_preview": True,
        "requires_status_code": True,
        "requires_body_hash": False,
        "requires_content_type": True,
    },
    _CHECK_STATUS_DIFF: {
        "compare_mode": "status_compare",
        "baseline_fields": ["status_code"],
        "requires_body_preview": False,
        "requires_status_code": True,
        "requires_body_hash": False,
        "requires_content_type": False,
    },
}
_EVIDENCE_RANK = {"": 0, "low": 1, "medium": 2, "strong": 3}
_BASELINE_FIELD_ORDER = ("body_preview", "status_code", "body_hash", "content_type")
_EXECUTION_SURFACE_QUERY_PARAM = "query_param"
_EXECUTION_SURFACE_FORM_FIELD = "form_field"
_EXECUTION_SURFACE_ENDPOINT = "endpoint"
_EXECUTION_SURFACE_UNKNOWN = "unknown"
_EXECUTION_MODE_PARAM_ONLY = "param_only"
_EXECUTION_MODE_ENDPOINT_ONLY = "endpoint_only"
_EXECUTION_MODE_HYBRID = "hybrid"
_EXECUTION_MODE_UNAVAILABLE = "unavailable"


def _empty_contract() -> dict[str, Any]:
    return {
        "all": [],
        "summary": {
            "total": 0,
            "ready_total": 0,
            "with_param_targets": 0,
            "reflection_checks": 0,
            "error_pattern_checks": 0,
            "status_diff_checks": 0,
            "types_present": [],
            "checks_present": [],
            "total_checks": 0,
            "unique_checks_present": [],
            "plans_with_checks": 0,
            "plans_without_checks": 0,
            "plans_safe_mode_total": 0,
            "candidate_targets_total": 0,
            "unique_candidate_targets": 0,
            "candidate_to_check_density": 0.0,
            "avg_checks_per_plan": 0.0,
            "avg_candidate_targets_per_plan": 0.0,
            "ready_candidate_targets_total": 0,
            "ready_candidate_targets_unique": 0,
            "ready_candidate_coverage_ratio": 0.0,
            "evidence_levels_present": [],
            "methods_present": [],
            "unique_targets": 0,
            "target_sources_present": [],
            "targets_from_candidate_url": 0,
            "targets_from_final_url": 0,
            "targets_from_request_url": 0,
            "targets_from_discovery_base_url": 0,
            "targets_from_unknown": 0,
            "total_check_plan_items": 0,
            "ready_check_plan_items": 0,
            "reflection_probe_items": 0,
            "error_probe_items": 0,
            "status_probe_items": 0,
            "param_required_check_items": 0,
            "non_param_check_items": 0,
            "payload_families_present": [],
            "check_types_present": [],
            "plans_with_check_plan": 0,
            "plans_without_check_plan": 0,
            "avg_check_plan_items_per_plan": 0.0,
            "plans_requiring_body_preview": 0,
            "plans_requiring_status_code": 0,
            "plans_requiring_body_hash": 0,
            "plans_requiring_content_type": 0,
            "check_plan_items_requiring_body_preview": 0,
            "check_plan_items_requiring_status_code": 0,
            "check_plan_items_requiring_body_hash": 0,
            "check_plan_items_requiring_content_type": 0,
            "comparison_modes_present": [],
            "reflection_compare_items": 0,
            "error_pattern_compare_items": 0,
            "status_compare_items": 0,
            "baseline_field_body_preview_total": 0,
            "baseline_field_status_code_total": 0,
            "baseline_field_body_hash_total": 0,
            "baseline_field_content_type_total": 0,
            "execution_ready_check_plan_items": 0,
            "blocked_check_plan_items": 0,
            "plans_baseline_inputs_complete": 0,
            "plans_with_missing_baseline_fields": 0,
            "missing_body_preview_items": 0,
            "missing_status_code_items": 0,
            "missing_body_hash_items": 0,
            "missing_content_type_items": 0,
            "missing_baseline_fields_present": [],
            "plans_blocked_by_body_preview": 0,
            "plans_blocked_by_status_code": 0,
            "plans_blocked_by_body_hash": 0,
            "plans_blocked_by_content_type": 0,
            "execution_ready_ratio": 0.0,
            "baseline_completeness_ratio": 0.0,
            "parameterized_check_plan_items": 0,
            "endpoint_level_check_plan_items": 0,
            "plans_with_parameterized_checks": 0,
            "plans_with_endpoint_level_checks": 0,
            "total_effective_targets": 0,
            "avg_effective_targets_per_plan": 0.0,
            "execution_modes_present": [],
            "surface_types_present": [],
            "param_only_items": 0,
            "endpoint_only_items": 0,
            "hybrid_items": 0,
            "unavailable_surface_items": 0,
            "plans_param_only": 0,
            "plans_endpoint_only": 0,
            "plans_hybrid": 0,
            "plans_with_unavailable_surface": 0,
            "parameterized_ratio": 0.0,
            "endpoint_level_ratio": 0.0,
        },
    }


def _clean_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, bool):
            return int(value)
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


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


def _round_metric(value: float) -> float:
    return round(float(value), 3)


def _build_artifact_index(finding_artifacts: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    all_artifacts = finding_artifacts.get("all") if isinstance(finding_artifacts, Mapping) else None
    if not isinstance(all_artifacts, list):
        return {}
    index: dict[str, dict[str, Any]] = {}
    for artifact in all_artifacts:
        if not isinstance(artifact, Mapping):
            continue
        artifact_id = _clean_str(artifact.get("artifact_id"))
        if artifact_id and artifact_id not in index:
            index[artifact_id] = dict(artifact)
    return index


def _compute_suggested_checks(artifact_types: list[str]) -> list[str]:
    out: list[str] = []
    present = set(artifact_types)
    if "xss_candidate" in present:
        out.append(_CHECK_REFLECTION_DIFF)
    if "sqli_candidate" in present:
        out.extend((_CHECK_ERROR_PATTERN_DIFF, _CHECK_STATUS_DIFF))
    if "lfi_candidate" in present:
        out.extend((_CHECK_ERROR_PATTERN_DIFF, _CHECK_STATUS_DIFF))
    if "ssrf_candidate" in present:
        out.append(_CHECK_STATUS_DIFF)

    deduped: list[str] = []
    seen: set[str] = set()
    for check in out:
        if check in _CHECK_ORDER and check not in seen:
            deduped.append(check)
            seen.add(check)
    return deduped


def _compute_evidence_level(item: Mapping[str, Any], ready_for_validation: bool) -> str:
    if _clean_str(item.get("baseline_body_hash")):
        return "strong"
    if _safe_int(item.get("baseline_status_code"), 0) > 0:
        return "medium"
    if ready_for_validation:
        return "low"
    return ""


def _build_check_plan(
    *,
    suggested_checks: list[str],
    param_targets: list[str],
    ready_for_validation: bool,
    safe_mode: bool,
    target_url: str,
    target_source: str,
    baseline_availability: Mapping[str, bool],
) -> list[dict[str, Any]]:
    if not suggested_checks:
        return []

    clean_param_targets = _stable_dedup_str_list(param_targets)
    param_targets_count = len(clean_param_targets)
    requires_param_target = bool(param_targets_count > 0)
    seen: set[str] = set()
    check_plan: list[dict[str, Any]] = []
    for raw_check in suggested_checks:
        check_type = _clean_str(raw_check)
        if check_type in seen:
            continue
        seen.add(check_type)
        if check_type not in _CHECK_ORDER:
            continue
        comparison = dict(_CHECK_COMPARISON_CONTRACT.get(check_type) or {})
        comparison["baseline_fields"] = list(comparison.get("baseline_fields") or [])
        missing_fields: list[str] = []
        for field_name in _BASELINE_FIELD_ORDER:
            required_flag = bool((comparison or {}).get(f"requires_{field_name}"))
            if required_flag and not bool(baseline_availability.get(field_name)):
                missing_fields.append(field_name)
        all_required_available = not missing_fields
        baseline_inputs = {
            "body_preview_available": bool(baseline_availability.get("body_preview")),
            "status_code_available": bool(baseline_availability.get("status_code")),
            "body_hash_available": bool(baseline_availability.get("body_hash")),
            "content_type_available": bool(baseline_availability.get("content_type")),
            "all_required_available": all_required_available,
            "missing_fields": missing_fields,
        }
        ready = bool(ready_for_validation and safe_mode and check_type in _CHECK_ORDER)
        has_target_url = bool(_clean_str(target_url))
        if not has_target_url and not clean_param_targets:
            execution_surface = {
                "mode": _EXECUTION_MODE_UNAVAILABLE,
                "target_count": 0,
                "targets_present": False,
                "surface_types": [],
                "primary_surface": _EXECUTION_SURFACE_UNKNOWN,
            }
        elif clean_param_targets:
            execution_surface = {
                "mode": _EXECUTION_MODE_PARAM_ONLY,
                "target_count": param_targets_count,
                "targets_present": True,
                "surface_types": [_EXECUTION_SURFACE_QUERY_PARAM],
                "primary_surface": _EXECUTION_SURFACE_QUERY_PARAM,
            }
        else:
            execution_surface = {
                "mode": _EXECUTION_MODE_ENDPOINT_ONLY,
                "target_count": 0,
                "targets_present": False,
                "surface_types": [_EXECUTION_SURFACE_ENDPOINT],
                "primary_surface": _EXECUTION_SURFACE_ENDPOINT,
            }
        mode = _clean_str(execution_surface.get("mode"))
        parameterized = bool(mode == _EXECUTION_MODE_PARAM_ONLY)
        endpoint_level = bool(mode == _EXECUTION_MODE_ENDPOINT_ONLY)
        effective_target_count = (
            int(execution_surface.get("target_count") or 0)
            if parameterized
            else (1 if endpoint_level and has_target_url else 0)
        )

        check_plan.append(
            {
                "check_type": check_type,
                "payload_family": _CHECK_PAYLOAD_FAMILY[check_type],
                "requires_param_target": requires_param_target,
                "param_targets_count": int(param_targets_count),
                "baseline_required": True,
                "ready": ready,
                "safe_mode": bool(safe_mode),
                "target_url": target_url,
                "target_source": target_source,
                "comparison": comparison,
                "baseline_inputs": baseline_inputs,
                "execution_ready": bool(ready and all_required_available),
                "execution_surface": execution_surface,
                "parameterized": parameterized,
                "endpoint_level": endpoint_level,
                "effective_target_count": int(effective_target_count),
            }
        )
    return check_plan


def build_validation_plan(
    *,
    replay_manifest: Mapping[str, Any] | None = None,
    finding_artifacts: Mapping[str, Any] | None = None,
    candidates: Mapping[str, Any] | None = None,
    request_recipe: Mapping[str, Any] | None = None,
    response_snapshot: Mapping[str, Any] | None = None,
    final_url: Any = "",
    discovery: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    del candidates

    payload = _empty_contract()
    manifest_items = replay_manifest.get("all") if isinstance(replay_manifest, Mapping) else None
    if not isinstance(manifest_items, list):
        return payload

    recipe = request_recipe if isinstance(request_recipe, Mapping) else {}
    snapshot = response_snapshot if isinstance(response_snapshot, Mapping) else {}
    recipe_url = _clean_str(recipe.get("url"))
    recipe_method = _clean_str(recipe.get("method"))
    fallback_final_url = _clean_str(final_url)
    discovery_base_url = _clean_str(discovery.get("base_url")) if isinstance(discovery, Mapping) else ""
    artifacts_by_id = _build_artifact_index(finding_artifacts)

    plan_items: list[dict[str, Any]] = []
    for manifest_item in manifest_items:
        if not isinstance(manifest_item, Mapping):
            continue

        replay_key = _clean_str(manifest_item.get("replay_key"))
        target_url, target_source = resolve_precise_target(
            candidate_url=_clean_str(manifest_item.get("target_url")),
            final_url=fallback_final_url,
            request_url=recipe_url,
            discovery_base_url=discovery_base_url,
        )
        manifest_target_source = normalize_target_source(manifest_item.get("target_source"))
        if target_source == "candidate_url" and manifest_target_source != "unknown":
            target_source = manifest_target_source
        method = _clean_str(manifest_item.get("method")) or recipe_method or ""
        artifact_ids = _stable_dedup_str_list(manifest_item.get("artifact_ids"))
        artifact_types = _stable_dedup_str_list(manifest_item.get("artifact_types"))

        param_targets_raw: list[Any] = []
        for artifact_id in artifact_ids:
            artifact = artifacts_by_id.get(artifact_id)
            if not isinstance(artifact, Mapping):
                continue
            param = _clean_str(artifact.get("param"))
            if param:
                param_targets_raw.append(param)
        param_targets = _stable_dedup_str_list(param_targets_raw)

        suggested_checks = _compute_suggested_checks(artifact_types)
        ready_for_validation = bool(
            bool(manifest_item.get("ready_for_validation"))
            and bool(target_url)
            and bool(method)
        )
        evidence_level = _compute_evidence_level(manifest_item, ready_for_validation)
        safe_mode = True
        baseline_body_preview = _clean_str(snapshot.get("body_preview"))
        baseline_status_code = _safe_int(manifest_item.get("baseline_status_code"), 0)
        baseline_body_hash = _clean_str(manifest_item.get("baseline_body_hash"))
        baseline_content_type = _clean_str(manifest_item.get("baseline_content_type"))
        if baseline_status_code <= 0:
            baseline_status_code = _safe_int(snapshot.get("status_code"), 0)
        if not baseline_body_hash:
            baseline_body_hash = _clean_str(snapshot.get("body_hash"))
        if not baseline_content_type:
            baseline_content_type = _clean_str(snapshot.get("content_type"))
        if (not baseline_status_code or not baseline_body_hash or not baseline_content_type) and artifact_ids:
            for artifact_id in artifact_ids:
                artifact = artifacts_by_id.get(artifact_id)
                if not isinstance(artifact, Mapping):
                    continue
                if baseline_status_code <= 0:
                    baseline_status_code = _safe_int(artifact.get("baseline_status_code"), 0)
                if not baseline_body_hash:
                    baseline_body_hash = _clean_str(artifact.get("baseline_body_hash"))
                if not baseline_content_type:
                    baseline_content_type = _clean_str(artifact.get("baseline_content_type"))
                if baseline_status_code > 0 and baseline_body_hash and baseline_content_type:
                    break
        baseline_availability = {
            "body_preview": bool(baseline_body_preview),
            "status_code": bool(baseline_status_code > 0),
            "body_hash": bool(baseline_body_hash),
            "content_type": bool(baseline_content_type),
        }
        check_plan = _build_check_plan(
            suggested_checks=suggested_checks,
            param_targets=param_targets,
            ready_for_validation=ready_for_validation,
            safe_mode=safe_mode,
            target_url=target_url,
            target_source=target_source,
            baseline_availability=baseline_availability,
        )
        execution_modes_present = sorted(
            {
                _clean_str((check_item.get("execution_surface") or {}).get("mode"))
                for check_item in check_plan
                if isinstance(check_item, Mapping)
                and _clean_str((check_item.get("execution_surface") or {}).get("mode"))
            }
        )
        surface_types_present = sorted(
            {
                _clean_str(surface_type)
                for check_item in check_plan
                if isinstance(check_item, Mapping)
                for surface_type in ((check_item.get("execution_surface") or {}).get("surface_types") or [])
                if _clean_str(surface_type)
            }
        )
        parameterized_checks = sum(
            1
            for check_item in check_plan
            if isinstance(check_item, Mapping) and bool(check_item.get("parameterized"))
        )
        endpoint_level_checks = sum(
            1
            for check_item in check_plan
            if isinstance(check_item, Mapping) and bool(check_item.get("endpoint_level"))
        )
        total_effective_targets = sum(
            _safe_int(check_item.get("effective_target_count"), 0)
            for check_item in check_plan
            if isinstance(check_item, Mapping)
        )
        missing_baseline_fields = sorted(
            {
                _clean_str(field)
                for check_item in check_plan
                if isinstance(check_item, Mapping)
                for field in ((check_item.get("baseline_inputs") or {}).get("missing_fields") or [])
                if _clean_str(field) in _BASELINE_FIELD_ORDER
            }
        )
        execution_ready_checks = sum(
            1
            for check_item in check_plan
            if isinstance(check_item, Mapping) and bool(check_item.get("execution_ready"))
        )
        blocked_checks = max(len(check_plan) - execution_ready_checks, 0)

        plan_items.append(
            {
                "replay_key": replay_key,
                "target_url": target_url,
                "target_source": target_source,
                "method": method,
                "artifact_ids": artifact_ids,
                "artifact_types": artifact_types,
                "param_targets": param_targets,
                "suggested_checks": suggested_checks,
                "check_plan": check_plan,
                "evidence_level": evidence_level,
                "ready_for_validation": ready_for_validation,
                "safe_mode": safe_mode,
                "requires_any_body_preview": any(
                    isinstance(check_item, Mapping)
                    and bool((check_item.get("comparison") or {}).get("requires_body_preview"))
                    for check_item in check_plan
                ),
                "requires_any_status_code": any(
                    isinstance(check_item, Mapping)
                    and bool((check_item.get("comparison") or {}).get("requires_status_code"))
                    for check_item in check_plan
                ),
                "requires_any_body_hash": any(
                    isinstance(check_item, Mapping)
                    and bool((check_item.get("comparison") or {}).get("requires_body_hash"))
                    for check_item in check_plan
                ),
                "requires_any_content_type": any(
                    isinstance(check_item, Mapping)
                    and bool((check_item.get("comparison") or {}).get("requires_content_type"))
                    for check_item in check_plan
                ),
                "comparison_modes_present": sorted(
                    {
                        _clean_str((check_item.get("comparison") or {}).get("compare_mode"))
                        for check_item in check_plan
                        if isinstance(check_item, Mapping)
                        and _clean_str((check_item.get("comparison") or {}).get("compare_mode"))
                    }
                ),
                "baseline_inputs_complete": bool(check_plan) and bool(blocked_checks == 0),
                "missing_baseline_fields": missing_baseline_fields,
                "execution_ready_checks": execution_ready_checks,
                "blocked_checks": blocked_checks,
                "execution_blockers_present": list(missing_baseline_fields),
                "execution_modes_present": execution_modes_present,
                "surface_types_present": surface_types_present,
                "parameterized_checks": parameterized_checks,
                "endpoint_level_checks": endpoint_level_checks,
                "total_effective_targets": int(total_effective_targets),
                "has_parameterized_checks": bool(parameterized_checks > 0),
                "has_endpoint_level_checks": bool(endpoint_level_checks > 0),
            }
        )

    plan_items.sort(
        key=lambda item: (
            -int(bool(item.get("ready_for_validation"))),
            -_EVIDENCE_RANK.get(_clean_str(item.get("evidence_level")), 0),
            -len(item.get("suggested_checks") or []),
            _clean_str(item.get("replay_key")),
            _clean_str(item.get("target_url")),
        )
    )

    types_present: list[str] = []
    checks_present: list[str] = []
    seen_types: set[str] = set()
    seen_checks: set[str] = set()
    for item in plan_items:
        for artifact_type in item.get("artifact_types", []):
            clean = _clean_str(artifact_type)
            if clean and clean not in seen_types:
                types_present.append(clean)
                seen_types.add(clean)
        for check in item.get("suggested_checks", []):
            clean = _clean_str(check)
            if clean and clean not in seen_checks:
                checks_present.append(clean)
                seen_checks.add(clean)

    payload["all"] = plan_items
    total_plans = len(plan_items)
    total_checks = sum(len(item.get("suggested_checks") or []) for item in plan_items)
    total_check_plan_items = sum(len(item.get("check_plan") or []) for item in plan_items)
    ready_check_plan_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and bool(check_item.get("ready"))
    )
    parameterized_check_plan_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and bool(check_item.get("parameterized"))
    )
    endpoint_level_check_plan_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and bool(check_item.get("endpoint_level"))
    )
    total_effective_targets = sum(
        _safe_int(check_item.get("effective_target_count"), 0)
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
    )
    execution_modes_present = sorted(
        {
            _clean_str((check_item.get("execution_surface") or {}).get("mode"))
            for item in plan_items
            for check_item in (item.get("check_plan") or [])
            if isinstance(check_item, Mapping)
            and _clean_str((check_item.get("execution_surface") or {}).get("mode"))
        }
    )
    surface_types_present = sorted(
        {
            _clean_str(surface_type)
            for item in plan_items
            for check_item in (item.get("check_plan") or [])
            if isinstance(check_item, Mapping)
            for surface_type in ((check_item.get("execution_surface") or {}).get("surface_types") or [])
            if _clean_str(surface_type)
        }
    )
    param_only_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and _clean_str((check_item.get("execution_surface") or {}).get("mode")) == _EXECUTION_MODE_PARAM_ONLY
    )
    endpoint_only_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and _clean_str((check_item.get("execution_surface") or {}).get("mode")) == _EXECUTION_MODE_ENDPOINT_ONLY
    )
    hybrid_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and _clean_str((check_item.get("execution_surface") or {}).get("mode")) == _EXECUTION_MODE_HYBRID
    )
    unavailable_surface_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and _clean_str((check_item.get("execution_surface") or {}).get("mode")) == _EXECUTION_MODE_UNAVAILABLE
    )
    reflection_probe_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and _clean_str(check_item.get("payload_family")) == "reflection_probe"
    )
    error_probe_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and _clean_str(check_item.get("payload_family")) == "error_probe"
    )
    status_probe_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and _clean_str(check_item.get("payload_family")) == "status_probe"
    )
    param_required_check_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and bool(check_item.get("requires_param_target"))
    )
    non_param_check_items = max(total_check_plan_items - param_required_check_items, 0)
    check_plan_items_requiring_body_preview = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and bool((check_item.get("comparison") or {}).get("requires_body_preview"))
    )
    check_plan_items_requiring_status_code = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and bool((check_item.get("comparison") or {}).get("requires_status_code"))
    )
    check_plan_items_requiring_body_hash = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and bool((check_item.get("comparison") or {}).get("requires_body_hash"))
    )
    check_plan_items_requiring_content_type = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and bool((check_item.get("comparison") or {}).get("requires_content_type"))
    )
    comparison_modes_present = sorted(
        {
            _clean_str((check_item.get("comparison") or {}).get("compare_mode"))
            for item in plan_items
            for check_item in (item.get("check_plan") or [])
            if isinstance(check_item, Mapping)
            and _clean_str((check_item.get("comparison") or {}).get("compare_mode"))
        }
    )
    reflection_compare_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and _clean_str((check_item.get("comparison") or {}).get("compare_mode")) == "reflection_compare"
    )
    error_pattern_compare_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and _clean_str((check_item.get("comparison") or {}).get("compare_mode")) == "error_pattern_compare"
    )
    status_compare_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and _clean_str((check_item.get("comparison") or {}).get("compare_mode")) == "status_compare"
    )
    baseline_field_body_preview_total = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        for field in ((check_item.get("comparison") or {}).get("baseline_fields") or [])
        if _clean_str(field) == "body_preview"
    )
    baseline_field_status_code_total = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        for field in ((check_item.get("comparison") or {}).get("baseline_fields") or [])
        if _clean_str(field) == "status_code"
    )
    baseline_field_body_hash_total = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        for field in ((check_item.get("comparison") or {}).get("baseline_fields") or [])
        if _clean_str(field) == "body_hash"
    )
    baseline_field_content_type_total = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        for field in ((check_item.get("comparison") or {}).get("baseline_fields") or [])
        if _clean_str(field) == "content_type"
    )
    execution_ready_check_plan_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and bool(check_item.get("execution_ready"))
    )
    blocked_check_plan_items = max(total_check_plan_items - execution_ready_check_plan_items, 0)
    plans_baseline_inputs_complete = sum(1 for item in plan_items if bool(item.get("baseline_inputs_complete")))
    plans_with_missing_baseline_fields = sum(1 for item in plan_items if bool(item.get("missing_baseline_fields")))
    missing_body_preview_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and "body_preview" in ((check_item.get("baseline_inputs") or {}).get("missing_fields") or [])
    )
    missing_status_code_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and "status_code" in ((check_item.get("baseline_inputs") or {}).get("missing_fields") or [])
    )
    missing_body_hash_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and "body_hash" in ((check_item.get("baseline_inputs") or {}).get("missing_fields") or [])
    )
    missing_content_type_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and "content_type" in ((check_item.get("baseline_inputs") or {}).get("missing_fields") or [])
    )
    missing_baseline_fields_present = sorted(
        {
            _clean_str(field)
            for item in plan_items
            for field in (item.get("missing_baseline_fields") or [])
            if _clean_str(field) in _BASELINE_FIELD_ORDER
        }
    )
    plans_blocked_by_body_preview = sum(
        1 for item in plan_items if "body_preview" in (item.get("missing_baseline_fields") or [])
    )
    plans_blocked_by_status_code = sum(
        1 for item in plan_items if "status_code" in (item.get("missing_baseline_fields") or [])
    )
    plans_blocked_by_body_hash = sum(
        1 for item in plan_items if "body_hash" in (item.get("missing_baseline_fields") or [])
    )
    plans_blocked_by_content_type = sum(
        1 for item in plan_items if "content_type" in (item.get("missing_baseline_fields") or [])
    )
    payload_families_present = sorted(
        {
            _clean_str(check_item.get("payload_family"))
            for item in plan_items
            for check_item in (item.get("check_plan") or [])
            if isinstance(check_item, Mapping) and _clean_str(check_item.get("payload_family"))
        }
    )
    check_types_present = sorted(
        {
            _clean_str(check_item.get("check_type"))
            for item in plan_items
            for check_item in (item.get("check_plan") or [])
            if isinstance(check_item, Mapping) and _clean_str(check_item.get("check_type"))
        }
    )
    plans_with_checks = sum(1 for item in plan_items if bool(item.get("suggested_checks")))
    plans_with_check_plan = sum(1 for item in plan_items if bool(item.get("check_plan")))
    candidate_targets_total = sum(len(item.get("artifact_ids") or []) for item in plan_items)
    all_candidate_ids = {
        _clean_str(artifact_id)
        for item in plan_items
        for artifact_id in (item.get("artifact_ids") or [])
        if _clean_str(artifact_id)
    }
    ready_candidate_ids = {
        _clean_str(artifact_id)
        for item in plan_items
        if bool(item.get("ready_for_validation"))
        for artifact_id in (item.get("artifact_ids") or [])
        if _clean_str(artifact_id)
    }
    ready_candidate_targets_total = sum(
        len(item.get("artifact_ids") or []) for item in plan_items if bool(item.get("ready_for_validation"))
    )
    unique_candidate_targets = len(all_candidate_ids)
    methods_present = sorted(
        {
            _clean_str(item.get("method"))
            for item in plan_items
            if _clean_str(item.get("method"))
        }
    )
    evidence_levels_present = sorted(
        {
            _clean_str(item.get("evidence_level"))
            for item in plan_items
            if _clean_str(item.get("evidence_level"))
        }
    )

    unique_targets = {
        _clean_str(item.get("target_url"))
        for item in plan_items
        if _clean_str(item.get("target_url"))
    }
    target_source_counts = {
        "candidate_url": 0,
        "final_url": 0,
        "request_url": 0,
        "discovery_base_url": 0,
        "unknown": 0,
    }
    for item in plan_items:
        source = normalize_target_source(item.get("target_source"))
        target_source_counts[source] = int(target_source_counts.get(source, 0)) + 1
    target_sources_present = sorted(
        source for source, count in target_source_counts.items() if int(count or 0) > 0
    )

    payload["summary"] = {
        "total": total_plans,
        "ready_total": sum(1 for item in plan_items if bool(item.get("ready_for_validation"))),
        "with_param_targets": sum(1 for item in plan_items if bool(item.get("param_targets"))),
        "reflection_checks": sum(
            1 for item in plan_items if _CHECK_REFLECTION_DIFF in (item.get("suggested_checks") or [])
        ),
        "error_pattern_checks": sum(
            1 for item in plan_items if _CHECK_ERROR_PATTERN_DIFF in (item.get("suggested_checks") or [])
        ),
        "status_diff_checks": sum(
            1 for item in plan_items if _CHECK_STATUS_DIFF in (item.get("suggested_checks") or [])
        ),
        "types_present": types_present,
        "checks_present": checks_present,
        "total_checks": total_checks,
        "unique_checks_present": sorted(set(checks_present)),
        "plans_with_checks": plans_with_checks,
        "plans_without_checks": max(total_plans - plans_with_checks, 0),
        "plans_safe_mode_total": sum(1 for item in plan_items if bool(item.get("safe_mode"))),
        "candidate_targets_total": candidate_targets_total,
        "unique_candidate_targets": unique_candidate_targets,
        "candidate_to_check_density": _round_metric(
            (total_checks / unique_candidate_targets) if unique_candidate_targets else 0.0
        ),
        "avg_checks_per_plan": _round_metric((total_checks / total_plans) if total_plans else 0.0),
        "avg_candidate_targets_per_plan": _round_metric(
            (candidate_targets_total / total_plans) if total_plans else 0.0
        ),
        "ready_candidate_targets_total": ready_candidate_targets_total,
        "ready_candidate_targets_unique": len(ready_candidate_ids),
        "ready_candidate_coverage_ratio": _round_metric(
            (len(ready_candidate_ids) / unique_candidate_targets) if unique_candidate_targets else 0.0
        ),
        "evidence_levels_present": evidence_levels_present,
        "methods_present": methods_present,
        "unique_targets": len(unique_targets),
        "target_sources_present": target_sources_present,
        "targets_from_candidate_url": int(target_source_counts.get("candidate_url", 0)),
        "targets_from_final_url": int(target_source_counts.get("final_url", 0)),
        "targets_from_request_url": int(target_source_counts.get("request_url", 0)),
        "targets_from_discovery_base_url": int(target_source_counts.get("discovery_base_url", 0)),
        "targets_from_unknown": int(target_source_counts.get("unknown", 0)),
        "total_check_plan_items": total_check_plan_items,
        "ready_check_plan_items": ready_check_plan_items,
        "reflection_probe_items": reflection_probe_items,
        "error_probe_items": error_probe_items,
        "status_probe_items": status_probe_items,
        "param_required_check_items": param_required_check_items,
        "non_param_check_items": non_param_check_items,
        "payload_families_present": payload_families_present,
        "check_types_present": check_types_present,
        "plans_with_check_plan": plans_with_check_plan,
        "plans_without_check_plan": max(total_plans - plans_with_check_plan, 0),
        "avg_check_plan_items_per_plan": _round_metric(
            (total_check_plan_items / total_plans) if total_plans else 0.0
        ),
        "plans_requiring_body_preview": sum(1 for item in plan_items if bool(item.get("requires_any_body_preview"))),
        "plans_requiring_status_code": sum(1 for item in plan_items if bool(item.get("requires_any_status_code"))),
        "plans_requiring_body_hash": sum(1 for item in plan_items if bool(item.get("requires_any_body_hash"))),
        "plans_requiring_content_type": sum(1 for item in plan_items if bool(item.get("requires_any_content_type"))),
        "check_plan_items_requiring_body_preview": check_plan_items_requiring_body_preview,
        "check_plan_items_requiring_status_code": check_plan_items_requiring_status_code,
        "check_plan_items_requiring_body_hash": check_plan_items_requiring_body_hash,
        "check_plan_items_requiring_content_type": check_plan_items_requiring_content_type,
        "comparison_modes_present": comparison_modes_present,
        "reflection_compare_items": reflection_compare_items,
        "error_pattern_compare_items": error_pattern_compare_items,
        "status_compare_items": status_compare_items,
        "baseline_field_body_preview_total": baseline_field_body_preview_total,
        "baseline_field_status_code_total": baseline_field_status_code_total,
        "baseline_field_body_hash_total": baseline_field_body_hash_total,
        "baseline_field_content_type_total": baseline_field_content_type_total,
        "execution_ready_check_plan_items": execution_ready_check_plan_items,
        "blocked_check_plan_items": blocked_check_plan_items,
        "plans_baseline_inputs_complete": plans_baseline_inputs_complete,
        "plans_with_missing_baseline_fields": plans_with_missing_baseline_fields,
        "missing_body_preview_items": missing_body_preview_items,
        "missing_status_code_items": missing_status_code_items,
        "missing_body_hash_items": missing_body_hash_items,
        "missing_content_type_items": missing_content_type_items,
        "missing_baseline_fields_present": missing_baseline_fields_present,
        "plans_blocked_by_body_preview": plans_blocked_by_body_preview,
        "plans_blocked_by_status_code": plans_blocked_by_status_code,
        "plans_blocked_by_body_hash": plans_blocked_by_body_hash,
        "plans_blocked_by_content_type": plans_blocked_by_content_type,
        "execution_ready_ratio": _round_metric(
            (execution_ready_check_plan_items / total_check_plan_items) if total_check_plan_items else 0.0
        ),
        "baseline_completeness_ratio": _round_metric(
            (plans_baseline_inputs_complete / total_plans) if total_plans else 0.0
        ),
        "parameterized_check_plan_items": parameterized_check_plan_items,
        "endpoint_level_check_plan_items": endpoint_level_check_plan_items,
        "plans_with_parameterized_checks": sum(1 for item in plan_items if bool(item.get("has_parameterized_checks"))),
        "plans_with_endpoint_level_checks": sum(
            1 for item in plan_items if bool(item.get("has_endpoint_level_checks"))
        ),
        "total_effective_targets": int(total_effective_targets),
        "avg_effective_targets_per_plan": _round_metric(
            (total_effective_targets / total_plans) if total_plans else 0.0
        ),
        "execution_modes_present": execution_modes_present,
        "surface_types_present": surface_types_present,
        "param_only_items": param_only_items,
        "endpoint_only_items": endpoint_only_items,
        "hybrid_items": hybrid_items,
        "unavailable_surface_items": unavailable_surface_items,
        "plans_param_only": sum(1 for item in plan_items if _EXECUTION_MODE_PARAM_ONLY in (item.get("execution_modes_present") or [])),
        "plans_endpoint_only": sum(
            1 for item in plan_items if _EXECUTION_MODE_ENDPOINT_ONLY in (item.get("execution_modes_present") or [])
        ),
        "plans_hybrid": sum(1 for item in plan_items if _EXECUTION_MODE_HYBRID in (item.get("execution_modes_present") or [])),
        "plans_with_unavailable_surface": sum(
            1 for item in plan_items if _EXECUTION_MODE_UNAVAILABLE in (item.get("execution_modes_present") or [])
        ),
        "parameterized_ratio": _round_metric(
            (parameterized_check_plan_items / total_check_plan_items) if total_check_plan_items else 0.0
        ),
        "endpoint_level_ratio": _round_metric(
            (endpoint_level_check_plan_items / total_check_plan_items) if total_check_plan_items else 0.0
        ),
    }
    return payload
