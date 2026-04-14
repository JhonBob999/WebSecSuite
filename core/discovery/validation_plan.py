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
_MUTATION_STRATEGY_PARAM_REPLACE = "param_replace"
_MUTATION_STRATEGY_ENDPOINT_COMPARE = "endpoint_compare"
_MUTATION_STRATEGY_UNAVAILABLE = "unavailable"
_MUTATION_SLOT_PARAM = "param_slot"
_MUTATION_SLOT_ENDPOINT = "endpoint_slot"
_MUTATION_SLOT_NONE = "none"
_MUTATION_SORT_WEIGHT = {
    _MUTATION_STRATEGY_PARAM_REPLACE: 1,
    _MUTATION_STRATEGY_ENDPOINT_COMPARE: 2,
    _MUTATION_STRATEGY_UNAVAILABLE: 3,
}
_EXECUTION_LANE_READY_PARAM = "ready_param"
_EXECUTION_LANE_READY_ENDPOINT = "ready_endpoint"
_EXECUTION_LANE_BLOCKED_PARAM = "blocked_param"
_EXECUTION_LANE_BLOCKED_ENDPOINT = "blocked_endpoint"
_EXECUTION_LANE_UNAVAILABLE = "unavailable"
_EXECUTION_LANE_PRIORITY = {
    _EXECUTION_LANE_READY_PARAM: 1,
    _EXECUTION_LANE_READY_ENDPOINT: 2,
    _EXECUTION_LANE_BLOCKED_PARAM: 3,
    _EXECUTION_LANE_BLOCKED_ENDPOINT: 4,
    _EXECUTION_LANE_UNAVAILABLE: 5,
}
_VALIDATOR_JOB_SAFE = "safe_validation"
_VALIDATOR_JOB_BLOCKED = "blocked_validation"
_VALIDATOR_JOB_UNAVAILABLE = "unavailable_validation"
_QUEUE_DISPATCH_READY_ONLY = "ready_only"
_QUEUE_DISPATCH_MIXED = "mixed"
_QUEUE_DISPATCH_BLOCKED_ONLY = "blocked_only"
_QUEUE_DISPATCH_UNAVAILABLE_ONLY = "unavailable_only"
_QUEUE_DISPATCH_EMPTY = "empty"
_QUEUE_DISPATCH_VALID_MODES = {
    _QUEUE_DISPATCH_READY_ONLY,
    _QUEUE_DISPATCH_MIXED,
    _QUEUE_DISPATCH_BLOCKED_ONLY,
    _QUEUE_DISPATCH_UNAVAILABLE_ONLY,
    _QUEUE_DISPATCH_EMPTY,
}
_VALIDATOR_JOB_TYPE_PRECEDENCE = {
    _VALIDATOR_JOB_SAFE: 1,
    _VALIDATOR_JOB_BLOCKED: 2,
    _VALIDATOR_JOB_UNAVAILABLE: 3,
}
_BLOCKER_REASON_MISSING_BODY_PREVIEW = "missing_body_preview"
_BLOCKER_REASON_MISSING_STATUS_CODE = "missing_status_code"
_BLOCKER_REASON_MISSING_BODY_HASH = "missing_body_hash"
_BLOCKER_REASON_MISSING_CONTENT_TYPE = "missing_content_type"
_BLOCKER_REASON_UNAVAILABLE_SURFACE = "unavailable_surface"
_BLOCKER_REASON_NO_PARAM_TARGETS = "no_param_targets"
_BLOCKER_REASON_BLOCKED_UNKNOWN = "blocked_unknown"
_BLOCKER_REASON_UNAVAILABLE_UNKNOWN = "unavailable_unknown"
_BLOCKER_REASON_ORDER = (
    _BLOCKER_REASON_MISSING_BODY_PREVIEW,
    _BLOCKER_REASON_MISSING_STATUS_CODE,
    _BLOCKER_REASON_MISSING_BODY_HASH,
    _BLOCKER_REASON_MISSING_CONTENT_TYPE,
    _BLOCKER_REASON_UNAVAILABLE_SURFACE,
    _BLOCKER_REASON_NO_PARAM_TARGETS,
    _BLOCKER_REASON_BLOCKED_UNKNOWN,
    _BLOCKER_REASON_UNAVAILABLE_UNKNOWN,
)
_BASELINE_BLOCKER_REASONS = {
    _BLOCKER_REASON_MISSING_BODY_PREVIEW,
    _BLOCKER_REASON_MISSING_STATUS_CODE,
    _BLOCKER_REASON_MISSING_BODY_HASH,
    _BLOCKER_REASON_MISSING_CONTENT_TYPE,
}
_BLOCKED_SIDE_REASONS = _BASELINE_BLOCKER_REASONS | {
    _BLOCKER_REASON_NO_PARAM_TARGETS,
    _BLOCKER_REASON_BLOCKED_UNKNOWN,
}
_UNAVAILABLE_SIDE_REASONS = {
    _BLOCKER_REASON_UNAVAILABLE_SURFACE,
    _BLOCKER_REASON_UNAVAILABLE_UNKNOWN,
}


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
            "ready_param_items": 0,
            "ready_endpoint_items": 0,
            "blocked_param_items": 0,
            "blocked_endpoint_items": 0,
            "unavailable_items": 0,
            "execution_lanes_present": [],
            "highest_priority_plans": 0,
            "ready_queue_total": 0,
            "blocked_queue_total": 0,
            "avg_queue_size_per_plan": 0.0,
            "avg_ready_queue_per_plan": 0.0,
            "avg_blocked_queue_per_plan": 0.0,
            "plans_primary_ready_param": 0,
            "plans_primary_ready_endpoint": 0,
            "plans_primary_blocked_param": 0,
            "plans_primary_blocked_endpoint": 0,
            "plans_primary_unavailable": 0,
            "execution_priority_min": 0,
            "execution_priority_max": 0,
            "param_replace_items": 0,
            "endpoint_compare_items": 0,
            "unavailable_mutation_items": 0,
            "mutating_check_plan_items": 0,
            "baseline_only_check_plan_items": 0,
            "mutation_ready_check_plan_items": 0,
            "mutation_strategies_present": [],
            "plans_with_mutating_checks": 0,
            "plans_with_baseline_only_checks": 0,
            "total_mutation_slots": 0,
            "avg_mutation_slots_per_plan": 0.0,
            "mutation_ready_ratio": 0.0,
            "plans_primary_param_replace": 0,
            "plans_primary_endpoint_compare": 0,
            "validator_jobs_total": 0,
            "validator_jobs_ready": 0,
            "validator_jobs_blocked": 0,
            "validator_jobs_unavailable": 0,
            "validator_job_types_present": [],
            "safe_validation_jobs": 0,
            "blocked_validation_jobs": 0,
            "unavailable_validation_jobs": 0,
            "plans_with_ready_validator_jobs": 0,
            "plans_with_blocked_validator_jobs": 0,
            "plans_with_unavailable_validator_jobs": 0,
            "validator_job_ready_ratio": 0.0,
            "unique_validator_job_ids": 0,
            "avg_validator_jobs_per_plan": 0.0,
            "avg_ready_validator_jobs_per_plan": 0.0,
            "plans_primary_safe_validation": 0,
            "plans_primary_blocked_validation": 0,
            "plans_primary_unavailable_validation": 0,
        },
    }


def _empty_validator_queue_contract() -> dict[str, Any]:
    return {
        "all": [],
        "summary": {
            "total": 0,
            "dispatch_ready_total": 0,
            "jobs_total": 0,
            "jobs_ready": 0,
            "jobs_blocked": 0,
            "jobs_unavailable": 0,
            "unique_targets": 0,
            "methods_present": [],
            "target_sources_present": [],
            "validator_job_types_present": [],
            "compare_modes_present": [],
            "mutation_strategies_present": [],
            "execution_lanes_present": [],
            "max_queue_size": 0,
            "min_queue_size": 0,
            "avg_queue_size": 0.0,
            "ready_queue_ratio": 0.0,
            "validator_job_ready_ratio": 0.0,
            "primary_ready_queues": 0,
            "unique_validator_job_ids": 0,
            "ready_only_queues": 0,
            "mixed_queues": 0,
            "blocked_only_queues": 0,
            "unavailable_only_queues": 0,
            "empty_queues": 0,
            "dispatch_jobs_total": 0,
            "blocked_jobs_total": 0,
            "unavailable_jobs_total": 0,
            "fully_dispatchable_queues": 0,
            "partially_dispatchable_queues": 0,
            "primary_dispatchable_queues": 0,
            "dispatch_modes_present": [],
            "avg_dispatch_jobs_per_queue": 0.0,
            "avg_blocked_jobs_per_queue": 0.0,
            "avg_unavailable_jobs_per_queue": 0.0,
            "fully_dispatchable_ratio": 0.0,
            "dispatch_job_ratio": 0.0,
            "queues_with_blocker_reasons": 0,
            "blocker_reasons_present": [],
            "primary_blocker_reasons_present": [],
            "missing_body_preview_queues": 0,
            "missing_status_code_queues": 0,
            "missing_body_hash_queues": 0,
            "missing_content_type_queues": 0,
            "unavailable_surface_queues": 0,
            "no_param_target_queues": 0,
            "blocked_unknown_queues": 0,
            "unavailable_unknown_queues": 0,
            "queues_with_baseline_blockers": 0,
            "queues_with_surface_blockers": 0,
            "queues_with_param_target_blockers": 0,
            "avg_blocker_reasons_per_queue": 0.0,
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


def _safe_sort_value(value: Any, default: str = "-") -> str:
    clean = _clean_str(value)
    return clean if clean else default


def _compute_execution_lane(
    *,
    mode: str,
    execution_ready: bool,
    parameterized: bool,
    endpoint_level: bool,
) -> str:
    if mode == _EXECUTION_MODE_UNAVAILABLE:
        return _EXECUTION_LANE_UNAVAILABLE
    if execution_ready and parameterized:
        return _EXECUTION_LANE_READY_PARAM
    if execution_ready and endpoint_level:
        return _EXECUTION_LANE_READY_ENDPOINT
    if (not execution_ready) and parameterized:
        return _EXECUTION_LANE_BLOCKED_PARAM
    if (not execution_ready) and endpoint_level:
        return _EXECUTION_LANE_BLOCKED_ENDPOINT
    return _EXECUTION_LANE_UNAVAILABLE


def _compute_execution_priority(lane: str) -> int:
    return int(_EXECUTION_LANE_PRIORITY.get(_clean_str(lane), 5))


def _build_mutation_binding(
    *,
    mode: str,
    effective_target_count: int,
    has_target_url: bool,
) -> dict[str, Any]:
    clean_mode = _clean_str(mode)
    safe_effective_target_count = max(_safe_int(effective_target_count, 0), 0)
    if clean_mode in {_EXECUTION_MODE_PARAM_ONLY, _EXECUTION_MODE_HYBRID}:
        return {
            "strategy": _MUTATION_STRATEGY_PARAM_REPLACE,
            "mutating": True,
            "slot_count": max(1, safe_effective_target_count),
            "slot_type": _MUTATION_SLOT_PARAM,
            "baseline_only": False,
        }
    if clean_mode == _EXECUTION_MODE_ENDPOINT_ONLY:
        slot_count = 1 if bool(has_target_url) else 0
        return {
            "strategy": _MUTATION_STRATEGY_ENDPOINT_COMPARE,
            "mutating": False,
            "slot_count": int(slot_count),
            "slot_type": _MUTATION_SLOT_ENDPOINT if slot_count == 1 else _MUTATION_SLOT_NONE,
            "baseline_only": True,
        }
    return {
        "strategy": _MUTATION_STRATEGY_UNAVAILABLE,
        "mutating": False,
        "slot_count": 0,
        "slot_type": _MUTATION_SLOT_NONE,
        "baseline_only": True,
    }


def _build_execution_sort_key(
    *,
    lane: str,
    priority: int,
    target_url: str,
    check_type: str,
    target_source: str,
    primary_surface: str,
) -> str:
    parts = [
        _safe_sort_value(lane),
        str(int(priority)),
        _safe_sort_value(target_url),
        _safe_sort_value(check_type),
        _safe_sort_value(target_source),
        _safe_sort_value(primary_surface),
    ]
    return "|".join(parts)


def _build_validator_job(
    *,
    safe_mode: bool,
    target_url: str,
    target_source: str,
    check_type: str,
    compare_mode: str,
    execution_lane: str,
    mutation_strategy: str,
    mutation_ready: bool,
) -> dict[str, Any]:
    clean_compare_mode = _clean_str(compare_mode)
    clean_mutation_strategy = _clean_str(mutation_strategy) or _MUTATION_STRATEGY_UNAVAILABLE
    clean_execution_lane = _clean_str(execution_lane)
    if clean_execution_lane in {_EXECUTION_LANE_READY_PARAM, _EXECUTION_LANE_READY_ENDPOINT} and bool(mutation_ready):
        job_type = _VALIDATOR_JOB_SAFE
    elif clean_execution_lane in {_EXECUTION_LANE_BLOCKED_PARAM, _EXECUTION_LANE_BLOCKED_ENDPOINT}:
        job_type = _VALIDATOR_JOB_BLOCKED
    else:
        job_type = _VALIDATOR_JOB_UNAVAILABLE
    job_id = "|".join(
        [
            _safe_sort_value(target_url),
            _safe_sort_value(check_type),
            _safe_sort_value(clean_compare_mode),
            _safe_sort_value(clean_execution_lane),
            _safe_sort_value(clean_mutation_strategy),
        ]
    )
    return {
        "job_id": job_id,
        "job_type": job_type,
        "job_ready": bool(job_type == _VALIDATOR_JOB_SAFE),
        "safe_mode": bool(safe_mode),
        "target_url": target_url,
        "target_source": target_source,
        "check_type": check_type,
        "compare_mode": clean_compare_mode,
        "execution_lane": clean_execution_lane,
        "mutation_strategy": clean_mutation_strategy,
    }


def _build_validator_queue_key(
    *,
    target_url: str,
    method: str,
    target_source: str,
    safe_mode: bool,
) -> str:
    return "|".join(
        [
            _safe_sort_value(target_url),
            _safe_sort_value(method),
            _safe_sort_value(target_source),
            "true" if bool(safe_mode) else "false",
        ]
    )


def _build_queue_dispatch_contract(
    dispatch_job_ids: list[str], blocked_job_ids: list[str], unavailable_job_ids: list[str]
) -> dict[str, Any]:
    dispatch_job_ids = sorted({_clean_str(job_id) for job_id in dispatch_job_ids if _clean_str(job_id)})
    blocked_job_ids = sorted({_clean_str(job_id) for job_id in blocked_job_ids if _clean_str(job_id)})
    unavailable_job_ids = sorted({_clean_str(job_id) for job_id in unavailable_job_ids if _clean_str(job_id)})
    dispatch_job_count = len(dispatch_job_ids)
    blocked_job_count = len(blocked_job_ids)
    unavailable_job_count = len(unavailable_job_ids)
    jobs_total = dispatch_job_count + blocked_job_count + unavailable_job_count

    if jobs_total == 0:
        dispatch_mode = _QUEUE_DISPATCH_EMPTY
    elif dispatch_job_count > 0 and blocked_job_count == 0 and unavailable_job_count == 0:
        dispatch_mode = _QUEUE_DISPATCH_READY_ONLY
    elif dispatch_job_count == 0 and blocked_job_count > 0 and unavailable_job_count == 0:
        dispatch_mode = _QUEUE_DISPATCH_BLOCKED_ONLY
    elif dispatch_job_count == 0 and blocked_job_count == 0 and unavailable_job_count > 0:
        dispatch_mode = _QUEUE_DISPATCH_UNAVAILABLE_ONLY
    else:
        dispatch_mode = _QUEUE_DISPATCH_MIXED
    if dispatch_mode not in _QUEUE_DISPATCH_VALID_MODES:
        dispatch_mode = _QUEUE_DISPATCH_EMPTY if jobs_total == 0 else _QUEUE_DISPATCH_MIXED

    fully_dispatchable = bool(jobs_total > 0 and dispatch_job_count == jobs_total)
    dispatch_ratio = _round_metric((dispatch_job_count / jobs_total) if jobs_total else 0.0)
    primary_dispatch_job_id = dispatch_job_ids[0] if dispatch_job_ids else ""
    return {
        "dispatch_mode": dispatch_mode,
        "dispatch_job_ids": dispatch_job_ids,
        "blocked_job_ids": blocked_job_ids,
        "unavailable_job_ids": unavailable_job_ids,
        "dispatch_job_count": dispatch_job_count,
        "blocked_job_count": blocked_job_count,
        "unavailable_job_count": unavailable_job_count,
        "jobs_total": jobs_total,
        "fully_dispatchable": fully_dispatchable,
        "dispatch_ratio": dispatch_ratio,
        "primary_dispatch_job_id": primary_dispatch_job_id,
        "has_dispatchable_jobs": bool(dispatch_job_count > 0),
    }


def _build_queue_blocker_diagnostics(
    *,
    check_items: list[Mapping[str, Any]],
    blocked_job_count: int,
    unavailable_job_count: int,
) -> dict[str, Any]:
    reason_counts: dict[str, int] = {}

    def _inc(reason: str) -> None:
        clean_reason = _clean_str(reason)
        if clean_reason not in _BLOCKER_REASON_ORDER:
            return
        reason_counts[clean_reason] = int(reason_counts.get(clean_reason, 0)) + 1

    for check_item in check_items:
        if not isinstance(check_item, Mapping):
            continue
        validator_job = check_item.get("validator_job") or {}
        if not isinstance(validator_job, Mapping):
            continue
        job_type = _clean_str(validator_job.get("job_type"))
        if job_type not in {_VALIDATOR_JOB_BLOCKED, _VALIDATOR_JOB_UNAVAILABLE}:
            continue
        missing_fields = {
            _clean_str(field_name)
            for field_name in ((check_item.get("baseline_inputs") or {}).get("missing_fields") or [])
            if _clean_str(field_name) in _BASELINE_FIELD_ORDER
        }
        if "body_preview" in missing_fields:
            _inc(_BLOCKER_REASON_MISSING_BODY_PREVIEW)
        if "status_code" in missing_fields:
            _inc(_BLOCKER_REASON_MISSING_STATUS_CODE)
        if "body_hash" in missing_fields:
            _inc(_BLOCKER_REASON_MISSING_BODY_HASH)
        if "content_type" in missing_fields:
            _inc(_BLOCKER_REASON_MISSING_CONTENT_TYPE)
        execution_mode = _clean_str((check_item.get("execution_surface") or {}).get("mode"))
        if execution_mode == _EXECUTION_MODE_UNAVAILABLE:
            _inc(_BLOCKER_REASON_UNAVAILABLE_SURFACE)
        requires_param_target = bool(check_item.get("requires_param_target"))
        effective_target_count = _safe_int(check_item.get("effective_target_count"), 0)
        if requires_param_target and effective_target_count <= 0:
            _inc(_BLOCKER_REASON_NO_PARAM_TARGETS)

    if blocked_job_count > 0 and not any(reason_counts.get(reason, 0) > 0 for reason in _BLOCKED_SIDE_REASONS):
        _inc(_BLOCKER_REASON_BLOCKED_UNKNOWN)
    if unavailable_job_count > 0 and not any(
        reason_counts.get(reason, 0) > 0 for reason in _UNAVAILABLE_SIDE_REASONS
    ):
        _inc(_BLOCKER_REASON_UNAVAILABLE_UNKNOWN)

    blocker_reasons = [reason for reason in _BLOCKER_REASON_ORDER if _safe_int(reason_counts.get(reason), 0) > 0]
    blocked_reasons_present = [reason for reason in blocker_reasons if reason in _BLOCKED_SIDE_REASONS]
    unavailable_reasons_present = [reason for reason in blocker_reasons if reason in _UNAVAILABLE_SIDE_REASONS]
    primary_blocker_reason = blocker_reasons[0] if blocker_reasons else ""
    filtered_counts = {reason: int(reason_counts[reason]) for reason in blocker_reasons}
    return {
        "blocker_reasons": blocker_reasons,
        "blocker_reason_counts": filtered_counts,
        "primary_blocker_reason": primary_blocker_reason,
        "has_blocker_reasons": bool(blocker_reasons),
        "blocked_reasons_present": blocked_reasons_present,
        "unavailable_reasons_present": unavailable_reasons_present,
    }


def build_validator_queue(validation_plan: Mapping[str, Any] | None = None) -> dict[str, Any]:
    payload = _empty_validator_queue_contract()
    if not isinstance(validation_plan, Mapping):
        return payload

    plan_items = validation_plan.get("all")
    if not isinstance(plan_items, list):
        return payload

    grouped: dict[str, dict[str, Any]] = {}
    for plan_item in plan_items:
        if not isinstance(plan_item, Mapping):
            continue
        method = _clean_str(plan_item.get("method"))
        safe_mode = bool(plan_item.get("safe_mode"))
        for check_item in (plan_item.get("check_plan") or []):
            if not isinstance(check_item, Mapping):
                continue
            validator_job = check_item.get("validator_job") or {}
            if not isinstance(validator_job, Mapping):
                continue
            target_url = _clean_str(validator_job.get("target_url"))
            target_source = _clean_str(validator_job.get("target_source"))
            queue_key = _build_validator_queue_key(
                target_url=target_url,
                method=method,
                target_source=target_source,
                safe_mode=safe_mode,
            )
            group = grouped.setdefault(
                queue_key,
                {
                    "queue_key": queue_key,
                    "target_url": target_url,
                    "method": method,
                    "target_source": target_source,
                    "safe_mode": bool(safe_mode),
                    "validator_job_ids": [],
                    "validator_job_types": [],
                    "check_types": [],
                    "compare_modes": [],
                    "mutation_strategies": [],
                    "execution_lanes": [],
                    "jobs_total": 0,
                    "jobs_ready": 0,
                    "jobs_blocked": 0,
                    "jobs_unavailable": 0,
                    "primary_job_id": "",
                    "dispatch_ready": False,
                    "highest_job_priority": 0,
                    "queue_job_ids_unique": 0,
                    "_all_job_ids": set(),
                    "_ready_job_ids": set(),
                    "_dispatch_job_ids": set(),
                    "_blocked_job_ids": set(),
                    "_unavailable_job_ids": set(),
                    "_job_types": set(),
                    "_check_types": set(),
                    "_compare_modes": set(),
                    "_mutation_strategies": set(),
                    "_execution_lanes": set(),
                    "_priorities": [],
                    "_check_items": [],
                },
            )
            job_id = _clean_str(validator_job.get("job_id"))
            job_type = _clean_str(validator_job.get("job_type"))
            check_type = _clean_str(validator_job.get("check_type"))
            compare_mode = _clean_str(validator_job.get("compare_mode"))
            mutation_strategy = _clean_str(validator_job.get("mutation_strategy"))
            execution_lane = _clean_str(validator_job.get("execution_lane"))
            job_ready = bool(validator_job.get("job_ready"))
            execution_priority = _safe_int(check_item.get("execution_priority"), 0)

            group["jobs_total"] = int(group["jobs_total"]) + 1
            if job_ready:
                group["jobs_ready"] = int(group["jobs_ready"]) + 1
            if job_type == _VALIDATOR_JOB_BLOCKED:
                group["jobs_blocked"] = int(group["jobs_blocked"]) + 1
            elif job_type == _VALIDATOR_JOB_UNAVAILABLE:
                group["jobs_unavailable"] = int(group["jobs_unavailable"]) + 1

            if job_id:
                group["_all_job_ids"].add(job_id)
                if job_ready:
                    group["_ready_job_ids"].add(job_id)
                if job_type == _VALIDATOR_JOB_SAFE:
                    group["_dispatch_job_ids"].add(job_id)
                elif job_type == _VALIDATOR_JOB_BLOCKED:
                    group["_blocked_job_ids"].add(job_id)
                elif job_type == _VALIDATOR_JOB_UNAVAILABLE:
                    group["_unavailable_job_ids"].add(job_id)
            if job_type:
                group["_job_types"].add(job_type)
            if check_type:
                group["_check_types"].add(check_type)
            if compare_mode:
                group["_compare_modes"].add(compare_mode)
            if mutation_strategy:
                group["_mutation_strategies"].add(mutation_strategy)
            if execution_lane:
                group["_execution_lanes"].add(execution_lane)
            if execution_priority > 0:
                group["_priorities"].append(execution_priority)
            group["_check_items"].append(check_item)

    queue_items: list[dict[str, Any]] = []
    for queue_key in sorted(grouped.keys()):
        group = grouped[queue_key]
        all_job_ids = sorted(group.pop("_all_job_ids"))
        ready_job_ids = sorted(group.pop("_ready_job_ids"))
        dispatch_job_ids = sorted(group.pop("_dispatch_job_ids"))
        blocked_job_ids = sorted(group.pop("_blocked_job_ids"))
        unavailable_job_ids = sorted(group.pop("_unavailable_job_ids"))
        job_types = sorted(group.pop("_job_types"))
        check_types = sorted(group.pop("_check_types"))
        compare_modes = sorted(group.pop("_compare_modes"))
        mutation_strategies = sorted(group.pop("_mutation_strategies"))
        execution_lanes = sorted(group.pop("_execution_lanes"))
        priorities = group.pop("_priorities")
        check_items = list(group.pop("_check_items"))
        primary_job_id = ""
        if ready_job_ids:
            primary_job_id = ready_job_ids[0]
        elif all_job_ids:
            primary_job_id = all_job_ids[0]

        group["validator_job_ids"] = all_job_ids
        group["validator_job_types"] = job_types
        group["check_types"] = check_types
        group["compare_modes"] = compare_modes
        group["mutation_strategies"] = mutation_strategies
        group["execution_lanes"] = execution_lanes
        group["primary_job_id"] = primary_job_id
        group["dispatch_ready"] = bool(group.get("jobs_ready", 0) > 0)
        group["highest_job_priority"] = min(priorities) if priorities else 0
        group["queue_job_ids_unique"] = len(all_job_ids)
        queue_dispatch = _build_queue_dispatch_contract(dispatch_job_ids, blocked_job_ids, unavailable_job_ids)
        dispatch_job_count = _safe_int(queue_dispatch.get("dispatch_job_count"), 0)
        blocked_job_count = _safe_int(queue_dispatch.get("blocked_job_count"), 0)
        unavailable_job_count = _safe_int(queue_dispatch.get("unavailable_job_count"), 0)
        dispatch_diagnostics = _build_queue_blocker_diagnostics(
            check_items=check_items,
            blocked_job_count=blocked_job_count,
            unavailable_job_count=unavailable_job_count,
        )
        group["dispatch"] = queue_dispatch
        group["dispatch_diagnostics"] = dispatch_diagnostics
        group["dispatch_mode"] = _clean_str(queue_dispatch.get("dispatch_mode"))
        group["dispatch_job_count"] = dispatch_job_count
        group["blocked_job_count"] = blocked_job_count
        group["unavailable_job_count"] = unavailable_job_count
        group["jobs_total"] = _safe_int(queue_dispatch.get("jobs_total"), 0)
        group["jobs_ready"] = dispatch_job_count
        group["jobs_blocked"] = blocked_job_count
        group["jobs_unavailable"] = unavailable_job_count
        group["primary_dispatch_job_id"] = _clean_str(queue_dispatch.get("primary_dispatch_job_id"))
        group["dispatch_ratio"] = _round_metric(queue_dispatch.get("dispatch_ratio") or 0.0)
        group["fully_dispatchable"] = bool(queue_dispatch.get("fully_dispatchable"))
        group["blocker_reasons"] = list(dispatch_diagnostics.get("blocker_reasons") or [])
        group["primary_blocker_reason"] = _clean_str(dispatch_diagnostics.get("primary_blocker_reason"))
        group["blocker_reasons_count"] = len(group["blocker_reasons"])
        group["has_blocker_reasons"] = bool(dispatch_diagnostics.get("has_blocker_reasons"))
        queue_items.append(group)

    all_job_ids_global = {
        _clean_str(job_id)
        for item in queue_items
        for job_id in (item.get("validator_job_ids") or [])
        if _clean_str(job_id)
    }
    methods_present = sorted({_clean_str(item.get("method")) for item in queue_items if _clean_str(item.get("method"))})
    target_sources_present = sorted(
        {_clean_str(item.get("target_source")) for item in queue_items if _clean_str(item.get("target_source"))}
    )
    validator_job_types_present = sorted(
        {
            _clean_str(job_type)
            for item in queue_items
            for job_type in (item.get("validator_job_types") or [])
            if _clean_str(job_type)
        }
    )
    compare_modes_present = sorted(
        {
            _clean_str(compare_mode)
            for item in queue_items
            for compare_mode in (item.get("compare_modes") or [])
            if _clean_str(compare_mode)
        }
    )
    mutation_strategies_present = sorted(
        {
            _clean_str(strategy)
            for item in queue_items
            for strategy in (item.get("mutation_strategies") or [])
            if _clean_str(strategy)
        }
    )
    execution_lanes_present = sorted(
        {
            _clean_str(lane)
            for item in queue_items
            for lane in (item.get("execution_lanes") or [])
            if _clean_str(lane)
        }
    )
    queue_sizes = [_safe_int(item.get("jobs_total"), 0) for item in queue_items]
    total = len(queue_items)
    dispatch_ready_total = sum(1 for item in queue_items if bool(item.get("dispatch_ready")))
    jobs_total = sum(_safe_int(item.get("jobs_total"), 0) for item in queue_items)
    jobs_ready = sum(_safe_int(item.get("jobs_ready"), 0) for item in queue_items)
    jobs_blocked = sum(_safe_int(item.get("jobs_blocked"), 0) for item in queue_items)
    jobs_unavailable = sum(_safe_int(item.get("jobs_unavailable"), 0) for item in queue_items)
    dispatch_jobs_total = sum(_safe_int(item.get("dispatch_job_count"), 0) for item in queue_items)
    blocked_jobs_total = sum(_safe_int(item.get("blocked_job_count"), 0) for item in queue_items)
    unavailable_jobs_total = sum(_safe_int(item.get("unavailable_job_count"), 0) for item in queue_items)
    ready_only_queues = sum(1 for item in queue_items if _clean_str(item.get("dispatch_mode")) == _QUEUE_DISPATCH_READY_ONLY)
    mixed_queues = sum(1 for item in queue_items if _clean_str(item.get("dispatch_mode")) == _QUEUE_DISPATCH_MIXED)
    blocked_only_queues = sum(
        1 for item in queue_items if _clean_str(item.get("dispatch_mode")) == _QUEUE_DISPATCH_BLOCKED_ONLY
    )
    unavailable_only_queues = sum(
        1 for item in queue_items if _clean_str(item.get("dispatch_mode")) == _QUEUE_DISPATCH_UNAVAILABLE_ONLY
    )
    empty_queues = sum(1 for item in queue_items if _clean_str(item.get("dispatch_mode")) == _QUEUE_DISPATCH_EMPTY)
    fully_dispatchable_queues = sum(1 for item in queue_items if bool(item.get("fully_dispatchable")))
    partially_dispatchable_queues = sum(
        1
        for item in queue_items
        if _safe_int(item.get("dispatch_job_count"), 0) > 0 and not bool(item.get("fully_dispatchable"))
    )
    primary_dispatchable_queues = sum(1 for item in queue_items if bool(_clean_str(item.get("primary_dispatch_job_id"))))
    dispatch_modes_present = sorted(
        {_clean_str(item.get("dispatch_mode")) for item in queue_items if _clean_str(item.get("dispatch_mode"))}
    )
    unique_targets = len({_clean_str(item.get("target_url")) for item in queue_items if _clean_str(item.get("target_url"))})
    blocker_reasons_present = sorted(
        {
            _clean_str(reason)
            for item in queue_items
            for reason in (item.get("blocker_reasons") or [])
            if _clean_str(reason) in _BLOCKER_REASON_ORDER
        },
        key=lambda reason: _BLOCKER_REASON_ORDER.index(reason),
    )
    primary_blocker_reasons_present = sorted(
        {
            _clean_str(item.get("primary_blocker_reason"))
            for item in queue_items
            if _clean_str(item.get("primary_blocker_reason")) in _BLOCKER_REASON_ORDER
        },
        key=lambda reason: _BLOCKER_REASON_ORDER.index(reason),
    )
    queues_with_blocker_reasons = sum(1 for item in queue_items if bool(item.get("has_blocker_reasons")))
    missing_body_preview_queues = sum(
        1 for item in queue_items if _BLOCKER_REASON_MISSING_BODY_PREVIEW in (item.get("blocker_reasons") or [])
    )
    missing_status_code_queues = sum(
        1 for item in queue_items if _BLOCKER_REASON_MISSING_STATUS_CODE in (item.get("blocker_reasons") or [])
    )
    missing_body_hash_queues = sum(
        1 for item in queue_items if _BLOCKER_REASON_MISSING_BODY_HASH in (item.get("blocker_reasons") or [])
    )
    missing_content_type_queues = sum(
        1 for item in queue_items if _BLOCKER_REASON_MISSING_CONTENT_TYPE in (item.get("blocker_reasons") or [])
    )
    unavailable_surface_queues = sum(
        1 for item in queue_items if _BLOCKER_REASON_UNAVAILABLE_SURFACE in (item.get("blocker_reasons") or [])
    )
    no_param_target_queues = sum(
        1 for item in queue_items if _BLOCKER_REASON_NO_PARAM_TARGETS in (item.get("blocker_reasons") or [])
    )
    blocked_unknown_queues = sum(
        1 for item in queue_items if _BLOCKER_REASON_BLOCKED_UNKNOWN in (item.get("blocker_reasons") or [])
    )
    unavailable_unknown_queues = sum(
        1 for item in queue_items if _BLOCKER_REASON_UNAVAILABLE_UNKNOWN in (item.get("blocker_reasons") or [])
    )
    queues_with_baseline_blockers = sum(
        1 for item in queue_items if any(reason in _BASELINE_BLOCKER_REASONS for reason in (item.get("blocker_reasons") or []))
    )
    queues_with_surface_blockers = unavailable_surface_queues
    queues_with_param_target_blockers = no_param_target_queues

    payload["all"] = queue_items
    payload["summary"] = {
        "total": total,
        "dispatch_ready_total": dispatch_ready_total,
        "jobs_total": jobs_total,
        "jobs_ready": jobs_ready,
        "jobs_blocked": jobs_blocked,
        "jobs_unavailable": jobs_unavailable,
        "unique_targets": unique_targets,
        "methods_present": methods_present,
        "target_sources_present": target_sources_present,
        "validator_job_types_present": validator_job_types_present,
        "compare_modes_present": compare_modes_present,
        "mutation_strategies_present": mutation_strategies_present,
        "execution_lanes_present": execution_lanes_present,
        "max_queue_size": max(queue_sizes) if queue_sizes else 0,
        "min_queue_size": min(queue_sizes) if queue_sizes else 0,
        "avg_queue_size": _round_metric((jobs_total / total) if total else 0.0),
        "ready_queue_ratio": _round_metric((dispatch_ready_total / total) if total else 0.0),
        "validator_job_ready_ratio": _round_metric((jobs_ready / jobs_total) if jobs_total else 0.0),
        "primary_ready_queues": sum(
            1 for item in queue_items if bool(item.get("dispatch_ready")) and bool(_clean_str(item.get("primary_job_id")))
        ),
        "unique_validator_job_ids": len(all_job_ids_global),
        "ready_only_queues": ready_only_queues,
        "mixed_queues": mixed_queues,
        "blocked_only_queues": blocked_only_queues,
        "unavailable_only_queues": unavailable_only_queues,
        "empty_queues": empty_queues,
        "dispatch_jobs_total": dispatch_jobs_total,
        "blocked_jobs_total": blocked_jobs_total,
        "unavailable_jobs_total": unavailable_jobs_total,
        "fully_dispatchable_queues": fully_dispatchable_queues,
        "partially_dispatchable_queues": partially_dispatchable_queues,
        "primary_dispatchable_queues": primary_dispatchable_queues,
        "dispatch_modes_present": dispatch_modes_present,
        "avg_dispatch_jobs_per_queue": _round_metric((dispatch_jobs_total / total) if total else 0.0),
        "avg_blocked_jobs_per_queue": _round_metric((blocked_jobs_total / total) if total else 0.0),
        "avg_unavailable_jobs_per_queue": _round_metric((unavailable_jobs_total / total) if total else 0.0),
        "fully_dispatchable_ratio": _round_metric((fully_dispatchable_queues / total) if total else 0.0),
        "dispatch_job_ratio": _round_metric((dispatch_jobs_total / jobs_total) if jobs_total else 0.0),
        "queues_with_blocker_reasons": queues_with_blocker_reasons,
        "blocker_reasons_present": blocker_reasons_present,
        "primary_blocker_reasons_present": primary_blocker_reasons_present,
        "missing_body_preview_queues": missing_body_preview_queues,
        "missing_status_code_queues": missing_status_code_queues,
        "missing_body_hash_queues": missing_body_hash_queues,
        "missing_content_type_queues": missing_content_type_queues,
        "unavailable_surface_queues": unavailable_surface_queues,
        "no_param_target_queues": no_param_target_queues,
        "blocked_unknown_queues": blocked_unknown_queues,
        "unavailable_unknown_queues": unavailable_unknown_queues,
        "queues_with_baseline_blockers": queues_with_baseline_blockers,
        "queues_with_surface_blockers": queues_with_surface_blockers,
        "queues_with_param_target_blockers": queues_with_param_target_blockers,
        "avg_blocker_reasons_per_queue": _round_metric(
            (
                sum(_safe_int(item.get("blocker_reasons_count"), 0) for item in queue_items)
                / total
            )
            if total
            else 0.0
        ),
    }
    return payload


def get_validator_queue_dispatch_fixture(case_name: str) -> list[dict[str, Any]]:
    case = _clean_str(case_name).lower()
    target_url = "https://fixture.local/path"
    base = {
        "target_url": target_url,
        "target_source": "synthetic_fixture",
        "check_type": _CHECK_STATUS_DIFF,
        "compare_mode": "status_compare",
        "mutation_strategy": _MUTATION_STRATEGY_ENDPOINT_COMPARE,
        "requires_param_target": False,
        "effective_target_count": 1,
        "baseline_missing_fields": [],
        "execution_mode": _EXECUTION_MODE_ENDPOINT_ONLY,
    }
    if case == _QUEUE_DISPATCH_READY_ONLY:
        return [
            {
                **base,
                "job_id": "fixture-ready-1",
                "job_type": _VALIDATOR_JOB_SAFE,
                "execution_lane": _EXECUTION_LANE_READY_ENDPOINT,
            }
        ]
    if case == _QUEUE_DISPATCH_MIXED:
        return [
            {
                **base,
                "job_id": "fixture-ready-1",
                "job_type": _VALIDATOR_JOB_SAFE,
                "execution_lane": _EXECUTION_LANE_READY_ENDPOINT,
            },
            {
                **base,
                "job_id": "fixture-blocked-1",
                "job_type": _VALIDATOR_JOB_BLOCKED,
                "execution_lane": _EXECUTION_LANE_BLOCKED_ENDPOINT,
                "baseline_missing_fields": ["body_preview"],
            },
        ]
    if case == _QUEUE_DISPATCH_BLOCKED_ONLY:
        return [
            {
                **base,
                "job_id": "fixture-blocked-1",
                "job_type": _VALIDATOR_JOB_BLOCKED,
                "execution_lane": _EXECUTION_LANE_BLOCKED_ENDPOINT,
                "baseline_missing_fields": ["body_preview"],
            }
        ]
    if case == _QUEUE_DISPATCH_UNAVAILABLE_ONLY:
        return [
            {
                **base,
                "job_id": "fixture-unavailable-1",
                "job_type": _VALIDATOR_JOB_UNAVAILABLE,
                "execution_lane": _EXECUTION_LANE_UNAVAILABLE,
                "execution_mode": _EXECUTION_MODE_UNAVAILABLE,
            }
        ]
    if case == "mixed_param_target":
        return [
            {
                **base,
                "job_id": "fixture-ready-1",
                "job_type": _VALIDATOR_JOB_SAFE,
                "execution_lane": _EXECUTION_LANE_READY_ENDPOINT,
            },
            {
                **base,
                "job_id": "fixture-blocked-param-1",
                "job_type": _VALIDATOR_JOB_BLOCKED,
                "execution_lane": _EXECUTION_LANE_BLOCKED_PARAM,
                "requires_param_target": True,
                "effective_target_count": 0,
                "execution_mode": _EXECUTION_MODE_PARAM_ONLY,
            },
        ]
    if case == _QUEUE_DISPATCH_EMPTY:
        return []
    return []


def build_synthetic_validator_queue_case(case_name: str) -> dict[str, Any]:
    fixture_jobs = get_validator_queue_dispatch_fixture(case_name)
    plan_item: dict[str, Any] = {"method": "GET", "safe_mode": True, "check_plan": []}
    for job in fixture_jobs:
        job_type = _clean_str(job.get("job_type"))
        validator_job = {
            "job_id": _clean_str(job.get("job_id")),
            "job_type": job_type,
            "job_ready": bool(job_type == _VALIDATOR_JOB_SAFE),
            "target_url": _clean_str(job.get("target_url")),
            "target_source": _clean_str(job.get("target_source")),
            "check_type": _clean_str(job.get("check_type")),
            "compare_mode": _clean_str(job.get("compare_mode")),
            "execution_lane": _clean_str(job.get("execution_lane")),
            "mutation_strategy": _clean_str(job.get("mutation_strategy")),
        }
        plan_item["check_plan"].append(
            {
                "execution_priority": 1,
                "requires_param_target": bool(job.get("requires_param_target")),
                "effective_target_count": _safe_int(job.get("effective_target_count"), 0),
                "baseline_inputs": {"missing_fields": list(job.get("baseline_missing_fields") or [])},
                "execution_surface": {"mode": _clean_str(job.get("execution_mode"))},
                "validator_job": validator_job,
            }
        )
    return {"all": [plan_item]}


def _self_check_validator_queue_dispatch_cases() -> dict[str, Any]:
    cases = [
        _QUEUE_DISPATCH_READY_ONLY,
        _QUEUE_DISPATCH_MIXED,
        _QUEUE_DISPATCH_BLOCKED_ONLY,
        _QUEUE_DISPATCH_UNAVAILABLE_ONLY,
        _QUEUE_DISPATCH_EMPTY,
    ]
    out: dict[str, Any] = {}
    for case_name in cases:
        synthetic_plan = build_synthetic_validator_queue_case(case_name)
        queue_payload = build_validator_queue(synthetic_plan)
        queue_item = ((queue_payload.get("all") or [None])[0]) or {}
        dispatch_mode = _clean_str(queue_item.get("dispatch_mode"))
        if not dispatch_mode and case_name == _QUEUE_DISPATCH_EMPTY:
            dispatch_mode = _QUEUE_DISPATCH_EMPTY
        out[case_name] = {
            "queue_total": _safe_int((queue_payload.get("summary") or {}).get("total"), 0),
            "dispatch_mode": dispatch_mode,
            "dispatch_job_count": _safe_int(queue_item.get("dispatch_job_count"), 0),
            "blocked_job_count": _safe_int(queue_item.get("blocked_job_count"), 0),
            "unavailable_job_count": _safe_int(queue_item.get("unavailable_job_count"), 0),
            "jobs_total": _safe_int(queue_item.get("jobs_total"), 0),
            "fully_dispatchable": bool(queue_item.get("fully_dispatchable")),
            "dispatch_ratio": _round_metric(queue_item.get("dispatch_ratio") or 0.0),
            "primary_dispatch_job_id": _clean_str(queue_item.get("primary_dispatch_job_id")),
        }
    return out


def _self_check_validator_queue_blocker_diagnostics_cases() -> dict[str, Any]:
    cases = [
        _QUEUE_DISPATCH_READY_ONLY,
        _QUEUE_DISPATCH_BLOCKED_ONLY,
        _QUEUE_DISPATCH_UNAVAILABLE_ONLY,
        "mixed_param_target",
        _QUEUE_DISPATCH_EMPTY,
    ]
    out: dict[str, Any] = {}
    for case_name in cases:
        synthetic_plan = build_synthetic_validator_queue_case(case_name)
        queue_payload = build_validator_queue(synthetic_plan)
        queue_item = ((queue_payload.get("all") or [None])[0]) or {}
        out[case_name] = {
            "dispatch_mode": _clean_str(queue_item.get("dispatch_mode")) or _QUEUE_DISPATCH_EMPTY,
            "blocker_reasons": list(queue_item.get("blocker_reasons") or []),
            "primary_blocker_reason": _clean_str(queue_item.get("primary_blocker_reason")),
            "has_blocker_reasons": bool(queue_item.get("has_blocker_reasons")),
        }
    return out


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
        execution_ready = bool(ready and all_required_available)
        execution_lane = _compute_execution_lane(
            mode=mode,
            execution_ready=execution_ready,
            parameterized=parameterized,
            endpoint_level=endpoint_level,
        )
        execution_priority = _compute_execution_priority(execution_lane)
        execution_sort_key = _build_execution_sort_key(
            lane=execution_lane,
            priority=execution_priority,
            target_url=target_url,
            check_type=check_type,
            target_source=target_source,
            primary_surface=_clean_str(execution_surface.get("primary_surface")),
        )
        effective_target_count = (
            int(execution_surface.get("target_count") or 0)
            if parameterized
            else (1 if endpoint_level and has_target_url else 0)
        )
        mutation_binding = _build_mutation_binding(
            mode=mode,
            effective_target_count=effective_target_count,
            has_target_url=has_target_url,
        )
        mutation_strategy = _clean_str(mutation_binding.get("strategy"))
        mutation_ready = bool(
            execution_ready
            and mutation_strategy != _MUTATION_STRATEGY_UNAVAILABLE
            and _safe_int(mutation_binding.get("slot_count"), 0) > 0
        )
        mutation_sort_weight = int(_MUTATION_SORT_WEIGHT.get(mutation_strategy, 3))
        validator_job = _build_validator_job(
            safe_mode=bool(safe_mode),
            target_url=target_url,
            target_source=target_source,
            check_type=check_type,
            compare_mode=_clean_str(comparison.get("compare_mode")),
            execution_lane=execution_lane,
            mutation_strategy=mutation_strategy,
            mutation_ready=mutation_ready,
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
                "execution_ready": execution_ready,
                "execution_surface": execution_surface,
                "parameterized": parameterized,
                "endpoint_level": endpoint_level,
                "effective_target_count": int(effective_target_count),
                "execution_lane": execution_lane,
                "execution_priority": int(execution_priority),
                "execution_sort_key": execution_sort_key,
                "mutation_binding": mutation_binding,
                "mutation_ready": mutation_ready,
                "mutation_sort_weight": mutation_sort_weight,
                "validator_job": validator_job,
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
        mutation_strategies_present = sorted(
            {
                _clean_str((check_item.get("mutation_binding") or {}).get("strategy"))
                for check_item in check_plan
                if isinstance(check_item, Mapping)
                and _clean_str((check_item.get("mutation_binding") or {}).get("strategy"))
            }
        )
        mutating_checks = sum(
            1
            for check_item in check_plan
            if isinstance(check_item, Mapping)
            and bool((check_item.get("mutation_binding") or {}).get("mutating"))
        )
        baseline_only_checks = sum(
            1
            for check_item in check_plan
            if isinstance(check_item, Mapping)
            and bool((check_item.get("mutation_binding") or {}).get("baseline_only"))
        )
        mutation_ready_checks = sum(
            1
            for check_item in check_plan
            if isinstance(check_item, Mapping) and bool(check_item.get("mutation_ready"))
        )
        total_mutation_slots = sum(
            _safe_int((check_item.get("mutation_binding") or {}).get("slot_count"), 0)
            for check_item in check_plan
            if isinstance(check_item, Mapping)
        )
        if check_plan:
            primary_mutation_strategy = min(
                (
                    (
                        _safe_int(check_item.get("mutation_sort_weight"), 3),
                        _clean_str((check_item.get("mutation_binding") or {}).get("strategy")),
                    )
                    for check_item in check_plan
                    if isinstance(check_item, Mapping)
                    and _clean_str((check_item.get("mutation_binding") or {}).get("strategy"))
                ),
                default=(3, ""),
            )[1]
        else:
            primary_mutation_strategy = ""
        execution_lanes_present = sorted(
            {
                _clean_str(check_item.get("execution_lane"))
                for check_item in check_plan
                if isinstance(check_item, Mapping)
                and _clean_str(check_item.get("execution_lane")) in _EXECUTION_LANE_PRIORITY
            }
        )
        execution_priorities = [
            _compute_execution_priority(check_item.get("execution_lane"))
            for check_item in check_plan
            if isinstance(check_item, Mapping)
        ]
        highest_execution_priority = min(execution_priorities) if execution_priorities else 0
        ready_checks_sorted = sum(
            1
            for check_item in check_plan
            if isinstance(check_item, Mapping)
            and _clean_str(check_item.get("execution_lane"))
            in {_EXECUTION_LANE_READY_PARAM, _EXECUTION_LANE_READY_ENDPOINT}
        )
        blocked_checks_sorted = sum(
            1
            for check_item in check_plan
            if isinstance(check_item, Mapping)
            and _clean_str(check_item.get("execution_lane"))
            in {
                _EXECUTION_LANE_BLOCKED_PARAM,
                _EXECUTION_LANE_BLOCKED_ENDPOINT,
                _EXECUTION_LANE_UNAVAILABLE,
            }
        )
        if check_plan:
            primary_check_item = min(
                (
                    check_item
                    for check_item in check_plan
                    if isinstance(check_item, Mapping)
                ),
                key=lambda item: (
                    _compute_execution_priority(item.get("execution_lane")),
                    _safe_sort_value(item.get("execution_sort_key")),
                ),
                default={},
            )
            primary_execution_lane = (
                _clean_str(primary_check_item.get("execution_lane"))
                if isinstance(primary_check_item, Mapping)
                else ""
            )
        else:
            primary_execution_lane = ""
        validator_jobs_total = len(check_plan)
        validator_jobs_ready = sum(
            1
            for check_item in check_plan
            if isinstance(check_item, Mapping) and bool((check_item.get("validator_job") or {}).get("job_ready"))
        )
        validator_job_types_present = sorted(
            {
                _clean_str((check_item.get("validator_job") or {}).get("job_type"))
                for check_item in check_plan
                if isinstance(check_item, Mapping)
                and _clean_str((check_item.get("validator_job") or {}).get("job_type"))
            }
        )
        primary_validator_job_type = min(
            validator_job_types_present,
            key=lambda job_type: _safe_int(_VALIDATOR_JOB_TYPE_PRECEDENCE.get(job_type), 99),
            default="",
        )
        validator_job_ids_unique = len(
            {
                _clean_str((check_item.get("validator_job") or {}).get("job_id"))
                for check_item in check_plan
                if isinstance(check_item, Mapping)
                and _clean_str((check_item.get("validator_job") or {}).get("job_id"))
            }
        )

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
                "execution_lanes_present": execution_lanes_present,
                "highest_execution_priority": int(highest_execution_priority),
                "ready_checks_sorted": int(ready_checks_sorted),
                "blocked_checks_sorted": int(blocked_checks_sorted),
                "primary_execution_lane": primary_execution_lane,
                "execution_queue_size": len(check_plan),
                "mutation_strategies_present": mutation_strategies_present,
                "mutating_checks": int(mutating_checks),
                "baseline_only_checks": int(baseline_only_checks),
                "mutation_ready_checks": int(mutation_ready_checks),
                "total_mutation_slots": int(total_mutation_slots),
                "primary_mutation_strategy": primary_mutation_strategy,
                "has_mutating_checks": bool(mutating_checks > 0),
                "has_baseline_only_checks": bool(baseline_only_checks > 0),
                "validator_jobs_total": int(validator_jobs_total),
                "validator_jobs_ready": int(validator_jobs_ready),
                "validator_job_types_present": validator_job_types_present,
                "primary_validator_job_type": primary_validator_job_type,
                "validator_job_ids_unique": int(validator_job_ids_unique),
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
    ready_param_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and _clean_str(check_item.get("execution_lane")) == _EXECUTION_LANE_READY_PARAM
    )
    ready_endpoint_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and _clean_str(check_item.get("execution_lane")) == _EXECUTION_LANE_READY_ENDPOINT
    )
    blocked_param_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and _clean_str(check_item.get("execution_lane")) == _EXECUTION_LANE_BLOCKED_PARAM
    )
    blocked_endpoint_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and _clean_str(check_item.get("execution_lane")) == _EXECUTION_LANE_BLOCKED_ENDPOINT
    )
    unavailable_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and _clean_str(check_item.get("execution_lane")) == _EXECUTION_LANE_UNAVAILABLE
    )
    execution_lanes_present = sorted(
        {
            _clean_str(check_item.get("execution_lane"))
            for item in plan_items
            for check_item in (item.get("check_plan") or [])
            if isinstance(check_item, Mapping)
            and _clean_str(check_item.get("execution_lane")) in _EXECUTION_LANE_PRIORITY
        }
    )
    all_execution_priorities = [
        _compute_execution_priority(check_item.get("execution_lane"))
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
    ]
    mutation_strategies_present = sorted(
        {
            _clean_str((check_item.get("mutation_binding") or {}).get("strategy"))
            for item in plan_items
            for check_item in (item.get("check_plan") or [])
            if isinstance(check_item, Mapping)
            and _clean_str((check_item.get("mutation_binding") or {}).get("strategy"))
        }
    )
    param_replace_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and _clean_str((check_item.get("mutation_binding") or {}).get("strategy")) == _MUTATION_STRATEGY_PARAM_REPLACE
    )
    endpoint_compare_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and _clean_str((check_item.get("mutation_binding") or {}).get("strategy"))
        == _MUTATION_STRATEGY_ENDPOINT_COMPARE
    )
    unavailable_mutation_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and _clean_str((check_item.get("mutation_binding") or {}).get("strategy")) == _MUTATION_STRATEGY_UNAVAILABLE
    )
    mutating_check_plan_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and bool((check_item.get("mutation_binding") or {}).get("mutating"))
    )
    baseline_only_check_plan_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
        and bool((check_item.get("mutation_binding") or {}).get("baseline_only"))
    )
    mutation_ready_check_plan_items = sum(
        1
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and bool(check_item.get("mutation_ready"))
    )
    total_mutation_slots = sum(
        _safe_int((check_item.get("mutation_binding") or {}).get("slot_count"), 0)
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping)
    )
    ready_queue_total = ready_param_items + ready_endpoint_items
    blocked_queue_total = blocked_param_items + blocked_endpoint_items + unavailable_items
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
    all_validator_jobs = [
        (check_item.get("validator_job") or {})
        for item in plan_items
        for check_item in (item.get("check_plan") or [])
        if isinstance(check_item, Mapping) and isinstance((check_item.get("validator_job") or {}), Mapping)
    ]
    validator_jobs_total = len(all_validator_jobs)
    validator_jobs_ready = sum(1 for job in all_validator_jobs if bool(job.get("job_ready")))
    safe_validation_jobs = sum(
        1 for job in all_validator_jobs if _clean_str(job.get("job_type")) == _VALIDATOR_JOB_SAFE
    )
    blocked_validation_jobs = sum(
        1 for job in all_validator_jobs if _clean_str(job.get("job_type")) == _VALIDATOR_JOB_BLOCKED
    )
    unavailable_validation_jobs = sum(
        1 for job in all_validator_jobs if _clean_str(job.get("job_type")) == _VALIDATOR_JOB_UNAVAILABLE
    )
    validator_job_types_present = sorted(
        {_clean_str(job.get("job_type")) for job in all_validator_jobs if _clean_str(job.get("job_type"))}
    )
    unique_validator_job_ids = len(
        {_clean_str(job.get("job_id")) for job in all_validator_jobs if _clean_str(job.get("job_id"))}
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
        "ready_param_items": ready_param_items,
        "ready_endpoint_items": ready_endpoint_items,
        "blocked_param_items": blocked_param_items,
        "blocked_endpoint_items": blocked_endpoint_items,
        "unavailable_items": unavailable_items,
        "execution_lanes_present": execution_lanes_present,
        "highest_priority_plans": sum(
            1 for item in plan_items if _safe_int(item.get("highest_execution_priority"), 0) == 1
        ),
        "ready_queue_total": ready_queue_total,
        "blocked_queue_total": blocked_queue_total,
        "avg_queue_size_per_plan": _round_metric((total_check_plan_items / total_plans) if total_plans else 0.0),
        "avg_ready_queue_per_plan": _round_metric((ready_queue_total / total_plans) if total_plans else 0.0),
        "avg_blocked_queue_per_plan": _round_metric((blocked_queue_total / total_plans) if total_plans else 0.0),
        "plans_primary_ready_param": sum(
            1 for item in plan_items if _clean_str(item.get("primary_execution_lane")) == _EXECUTION_LANE_READY_PARAM
        ),
        "plans_primary_ready_endpoint": sum(
            1
            for item in plan_items
            if _clean_str(item.get("primary_execution_lane")) == _EXECUTION_LANE_READY_ENDPOINT
        ),
        "plans_primary_blocked_param": sum(
            1 for item in plan_items if _clean_str(item.get("primary_execution_lane")) == _EXECUTION_LANE_BLOCKED_PARAM
        ),
        "plans_primary_blocked_endpoint": sum(
            1
            for item in plan_items
            if _clean_str(item.get("primary_execution_lane")) == _EXECUTION_LANE_BLOCKED_ENDPOINT
        ),
        "plans_primary_unavailable": sum(
            1 for item in plan_items if _clean_str(item.get("primary_execution_lane")) == _EXECUTION_LANE_UNAVAILABLE
        ),
        "execution_priority_min": min(all_execution_priorities) if all_execution_priorities else 0,
        "execution_priority_max": max(all_execution_priorities) if all_execution_priorities else 0,
        "param_replace_items": param_replace_items,
        "endpoint_compare_items": endpoint_compare_items,
        "unavailable_mutation_items": unavailable_mutation_items,
        "mutating_check_plan_items": mutating_check_plan_items,
        "baseline_only_check_plan_items": baseline_only_check_plan_items,
        "mutation_ready_check_plan_items": mutation_ready_check_plan_items,
        "mutation_strategies_present": mutation_strategies_present,
        "plans_with_mutating_checks": sum(1 for item in plan_items if bool(item.get("has_mutating_checks"))),
        "plans_with_baseline_only_checks": sum(1 for item in plan_items if bool(item.get("has_baseline_only_checks"))),
        "total_mutation_slots": int(total_mutation_slots),
        "avg_mutation_slots_per_plan": _round_metric((total_mutation_slots / total_plans) if total_plans else 0.0),
        "mutation_ready_ratio": _round_metric(
            (mutation_ready_check_plan_items / total_check_plan_items) if total_check_plan_items else 0.0
        ),
        "plans_primary_param_replace": sum(
            1
            for item in plan_items
            if _clean_str(item.get("primary_mutation_strategy")) == _MUTATION_STRATEGY_PARAM_REPLACE
        ),
        "plans_primary_endpoint_compare": sum(
            1
            for item in plan_items
            if _clean_str(item.get("primary_mutation_strategy")) == _MUTATION_STRATEGY_ENDPOINT_COMPARE
        ),
        "validator_jobs_total": validator_jobs_total,
        "validator_jobs_ready": validator_jobs_ready,
        "validator_jobs_blocked": blocked_validation_jobs,
        "validator_jobs_unavailable": unavailable_validation_jobs,
        "validator_job_types_present": validator_job_types_present,
        "safe_validation_jobs": safe_validation_jobs,
        "blocked_validation_jobs": blocked_validation_jobs,
        "unavailable_validation_jobs": unavailable_validation_jobs,
        "plans_with_ready_validator_jobs": sum(1 for item in plan_items if _safe_int(item.get("validator_jobs_ready"), 0) > 0),
        "plans_with_blocked_validator_jobs": sum(
            1
            for item in plan_items
            if _VALIDATOR_JOB_BLOCKED in (item.get("validator_job_types_present") or [])
        ),
        "plans_with_unavailable_validator_jobs": sum(
            1
            for item in plan_items
            if _VALIDATOR_JOB_UNAVAILABLE in (item.get("validator_job_types_present") or [])
        ),
        "validator_job_ready_ratio": _round_metric(
            (validator_jobs_ready / validator_jobs_total) if validator_jobs_total else 0.0
        ),
        "unique_validator_job_ids": unique_validator_job_ids,
        "avg_validator_jobs_per_plan": _round_metric((validator_jobs_total / total_plans) if total_plans else 0.0),
        "avg_ready_validator_jobs_per_plan": _round_metric(
            (validator_jobs_ready / total_plans) if total_plans else 0.0
        ),
        "plans_primary_safe_validation": sum(
            1 for item in plan_items if _clean_str(item.get("primary_validator_job_type")) == _VALIDATOR_JOB_SAFE
        ),
        "plans_primary_blocked_validation": sum(
            1 for item in plan_items if _clean_str(item.get("primary_validator_job_type")) == _VALIDATOR_JOB_BLOCKED
        ),
        "plans_primary_unavailable_validation": sum(
            1 for item in plan_items if _clean_str(item.get("primary_validator_job_type")) == _VALIDATOR_JOB_UNAVAILABLE
        ),
    }
    return payload
