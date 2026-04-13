from __future__ import annotations

from typing import Any, Mapping

_CHECK_REFLECTION_DIFF = "reflection_diff"
_CHECK_ERROR_PATTERN_DIFF = "error_pattern_diff"
_CHECK_STATUS_DIFF = "status_diff"
_CHECK_ORDER = (
    _CHECK_REFLECTION_DIFF,
    _CHECK_ERROR_PATTERN_DIFF,
    _CHECK_STATUS_DIFF,
)
_EVIDENCE_RANK = {"": 0, "low": 1, "medium": 2, "strong": 3}


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


def build_validation_plan(
    *,
    replay_manifest: Mapping[str, Any] | None = None,
    finding_artifacts: Mapping[str, Any] | None = None,
    candidates: Mapping[str, Any] | None = None,
    request_recipe: Mapping[str, Any] | None = None,
    final_url: Any = "",
) -> dict[str, Any]:
    del candidates

    payload = _empty_contract()
    manifest_items = replay_manifest.get("all") if isinstance(replay_manifest, Mapping) else None
    if not isinstance(manifest_items, list):
        return payload

    recipe = request_recipe if isinstance(request_recipe, Mapping) else {}
    recipe_url = _clean_str(recipe.get("url"))
    recipe_method = _clean_str(recipe.get("method"))
    fallback_final_url = _clean_str(final_url)
    artifacts_by_id = _build_artifact_index(finding_artifacts)

    plan_items: list[dict[str, Any]] = []
    for manifest_item in manifest_items:
        if not isinstance(manifest_item, Mapping):
            continue

        replay_key = _clean_str(manifest_item.get("replay_key"))
        target_url = _clean_str(manifest_item.get("target_url")) or recipe_url or fallback_final_url or ""
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

        plan_items.append(
            {
                "replay_key": replay_key,
                "target_url": target_url,
                "method": method,
                "artifact_ids": artifact_ids,
                "artifact_types": artifact_types,
                "param_targets": param_targets,
                "suggested_checks": suggested_checks,
                "evidence_level": evidence_level,
                "ready_for_validation": ready_for_validation,
                "safe_mode": True,
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
    plans_with_checks = sum(1 for item in plan_items if bool(item.get("suggested_checks")))
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
    }
    return payload
