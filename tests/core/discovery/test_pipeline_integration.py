"""
End-to-end tests for the discovery/candidate/replay/validation pipeline
that ScraperRunnable.run() chains together (build_finding_artifacts ->
replay_groups -> replay_manifest -> validation_plan -> validator_queue ->
validator_handoff). These exist as a regression net for collapsing the
duplicated pipeline blocks in core/scraper/runnables.py.
"""
import copy

from core.discovery.url_discovery import discover
from core.discovery.candidate_generation import generate_candidates
from core.discovery.finding_artifacts import build_finding_artifacts
from core.discovery.replay_groups import build_replay_groups
from core.discovery.replay_manifest import build_replay_manifest
from core.discovery.validation_plan import (
    build_validation_plan,
    build_validator_handoff,
    build_validator_queue,
)


SAMPLE_HTML = """
<html><body>
<a href="/login?next=/dashboard">login</a>
<a href="/admin/users?id=1">admin users</a>
<script src="/static/app.js"></script>
</body></html>
"""
FINAL_URL = "https://example.com/"

REQUEST_RECIPE = {
    "url": FINAL_URL,
    "method": "GET",
    "headers": {"User-Agent": "test"},
    "cookie_path": "",
    "redirects": 0,
    "timeout": 15.0,
    "payload_source": "direct_url",
    "timestamp": "2026-01-01T00:00:00Z",
}
RESPONSE_SNAPSHOT = {
    "status_code": 200,
    "headers": {"content-type": "text/html"},
    "content_type": "text/html",
    "content_length": len(SAMPLE_HTML),
    "body_preview": SAMPLE_HTML[:200],
    "body_hash": "deadbeef",
}


def _run_pipeline(html: str, final_url: str):
    discovery = discover(html, final_url)
    candidates = generate_candidates(
        final_url=final_url,
        classified_urls_by_scope=discovery.get("classified_urls_by_scope"),
        parameter_intelligence=discovery.get("parameter_intelligence"),
    )
    finding_artifacts = build_finding_artifacts(
        candidates=candidates,
        request_recipe=REQUEST_RECIPE,
        response_snapshot=RESPONSE_SNAPSHOT,
        status_code=200,
        final_url=final_url,
        discovery=discovery,
    )
    replay_groups = build_replay_groups(
        finding_artifacts=finding_artifacts,
        request_recipe=REQUEST_RECIPE,
        response_snapshot=RESPONSE_SNAPSHOT,
        final_url=final_url,
        discovery=discovery,
    )
    replay_manifest = build_replay_manifest(
        replay_groups=replay_groups,
        finding_artifacts=finding_artifacts,
        request_recipe=REQUEST_RECIPE,
        response_snapshot=RESPONSE_SNAPSHOT,
        final_url=final_url,
        discovery=discovery,
    )
    validation_plan = build_validation_plan(
        replay_manifest=replay_manifest,
        finding_artifacts=finding_artifacts,
        candidates=candidates,
        request_recipe=REQUEST_RECIPE,
        response_snapshot=RESPONSE_SNAPSHOT,
        final_url=final_url,
        discovery=discovery,
    )
    validator_queue = build_validator_queue(validation_plan)
    validator_handoff = build_validator_handoff(validator_queue, validation_plan)
    return {
        "discovery": discovery,
        "candidates": candidates,
        "finding_artifacts": finding_artifacts,
        "replay_groups": replay_groups,
        "replay_manifest": replay_manifest,
        "validation_plan": validation_plan,
        "validator_queue": validator_queue,
        "validator_handoff": validator_handoff,
    }


def test_pipeline_end_to_end_with_candidates():
    result = _run_pipeline(SAMPLE_HTML, FINAL_URL)

    assert result["candidates"]["summary"]["total"] == 6
    assert set(result["candidates"]["summary"]["types_present"]) == {
        "sqli_candidate",
        "ssrf_candidate",
        "xss_candidate",
    }

    fa_summary = result["finding_artifacts"]["summary"]
    assert fa_summary["total"] == 6
    assert fa_summary["replay_ready_total"] == 6
    assert fa_summary["unique_artifact_ids"] == 6

    rg_summary = result["replay_groups"]["summary"]
    assert rg_summary["total"] == 6
    assert rg_summary["unique_targets"] == 3

    rm_summary = result["replay_manifest"]["summary"]
    assert rm_summary["total"] == 6
    assert rm_summary["ready_total"] == 6

    vp = result["validation_plan"]
    assert len(vp["all"]) == 6
    assert vp["summary"]["total"] == 6

    vq_summary = result["validator_queue"]["summary"]
    assert vq_summary["total"] == 3  # queues grouped by (target_url, method, target_source, safe_mode)
    assert vq_summary["jobs_ready"] == 8
    assert vq_summary["jobs_blocked"] == 0
    assert vq_summary["ready_queue_ratio"] == 1.0

    vh_summary = result["validator_handoff"]["summary"]
    assert vh_summary["total"] == 3
    assert vh_summary["ready_total"] == 3
    assert vh_summary["not_ready_total"] == 0
    assert vh_summary["dispatch_jobs_total"] == 8


def test_pipeline_is_deterministic_for_same_input():
    first = _run_pipeline(SAMPLE_HTML, FINAL_URL)
    second = _run_pipeline(SAMPLE_HTML, FINAL_URL)
    assert first == second


def test_pipeline_handles_missing_upstream_stages_without_crashing():
    """
    Mirrors the except-branches in ScraperRunnable.run(), where a request
    fails before discovery/candidates ever get built and the pipeline is
    called with None inputs.
    """
    finding_artifacts = build_finding_artifacts(
        candidates=None,
        request_recipe=None,
        response_snapshot=None,
        status_code=None,
        final_url=None,
        discovery=None,
    )
    replay_groups = build_replay_groups(
        finding_artifacts=finding_artifacts,
        request_recipe=None,
        response_snapshot=None,
        final_url=None,
        discovery=None,
    )
    replay_manifest = build_replay_manifest(
        replay_groups=replay_groups,
        finding_artifacts=finding_artifacts,
        request_recipe=None,
        response_snapshot=None,
        final_url=None,
        discovery=None,
    )
    validation_plan = build_validation_plan(
        replay_manifest=replay_manifest,
        finding_artifacts=finding_artifacts,
        candidates=None,
        request_recipe=None,
        response_snapshot=None,
        final_url=None,
        discovery=None,
    )
    validator_queue = build_validator_queue(validation_plan)
    validator_handoff = build_validator_handoff(validator_queue, validation_plan)

    assert finding_artifacts["all"] == []
    assert replay_groups["all"] == []
    assert replay_manifest["all"] == []
    assert validation_plan["all"] == []
    assert validator_queue["all"] == []
    assert validator_queue["summary"]["total"] == 0
    assert validator_handoff["all"] == []
    assert validator_handoff["summary"]["total"] == 0


def test_pipeline_does_not_mutate_its_inputs():
    """
    Guards against the pipeline stages secretly mutating shared dicts in
    place, which would matter once runnables.py stops rebuilding fresh
    dicts for every branch.
    """
    recipe_before = copy.deepcopy(REQUEST_RECIPE)
    snapshot_before = copy.deepcopy(RESPONSE_SNAPSHOT)

    _run_pipeline(SAMPLE_HTML, FINAL_URL)

    assert REQUEST_RECIPE == recipe_before
    assert RESPONSE_SNAPSHOT == snapshot_before
