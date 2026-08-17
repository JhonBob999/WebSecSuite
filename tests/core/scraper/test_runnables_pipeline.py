"""
Tests for build_discovery_pipeline_artifacts(), the helper extracted from
ScraperRunnable.run() to remove the 3x-duplicated finding_artifacts ->
replay_groups -> replay_manifest -> validation_plan -> validator_queue ->
validator_handoff block (success branch + httpx.HTTPError branch + generic
Exception branch all used to inline the same 6 calls).
"""
from core.discovery.url_discovery import discover
from core.discovery.candidate_generation import generate_candidates
from core.scraper.runnables import build_discovery_pipeline_artifacts


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


def _success_result() -> dict:
    """Mirrors the `result` dict as built by ScraperRunnable.run()'s success branch."""
    discovery = discover(SAMPLE_HTML, FINAL_URL)
    candidates = generate_candidates(
        final_url=FINAL_URL,
        classified_urls_by_scope=discovery.get("classified_urls_by_scope"),
        parameter_intelligence=discovery.get("parameter_intelligence"),
    )
    return {
        "status_code": 200,
        "final_url": FINAL_URL,
        "discovery": discovery,
        "candidates": candidates,
        "candidates_summary": candidates.get("summary", {}),
        "request_recipe": REQUEST_RECIPE,
        "response_snapshot": RESPONSE_SNAPSHOT,
    }


def test_success_path_populates_all_six_stages():
    out = build_discovery_pipeline_artifacts(_success_result())

    assert out["finding_artifacts"]["summary"]["total"] == 6
    assert out["replay_groups"]["summary"]["total"] == 6
    assert out["replay_manifest"]["summary"]["total"] == 6
    assert len(out["validation_plan"]["all"]) == 6
    assert out["validator_queue"]["summary"]["total"] == 3
    assert out["validator_handoff"]["summary"]["total"] == 3
    assert out["validator_handoff"]["summary"]["not_ready_total"] == 0


def test_mutates_and_returns_the_same_dict():
    result = _success_result()
    out = build_discovery_pipeline_artifacts(result)
    assert out is result


def test_error_path_shape_matches_except_branches():
    """
    ScraperRunnable's except branches build self.task.result with only
    error/js_recon/request_recipe/response_snapshot before calling this
    helper -- no status_code, final_url, discovery, or candidates key.
    """
    error_result = {
        "error": "httpx error: boom",
        "request_recipe": REQUEST_RECIPE,
        "response_snapshot": {
            "status_code": None,
            "headers": {},
            "content_type": "",
            "content_length": 0,
            "body_preview": "",
            "body_hash": "",
        },
    }
    out = build_discovery_pipeline_artifacts(error_result)

    assert out["finding_artifacts"]["all"] == []
    assert out["replay_groups"]["all"] == []
    assert out["replay_manifest"]["all"] == []
    assert out["validation_plan"]["all"] == []
    assert out["validator_queue"]["all"] == []
    assert out["validator_queue"]["summary"]["total"] == 0
    assert out["validator_handoff"]["all"] == []
    assert out["validator_handoff"]["summary"]["total"] == 0
    # original keys survive untouched
    assert out["error"] == "httpx error: boom"


def test_empty_dict_does_not_crash():
    out = build_discovery_pipeline_artifacts({})
    assert out["finding_artifacts"]["all"] == []
    assert out["validator_handoff"]["summary"]["total"] == 0
