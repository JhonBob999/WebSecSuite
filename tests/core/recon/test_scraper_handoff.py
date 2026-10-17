"""Scraper handoffs expose only factual, bounded, offline hostname evidence."""

from copy import deepcopy
from datetime import datetime, timezone
import json

import pytest

from core.scraper.task_types import ScrapeTask, TaskStatus


def api():
    from core.recon import scraper_handoff

    return scraper_handoff


def completed_task():
    task = ScrapeTask(id="opaque-task-id", url="https://Example.test/private?token=secret-query")
    task.status = TaskStatus.DONE
    task.result = {
        "status_code": 403,
        "final_url": "https://Final.Example.test/private?token=secret-final-query",
        "headers": {"Authorization": "Bearer secret-auth", "Set-Cookie": "secret-cookie"},
        "request_recipe": {
            "timestamp": "2026-10-17T12:00:00Z",
            "url": task.url,
            "headers": {"Authorization": "secret-auth"},
            "cookie_path": "secret-cookie-path",
        },
        "response_snapshot": {"status_code": 403, "body_preview": "secret-body"},
    }
    task.params = {"proxy": "http://user:secret-proxy@proxy.test:8000"}
    return task


@pytest.mark.parametrize("url, expected", [
    ("https://EXAMPLE.test/path?token=secret#fragment", "example.test"),
    ("http://bücher.de:8080/", "xn--bcher-kva.de"),
    ("https://example.test./", "example.test"),
])
def test_http_hostname_uses_r1_normalization(url, expected):
    assert api().hostname_from_http_url(url) == expected


@pytest.mark.parametrize("url", [
    "example.test", "ftp://example.test/", "file:///example.test", "//example.test/",
    "https://user:secret@example.test/", "https://example.test:99999/",
    "https://example.test:bad/", "https://example.test:/", "https://example.test\\@other.test/",
    "https://example.test/\r\nAuthorization: secret", "https://127.0.0.1/",
    "https://[::1]/", "https://localhost/", "https://*.example.test/", "https:///path",
    "https://example.test /", None,
])
def test_unsupported_urls_fail_without_echoing_credentials(url):
    with pytest.raises(ValueError) as error:
        api().hostname_from_http_url(url)
    assert "secret" not in str(error.value)


def test_completed_response_handoff_is_immutable_safe_and_idempotent():
    task = completed_task()
    before = deepcopy(task)
    batch = api().build_scraper_observation_batch(task)
    assert batch == api().build_scraper_observation_batch(task)
    assert task == before
    assert len(batch.observations) == 1
    observation = batch.observations[0]
    assert observation.source == "Scraper"
    assert observation.entity_type == "hostname"
    assert observation.entity_key == "recon:hostname:final.example.test"
    assert observation.value == "final.example.test"
    assert observation.evidence[0].metadata["http_status"] == 403
    transferred = json.dumps([observation.to_dict()])
    assert "secret" not in transferred
    assert "token" not in transferred
    assert "Authorization" not in transferred
    assert "private" not in transferred
    assert task.id not in transferred
    assert "http" not in observation.evidence[0].ref
    assert "scraper" in observation.evidence[0].ref


@pytest.mark.parametrize("status", [
    TaskStatus.PENDING, TaskStatus.RUNNING, TaskStatus.PAUSED,
    TaskStatus.FAILED, TaskStatus.STOPPED, TaskStatus.ERROR,
])
def test_unfinished_or_failed_task_cannot_transfer_even_with_previous_response(status):
    task = completed_task()
    task.status = status
    with pytest.raises(ValueError, match="completed HTTP response"):
        api().build_scraper_observation_batch(task)


@pytest.mark.parametrize("result", [
    None, {}, {"error": "secret-error"}, {"status_code": None}, {"status_code": True},
    {"status_code": "200"}, {"status_code": 99}, {"status_code": 600},
    {"status_code": 200, "error": "secret-error"},
    {"status_code": 200, "response_snapshot": {"status_code": None}},
    {"status_code": 200, "response_snapshot": {"status_code": 404}},
])
def test_done_status_without_real_response_is_rejected(result):
    task = completed_task()
    task.result = result
    with pytest.raises(ValueError, match="completed HTTP response") as error:
        api().build_scraper_observation_batch(task)
    assert "secret-error" not in str(error.value)


def test_run_provenance_uses_persisted_response_timestamp_and_task_identity():
    task = completed_task()
    first = api().build_scraper_observation_batch(task)
    task.finished_at = datetime.now(timezone.utc)
    assert api().build_scraper_observation_batch(task) == first
    task.result["request_recipe"]["timestamp"] = "2026-10-17T12:01:00Z"
    second = api().build_scraper_observation_batch(task)
    assert second.run_id != first.run_id
    task.id = "different-task-id"
    assert api().build_scraper_observation_batch(task).run_id != second.run_id


def test_legacy_completed_result_without_timestamp_has_stable_provenance():
    task = completed_task()
    task.result = {"status_code": 204}
    task.finished_at = datetime.now(timezone.utc)
    before_session_restore = api().build_scraper_observation_batch(task)
    task.finished_at = None  # Runtime dates are not saved by SessionController.
    assert api().build_scraper_observation_batch(task) == before_session_restore
    assert api().build_scraper_observation_batch(task) == api().build_scraper_observation_batch(task)
    assert api().build_scraper_observation_batch(task).observations[0].value == "example.test"
