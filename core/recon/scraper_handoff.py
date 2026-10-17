"""Narrow, offline Scraper handoffs without request or response secrets."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from urllib.parse import urlsplit

from core.recon.observations import EvidenceRef, Observation, ObservationBatch
from core.recon.targets import normalize_hostname
from core.scraper.task_types import TaskStatus


def hostname_from_http_url(url: object) -> str:
    """Extract only an R1-compatible hostname; never return URL credentials."""
    if not isinstance(url, str) or not url or len(url) > 16_384:
        raise ValueError("Choose a task with a valid HTTP or HTTPS URL.")
    if "\\" in url or any(character.isspace() or unicodedata.category(character)[0] == "C"
                            for character in url):
        raise ValueError("The task URL contains unsafe whitespace or control characters.")
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing credentials cannot be sent to Recon.")
        if parsed.netloc.endswith(":") or (parsed.port is not None and parsed.port < 1):
            raise ValueError
    except ValueError as error:
        if str(error) == "URLs containing credentials cannot be sent to Recon.":
            raise
        raise ValueError("Choose a task with a valid HTTP or HTTPS URL and port.") from None
    try:
        return normalize_hostname(parsed.hostname)
    except ValueError:
        raise ValueError("The task URL hostname is unsupported; Recon accepts domain hostnames only.") from None


def _digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _run_marker(result: dict) -> object:
    recipe = result.get("request_recipe")
    timestamp = recipe.get("timestamp") if isinstance(recipe, dict) else None
    if isinstance(timestamp, str) and 0 < len(timestamp) <= 128:
        # This timestamp is part of the saved result, unlike runtime task dates.
        return {"response_timestamp": timestamp}
    # Legacy completed results have no run date. Repeated equivalent transfers
    # intentionally share identity rather than inventing a new execution time.
    return {"legacy_result": True}


def build_scraper_observation_batch(task) -> ObservationBatch:
    """Use the authoritative completed task result, never a stale UI cache."""
    failure = "Only a task with a real completed HTTP response can be sent to Asset Inventory."
    result = getattr(task, "result", None)
    if getattr(task, "status", None) != TaskStatus.DONE or not isinstance(result, dict):
        raise ValueError(failure)
    code = result.get("status_code")
    if (type(code) is not int or not 100 <= code <= 599
            or result.get("error") or result.get("last_error")):
        raise ValueError(failure)
    if "response_snapshot" in result:
        snapshot = result["response_snapshot"]
        if (not isinstance(snapshot, dict) or type(snapshot.get("status_code")) is not int
                or snapshot["status_code"] != code):
            raise ValueError(failure)
    task_id = getattr(task, "id", None)
    if not isinstance(task_id, str) or not task_id or len(task_id) > 1024:
        raise ValueError("The Scraper task has no valid stable identity.")
    response_url = result.get("final_url") or result.get("url") or getattr(task, "url", None)
    hostname = hostname_from_http_url(response_url)
    task_ref = "scraper-task:" + _digest(task_id)
    run_digest = _digest({
        "task": task_ref, "run": _run_marker(result),
        "hostname": hostname, "http_status": code,
    })
    run_id = "scraper-run:" + run_digest
    evidence = EvidenceRef(
        ref=task_ref + "/run/" + run_digest,
        kind="scraper_http_response",
        _metadata_json=json.dumps({"http_status": code}, separators=(",", ":")),
    )
    observation = Observation(
        run_id=run_id, id="hostname", source="Scraper",
        entity_key="recon:hostname:" + hostname, entity_type="hostname", value=hostname,
        evidence=(evidence,),
    )
    return ObservationBatch(run_id, (observation,), record_indices=(1,))
