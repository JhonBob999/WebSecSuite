"""Public runtime gates, completion, and atomic inventory provenance offline."""

import pytest

from core.recon import public_target as public
from core.recon.process_supervisor import JobSnapshot, JobState
from tests.core.recon.test_nmap_runtime import runtime, XML
from tests.core.recon.test_public_target import FakeLookup


PUBLIC_XML = XML.replace(b"127.0.0.1", b"8.8.8.8")


def ready(runtime, monkeypatch):
    runtime.ready()
    monkeypatch.setattr(runtime.controller.public_preflight, "_lookup_factory", FakeLookup)
    monkeypatch.setattr(runtime.module, "approve_public_nmap", lambda *args, **kwargs: "public-approval")
    monkeypatch.setattr(runtime.module, "prepare_nmap_public_scan", lambda *args: "public-spec")


def resolve(runtime):
    service = runtime.controller.public_preflight
    service.start((public.PUBLIC_HOSTNAME,))
    service._lookup.finished.emit()
    assert service.is_fresh


def start(runtime, **changes):
    fields = dict(address="8.8.8.8", scope_confirmed=True, confirmed=True)
    fields.update(changes)
    return runtime.controller.start_public_scan((public.PUBLIC_HOSTNAME,), **fields)


def finish(runtime, *, state=JobState.SUCCEEDED, content=PUBLIC_XML, **changes):
    fields = dict(job_id=str(len(runtime.supervisor.submitted)), adapter_id="nmap.public-quick-discovery",
                  state=state, stdout=content, stderr=b"", exit_code=0)
    fields.update(changes)
    runtime.supervisor.job_finished.emit(JobSnapshot(**fields))


def test_public_run_requires_verified_tool_fresh_dns_and_explicit_scope_and_ip(runtime, monkeypatch):
    with pytest.raises(ValueError):
        start(runtime)
    ready(runtime, monkeypatch)
    with pytest.raises(ValueError):
        start(runtime)
    resolve(runtime)
    for changes in ({"scope_confirmed": False}, {"confirmed": False}, {"address": ""},
                    {"address": "9.9.9.9"}, {"address": "127.0.0.1"}):
        with pytest.raises(ValueError):
            start(runtime, **changes)
    assert runtime.supervisor.submitted == ["verify-spec"]
    assert runtime.controller.public_preflight.is_fresh
    with pytest.raises(ValueError):
        runtime.controller.start_public_scan(("other.example",), address="8.8.8.8",
                                              scope_confirmed=True, confirmed=True)
    assert runtime.supervisor.submitted == ["verify-spec"]


def test_success_imports_distinct_runs_with_exact_ip_and_dns_provenance(runtime, monkeypatch):
    ready(runtime, monkeypatch)
    before_assets = runtime.inventory.assets
    for number in range(2):
        resolve(runtime)
        start(runtime)
        assert not runtime.controller.public_preflight.is_fresh
        with pytest.raises(ValueError):
            start(runtime)
        finish(runtime)
        assert len(runtime.inventory.import_history) == number + 2
        assert runtime.controller.can_run
        assert "1 open" in runtime.controller.status.lower()
        assert public.PUBLIC_HOSTNAME in runtime.inventory.import_history[-1].label
        assert "8.8.8.8" in runtime.inventory.import_history[-1].label
    assert runtime.inventory.import_history[-1].run_id != runtime.inventory.import_history[-2].run_id
    asset = next(item for item in runtime.inventory.assets if item.value == "8.8.8.8" and item.port == 8080)
    assert asset.sources == ("nmap",)
    assert len(asset.observations) == 2
    metadata = next(item.metadata for item in asset.observations[0].evidence if item.kind == "nmap-run")
    assert metadata["profile"] == public.PUBLIC_PROFILE and metadata["target"] == "8.8.8.8"
    assert metadata["approved_hostname"] == public.PUBLIC_HOSTNAME
    assert metadata["dns_observation"]["ownership_verified"] is False
    assert all(any(item.entity_key == original.entity_key for item in runtime.inventory.assets) for original in before_assets)


@pytest.mark.parametrize("changes", [dict(state=JobState.CANCELLED), dict(state=JobState.TIMED_OUT),
    dict(state=JobState.FAILED), dict(exit_code=1), dict(stdout_truncated=True), dict(stderr_truncated=True),
    dict(content=PUBLIC_XML[:-20]), dict(content=XML), dict(adapter_id="nmap.local-self-test")])
def test_public_failures_preserve_all_existing_inventory_and_history(runtime, monkeypatch, changes):
    ready(runtime, monkeypatch)
    before = runtime.inventory.assets, runtime.inventory.observations, runtime.inventory.import_history
    resolve(runtime)
    start(runtime)
    finish(runtime, **changes)
    assert (runtime.inventory.assets, runtime.inventory.observations, runtime.inventory.import_history) == before
    assert not runtime.controller.busy
    assert not runtime.controller.public_preflight.is_fresh


def test_public_zero_open_is_success_and_stop_wins_over_late_success(runtime, monkeypatch):
    ready(runtime, monkeypatch)
    resolve(runtime)
    start(runtime)
    finish(runtime, content=PUBLIC_XML.replace(b'state="open"', b'state="filtered"'))
    assert "0 open" in runtime.controller.status.lower()
    assert len(runtime.inventory.import_history) == 2
    resolve(runtime)
    job = start(runtime)
    runtime.controller.stop()
    assert runtime.supervisor.cancelled == [job]
    finish(runtime)
    assert len(runtime.inventory.import_history) == 2
    assert "cancelled" in runtime.controller.status.lower()


def test_failed_prepare_consumes_preflight_and_never_submits_or_retries(runtime, monkeypatch):
    ready(runtime, monkeypatch)
    resolve(runtime)

    def reject(*_args):
        raise ValueError("Executable changed.")

    monkeypatch.setattr(runtime.module, "prepare_nmap_public_scan", reject)
    with pytest.raises(ValueError):
        start(runtime)
    assert not runtime.controller.public_preflight.is_fresh
    assert runtime.supervisor.submitted == ["verify-spec"]


def test_dns_busy_blocks_local_execution_and_shutdown_cancels_lookup(runtime, monkeypatch):
    ready(runtime, monkeypatch)
    runtime.controller.public_preflight.start((public.PUBLIC_HOSTNAME,))
    lookup = runtime.controller.public_preflight._lookup
    assert not runtime.controller.can_run
    with pytest.raises(ValueError):
        runtime.controller.start_self_test(confirmed=True)
    runtime.controller.shutdown(immediate=True)
    assert lookup.aborted
    assert runtime.controller.public_preflight.observation is None
