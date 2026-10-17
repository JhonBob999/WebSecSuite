"""Profile runs share the Nmap lifecycle and import only validated complete XML."""

from types import SimpleNamespace

import pytest

from core.recon.nmap_profiles import BUILTIN_PROFILES
from core.recon.process_supervisor import JobSnapshot, JobState
from tests.core.recon.test_nmap_runtime import runtime
from tests.core.recon.test_nmap_public_runtime import resolve, PUBLIC_XML
from tests.core.recon.test_public_target import FakeLookup


PROFILE = BUILTIN_PROFILES[1]
PROFILE_XML = PUBLIC_XML.replace(b'numservices="4" services="80,443,8080,8443"',
    b'numservices="8" services="80,443,8000,8080-8081,8443,8888,9443"').replace(b'count="3"', b'count="7"')


def ready(runtime, monkeypatch):
    runtime.ready()
    monkeypatch.setattr(runtime.controller.public_preflight, "_lookup_factory", FakeLookup)
    monkeypatch.setattr(runtime.module, "approve_profile_nmap",
                        lambda *args, profile, **kwargs: SimpleNamespace(profile=profile))
    monkeypatch.setattr(runtime.module, "prepare_nmap_profile_scan", lambda *args: "profile-spec")


def start(runtime, **changes):
    fields = dict(profile=PROFILE, profile_store=None, address="8.8.8.8", scope_confirmed=True, confirmed=True)
    fields.update(changes)
    return runtime.controller.start_profile_scan(("ginandjuice.shop",), **fields)


def finish(runtime, **changes):
    fields = dict(job_id=str(len(runtime.supervisor.submitted)), adapter_id="nmap.public-profile",
                  state=JobState.SUCCEEDED, stdout=PROFILE_XML, stderr=b"", exit_code=0)
    fields.update(changes)
    runtime.supervisor.job_finished.emit(JobSnapshot(**fields))


def test_profile_success_preserves_inventory_and_adds_distinct_provenance(runtime, monkeypatch):
    ready(runtime, monkeypatch)
    original = runtime.inventory.observations
    for _ in range(2):
        resolve(runtime)
        start(runtime)
        assert runtime.controller.busy
        finish(runtime)
    assert all(item in runtime.inventory.observations for item in original)
    assert len(runtime.inventory.import_history) == 3
    first, second = runtime.inventory.import_history[-2:]
    assert first.run_id != second.run_id
    assert "Web Services" in second.label
    service = next(item for item in runtime.inventory.assets if item.value == "8.8.8.8" and item.port == 8080)
    evidence = next(item.metadata for item in service.observations[-1].evidence if item.kind == "nmap-run")
    assert evidence["profile_id"] == "web-services"
    assert evidence["executable_version"] == "7.95"
    assert evidence["ports"] == [80, 443, 8000, 8080, 8081, 8443, 8888, 9443]
    assert "1 open" in runtime.controller.status.lower()


@pytest.mark.parametrize("changes", [dict(state=JobState.CANCELLED), dict(state=JobState.TIMED_OUT),
    dict(state=JobState.FAILED), dict(exit_code=1), dict(stdout_truncated=True), dict(stderr_truncated=True),
    dict(stdout=PROFILE_XML[:-20]), dict(stdout=PUBLIC_XML), dict(adapter_id="nmap.public-quick-discovery")])
def test_profile_failure_is_atomic_and_never_retries(runtime, monkeypatch, changes):
    ready(runtime, monkeypatch)
    original = runtime.inventory.assets, runtime.inventory.observations, runtime.inventory.import_history
    resolve(runtime)
    start(runtime)
    finish(runtime, **changes)
    assert (runtime.inventory.assets, runtime.inventory.observations, runtime.inventory.import_history) == original
    assert not runtime.controller.busy and not runtime.controller.public_preflight.is_fresh
    assert runtime.supervisor.submitted == ["verify-spec", "profile-spec"]


def test_profile_stop_wins_over_late_success_and_zero_open_succeeds(runtime, monkeypatch):
    ready(runtime, monkeypatch)
    resolve(runtime)
    job = start(runtime)
    runtime.controller.stop()
    finish(runtime)
    assert runtime.supervisor.cancelled == [job]
    assert len(runtime.inventory.import_history) == 1
    resolve(runtime)
    start(runtime)
    finish(runtime, stdout=PROFILE_XML.replace(b'state="open"', b'state="filtered"'))
    assert len(runtime.inventory.import_history) == 2
    assert "0 open" in runtime.controller.status.lower()


def test_profile_guards_and_reentrant_preflight_callback_cannot_submit_twice(runtime, monkeypatch):
    ready(runtime, monkeypatch)
    with pytest.raises(ValueError):
        start(runtime)
    resolve(runtime)
    for changes in ({"profile": BUILTIN_PROFILES[2]}, {"scope_confirmed": False},
                    {"confirmed": False}, {"address": "9.9.9.9"}):
        with pytest.raises(ValueError):
            start(runtime, **changes)
    attempts = []

    def changed():
        if runtime.controller.busy and not runtime.controller.public_preflight.observation:
            with pytest.raises(ValueError):
                start(runtime)
            attempts.append(True)

    runtime.controller.changed.connect(changed)
    start(runtime)
    assert attempts and runtime.supervisor.submitted == ["verify-spec", "profile-spec"]


@pytest.mark.parametrize("operation", ["stop", "shutdown"])
def test_stop_or_shutdown_during_consumed_preflight_never_submits(runtime, monkeypatch, operation):
    ready(runtime, monkeypatch)
    resolve(runtime)
    cancelled = []

    def cancel_when_consumed():
        if not cancelled and runtime.controller.busy and not runtime.controller.public_preflight.observation:
            cancelled.append(True)
            getattr(runtime.controller, operation)()

    runtime.controller.public_preflight.changed.connect(cancel_when_consumed)
    with pytest.raises(ValueError, match="cancelled"):
        start(runtime)
    assert runtime.supervisor.submitted == ["verify-spec"]
    assert not runtime.controller.busy and len(runtime.inventory.import_history) == 1


@pytest.mark.parametrize("operation", ["stop", "shutdown"])
def test_synchronous_queued_cancellation_does_not_leave_runtime_busy(runtime, monkeypatch, operation):
    ready(runtime, monkeypatch)
    resolve(runtime)
    submit = runtime.supervisor.submit

    def emit_queued(spec):
        job_id = submit(spec)
        runtime.supervisor.job_changed.emit(JobSnapshot(job_id, "nmap.public-profile", JobState.QUEUED, b"", b""))
        return job_id

    def cancel(job_id):
        runtime.supervisor.job_finished.emit(JobSnapshot(job_id, "nmap.public-profile", JobState.CANCELLED, b"", b""))

    def cancel_queued(snapshot):
        if snapshot.state == JobState.QUEUED:
            getattr(runtime.controller, operation)()

    monkeypatch.setattr(runtime.supervisor, "submit", emit_queued)
    monkeypatch.setattr(runtime.supervisor, "cancel", cancel)
    # The real supervisor cancels queued jobs synchronously during shutdown.
    if operation == "shutdown":
        monkeypatch.setattr(runtime.supervisor, "shutdown", lambda **kwargs: cancel("2"))
    runtime.supervisor.job_changed.connect(cancel_queued)
    start(runtime)
    assert not runtime.controller.busy and len(runtime.inventory.import_history) == 1
    assert "cancelled" in runtime.controller.status.lower()
