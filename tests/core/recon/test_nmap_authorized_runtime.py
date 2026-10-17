"""Authorized profiles use the existing lifecycle and atomic import boundary."""

from types import SimpleNamespace
from dataclasses import replace

import pytest

from core.recon.nmap_profiles import BUILTIN_PROFILES
from core.recon.process_supervisor import JobSnapshot, JobState
from tests.core.recon.test_nmap_runtime import runtime, XML


def test_legacy_profile_route_rejects_extended_settings_instead_of_dropping_them():
    from core.recon.nmap_profiles import duplicate_profile
    from core.recon.nmap_profile_execution import execution_reasons

    profile = replace(duplicate_profile(BUILTIN_PROFILES[1]), os_detection=True)
    assert execution_reasons(profile)


def configure(runtime, monkeypatch):
    runtime.ready()
    approval = SimpleNamespace(profile=BUILTIN_PROFILES[0], scope=object(),
        _arguments=(), scripts=(), _version="7.95", _sha256="a" * 64)
    monkeypatch.setattr(runtime.module, "approve_authorized_nmap", lambda *a, **k: approval)
    monkeypatch.setattr(runtime.module, "prepare_nmap_authorized_scan", lambda *a: "authorized-spec")
    monkeypatch.setattr(runtime.module, "release_authorized_approval", lambda value: None)
    return approval


def start(runtime, approval):
    return runtime.controller.start_authorized_scan(approval.scope,
        profile=approval.profile, scope_confirmed=True, confirmed=True)


def finish(runtime, **changes):
    values = dict(job_id=str(len(runtime.supervisor.submitted)), adapter_id="nmap.authorized-profile",
        state=JobState.SUCCEEDED, stdout=XML, stderr=b"", exit_code=0)
    values.update(changes)
    runtime.supervisor.job_finished.emit(JobSnapshot(**values))


def test_authorized_scan_uses_shared_supervisor_and_rejects_duplicate_submission(runtime, monkeypatch):
    approval = configure(runtime, monkeypatch)
    job = start(runtime, approval)
    assert runtime.controller.busy
    with pytest.raises(ValueError, match="already running"):
        start(runtime, approval)
    runtime.controller.stop()
    assert runtime.supervisor.cancelled == [job]
    finish(runtime)
    assert not runtime.controller.busy
    assert len(runtime.inventory.import_history) == 1


@pytest.mark.parametrize("changes", [dict(state=JobState.CANCELLED), dict(state=JobState.TIMED_OUT),
    dict(state=JobState.FAILED), dict(exit_code=2), dict(stdout_truncated=True),
    dict(adapter_id="nmap.public-profile")])
def test_unsuccessful_authorized_output_never_reaches_parser_or_inventory(runtime, monkeypatch, changes):
    approval = configure(runtime, monkeypatch)
    monkeypatch.setattr(runtime.module, "parse_authorized_nmap_output",
        lambda *a, **k: pytest.fail("failed output must not be parsed"))
    original = runtime.inventory.assets, runtime.inventory.observations, runtime.inventory.import_history
    start(runtime, approval)
    finish(runtime, **changes)
    assert (runtime.inventory.assets, runtime.inventory.observations, runtime.inventory.import_history) == original
    assert runtime.supervisor.submitted == ["verify-spec", "authorized-spec"]
    assert not runtime.controller.busy


def test_stop_during_queued_signal_wins_before_launch(runtime, monkeypatch):
    approval = configure(runtime, monkeypatch)

    def submit(spec):
        runtime.supervisor.submitted.append(spec)
        runtime.supervisor.job_changed.emit(JobSnapshot("2", "nmap.authorized-profile", JobState.QUEUED, b"", b""))
        runtime.controller.stop()
        finish(runtime, state=JobState.CANCELLED)
        return "2"

    monkeypatch.setattr(runtime.supervisor, "submit", submit)
    start(runtime, approval)
    assert runtime.supervisor.cancelled == ["2"]
    assert not runtime.controller.busy
    assert "cancelled" in runtime.controller.status.lower()


def test_successful_authorized_output_imports_once_and_opens_shared_evidence_payload(runtime, monkeypatch):
    from core.recon.nmap_scope import resolve_scope
    from core.recon.nmap_profiles import configuration_arguments

    approval = configure(runtime, monkeypatch)
    approval.scope = resolve_scope(("127.0.0.1",))
    approval._arguments = (*configuration_arguments(approval.profile), "127.0.0.1")
    released = []
    monkeypatch.setattr(runtime.module, "release_authorized_approval", released.append)
    start(runtime, approval)
    finish(runtime)
    finish(runtime)
    assert released == [approval]
    assert len(runtime.inventory.import_history) == 2
    assert "1 open TCP/UDP" in runtime.controller.status
    payload = runtime.controller.last_authorized_result
    assert payload["profile"] == "Quick Network Discovery"
    assert any(item["type"] == "service" for item in payload["observations"])


def test_invalid_authorized_xml_preserves_inventory_and_releases_installation(runtime, monkeypatch):
    from core.recon.nmap_scope import resolve_scope

    approval = configure(runtime, monkeypatch)
    approval.scope = resolve_scope(("127.0.0.1",))
    released = []
    monkeypatch.setattr(runtime.module, "release_authorized_approval", released.append)
    start(runtime, approval)
    finish(runtime, stdout=XML[:-20])
    assert len(runtime.inventory.import_history) == 1
    assert released == [approval]
    assert runtime.controller.last_authorized_result is None
    assert "failed" in runtime.controller.status.lower()
