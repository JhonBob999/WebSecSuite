"""The real supervisor runs only injected processes for public capability tests."""

from pathlib import Path

import pytest

from core.recon import nmap_adapter as nmap
from core.recon.execution_policy import ExecutionPolicyError
from core.recon.process_supervisor import JobState
from tests.core.recon.test_nmap_adapter import candidate, version_result
from tests.core.recon.test_nmap_public_adapter import observation
from tests.core.recon.test_public_target import preflight
from tests.core.recon.test_process_supervisor import runtime, FakeProcess


def spec(candidate, observation):
    tool = nmap.verify_nmap_version(candidate, version_result())
    approval = nmap.approve_public_nmap(tool, observation, address="8.8.8.8",
                                       scope_confirmed=True, confirmed=True)
    return nmap.prepare_nmap_public_scan(tool, approval)


@pytest.mark.parametrize("reason", ["cancel", "timeout"])
def test_public_process_stop_and_timeout_use_existing_contained_lifecycle(runtime, candidate, observation, reason):
    supervisor = runtime.supervisor()
    job = supervisor.submit(spec(candidate, observation))
    runtime.pump()
    process = FakeProcess.instances[-1]
    assert process.arguments[-1] == "8.8.8.8" and "ginandjuice.shop" not in process.arguments
    assert runtime.timer(supervisor, "recon_timeout").interval == 40000
    process.complete_start()
    if reason == "cancel":
        supervisor.cancel(job)
    else:
        runtime.timer(supervisor, "recon_timeout").fire()
    assert process.terminations == 1
    runtime.timer(supervisor, "recon_termination_grace").fire()
    assert process.kills == 1
    process.finish()
    runtime.pump()
    assert supervisor.snapshot(job).state == (JobState.CANCELLED if reason == "cancel" else JobState.TIMED_OUT)


@pytest.mark.parametrize("change", ["expiry", "image", "containment"])
def test_public_queue_revalidates_before_any_process_is_created(runtime, candidate, observation, monkeypatch, change):
    supervisor = runtime.supervisor()
    execution = spec(candidate, observation)
    job = supervisor.submit(execution)
    if change == "expiry":
        monkeypatch.setattr(nmap, "monotonic", lambda: execution._approval.expires_at + 1)
    elif change == "image":
        Path(candidate.executable_path).write_bytes(b"MZ changed after submission")
    else:
        monkeypatch.setattr(nmap, "_process_safety", lambda: (False, "Unavailable"))
    runtime.pump()
    assert not FakeProcess.instances
    assert supervisor.snapshot(job).state == JobState.FAILED
    with pytest.raises(ExecutionPolicyError):
        supervisor.submit(execution)
