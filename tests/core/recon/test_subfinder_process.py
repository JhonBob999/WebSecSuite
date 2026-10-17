"""Subfinder capabilities pass through the existing supervisor, offline."""

from pathlib import Path

import pytest

from core.recon import subfinder_adapter as subfinder
from core.recon.execution_policy import ScopeApproval
from core.recon.process_supervisor import JobState
from tests.core.recon.test_subfinder_adapter import release, candidate, tool
from tests.core.recon.test_process_supervisor import runtime, FakeProcess


def spec(candidate):
    verified = tool(candidate)
    approval = subfinder.approve_subfinder_run(verified, ("example.com",), confirmed=True,
                                               approval=ScopeApproval(exact_domains=("example.com",)))
    return subfinder.prepare_subfinder_discovery(verified, approval)


@pytest.mark.parametrize("reason", ["cancel", "timeout", "shutdown"])
def test_passive_lifecycle_preserves_fixed_arguments_environment_and_stop(runtime, candidate, reason):
    supervisor = runtime.supervisor()
    execution = spec(candidate)
    job = supervisor.submit(execution)
    runtime.pump()
    process = FakeProcess.instances[-1]
    assert process.arguments == list(execution._plan.arguments)
    assert process.environment.value("SUBFINDER_CONFIG") == candidate._configuration.files[0]
    assert process.directory == execution._plan.working_directory
    assert runtime.timer(supervisor, "recon_timeout").interval == 150000
    process.complete_start()
    if reason == "cancel":
        supervisor.cancel(job)
    elif reason == "shutdown":
        supervisor.shutdown()
    else:
        runtime.timer(supervisor, "recon_timeout").fire()
    assert process.terminations == 1
    runtime.timer(supervisor, "recon_termination_grace").fire()
    assert process.kills == 1
    process.finish()
    runtime.pump()
    assert supervisor.snapshot(job).state == (JobState.TIMED_OUT if reason == "timeout" else JobState.CANCELLED)


@pytest.mark.parametrize("change", ["expiry", "image", "containment", "config"])
def test_passive_queue_revalidates_without_launch(runtime, candidate, monkeypatch, change):
    supervisor = runtime.supervisor()
    execution = spec(candidate)
    job = supervisor.submit(execution)
    if change == "expiry":
        monkeypatch.setattr(subfinder, "monotonic", lambda: execution._approval.expires_at + 1)
    elif change == "image":
        Path(candidate.executable_path).write_bytes(b"changed")
    elif change == "config":
        Path(candidate._configuration.files[0]).write_bytes(b"active: true\n")
    else:
        monkeypatch.setattr(subfinder, "_process_safety", lambda: (False, "Unavailable"))
    runtime.pump()
    assert not FakeProcess.instances
    assert supervisor.snapshot(job).state is JobState.FAILED


def test_complete_offline_setup_supervision_parse_and_atomic_inventory_flow(runtime, release, monkeypatch):
    from core.recon.inventory import AssetInventory
    from core.recon.subfinder_runtime import SubfinderRuntime
    from core.recon import subfinder_runtime

    supervisor = runtime.supervisor()
    monkeypatch.setattr(subfinder_runtime, "ProcessSupervisor", lambda: supervisor)
    monkeypatch.setattr(subfinder_runtime, "process_safety_status", lambda: (True, "Contained"))
    inventory = AssetInventory()
    controller = SubfinderRuntime(inventory)
    path, archive = release
    controller.approve_executable(str(path), archive_path=str(archive))
    runtime.pump()
    process = FakeProcess.instances[-1]
    process.complete_start()
    config_directory = str(Path(process.environment.value("SUBFINDER_CONFIG")).parent)
    process.feed(("[INF] Current Version: v2.17.0\r\n"
                  f"[INF] Subfinder Config Directory: {config_directory}\r\n").encode(), stderr=True)
    process.finish()
    runtime.pump()
    assert controller.can_run
    assert not inventory.import_history
    for _ in range(2):
        controller.start_discovery(("EXAMPLE.com.",), confirmed=True,
                                   approval=ScopeApproval(exact_domains=("example.com",)))
        runtime.pump()
        process = FakeProcess.instances[-1]
        assert process.arguments == ["-d", "example.com", "-oJ", "-cs", "-silent", "-nc", "-duc",
                                     "-rl", "2", "-timeout", "15", "-max-time", "2"]
        process.complete_start()
        process.feed(b'{"host":"api.example.com","input":"example.com","sources":["crtsh"]}\n')
        process.finish()
        runtime.pump()
    assert len(inventory.assets) == 1 and len(inventory.observations) == 2
    assert len(inventory.import_history) == 2
    assert len({entry.run_id for entry in inventory.import_history}) == 2
    assert all(item.source == "subfinder" and item.entity_type == "hostname" for item in inventory.observations)
    assert "1 discovered hostnames" in controller.status
    controller.shutdown(immediate=True)
    controller.deleteLater()
