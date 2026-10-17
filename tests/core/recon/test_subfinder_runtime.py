"""Offline runtime lifecycle tests with real observation/inventory integration."""

import importlib
import json
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QObject, Signal

from core.recon.execution_policy import ExecutionPolicyError, ScopeApproval, preflight_scope
from core.recon.inventory import AssetInventory
from core.recon.process_supervisor import JobSnapshot, JobState
from core.recon.subfinder_adapter import selected_subfinder_hostname


ROOT = "example.test"
VERSION_OUTPUT = b"[INF] Current Version: v2.17.0\n"
JSONL = (b'{"host":"api.example.test","input":"example.test","sources":["crtsh"]}\n'
         b'{"host":"API.EXAMPLE.TEST.","input":"example.test","sources":["alienvault"]}\n')


class ControlledSupervisor(QObject):
    job_changed = Signal(object)
    job_finished = Signal(object)

    def __init__(self):
        super().__init__()
        self.submitted = []
        self.cancelled = []
        self.closed = []
        self.on_submit = None
        self.finish_on_cancel = False

    def submit(self, spec):
        self.submitted.append(spec)
        job_id = f"synthetic-job-{len(self.submitted)}"
        self.job_changed.emit(JobSnapshot(job_id, spec.adapter_id, JobState.QUEUED, b"", b""))
        if self.on_submit is not None:
            self.on_submit(job_id, spec)
        return job_id

    def cancel(self, job_id):
        self.cancelled.append(job_id)
        if self.finish_on_cancel:
            self.job_finished.emit(JobSnapshot(job_id, self.submitted[-1].adapter_id,
                                               JobState.CANCELLED, b"", b""))

    def shutdown(self, *, immediate=False):
        self.closed.append(immediate)


@pytest.fixture
def runtime(monkeypatch, qapp):
    module = importlib.import_module("core.recon.subfinder_runtime")
    supervisor = ControlledSupervisor()
    candidate = SimpleNamespace(executable_path=r"C:\Approved\subfinder.exe", version="2.17.0")
    tool = SimpleNamespace(executable_path=candidate.executable_path, version=candidate.version,
                           _candidate=candidate)
    approved_calls = []
    discovery_calls = []

    def approve(path, *, archive_path, confirmed):
        approved_calls.append((path, archive_path, confirmed))
        return candidate

    def verify(actual_candidate, snapshot):
        if actual_candidate is not candidate or snapshot.stderr != VERSION_OUTPUT:
            raise ValueError("Raw version error token=private")
        return tool

    def approve_run(actual_tool, targets, *, confirmed, approval):
        discovery_calls.append((actual_tool, tuple(targets), confirmed, approval))
        root = selected_subfinder_hostname(targets)
        if (actual_tool is not tool or confirmed is not True or type(approval) is not ScopeApproval
                or root not in approval.exact_domains or not preflight_scope((root,), approval).allowed):
            raise ValueError("Controlled scope rejection.")
        return SimpleNamespace(hostname=root)

    monkeypatch.setattr(module, "ProcessSupervisor", lambda: supervisor)
    monkeypatch.setattr(module, "process_safety_status", lambda: (True, "Windows containment available."))
    monkeypatch.setattr(module, "approve_subfinder_path", approve)
    monkeypatch.setattr(module, "prepare_subfinder_version_check",
                        lambda value: SimpleNamespace(adapter_id="subfinder.version-check"))
    monkeypatch.setattr(module, "verify_subfinder_version", verify)
    monkeypatch.setattr(module, "approve_subfinder_run", approve_run)
    monkeypatch.setattr(module, "prepare_subfinder_discovery",
                        lambda verified, approval: SimpleNamespace(adapter_id="subfinder.passive-standard"))
    inventory = AssetInventory()
    inventory.import_json(json.dumps({
        "schema": "websecsuite.recon.observations", "version": 1, "run_id": "native-run",
        "observations": [{"id": "native-host", "source": "fixture", "type": "hostname",
                          "value": "api.example.test"}],
    }))
    controller = module.SubfinderRuntime(inventory)

    def finish(*, verify=False, content=None, **changes):
        values = dict(job_id=f"synthetic-job-{len(supervisor.submitted)}",
                      adapter_id="subfinder.version-check" if verify else "subfinder.passive-standard",
                      state=JobState.SUCCEEDED, stdout=b"" if verify else JSONL,
                      stderr=VERSION_OUTPUT if verify else b"", exit_code=0)
        if content is not None:
            values["stdout"] = content
        values.update(changes)
        snapshot = JobSnapshot(**values)
        supervisor.job_finished.emit(snapshot)
        return snapshot

    def ready():
        controller.approve_executable(candidate.executable_path, archive_path=r"C:\Approved\release.zip")
        finish(verify=True)
        assert controller.can_run

    def start(targets=(ROOT,), *, confirmed=True, approval=None):
        return controller.start_discovery(targets, confirmed=confirmed,
                                          approval=ScopeApproval(exact_domains=(ROOT,)) if approval is None else approval)

    yield SimpleNamespace(module=module, controller=controller, supervisor=supervisor,
                          candidate=candidate, tool=tool, inventory=inventory, ready=ready,
                          finish=finish, start=start, approved_calls=approved_calls,
                          discovery_calls=discovery_calls)
    controller.shutdown(immediate=True)
    controller.deleteLater()
    qapp.processEvents()


def test_construction_does_not_launch_and_only_verification_exposes_tool(runtime):
    assert not runtime.supervisor.submitted
    assert not runtime.controller.busy and not runtime.controller.can_run
    assert runtime.controller.executable_path == runtime.controller.version == ""
    runtime.controller.approve_executable(runtime.candidate.executable_path, archive_path="release.zip")
    assert runtime.approved_calls == [(runtime.candidate.executable_path, "release.zip", True)]
    assert runtime.controller.busy and not runtime.controller.can_run
    assert runtime.controller.executable_path == ""
    assert len(runtime.inventory.import_history) == 1
    runtime.finish(verify=True)
    assert runtime.controller.executable_path == runtime.tool.executable_path
    assert runtime.controller.version == "2.17.0" and runtime.controller.can_run
    assert len(runtime.inventory.import_history) == 1


@pytest.mark.parametrize("targets,confirmed,approval", [
    ((ROOT,), False, ScopeApproval(exact_domains=(ROOT,))),
    ((), True, ScopeApproval(exact_domains=(ROOT,))),
    ((ROOT, "other.test"), True, ScopeApproval(exact_domains=(ROOT,))),
    (("127.0.0.1",), True, ScopeApproval(exact_domains=(ROOT,))),
    ((ROOT,), True, ScopeApproval(subdomain_ranges=(ROOT,))),
    ((ROOT,), True, ScopeApproval(exact_domains=(ROOT,), excluded_domains=(ROOT,))),
])
def test_each_discovery_requires_selection_confirmation_and_explicit_scope(runtime, targets, confirmed, approval):
    runtime.ready()
    with pytest.raises(ValueError):
        runtime.start(targets, confirmed=confirmed, approval=approval)
    assert len(runtime.supervisor.submitted) == 1
    assert not runtime.controller.busy


def test_no_discovery_can_start_before_verification_or_while_an_operation_is_pending(runtime):
    with pytest.raises(ValueError):
        runtime.start()
    runtime.controller.approve_executable(runtime.candidate.executable_path, archive_path="release.zip")
    with pytest.raises(ValueError):
        runtime.start()
    with pytest.raises(ValueError):
        runtime.controller.approve_executable(runtime.candidate.executable_path, archive_path="other.zip")
    assert len(runtime.supervisor.submitted) == 1


def test_success_captures_root_merges_inventory_and_records_distinct_runs_once(runtime):
    runtime.ready()
    targets = ["EXAMPLE.TEST."]
    approval = ScopeApproval(exact_domains=(ROOT,))
    changes = []
    runtime.controller.inventory_changed.connect(lambda: changes.append(True))
    runtime.controller.start_discovery(targets, confirmed=True, approval=approval)
    targets[0] = "changed.test"
    snapshot = runtime.finish()
    runtime.supervisor.job_finished.emit(snapshot)
    assert len(changes) == 1
    assert len(runtime.inventory.assets) == 1 and runtime.inventory.assets[0].sources == ("fixture", "subfinder")
    entry = runtime.inventory.import_history[-1]
    assert entry.label == "Subfinder Passive Standard · example.test"
    assert entry.format_name == "Subfinder live JSONL"
    assert entry.run_id == "subfinder:passive:synthetic-job-2"
    assert entry.observation_count == 1 and entry.asset_count == 1
    assert "1 discovered hostnames" in runtime.controller.status
    assert "Added: 1" in runtime.controller.status and "Duplicates: 1" in runtime.controller.status
    assert "history" in runtime.controller.status.lower()
    runtime.start()
    runtime.finish()
    assert len(runtime.inventory.import_history) == 3 and len(runtime.inventory.observations) == 3
    assert runtime.inventory.import_history[-1].run_id == "subfinder:passive:synthetic-job-3"
    assert runtime.controller.can_run


def test_zero_result_success_records_history_and_notifies_inventory_consumers(runtime):
    runtime.ready()
    changes = []
    runtime.controller.inventory_changed.connect(lambda: changes.append(True))
    runtime.start()
    runtime.finish(content=b"")
    assert len(changes) == 1 and len(runtime.inventory.assets) == 1
    assert runtime.inventory.import_history[-1].observation_count == 0
    assert runtime.inventory.import_history[-1].run_id == "subfinder:passive:synthetic-job-2"
    assert "0 discovered hostnames" in runtime.controller.status and "history" in runtime.controller.status.lower()


@pytest.mark.parametrize("changes", [
    {"state": JobState.FAILED}, {"state": JobState.CANCELLED}, {"state": JobState.TIMED_OUT},
    {"state": JobState.RUNNING}, {"state": "SUCCEEDED"}, {"exit_code": 1}, {"exit_code": None},
    {"exit_code": True}, {"stdout_truncated": True}, {"stderr_truncated": True},
    {"stdout_truncated": 0}, {"adapter_id": "subfinder.version-check"},
    {"adapter_id": "unknown"}, {"content": JSONL[:-1]}, {"content": JSONL + b"{\n"},
    {"content": b"not JSON\n"}, {"content": "not bytes"}, {"stderr": "not bytes"},
])
def test_failed_unexpected_or_incomplete_results_never_import(runtime, changes):
    runtime.ready()
    before = runtime.inventory.assets, runtime.inventory.observations, runtime.inventory.import_history
    runtime.start()
    runtime.finish(**changes)
    assert all(current is old for current, old in zip(
        (runtime.inventory.assets, runtime.inventory.observations, runtime.inventory.import_history), before))
    assert not runtime.controller.busy
    assert "succeeded" not in runtime.controller.status.lower()


@pytest.mark.parametrize("changes", [
    {"adapter_id": "subfinder.passive-standard"}, {"state": JobState.FAILED},
    {"stdout_truncated": True}, {"stderr": b"unexpected token=private"},
])
def test_verification_failure_never_enables_discovery_or_imports_results(runtime, changes):
    runtime.controller.approve_executable(runtime.candidate.executable_path, archive_path="release.zip")
    runtime.finish(verify=True, **changes)
    assert not runtime.controller.can_run and runtime.controller.executable_path == ""
    assert len(runtime.inventory.import_history) == 1
    assert "private" not in runtime.controller.status
    with pytest.raises(ValueError):
        runtime.start()


def test_foreign_or_non_snapshot_events_cannot_complete_an_active_discovery(runtime):
    runtime.ready()
    runtime.start()
    runtime.finish(job_id="unrelated-job")
    runtime.supervisor.job_finished.emit(SimpleNamespace(job_id="synthetic-job-2"))
    assert runtime.controller.busy and len(runtime.inventory.import_history) == 1
    runtime.finish()
    assert not runtime.controller.busy and len(runtime.inventory.import_history) == 2


def test_stop_is_idempotent_and_wins_over_late_success(runtime):
    runtime.ready()
    job_id = runtime.start()
    runtime.controller.stop()
    runtime.controller.stop()
    assert runtime.supervisor.cancelled == [job_id]
    runtime.finish()
    assert len(runtime.inventory.import_history) == 1
    assert "cancelled" in runtime.controller.status.lower()
    assert runtime.controller.can_run


def test_synchronous_cancel_does_not_restore_stopping_or_a_completed_job(runtime):
    runtime.ready()
    runtime.supervisor.finish_on_cancel = True
    runtime.start()
    runtime.controller.stop()
    assert not runtime.controller.busy and runtime.controller.can_run
    assert "cancelled" in runtime.controller.status.lower() and "stopping" not in runtime.controller.status.lower()
    assert len(runtime.inventory.import_history) == 1


def test_reentrant_stop_during_submit_cancels_without_reinstating_busy_state(runtime):
    runtime.ready()
    runtime.supervisor.finish_on_cancel = True
    runtime.supervisor.on_submit = lambda *_: runtime.controller.stop()
    job_id = runtime.start()
    assert runtime.supervisor.cancelled == [job_id]
    assert not runtime.controller.busy and runtime.controller.can_run
    assert len(runtime.inventory.import_history) == 1
    runtime.finish()
    assert len(runtime.inventory.import_history) == 1


def test_stop_during_preparation_cancels_the_job_before_it_can_start(runtime, monkeypatch):
    runtime.ready()
    runtime.supervisor.finish_on_cancel = True

    def prepare(*_args):
        runtime.controller.stop()
        return SimpleNamespace(adapter_id="subfinder.passive-standard")

    monkeypatch.setattr(runtime.module, "prepare_subfinder_discovery", prepare)
    job_id = runtime.start()
    assert runtime.supervisor.cancelled == [job_id]
    assert not runtime.controller.busy and len(runtime.inventory.import_history) == 1


def test_unexpected_progress_state_is_ignored_without_exposing_diagnostics(runtime):
    runtime.ready()
    runtime.start()
    status = runtime.controller.status
    runtime.controller._job_changed(JobSnapshot("synthetic-job-2", "subfinder.passive-standard",
                                               "RUNNING", b"", b"", diagnostic="token=private"))
    assert runtime.controller.status == status and runtime.controller.busy
    runtime.finish()


def test_shutdown_during_submit_and_late_success_never_import_or_enable_run(runtime):
    runtime.ready()
    runtime.supervisor.on_submit = lambda *_: runtime.controller.shutdown(immediate=True)
    runtime.start()
    assert runtime.controller.executable_path == runtime.tool.executable_path
    runtime.finish()
    assert True in runtime.supervisor.closed
    assert not runtime.controller.busy and not runtime.controller.can_run
    assert runtime.controller.executable_path == ""
    assert len(runtime.inventory.import_history) == 1
    with pytest.raises(ValueError):
        runtime.start()


def test_inventory_signal_reentrancy_cannot_overwrite_the_next_operation_status(runtime):
    runtime.ready()
    launched = []

    def next_run():
        if not launched:
            launched.append(runtime.start())

    runtime.controller.inventory_changed.connect(next_run)
    runtime.start()
    runtime.finish()
    assert launched == ["synthetic-job-3"]
    assert runtime.controller.busy and "queued" in runtime.controller.status.lower()
    runtime.finish()
    assert not runtime.controller.busy and len(runtime.inventory.import_history) == 3


def test_safety_hold_blocks_setup_and_runs_and_never_submits(runtime, monkeypatch):
    runtime.ready()
    monkeypatch.setattr(runtime.module, "process_safety_status", lambda: (False, "Containment unavailable."))
    assert not runtime.controller.can_run and "Containment" in runtime.controller.safety_reason
    with pytest.raises(ValueError):
        runtime.start()
    with pytest.raises(ValueError):
        runtime.controller.approve_executable("untrusted.exe", archive_path="untrusted.zip")
    assert len(runtime.supervisor.submitted) == 1 and "HOLD" in runtime.controller.status


def test_trust_rejection_exposes_safe_hold_reason_and_revokes_previous_tool(runtime, monkeypatch):
    runtime.ready()

    def reject(*_args, **_kwargs):
        raise ExecutionPolicyError("The selected executable does not match the pinned release checksum.")

    monkeypatch.setattr(runtime.module, "approve_subfinder_path", reject)
    with pytest.raises(ValueError, match="pinned release checksum"):
        runtime.controller.approve_executable("untrusted.exe", archive_path="untrusted.zip")
    assert "HOLD" in runtime.controller.status and "pinned release checksum" in runtime.controller.status
    assert not runtime.controller.busy and not runtime.controller.can_run


@pytest.mark.parametrize("stage", ["approve_subfinder_path", "prepare_subfinder_version_check"])
def test_configuration_or_startup_os_error_clears_pending_verification_safely(runtime, monkeypatch, stage):
    runtime.ready()

    def reject(*args, **kwargs):
        raise OSError("C:\\private\\temporary\\provider-config.yaml")

    monkeypatch.setattr(runtime.module, stage, reject)
    with pytest.raises(ValueError):
        runtime.controller.approve_executable(runtime.candidate.executable_path, archive_path="release.zip")
    assert not runtime.controller.busy and not runtime.controller.can_run
    assert runtime.controller.executable_path == "" and "private" not in runtime.controller.status


def test_idle_shutdown_releases_verified_tool(runtime):
    runtime.ready()
    runtime.controller.shutdown(immediate=True)
    assert runtime.controller.executable_path == "" and runtime.controller.version == ""
    assert not runtime.controller.can_run


@pytest.mark.parametrize("stage", ["approve_subfinder_path", "prepare_subfinder_version_check"])
def test_replacing_or_failed_setup_revokes_previous_tool_without_raw_errors(runtime, monkeypatch, stage):
    runtime.ready()

    def reject(*args, **kwargs):
        raise ValueError("C:\\private\\provider-config.yaml token=private")

    monkeypatch.setattr(runtime.module, stage, reject)
    with pytest.raises(ValueError):
        runtime.controller.approve_executable("bad.exe", archive_path="bad.zip")
    assert not runtime.controller.can_run and runtime.controller.executable_path == ""
    assert not runtime.controller.busy and "private" not in runtime.controller.status
    assert len(runtime.supervisor.submitted) == 1


@pytest.mark.parametrize("stage", ["prepare_subfinder_discovery", "submit", "import_batch"])
def test_preparation_submit_or_atomic_import_rejection_never_mutates_inventory(runtime, monkeypatch, stage):
    runtime.ready()
    before = runtime.inventory.assets, runtime.inventory.observations, runtime.inventory.import_history

    def reject(*args, **kwargs):
        raise ValueError("Raw exception token=private")

    target = runtime.module if stage == "prepare_subfinder_discovery" else (
        runtime.supervisor if stage == "submit" else runtime.inventory)
    monkeypatch.setattr(target, stage, reject)
    if stage == "import_batch":
        runtime.start()
        runtime.finish()
    else:
        with pytest.raises(ValueError):
            runtime.start()
    assert all(current is old for current, old in zip(
        (runtime.inventory.assets, runtime.inventory.observations, runtime.inventory.import_history), before))
    assert not runtime.controller.busy and "private" not in runtime.controller.status
