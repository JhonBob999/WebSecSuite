"""Controller boundaries: fake process results, real atomic inventory imports."""

import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QObject, Signal

from core.recon.inventory import AssetInventory
from core.recon.observations import ObservationImportError
from core.recon.process_supervisor import JobSnapshot, JobState


XML = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.95" start="1735689600">
<scaninfo type="connect" protocol="tcp" numservices="4" services="80,443,8080,8443"/>
<host><status state="up" reason="user-set"/>
<address addr="127.0.0.1" addrtype="ipv4"/><hostnames/>
<ports><port protocol="tcp" portid="8080"><state state="open"/>
<service name="http-proxy" method="table" conf="3"/></port>
<extraports state="closed" count="3"/></ports></host>
<runstats><finished time="1735689601" exit="success"/>
<hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


class ControlledSupervisor(QObject):
    job_changed = Signal(object)
    job_finished = Signal(object)

    def __init__(self):
        super().__init__()
        self.submitted = []
        self.cancelled = []
        self.closed = []

    def submit(self, spec):
        self.submitted.append(spec)
        return str(len(self.submitted))

    def cancel(self, job_id):
        self.cancelled.append(job_id)

    def shutdown(self, *, immediate=False):
        self.closed.append(immediate)


@pytest.fixture
def runtime(monkeypatch, qapp):
    module = importlib.import_module("core.recon.nmap_runtime")
    supervisor = ControlledSupervisor()
    tool = SimpleNamespace(executable_path=r"C:\Nmap\nmap.exe", version="7.95", sha256="a" * 64)
    monkeypatch.setattr(module, "ProcessSupervisor", lambda: supervisor)
    monkeypatch.setattr(module, "process_safety_status", lambda: (True, "Windows tree containment available."))
    monkeypatch.setattr(module, "approve_nmap_path", lambda path, confirmed: tool)
    monkeypatch.setattr(module, "prepare_nmap_version_check", lambda candidate: "verify-spec")
    monkeypatch.setattr(module, "verify_nmap_version", lambda candidate, result: tool)
    monkeypatch.setattr(module, "prepare_nmap_self_test", lambda verified, **kwargs: "scan-spec")
    inventory = AssetInventory()
    fixture = Path(__file__).parents[2] / "fixtures" / "recon_observations_v1.json"
    inventory.import_file(fixture)
    controller = module.NmapRuntime(inventory)

    def finish(state=JobState.SUCCEEDED, content=XML, *, truncated=False, code=0, verify=False):
        adapter = "nmap.version-check" if verify else "nmap.local-self-test"
        snapshot = JobSnapshot(str(len(supervisor.submitted)), adapter, state, content, b"",
                               truncated, False, code, "Controlled result.")
        supervisor.job_finished.emit(snapshot)
        return snapshot

    def ready():
        controller.approve_executable(tool.executable_path)
        finish(content=b"Nmap version 7.95 ( https://nmap.org )\n", verify=True)
        assert controller.can_run

    yield SimpleNamespace(module=module, controller=controller, supervisor=supervisor,
                          inventory=inventory, finish=finish, ready=ready, tool=tool)
    controller.shutdown(immediate=True)
    controller.deleteLater()
    qapp.processEvents()


def test_initialization_and_discovery_do_not_launch_a_process(runtime):
    assert not runtime.supervisor.submitted
    assert not runtime.controller.busy
    assert not runtime.controller.can_run
    assert not runtime.controller.executable_path


def test_verification_is_separate_from_scan_and_exposes_only_validated_path(runtime):
    runtime.controller.approve_executable(runtime.tool.executable_path)
    assert runtime.supervisor.submitted == ["verify-spec"]
    assert runtime.controller.busy
    assert not runtime.controller.can_run
    assert not runtime.controller.executable_path
    runtime.finish(content=b"Nmap version 7.95 ( https://nmap.org )\n", verify=True)
    assert runtime.controller.version == "7.95"
    assert runtime.controller.executable_path == runtime.tool.executable_path
    assert runtime.controller.can_run
    assert len(runtime.inventory.import_history) == 1


@pytest.mark.parametrize("target,confirmed", [("127.0.0.1", False), ("example.com", True),
                                             ("127.0.0.2", True), ("127.0.0.1/32", True)])
def test_each_run_requires_confirmation_and_exact_loopback(runtime, target, confirmed):
    runtime.ready()
    with pytest.raises(ValueError):
        runtime.controller.start_self_test(confirmed=confirmed, target=target)
    assert runtime.supervisor.submitted == ["verify-spec"]


def test_success_merges_assets_and_history_once_with_nmap_provenance(runtime):
    runtime.ready()
    before = runtime.inventory.observations
    changes = []
    runtime.controller.inventory_changed.connect(lambda: changes.append(True))
    runtime.controller.start_self_test(confirmed=True)
    result = runtime.finish()
    runtime.supervisor.job_finished.emit(result)
    assert all(item in runtime.inventory.observations for item in before)
    assert len(runtime.inventory.import_history) == 2
    assert len(changes) == 1
    entry = runtime.inventory.import_history[-1]
    assert entry.format_name == "Nmap live XML"
    assert "Local Self-Test" in entry.label
    assert entry.run_id.startswith("nmap:sha256:")
    asset = next(asset for asset in runtime.inventory.assets if asset.port == 8080)
    assert asset.value == "127.0.0.1"
    assert asset.sources == ("nmap",)
    assert "1 open" in runtime.controller.status.lower()
    assert runtime.controller.can_run
    runtime.controller.start_self_test(confirmed=True)
    runtime.finish()
    assert len(runtime.inventory.import_history) == 2


def test_zero_open_ports_is_a_successful_recorded_run(runtime):
    runtime.ready()
    runtime.controller.start_self_test(confirmed=True)
    content = XML.replace(b'state="open"', b'state="closed"')
    runtime.finish(content=content)
    assert "0 open" in runtime.controller.status.lower()
    assert len(runtime.inventory.import_history) == 2
    assert runtime.inventory.import_history[-1].asset_count == 1


@pytest.mark.parametrize("state,truncated,content", [
    (JobState.FAILED, False, XML), (JobState.CANCELLED, False, XML),
    (JobState.TIMED_OUT, False, XML), (JobState.SUCCEEDED, True, XML),
    (JobState.SUCCEEDED, False, b"<nmaprun><host>"),
    (JobState.SUCCEEDED, False, XML.replace(b'exit="success"', b'exit="error"')),
])
def test_failed_execution_or_xml_preserves_inventory_and_history(runtime, state, truncated, content):
    runtime.ready()
    before = (runtime.inventory.assets, runtime.inventory.observations, runtime.inventory.import_history)
    runtime.controller.start_self_test(confirmed=True)
    runtime.finish(state, content, truncated=truncated, code=0 if state == JobState.SUCCEEDED else 1)
    assert (runtime.inventory.assets, runtime.inventory.observations, runtime.inventory.import_history) == before
    assert not runtime.controller.busy
    assert "succeeded" not in runtime.controller.status.lower()


def test_containment_failure_disables_setup_and_scan(runtime, monkeypatch):
    runtime.ready()
    monkeypatch.setattr(runtime.module, "process_safety_status", lambda: (False, "Containment unavailable."))
    assert not runtime.controller.can_run
    with pytest.raises(ValueError, match="Containment"):
        runtime.controller.start_self_test(confirmed=True)
    with pytest.raises(ValueError, match="Containment"):
        runtime.controller.approve_executable(runtime.tool.executable_path)
    assert runtime.supervisor.submitted == ["verify-spec"]


def test_replacing_executable_clears_previous_verification(runtime, monkeypatch):
    runtime.ready()

    def invalid(*args, **kwargs):
        raise ValueError("Invalid Nmap executable.")

    monkeypatch.setattr(runtime.module, "approve_nmap_path", invalid)
    with pytest.raises(ValueError):
        runtime.controller.approve_executable("invalid.exe")
    assert not runtime.controller.can_run
    assert not runtime.controller.executable_path


def test_stop_and_shutdown_never_import_the_active_result(runtime):
    runtime.ready()
    job_id = runtime.controller.start_self_test(confirmed=True)
    with pytest.raises(ValueError):
        runtime.controller.start_self_test(confirmed=True)
    runtime.controller.stop()
    assert runtime.supervisor.cancelled == [job_id]
    runtime.controller.shutdown(immediate=True)
    runtime.finish()
    assert len(runtime.inventory.import_history) == 1
    assert not runtime.controller.can_run


def test_atomic_import_rejection_is_reported_without_partial_mutation(runtime, monkeypatch):
    runtime.ready()
    before = runtime.inventory.assets, runtime.inventory.import_history

    def reject(*args, **kwargs):
        raise ObservationImportError("Controlled atomic import rejection.")

    monkeypatch.setattr(runtime.inventory, "import_batch", reject)
    runtime.controller.start_self_test(confirmed=True)
    runtime.finish()
    assert (runtime.inventory.assets, runtime.inventory.import_history) == before
    assert "failed" in runtime.controller.status.lower()


def test_unverified_or_unsuccessful_probe_cannot_enable_scan(runtime):
    runtime.controller.approve_executable(runtime.tool.executable_path)
    runtime.finish(JobState.FAILED, b"Nmap version 7.95", code=9, verify=True)
    assert not runtime.controller.can_run
    assert not runtime.controller.executable_path
    with pytest.raises(ValueError):
        runtime.controller.start_self_test(confirmed=True)
