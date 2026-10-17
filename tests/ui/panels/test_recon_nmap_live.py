"""R5 UI actions require explicit path approval and per-run local authorization."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QFileDialog, QMessageBox, QPushButton


class PreflightDouble(QObject):
    changed = Signal()
    observation = None
    busy = is_fresh = False
    status = "Public target preflight required."
    warnings = ()

    def clear(self):
        self.changed.emit()


class RuntimeDouble(QObject):
    changed = Signal()
    inventory_changed = Signal()

    def __init__(self, inventory, parent=None):
        super().__init__(parent)
        self.public_preflight = PreflightDouble(self)
        self.inventory = inventory
        self.busy = False
        self.can_run = False
        self.status = "Setup required: choose and verify nmap.exe."
        self.executable_path = ""
        self.version = ""
        self.safety_reason = "Process safety not validated."
        self.approvals = []
        self.executions = []
        self.stops = 0
        self.shutdowns = []
        self.start_error = ""

    def approve_executable(self, path):
        self.approvals.append(path)
        self.busy = True
        self.can_run = False
        self.status = "Verifying selected Nmap executable…"
        self.changed.emit()

    def start_self_test(self, confirmed, target="127.0.0.1"):
        if self.start_error:
            raise self.start_error
        self.executions.append((confirmed, target))
        self.busy = True
        self.can_run = False
        self.status = "Running Local Self-Test on 127.0.0.1…"
        self.changed.emit()
        return "local-run-1"

    def stop(self):
        self.stops += 1
        self.status = "Cancelling Local Self-Test…"
        self.changed.emit()

    def shutdown(self, immediate=False):
        self.shutdowns.append(immediate)


@pytest.fixture
def recon(qapp, monkeypatch):
    from ui.panels import recon_tab

    # Process launches are external to the UI; core lifecycle tests cover them.
    monkeypatch.setattr(recon_tab, "NmapRuntime", RuntimeDouble, raising=False)
    panel = recon_tab.ReconTab()
    yield panel
    panel.close()
    panel.deleteLater()
    qapp.processEvents()


def ready(recon):
    runtime = recon.nmap_runtime
    runtime.can_run = True
    runtime.busy = False
    runtime.safety_reason = ""
    runtime.executable_path = "C:/Tools/Nmap/nmap.exe"
    runtime.version = "7.95"
    runtime.status = "Ready for confirmed Local Self-Test."
    runtime.changed.emit()
    return runtime


def test_initialization_has_gated_local_action_without_program_execution(recon):
    runtime = recon.nmap_runtime
    assert runtime.inventory is recon.asset_inventory
    assert runtime.approvals == runtime.executions == []
    assert recon.ui.reconPages.count() == 2
    assert not recon.ui.btnNmapSelfTest.isEnabled()
    assert not recon.ui.btnStopNmap.isEnabled()
    assert "not validated" in recon.ui.nmapExecutableLabel.text().lower()
    assert "Process safety not validated" in recon.ui.nmapAdapterLabel.text()
    assert "Setup required" in recon.ui.nmapStatusLabel.text()
    assert [button.text() for button in recon.ui.toolManager.findChildren(QPushButton)] == [
        "Refresh Detection", "Choose Subfinder…", "Choose official archive…",
        "Verify / approve executable", "Manage Scan Profiles…", "Public Target Preflight",
        "Use checked targets", "Review concrete scope", "Inspect capabilities", "Choose Nmap…",
        "Local Self-Test", "Stop", "Public Scan", "Run Selected Profile…", "Run Authorized Profile…",
        "Run Passive Discovery", "Stop Subfinder", "Open results / evidence", "Run / Import History",
    ]


def test_path_choice_explicitly_starts_verification_and_disables_run(recon, monkeypatch):
    chosen = "C:/Tools/Nmap/nmap.exe"
    prompts = []

    def pick(parent, title, initial, file_filter):
        prompts.append((parent, title, initial, file_filter))
        return chosen, file_filter

    monkeypatch.setattr(QFileDialog, "getOpenFileName", pick)
    recon.ui.btnChooseNmap.click()
    assert prompts[0][0] is recon and "Nmap" in prompts[0][1]
    assert "nmap.exe" in prompts[0][3]
    assert recon.nmap_runtime.approvals == [chosen]
    assert recon.nmap_runtime.executions == []
    assert "Verifying" in recon.ui.nmapStatusLabel.text()
    assert not recon.ui.btnChooseNmap.isEnabled()
    assert not recon.ui.btnNmapSelfTest.isEnabled()
    assert recon.ui.btnStopNmap.isEnabled()


def test_cancelled_path_choice_does_not_approve_or_execute(recon, monkeypatch):
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: ("", ""))
    recon.ui.btnChooseNmap.click()
    assert recon.nmap_runtime.approvals == recon.nmap_runtime.executions == []
    assert not recon.ui.btnNmapSelfTest.isEnabled()


def test_discovered_candidate_only_suggests_picker_path_without_approval(recon, monkeypatch):
    chosen = "C:/Tools/Nmap/nmap.exe"
    record = SimpleNamespace(
        tool_id="nmap", display_name="Nmap", executable_path=chosen,
        status=SimpleNamespace(name="CANDIDATE_UNVERIFIED"), diagnostic="Candidate is unverified.",
    )
    recon.tool_discovery = SimpleNamespace(discover=lambda: (record,))
    recon.ui.btnRefreshDetection.click()
    assert recon.nmap_runtime.approvals == recon.nmap_runtime.executions == []
    assert not recon.ui.btnNmapSelfTest.isEnabled()
    suggestions = []
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args:
                        suggestions.append(args[2]) or ("", ""))
    recon.ui.btnChooseNmap.click()
    assert suggestions == [chosen]
    assert recon.nmap_runtime.approvals == []


def test_validated_runtime_enables_only_fixed_local_profile(recon):
    ready(recon)
    assert recon.ui.btnNmapSelfTest.isEnabled()
    assert not recon.ui.btnStopNmap.isEnabled()
    assert "C:/Tools/Nmap/nmap.exe" in recon.ui.nmapExecutableLabel.text()
    assert "7.95" in recon.ui.nmapVersionLabel.text()
    assert "available" in recon.ui.nmapAdapterLabel.text().lower()
    assert "local self-test" in recon.ui.nmapAdapterLabel.text().lower()
    assert "quick network discovery" in recon.ui.nmapAdapterLabel.text().lower()


def test_confirmation_is_explicit_and_decline_prevents_execution(recon, monkeypatch):
    runtime = ready(recon)
    prompts = []

    def decline(*args):
        prompts.append(args)
        return QMessageBox.No

    monkeypatch.setattr(QMessageBox, "question", decline)
    recon.ui.btnNmapSelfTest.click()
    assert runtime.executions == []
    assert prompts and prompts[0][-1] == QMessageBox.No
    text = prompts[0][2]
    for detail in ("127.0.0.1", "80, 443, 8080, 8443", "TCP connect",
                   "local TCP connections", "No external targets"):
        assert detail in text


def test_each_run_requires_confirmation_and_does_not_authorize_imported_targets(recon, monkeypatch):
    runtime = ready(recon)
    recon.ui.manualInput.setText("external.example.test")
    recon.ui.btnAddTarget.click()
    recon.ui.btnSelectAll.click()
    prompts = []
    monkeypatch.setattr(QMessageBox, "question", lambda *args:
                        prompts.append(args) or QMessageBox.Yes)
    recon.ui.btnNmapSelfTest.click()
    assert runtime.executions == [(True, "127.0.0.1")]
    assert not recon.ui.btnNmapSelfTest.isEnabled()
    assert recon.ui.btnStopNmap.isEnabled()
    assert recon.target_model.data(recon.target_model.index(0, recon.target_model.SCOPE)) == "Unreviewed"
    ready(recon)
    recon.ui.btnNmapSelfTest.click()
    assert len(prompts) == len(runtime.executions) == 2


def test_stop_is_available_during_work_and_reports_cancellation(recon):
    runtime = recon.nmap_runtime
    runtime.busy = True
    runtime.changed.emit()
    recon.ui.btnStopNmap.click()
    assert runtime.stops == 1
    assert "Cancelling" in recon.ui.nmapStatusLabel.text()


@pytest.mark.parametrize("status", [
    "Success: 0 open ports; imported 1 observation.",
    "Failed: Nmap exited with code 1.",
    "Timed out: Local Self-Test exceeded the overall deadline.",
    "Cancelled: Local Self-Test stopped.",
])
def test_terminal_states_are_visible_without_fabricated_progress(recon, status):
    runtime = recon.nmap_runtime
    runtime.status = status
    runtime.busy = False
    runtime.changed.emit()
    assert recon.ui.nmapStatusLabel.text() == status
    assert not recon.ui.btnStopNmap.isEnabled()
    assert "%" not in recon.ui.nmapStatusLabel.text()


@pytest.mark.parametrize("error_type", [ValueError, RuntimeError])
def test_runtime_rejection_is_shown_without_execution(recon, monkeypatch, error_type):
    runtime = ready(recon)
    runtime.start_error = error_type("Executable changed; choose and verify Nmap again.")
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.Yes)
    recon.ui.btnNmapSelfTest.click()
    assert runtime.executions == []
    assert "Executable changed" in recon.ui.nmapStatusLabel.text()


def test_live_inventory_signal_refreshes_existing_asset_table_and_history(recon):
    fixture = Path(__file__).parents[2] / "fixtures" / "nmap" / "recon.xml"
    recon.asset_inventory.import_nmap_file(fixture)
    assert recon.asset_model.rowCount() == 0
    recon.nmap_runtime.inventory_changed.emit()
    assert recon.asset_model.rowCount() == len(recon.asset_inventory.assets) > 0
    assert recon.ui.importHistory.count() == 2
    assert recon.ui.sourceFilter.findData("nmap") > 0
    assert recon.ui.importHistory.currentData() == ""


def test_closing_panel_requests_contained_process_cleanup(recon):
    runtime = recon.nmap_runtime
    recon.close()
    assert runtime.shutdowns == [True]
