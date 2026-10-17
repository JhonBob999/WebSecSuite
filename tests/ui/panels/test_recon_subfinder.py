"""Subfinder controls use mocked local setup and fresh per-run confirmation."""

import os
from pathlib import Path
import sys

import pytest
from PySide6.QtCore import QObject, QPoint, QRect, Qt, Signal
from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QFileDialog, QMessageBox

from core.recon.execution_policy import ScopeApproval


class RuntimeDouble(QObject):
    changed = Signal()
    inventory_changed = Signal()

    def __init__(self, inventory, parent=None):
        super().__init__(parent)
        self.busy = self.can_run = False
        self.executable_path = self.version = ""
        self.status = "Choose and verify Subfinder first."
        self.safety_reason = "Process containment not verified."
        self.approvals = []
        self.executions = []
        self.stops = 0
        self.shutdowns = []
        self.start_error = None

    def approve_executable(self, path, *, archive_path):
        self.approvals.append((path, archive_path))
        self.busy = True
        self.status = "Verifying local release and version…"
        self.changed.emit()

    def start_discovery(self, selected_targets, *, confirmed, approval):
        if self.start_error:
            raise self.start_error
        self.executions.append((selected_targets, confirmed, approval))
        self.busy = True
        self.status = "Passive discovery running."
        self.changed.emit()
        return "subfinder-run-1"

    def stop(self):
        self.stops += 1
        self.status = "Stopping Subfinder…"
        self.changed.emit()

    def shutdown(self, immediate=False):
        self.shutdowns.append(immediate)


@pytest.fixture(scope="module", autouse=True)
def windows_offscreen_fonts(qapp):
    original_font = qapp.font()
    font_ids = []
    if sys.platform == "win32" and not QFontDatabase.families():
        font_dir = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
        for filename in ("segoeui.ttf", "segoeuib.ttf"):
            font_id = QFontDatabase.addApplicationFont(str(font_dir / filename))
            if font_id >= 0:
                font_ids.append(font_id)
        if font_ids:
            qapp.setFont(QFont("Segoe UI", 9))
    yield
    if font_ids:
        qapp.setFont(original_font)
        for font_id in font_ids:
            QFontDatabase.removeApplicationFont(font_id)


@pytest.fixture
def recon(qapp, monkeypatch):
    from ui.panels import recon_tab

    monkeypatch.setattr(recon_tab, "SubfinderRuntime", RuntimeDouble)
    monkeypatch.setattr(recon_tab.ToolDiscoveryService, "discover", lambda _self: ())
    panel = recon_tab.ReconTab()
    panel.resize(1366, 768)
    panel.show()
    panel.ui.toolSelector.setCurrentIndex(panel.ui.toolSelector.findData("subfinder"))
    qapp.processEvents()
    yield panel
    panel.close()
    panel.deleteLater()
    qapp.processEvents()


def select_target(recon, hostname="example.test"):
    recon.ui.manualInput.setText(hostname)
    recon.ui.btnAddTarget.click()
    row = recon.target_model.rowCount() - 1
    recon.target_model.setData(recon.target_model.index(row, 0), Qt.Checked, Qt.CheckStateRole)
    return row


def ready(recon):
    runtime = recon.subfinder_runtime
    runtime.executable_path = "C:/Tools/Subfinder/subfinder.exe"
    runtime.version = "2.17.0"
    runtime.can_run = True
    runtime.safety_reason = ""
    runtime.changed.emit()
    return runtime


def choose_setup(recon, monkeypatch, tmp_path):
    executable = str(tmp_path / "subfinder.exe")
    archive = str(tmp_path / "subfinder_2.17.0_windows_amd64.zip")
    paths = iter((executable, archive))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: (next(paths), ""))
    recon.ui.btnChooseSubfinder.click()
    recon.ui.btnChooseSubfinderArchive.click()
    return executable, archive


def test_setup_and_discovery_start_disabled_without_explicit_actions(recon):
    ui, runtime = recon.ui, recon.subfinder_runtime
    assert ui.btnChooseSubfinder.isVisible()
    assert ui.btnChooseSubfinderArchive.isVisible()
    assert not ui.btnApproveSubfinder.isEnabled()
    assert not ui.btnRunSubfinder.isEnabled()
    assert not ui.btnStopSubfinder.isEnabled()
    select_target(recon)
    assert not ui.btnRunSubfinder.isEnabled()
    assert runtime.approvals == runtime.executions == []
    assert "2.17.0" in ui.toolInfo.labels["installation"].text()
    assert "third-party" in ui.toolInfo.labels["network"].text()


def test_setup_pickers_cancel_and_do_not_run_candidate(recon, monkeypatch, tmp_path):
    ui, runtime = recon.ui, recon.subfinder_runtime
    before = ui.subfinderExecutableLabel.text(), ui.subfinderArchiveLabel.text()
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: ("", ""))
    ui.btnChooseSubfinder.click()
    ui.btnChooseSubfinderArchive.click()
    assert (ui.subfinderExecutableLabel.text(), ui.subfinderArchiveLabel.text()) == before
    executable, archive = choose_setup(recon, monkeypatch, tmp_path)
    assert executable in ui.subfinderExecutableLabel.text()
    assert archive in ui.subfinderArchiveLabel.text()
    assert ui.btnApproveSubfinder.isEnabled()
    assert runtime.approvals == runtime.executions == []


def test_executable_approval_is_explicit_default_no_and_checks_both_paths(
    recon, monkeypatch, tmp_path,
):
    paths = choose_setup(recon, monkeypatch, tmp_path)
    prompts = []
    monkeypatch.setattr(QMessageBox, "question", lambda *args:
                        prompts.append(args) or QMessageBox.No)
    recon.ui.btnApproveSubfinder.click()
    assert recon.subfinder_runtime.approvals == []
    assert prompts[-1][-1] == QMessageBox.No
    for detail in (*paths, "2.17.0", "SHA-256", "official", "version"):
        assert detail in prompts[-1][2]
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.Yes)
    recon.ui.btnApproveSubfinder.click()
    assert recon.subfinder_runtime.approvals == [paths]
    assert recon.subfinder_runtime.executions == []
    assert not recon.ui.btnChooseSubfinder.isEnabled()
    assert not recon.ui.btnApproveSubfinder.isEnabled()
    assert recon.ui.btnStopSubfinder.isEnabled()


def test_setup_state_change_during_confirmation_invalidates_approval(recon, monkeypatch, tmp_path):
    choose_setup(recon, monkeypatch, tmp_path)

    def changed(*args):
        recon.subfinder_runtime.busy = True
        recon.subfinder_runtime.changed.emit()
        recon.subfinder_runtime.busy = False
        recon.subfinder_runtime.changed.emit()
        return QMessageBox.Yes

    monkeypatch.setattr(QMessageBox, "question", changed)
    recon.ui.btnApproveSubfinder.click()
    assert recon.subfinder_runtime.approvals == []
    assert "changed" in recon.ui.subfinderStatusLabel.text().lower()


def test_archive_change_during_setup_confirmation_requires_new_review(recon, monkeypatch, tmp_path):
    choose_setup(recon, monkeypatch, tmp_path)
    replacement = str(tmp_path / "subfinder_2.17.0_windows_arm64.zip")

    def changed(*args):
        monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: (replacement, ""))
        recon.subfinder_controls._choose_archive()
        return QMessageBox.Yes

    monkeypatch.setattr(QMessageBox, "question", changed)
    recon.ui.btnApproveSubfinder.click()
    assert replacement in recon.ui.subfinderArchiveLabel.text()
    assert recon.subfinder_runtime.approvals == []
    assert "changed" in recon.ui.subfinderStatusLabel.text().lower()


def test_setup_rejects_relative_file_choices_without_approval(recon, monkeypatch):
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: ("subfinder.exe", ""))
    recon.ui.btnChooseSubfinder.click()
    assert "absolute local" in recon.ui.subfinderStatusLabel.text()
    assert not recon.ui.btnApproveSubfinder.isEnabled()
    assert recon.subfinder_runtime.approvals == []


@pytest.mark.parametrize("archive", [False, True])
def test_changing_setup_disables_prior_verified_tool_until_new_verification(
    recon, monkeypatch, tmp_path, archive,
):
    runtime = ready(recon)
    select_target(recon)
    assert recon.ui.btnRunSubfinder.isEnabled()
    executable, zip_path = choose_setup(recon, monkeypatch, tmp_path)
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.Yes)
    recon.ui.btnApproveSubfinder.click()
    runtime.busy = False
    runtime.executable_path = executable
    runtime.changed.emit()
    assert recon.ui.btnRunSubfinder.isEnabled()
    replacement = str(tmp_path / ("replacement.zip" if archive else "replacement.exe"))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: (replacement, ""))
    (recon.ui.btnChooseSubfinderArchive if archive else recon.ui.btnChooseSubfinder).click()
    assert runtime.can_run
    assert not recon.ui.btnRunSubfinder.isEnabled()
    recon.subfinder_controls._confirm_discovery()
    assert runtime.executions == []
    recon.ui.btnApproveSubfinder.click()
    runtime.busy = False
    runtime.executable_path = executable if archive else replacement
    runtime.changed.emit()
    assert recon.ui.btnRunSubfinder.isEnabled()


def test_run_requires_one_checked_valid_target_and_preserves_target_scope(recon):
    ready(recon)
    assert not recon.ui.btnRunSubfinder.isEnabled()
    select_target(recon, "EXAMPLE.TEST")
    assert recon.ui.btnRunSubfinder.isEnabled()
    select_target(recon, "other.test")
    assert not recon.ui.btnRunSubfinder.isEnabled()
    recon.target_model.setData(recon.target_model.index(1, 0), Qt.Unchecked, Qt.CheckStateRole)
    recon.ui.targetTable.selectRow(1)
    assert recon.ui.btnRunSubfinder.isEnabled()
    recon.target_model.setData(recon.target_model.index(0, 1), "https://bad.test")
    assert not recon.ui.btnRunSubfinder.isEnabled()
    assert recon.subfinder_runtime.executions == []
    assert recon.target_model.index(1, recon.target_model.SCOPE).data() == "Unreviewed"


def test_checked_invalid_row_is_not_ignored_when_counting_selected_targets(recon):
    ready(recon)
    select_target(recon)
    select_target(recon, "other.test")
    # Defensive boundary for model state restored or mutated outside setData().
    recon.target_model._targets[1].validation_state = "Invalid: stale imported state"
    recon.target_model.inventoryChanged.emit()
    assert not recon.ui.btnRunSubfinder.isEnabled()
    recon.target_model._targets[0].selected = False
    recon.target_model.inventoryChanged.emit()
    assert not recon.ui.btnRunSubfinder.isEnabled()


def test_run_confirmation_is_default_no_and_describes_passive_network_limits(recon, monkeypatch):
    runtime = ready(recon)
    select_target(recon)
    prompts = []
    monkeypatch.setattr(QMessageBox, "question", lambda *args:
                        prompts.append(args) or QMessageBox.No)
    recon.ui.btnRunSubfinder.click()
    assert runtime.executions == []
    assert prompts[-1][-1] == QMessageBox.No
    for detail in ("example.test", "third-party", "logged", "-rl 2", "-timeout 15",
                   "-max-time 2", "150", "passive", "scope"):
        assert detail in prompts[-1][2]


def test_yes_constructs_fresh_exact_domain_grant_for_each_attempt(recon, monkeypatch):
    runtime = ready(recon)
    select_target(recon)
    recon.subfinder_controls.scope_approval = ScopeApproval(
        exact_domains=("unrelated.test",), subdomain_ranges=("unrelated.test",),
        excluded_domains=("excluded.test",),
    )
    prompts = []
    monkeypatch.setattr(QMessageBox, "question", lambda *args:
                        prompts.append(args) or QMessageBox.Yes)
    recon.ui.btnRunSubfinder.click()
    selected, confirmed, grant = runtime.executions[0]
    assert selected == ("example.test",)
    assert confirmed is True
    assert grant.exact_domains == ("example.test",)
    assert grant.subdomain_ranges == ()
    assert grant.excluded_domains == ("excluded.test",)
    assert recon.subfinder_controls.scope_approval.exact_domains == ("unrelated.test",)
    assert not recon.ui.btnRunSubfinder.isEnabled()
    runtime.busy = False
    runtime.changed.emit()
    recon.ui.btnRunSubfinder.click()
    assert len(prompts) == len(runtime.executions) == 2
    assert runtime.executions[1][2] is not grant
    assert recon.target_model.index(0, recon.target_model.SCOPE).data() == "Unreviewed"


@pytest.mark.parametrize("exclusions", [
    {"excluded_domains": ("api.example.test",)},
    {"excluded_subdomain_ranges": ("example.test",)},
])
def test_exclusions_override_selection_and_any_cached_scope(recon, monkeypatch, exclusions):
    ready(recon)
    select_target(recon, "api.example.test")
    recon.subfinder_controls.scope_approval = ScopeApproval(exact_domains=("api.example.test",), **exclusions)
    recon.subfinder_controls.refresh_runtime()
    prompts = []
    monkeypatch.setattr(QMessageBox, "question", lambda *args:
                        prompts.append(args) or QMessageBox.Yes)
    assert not recon.ui.btnRunSubfinder.isEnabled()
    recon.subfinder_controls._confirm_discovery()
    assert "excluded" in recon.ui.subfinderTargetLabel.text().lower()
    assert prompts == recon.subfinder_runtime.executions == []


@pytest.mark.parametrize("change", [
    "selection", "selection_roundtrip", "path", "version", "busy_roundtrip", "exclusion", "scope_roundtrip",
])
def test_modal_changes_invalidate_per_run_confirmation(recon, monkeypatch, change):
    runtime = ready(recon)
    select_target(recon)

    def changed(*args):
        if change.startswith("selection"):
            recon.target_model.set_all_selected(False)
            if change == "selection_roundtrip":
                recon.target_model.set_all_selected(True)
        elif change in ("exclusion", "scope_roundtrip"):
            recon.subfinder_controls.scope_approval = ScopeApproval(excluded_domains=("example.test",))
            if change == "scope_roundtrip":
                recon.subfinder_controls.scope_approval = ScopeApproval()
        else:
            if change == "path":
                runtime.executable_path = "C:/Other/subfinder.exe"
            elif change == "version":
                runtime.version = "2.17.1"
            else:
                runtime.busy = True
            runtime.changed.emit()
            if change == "busy_roundtrip":
                runtime.busy = False
                runtime.changed.emit()
        return QMessageBox.Yes

    monkeypatch.setattr(QMessageBox, "question", changed)
    recon.ui.btnRunSubfinder.click()
    assert runtime.executions == []
    assert "changed" in recon.ui.subfinderStatusLabel.text().lower()


def test_runtime_rejection_is_readable_and_stop_and_close_reach_runtime(recon, monkeypatch):
    runtime = ready(recon)
    select_target(recon)
    runtime.start_error = ValueError("Executable changed; verify again.")
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.Yes)
    recon.ui.btnRunSubfinder.click()
    assert runtime.executions == []
    assert "Executable changed" in recon.ui.subfinderStatusLabel.text()
    runtime.busy = True
    runtime.status = "Passive discovery running."
    runtime.changed.emit()
    recon.ui.btnStopSubfinder.click()
    assert runtime.stops == 1
    assert "Stopping" in recon.ui.subfinderStatusLabel.text()
    recon.close()
    assert runtime.shutdowns == [True]


def test_nmap_scope_and_tool_switches_do_not_authorize_subfinder(recon, monkeypatch):
    ready(recon)
    select_target(recon, "ginandjuice.shop")
    recon.ui.nmapPublicScope.setChecked(True)
    for tool in ("nmap", "httpx", "ffuf", "subfinder"):
        recon.ui.toolSelector.setCurrentIndex(recon.ui.toolSelector.findData(tool))
        assert recon.ui.subfinderInstallation.isVisible() == (tool == "subfinder")
        assert recon.ui.subfinderExecution.isVisible() == (tool == "subfinder")
        assert recon.ui.subfinderResults.isVisible() == (tool == "subfinder")
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.No)
    recon.ui.btnRunSubfinder.click()
    assert recon.subfinder_runtime.approvals == recon.subfinder_runtime.executions == []
    assert recon.subfinder_controls.scope_approval == ScopeApproval()
    for tool in ("httpx", "ffuf"):
        recon.ui.toolSelector.setCurrentIndex(recon.ui.toolSelector.findData(tool))
        assert "Execution disabled" in recon.ui.toolInfo.labels["execution"].text()


def test_runtime_import_signal_populates_shared_assets_sources_and_history(recon):
    from core.recon.process_supervisor import JobSnapshot, JobState
    from core.recon.subfinder_output import parse_subfinder_output

    select_target(recon)
    result = JobSnapshot(
        "ui-subfinder-job", "subfinder.passive-standard", JobState.SUCCEEDED,
        b'{"host":"api.example.test","input":"example.test","sources":["crtsh"]}\n',
        b"", exit_code=0,
    )
    batch = parse_subfinder_output(result, root_domain="example.test", run_id="ui-subfinder-run")
    recon.asset_inventory.import_batch(batch, label="Subfinder", format_name="Subfinder")
    assert recon.asset_model.rowCount() == 0
    recon.subfinder_runtime.inventory_changed.emit()
    assert recon.asset_model.rowCount() == 1
    assert recon.ui.sourceFilter.findData("subfinder") > 0
    assert recon.ui.importHistory.count() == 2
    assert "Subfinder" in recon.ui.importHistory.itemText(1)
    asset = recon.asset_model.asset_at(0)
    assert asset.value == "api.example.test"
    assert asset.observations[0].evidence
    recon.ui.btnSubfinderHistory.click()
    assert recon.ui.reconPages.currentIndex() == 1
    recon.ui.importHistory.setCurrentIndex(1)
    assert recon.asset_proxy.rowCount() == 1
    assert recon.target_model.index(0, recon.target_model.SCOPE).data() == "Unreviewed"


def test_narrow_scroll_hide_show_and_result_handoff_keep_runtime(recon, qapp):
    runtime = ready(recon)
    runtime.executable_path = "C:/Tools/" + "LongSubfinderDirectory" * 16 + "/subfinder.exe"
    runtime.status = "Completed: 3 names, 3 assets, 1 duplicate. " + "LongResultDetail" * 12
    runtime.changed.emit()
    recon.ui.reconSplitter.moveSplitter(recon.ui.reconSplitter.width() - 206, 1)
    qapp.processEvents()
    ui, scroll = recon.ui, recon.ui.toolInspectorScroll
    assert not scroll.horizontalScrollBar().isVisible()
    for label in (ui.subfinderExecutableLabel, ui.subfinderArchiveLabel, ui.subfinderVersionLabel,
                  ui.subfinderAdapterLabel, ui.subfinderTargetLabel, ui.subfinderStatusLabel,
                  ui.subfinderResultLabel):
        assert label.textFormat() == Qt.PlainText
        assert label.wordWrap()
        assert label.height() >= label.heightForWidth(label.width())
    for action in (ui.btnChooseSubfinder, ui.btnChooseSubfinderArchive, ui.btnApproveSubfinder,
                   ui.btnRunSubfinder, ui.btnStopSubfinder, ui.btnSubfinderHistory):
        scroll.ensureWidgetVisible(action)
        qapp.processEvents()
        rectangle = QRect(action.mapTo(scroll.viewport(), QPoint()), action.size())
        assert scroll.viewport().rect().contains(rectangle)
    width = ui.reconSplitter.sizes()[1]
    ui.btnToolInspectorToggle.click()
    ui.btnToolInspectorToggle.click()
    qapp.processEvents()
    assert abs(ui.reconSplitter.sizes()[1] - width) <= 3
    assert recon.subfinder_runtime is runtime
    assert runtime.status in ui.subfinderResultLabel.text()
    ui.btnSubfinderHistory.click()
    assert ui.reconPages.currentIndex() == 1
    assert ui.importHistory.hasFocus()
    assert runtime.approvals == runtime.executions == []
