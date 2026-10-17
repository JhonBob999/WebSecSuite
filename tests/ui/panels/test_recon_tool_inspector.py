"""UI-only Recon inspector and rejected-import review stay offline."""

import os
from pathlib import Path
import sys
from time import monotonic

import pytest
from PySide6.QtCore import QObject, QPoint, QRect, Qt, Signal
from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QComboBox, QFileDialog, QMessageBox, QScrollArea, QSplitter

from core.recon.tool_discovery import ToolDiscoveryRecord, ToolDiscoveryStatus


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
        self.busy = self.can_run = False
        self.status = "Setup required: choose and verify nmap.exe."
        self.executable_path = self.version = ""
        self.safety_reason = "Process safety not validated."
        self.approvals = []
        self.executions = []
        self.stops = 0

    def approve_executable(self, path):
        self.approvals.append(path)

    def start_self_test(self, confirmed, target="127.0.0.1"):
        self.executions.append((confirmed, target))
        self.busy, self.can_run = True, False
        self.status = "Running Local Self-Test on 127.0.0.1…"
        self.changed.emit()

    def stop(self):
        self.stops += 1
        self.status = "Cancelling Local Self-Test…"
        self.changed.emit()

    def shutdown(self, immediate=False):
        pass


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

    monkeypatch.setattr(recon_tab, "NmapRuntime", RuntimeDouble)
    widget = recon_tab.ReconTab()
    widget.resize(1366, 768)
    widget.show()
    qapp.processEvents()
    yield widget
    widget.close()
    widget.deleteLater()
    qapp.processEvents()


def choose(recon, tool_id):
    index = recon.ui.toolSelector.findData(tool_id)
    assert index >= 0
    recon.ui.toolSelector.setCurrentIndex(index)


def test_default_inspector_is_shared_by_both_recon_pages(recon, qapp):
    ui = recon.ui
    assert isinstance(ui.reconSplitter, QSplitter)
    assert ui.reconSplitter.orientation() == Qt.Horizontal
    assert ui.reconSplitter.widget(0) is ui.reconPages
    assert ui.reconSplitter.widget(1) is ui.toolManager
    assert isinstance(ui.toolInspectorScroll, QScrollArea)
    assert isinstance(ui.toolSelector, QComboBox)
    assert [ui.toolSelector.itemData(i) for i in range(ui.toolSelector.count())] == [
        "nmap", "subfinder", "httpx", "ffuf",
    ]
    assert ui.toolSelector.currentData() == "nmap"
    assert ui.btnToolInspectorToggle.text() == "Hide Tool Inspector"
    assert not ui.toolManager.isAncestorOf(ui.btnToolInspectorToggle)
    for page in (0, 1, 0):
        ui.reconPages.setCurrentIndex(page)
        qapp.processEvents()
        assert ui.toolManager.isVisible()
        assert ui.toolSelector.isVisible()
        assert ui.btnToolInspectorToggle.isVisible()
        assert ui.reconSplitter.sizes()[1] > 0


def test_invalid_target_toggle_preserves_report_target_checks_and_row_selection(recon, qapp):
    ui = recon.ui
    assert not ui.btnToggleInvalidTargets.isVisible()
    assert not ui.invalidCountLabel.isVisible()
    ui.pasteInput.setPlainText("keep.example.test\n--help\nhttps://bad.test/path")
    ui.btnAddPaste.click()
    ui.btnSelectAll.click()
    ui.targetTable.selectRow(0)
    ui.issueTable.selectRow(1)
    report = [[recon.issue_model.index(row, column).data() for column in range(3)]
              for row in range(recon.issue_model.rowCount())]
    target = [[recon.target_model.index(0, column).data() for column in range(5)]]
    selected_issues = ui.issueTable.selectionModel().selectedIndexes()
    selected_targets = ui.targetTable.selectionModel().selectedIndexes()
    assert ui.invalidCountLabel.text() == "Invalid Targets: 2"
    assert ui.btnToggleInvalidTargets.text() == "Hide Invalid Targets"
    assert ui.issueTable.isVisible()

    for _ in range(2):
        ui.btnToggleInvalidTargets.click()
        qapp.processEvents()
        assert not ui.issueTable.isVisible()
        assert ui.btnToggleInvalidTargets.text() == "Show Invalid Targets"
        assert ui.invalidCountLabel.text() == "Invalid Targets: 2"
        ui.btnToggleInvalidTargets.click()
        qapp.processEvents()
        assert ui.issueTable.isVisible()
        assert ui.issueTable.selectionModel().selectedIndexes() == selected_issues
        assert ui.targetTable.selectionModel().selectedIndexes() == selected_targets
        assert recon.target_model.selected_count == 1
        assert recon.target_model.index(0, recon.target_model.SCOPE).data() == "Unreviewed"
        assert [[recon.issue_model.index(row, column).data() for column in range(3)]
                for row in range(recon.issue_model.rowCount())] == report
        assert [[recon.target_model.index(0, column).data() for column in range(5)]] == target


def test_new_import_reveals_invalid_rows_and_valid_import_or_clear_hides_controls(
    recon, qapp, monkeypatch,
):
    ui = recon.ui
    ui.pasteInput.setPlainText("first.test\n--help")
    ui.btnAddPaste.click()
    ui.btnToggleInvalidTargets.click()
    assert not ui.issueTable.isVisible()
    ui.pasteInput.setPlainText("second.test\nhttps://bad.test\n--version")
    ui.btnAddPaste.click()
    qapp.processEvents()
    assert ui.issueTable.isVisible()
    assert ui.invalidCountLabel.text() == "Invalid Targets: 2"
    assert ui.btnToggleInvalidTargets.text() == "Hide Invalid Targets"
    ui.pasteInput.setPlainText("third.test")
    ui.btnAddPaste.click()
    assert recon.issue_model.rowCount() == 0
    assert not ui.issueTable.isVisible()
    assert not ui.btnToggleInvalidTargets.isVisible()
    assert not ui.invalidCountLabel.isVisible()
    ui.pasteInput.setPlainText("--help")
    ui.btnAddPaste.click()
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.Yes)
    ui.btnClearTargets.click()
    assert recon.issue_model.rowCount() == recon.target_model.rowCount() == 0
    assert not ui.issueTable.isVisible()
    assert not ui.btnToggleInvalidTargets.isVisible()
    assert not ui.invalidCountLabel.isVisible()


def test_hiding_inspector_reclaims_width_and_restores_manual_width_after_resize(recon, qapp):
    ui = recon.ui
    splitter = ui.reconSplitter
    splitter.moveSplitter(splitter.width() - 286, 1)
    qapp.processEvents()
    left_width, right_width = splitter.sizes()
    assert right_width > 0
    ui.btnToolInspectorToggle.click()
    qapp.processEvents()
    assert not ui.toolManager.isVisible()
    assert ui.btnToolInspectorToggle.text() == "Show Tool Inspector"
    assert splitter.sizes()[0] >= left_width + right_width - 2
    recon.resize(1600, 850)
    qapp.processEvents()
    ui.reconPages.setCurrentIndex(1)
    ui.btnToolInspectorToggle.click()
    qapp.processEvents()
    assert ui.toolManager.isVisible()
    assert ui.btnToolInspectorToggle.text() == "Hide Tool Inspector"
    assert abs(splitter.sizes()[1] - right_width) <= 3


def test_wide_inspector_restores_user_width_instead_of_capping_it_to_half(recon, qapp):
    recon.resize(1600, 850)
    qapp.processEvents()
    splitter = recon.ui.reconSplitter
    splitter.moveSplitter(splitter.width() - 876, 1)
    qapp.processEvents()
    right_width = splitter.sizes()[1]
    assert right_width > splitter.width() / 2
    recon.ui.btnToolInspectorToggle.click()
    recon.ui.btnToolInspectorToggle.click()
    qapp.processEvents()
    assert abs(splitter.sizes()[1] - right_width) <= 3


def test_tool_switches_show_selected_information_and_status_without_running_anything(
    recon, qapp, monkeypatch,
):
    ui = recon.ui
    runtime = recon.nmap_runtime
    fixture = Path(__file__).parents[2] / "fixtures" / "recon_observations_v1.json"
    assert recon.import_observations_file(fixture)
    ui.assetSearch.setText("EXAMPLE.COM")
    ui.assetTypeFilter.setCurrentIndex(ui.assetTypeFilter.findData("hostname"))
    ui.importHistory.setCurrentIndex(1)
    ui.assetTable.sortByColumn(0, Qt.DescendingOrder)
    ui.assetTable.selectRow(0)
    selected_asset = ui.assetTable.selectionModel().selectedRows()[0].data(recon.asset_model.EntityKeyRole)
    observations = recon.asset_inventory.observations
    ui.manualInput.setText("keep.example.test")
    ui.btnAddTarget.click()
    ui.btnSelectAll.click()
    refreshes = []
    monkeypatch.setattr(recon.tool_discovery, "discover", lambda: refreshes.append(True) or ())
    overviews = []
    for tool_id in ("nmap", "subfinder", "httpx", "ffuf", "nmap"):
        choose(recon, tool_id)
        qapp.processEvents()
        info = ui.toolInfo.labels
        assert set(info) == {"overview", "installation", "profiles", "network", "execution", "results"}
        assert all(label.text().strip() for label in info.values())
        overviews.append(info["overview"].text())
        for status_id, label in ui.toolLabels.items():
            assert label.isVisible() == (status_id == tool_id)
        assert ui.btnChooseNmap.isVisible() == (tool_id == "nmap")
        assert ui.btnNmapSelfTest.isVisible() == (tool_id == "nmap")
        assert ui.btnStopNmap.isVisible() == (tool_id == "nmap")
        assert ui.nmapPublicSetup.isVisible() == (tool_id == "nmap")
        assert ui.btnNmapPublicScan.isVisible() == (tool_id == "nmap")
        ui.btnToolInspectorToggle.click()
        ui.btnToolInspectorToggle.click()
        assert recon.nmap_runtime is runtime
    assert len(set(overviews)) == 4
    assert overviews[0] == overviews[-1]
    assert refreshes == runtime.approvals == runtime.executions == []
    assert not ui.btnNmapSelfTest.isEnabled()
    assert recon.target_model.selected_count == 1
    assert recon.target_model.index(0, recon.target_model.SCOPE).data() == "Unreviewed"
    assert recon.asset_inventory.observations is observations
    assert ui.assetSearch.text() == "EXAMPLE.COM"
    assert ui.assetTypeFilter.currentData() == "hostname"
    assert ui.importHistory.currentIndex() == 1
    assert recon.asset_proxy.sortOrder() == Qt.DescendingOrder
    assert ui.assetTable.selectionModel().selectedRows()[0].data(recon.asset_model.EntityKeyRole) == selected_asset
    assert ui.btnAssetDetails.isEnabled()


def test_refresh_keeps_selected_tool_and_error_discards_stale_detection(recon, qapp, monkeypatch):
    ui = recon.ui
    records = (
        ToolDiscoveryRecord("nmap", "Nmap", ToolDiscoveryStatus.CANDIDATE_UNVERIFIED,
                            "C:/Tools/candidate.exe", "Candidate is unverified."),
        ToolDiscoveryRecord("subfinder", "Subfinder", ToolDiscoveryStatus.NOT_FOUND,
                            None, "No executable found."),
        ToolDiscoveryRecord("httpx", "ProjectDiscovery httpx", ToolDiscoveryStatus.NAME_COLLISION,
                            None, "Python HTTPX launcher found."),
        ToolDiscoveryRecord("ffuf", "FFUF", ToolDiscoveryStatus.INVALID_CANDIDATE,
                            None, "Candidate is not an executable."),
    )
    monkeypatch.setattr(recon.tool_discovery, "discover", lambda: records)
    choose(recon, "httpx")
    ui.btnRefreshDetection.click()
    assert ui.toolSelector.currentData() == "httpx"
    expected = {"nmap": "Candidate found, not verified", "subfinder": "Not found",
                "httpx": "Name collision", "ffuf": "Invalid candidate"}
    for tool_id, status in expected.items():
        choose(recon, tool_id)
        qapp.processEvents()
        assert status in ui.toolLabels[tool_id].text()
        assert ui.toolLabels[tool_id].toolTip()
    assert "C:/Tools/candidate.exe" in ui.toolLabels["nmap"].text()

    def unavailable():
        raise OSError("secret-token")

    monkeypatch.setattr(recon.tool_discovery, "discover", unavailable)
    ui.btnRefreshDetection.click()
    assert "Detection unavailable" in ui.toolDetectionStatus.text()
    for label in ui.toolLabels.values():
        assert "Detection unavailable" in label.text()
        assert "candidate.exe" not in label.text()
        assert "secret-token" not in label.text() + label.toolTip()
    choose(recon, "nmap")
    suggestions = []
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args:
                        suggestions.append(args[2]) or ("", ""))
    ui.btnChooseNmap.click()
    assert suggestions == [""]
    assert recon.nmap_runtime.approvals == recon.nmap_runtime.executions == []


def test_running_nmap_state_and_local_confirmation_survive_tool_switches(
    recon, qapp, monkeypatch,
):
    ui = recon.ui
    runtime = recon.nmap_runtime
    runtime.can_run = True
    runtime.safety_reason = ""
    runtime.executable_path = "C:/Tools/Nmap/nmap.exe"
    runtime.version = "7.95"
    runtime.status = "Ready for confirmed Local Self-Test."
    runtime.changed.emit()
    ui.manualInput.setText("external.example.test")
    ui.btnAddTarget.click()
    ui.btnSelectAll.click()
    prompts = []
    monkeypatch.setattr(QMessageBox, "question", lambda *args:
                        prompts.append(args) or QMessageBox.No)
    ui.btnNmapSelfTest.click()
    assert runtime.executions == []
    assert prompts[-1][-1] == QMessageBox.No
    for detail in ("127.0.0.1", "80, 443, 8080, 8443", "TCP connect",
                   "local TCP connections", "No external targets"):
        assert detail in prompts[-1][2]
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.Yes)
    ui.btnNmapSelfTest.click()
    assert runtime.executions == [(True, "127.0.0.1")]
    running_status = ui.nmapStatusLabel.text()
    for tool_id in ("subfinder", "httpx", "ffuf", "nmap"):
        choose(recon, tool_id)
        ui.btnToolInspectorToggle.click()
        ui.btnToolInspectorToggle.click()
        qapp.processEvents()
        assert recon.nmap_runtime is runtime
        assert not ui.btnChooseNmap.isEnabled()
        assert not ui.btnNmapSelfTest.isEnabled()
        assert ui.btnStopNmap.isEnabled()
        assert ui.nmapStatusLabel.text() == running_status
    ui.btnStopNmap.click()
    assert runtime.stops == 1
    assert "Cancelling" in ui.nmapStatusLabel.text()
    assert recon.target_model.selected_count == 1
    assert recon.target_model.index(0, recon.target_model.SCOPE).data() == "Unreviewed"


def test_long_nmap_path_and_hidden_runtime_errors_wrap_without_losing_status(
    recon, qapp, monkeypatch,
):
    ui = recon.ui
    runtime = recon.nmap_runtime
    long_path = "C:/Tools/" + "LongUnbrokenToolFolder" * 18 + "/nmap.exe"
    diagnostic = "Local candidate remains unverified: " + "UnbrokenDiagnostic" * 20
    records = tuple(
        ToolDiscoveryRecord(tool_id, name, ToolDiscoveryStatus.CANDIDATE_UNVERIFIED,
                            long_path if tool_id == "nmap" else f"C:/Tools/{tool_id}.exe",
                            diagnostic if tool_id == "nmap" else "Compatibility unverified.")
        for tool_id, name in (("nmap", "Nmap"), ("subfinder", "Subfinder"),
                              ("httpx", "ProjectDiscovery httpx"), ("ffuf", "FFUF"))
    )
    monkeypatch.setattr(recon.tool_discovery, "discover", lambda: records)
    choose(recon, "ffuf")
    ui.btnToolInspectorToggle.click()
    ui.btnRefreshDetection.click()
    runtime.executable_path = long_path
    runtime.status = "Verification rejected: " + "LongRuntimeDiagnostic" * 20
    runtime.safety_reason = "Process containment unavailable: " + "ContainmentReason" * 15
    runtime.changed.emit()
    assert not ui.toolManager.isVisible()
    ui.btnToolInspectorToggle.click()
    assert ui.toolSelector.currentData() == "ffuf"
    choose(recon, "nmap")
    ui.reconSplitter.moveSplitter(ui.reconSplitter.width() - 206, 1)
    qapp.processEvents()
    scroll = ui.toolInspectorScroll
    assert ui.nmapStatusLabel.text() == runtime.status
    assert long_path in ui.nmapExecutableLabel.text()
    assert ui.toolDiagnostic.text() == diagnostic
    assert not scroll.horizontalScrollBar().isVisible()
    labels = (ui.toolLabels["nmap"], ui.toolDiagnostic, ui.nmapExecutableLabel,
              ui.nmapVersionLabel, ui.nmapAdapterLabel, ui.nmapStatusLabel,
              ui.toolInfo.labels["results"])
    rectangles = []
    for label in labels:
        assert label.isVisible()
        assert label.textFormat() == Qt.PlainText
        assert label.wordWrap()
        assert label.height() >= label.heightForWidth(label.width()), label.text()[:50]
        rectangle = QRect(label.mapTo(scroll.widget(), QPoint()), label.size())
        assert all(not rectangle.intersects(other) for other in rectangles)
        rectangles.append(rectangle)
        scroll.ensureWidgetVisible(label)
        qapp.processEvents()
        geometry = QRect(label.mapTo(scroll.viewport(), QPoint()), label.size())
        assert scroll.viewport().rect().intersects(geometry)
    assert recon.nmap_runtime is runtime
    assert runtime.approvals == runtime.executions == []


def test_visible_nmap_detection_refresh_reflows_new_candidate_path(recon, qapp, monkeypatch):
    ui = recon.ui
    assert ui.toolSelector.currentData() == "nmap"
    ui.reconSplitter.moveSplitter(ui.reconSplitter.width() - 206, 1)
    qapp.processEvents()
    candidate = "C:/Tools/" + "CandidateFolder" * 14 + "/nmap.exe"
    records = tuple(
        ToolDiscoveryRecord(tool_id, name, ToolDiscoveryStatus.CANDIDATE_UNVERIFIED,
                            candidate if tool_id == "nmap" else f"C:/Tools/{tool_id}.exe",
                            "Candidate is unverified; no program was run.")
        for tool_id, name in (("nmap", "Nmap"), ("subfinder", "Subfinder"),
                              ("httpx", "ProjectDiscovery httpx"), ("ffuf", "FFUF"))
    )
    monkeypatch.setattr(recon.tool_discovery, "discover", lambda: records)
    ui.btnRefreshDetection.click()
    qapp.processEvents()
    status = ui.toolLabels["nmap"]
    assert status.isVisible()
    assert candidate in status.text()
    # Wrapped text can need several deferred parent-layout requests to settle.
    deadline = monotonic() + 1
    while status.height() < status.heightForWidth(status.width()) and monotonic() < deadline:
        qapp.processEvents()
    assert status.height() >= status.heightForWidth(status.width())
    scroll = ui.toolInspectorScroll
    assert not scroll.horizontalScrollBar().isVisible()
    labels = (status, ui.toolDiagnostic, ui.nmapExecutableLabel,
              ui.nmapVersionLabel, ui.nmapAdapterLabel)
    rectangles = [QRect(label.mapTo(scroll.widget(), QPoint()), label.size())
                  for label in labels]
    for first, second in zip(rectangles, rectangles[1:]):
        assert not first.intersects(second)
    assert ui.toolSelector.currentData() == "nmap"
    assert recon.nmap_runtime.approvals == recon.nmap_runtime.executions == []


@pytest.mark.parametrize("width,height", [(1366, 768), (1024, 700)])
def test_inspector_wraps_and_scrolls_to_information_and_controls(recon, qapp, width, height):
    ui = recon.ui
    recon.resize(width, height)
    qapp.processEvents()
    assert recon.size().toTuple() == (width, height)
    # Exercise a narrow user-selected pane, rather than only its initial width.
    ui.reconSplitter.moveSplitter(ui.reconSplitter.width() - 206, 1)
    qapp.processEvents()
    scroll = ui.toolInspectorScroll
    assert not scroll.horizontalScrollBar().isVisible()
    viewport = scroll.viewport()
    for tool_id in ("nmap", "subfinder", "httpx", "ffuf"):
        choose(recon, tool_id)
        qapp.processEvents()
        rectangles = []
        for label in ui.toolInfo.labels.values():
            assert label.wordWrap()
            assert label.height() >= label.heightForWidth(label.width())
            rectangles.append(QRect(label.mapTo(scroll.widget(), QPoint()), label.size()))
        for first, second in zip(rectangles, rectangles[1:]):
            assert not first.intersects(second)
        for key in ("execution", "results"):
            label = ui.toolInfo.labels[key]
            scroll.ensureWidgetVisible(label)
            qapp.processEvents()
            visible_part = QRect(label.mapTo(viewport, QPoint()), label.size())
            assert viewport.rect().intersects(visible_part), key
    choose(recon, "nmap")
    # Selecting Nmap reveals its runtime controls and changes the content height.
    # Let Qt update the scroll range before asking it to reveal a child widget.
    qapp.processEvents()
    for button in (ui.btnNmapPreflight, ui.btnChooseNmap, ui.btnNmapSelfTest, ui.btnStopNmap, ui.btnNmapPublicScan):
        scroll.ensureWidgetVisible(button)
        qapp.processEvents()
        geometry = QRect(button.mapTo(viewport, QPoint()), button.size())
        assert viewport.rect().contains(geometry), button.text()
