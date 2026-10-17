"""Tools rehosts the real Nmap workflow while Recon keeps shared state."""

from pathlib import Path
import os
import sys

import pytest
from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QPushButton


@pytest.fixture(scope="module", autouse=True)
def windows_offscreen_fonts(qapp):
    original_font, font_ids = qapp.font(), []
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


class PendingLookup(QObject):
    """Hold a DNS request at the network boundary until Stop aborts it."""

    finished = Signal()

    def __init__(self, parent):
        super().__init__(parent)
        self.aborted = False

    def setType(self, kind):
        self.kind = kind

    def setName(self, name):
        self.name = name

    def lookup(self):
        pass

    def abort(self):
        self.aborted = True


NMAP_WIDGETS = (
    "nmapInstallation", "btnManageNmapProfiles", "nmapProfileSetup", "nmapPublicSetup",
    "nmapAuthorizedSetup", "nmapExecution", "btnNmapPublicScan", "btnNmapRunProfile",
    "btnNmapAuthorizedRun", "nmapPublicSummary", "nmapAuthorizedStatus", "btnNmapAuthorizedResults",
)

EXECUTION_BUTTONS = (
    "btnChooseNmap", "btnNmapSelfTest", "btnStopNmap", "btnNmapPublicScan",
    "btnNmapRunProfile", "btnNmapAuthorizedRun", "btnNmapScopePreflight",
    "btnNmapCapabilities", "btnNmapUseSelected", "btnManageNmapProfiles",
)


LOOPBACK_XML = b'''<?xml version="1.0" encoding="UTF-8"?>
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


@pytest.fixture
def tools_window(qapp, monkeypatch, tmp_path):
    from core.recon import nmap_profile_store
    from mainwindow import MainWindow

    monkeypatch.setattr(nmap_profile_store, "default_profile_path", lambda: tmp_path / "profiles.json")
    window = MainWindow()
    try:
        window.show()
        qapp.processEvents()
        yield window
    finally:
        window.scraper_tab.task_manager.shutdown(timeout_ms=1000)
        window.close()
        window.deleteLater()
        qapp.processEvents()


def test_tools_opens_a_functional_nmap_page_after_recon(tools_window, qapp):
    from PySide6.QtWidgets import QScrollArea, QTabWidget

    window = tools_window
    assert hasattr(window, "tools_tab"), "MainWindow must expose the new Tools workspace"
    tools, recon = window.tools_tab, window.recon_tab
    tabs = window.ui.tabWidget
    assert tabs.indexOf(tools) == tabs.indexOf(recon) + 1
    assert tabs.tabText(tabs.indexOf(tools)) == "Tools"
    assert isinstance(tools.ui.toolPages, QTabWidget)
    assert tools.ui.toolPages.count() == 1
    assert tools.ui.toolPages.tabText(0) == "Nmap"
    assert tools.ui.toolPages.widget(0) is tools.ui.nmapPage
    assert isinstance(tools.ui.nmapScroll, QScrollArea)
    tabs.setCurrentWidget(tools)
    qapp.processEvents()
    assert recon.ui.btnManageNmapProfiles.isVisible()
    assert recon.ui.btnNmapAuthorizedRun.isVisible()
    assert recon.ui.btnStopNmap.isVisible()


def test_rehosting_retains_the_original_widgets_controllers_and_state(qapp, monkeypatch, tmp_path):
    from core.recon import nmap_profile_store
    from ui.panels.recon_tab import ReconTab
    from ui.panels.tools_tab import ToolsTab
    from ui.recon_tool_info import ToolInformationView

    monkeypatch.setattr(nmap_profile_store, "default_profile_path", lambda: tmp_path / "profiles.json")
    recon = ReconTab()
    original_widgets = {name: getattr(recon.ui, name) for name in NMAP_WIDGETS}
    original_state = (recon.nmap_runtime, recon.asset_inventory, recon.target_model,
                      recon.nmap_profile_store, recon.public_nmap_controls, recon.authorized_nmap_controls)
    tools = ToolsTab(recon)
    try:
        tools.show()
        qapp.processEvents()
        assert isinstance(tools.ui.nmapInfo, ToolInformationView)
        for name, widget in original_widgets.items():
            assert getattr(recon.ui, name) is widget
            assert tools.ui.nmapInfo.isAncestorOf(widget), name
            assert not recon.ui.toolInfo.isAncestorOf(widget), name
            assert widget.isVisible(), name
        assert original_state == (recon.nmap_runtime, recon.asset_inventory, recon.target_model,
                                  recon.nmap_profile_store, recon.public_nmap_controls,
                                  recon.authorized_nmap_controls)
        assert recon.public_nmap_controls._recon is recon
        assert recon.authorized_nmap_controls._recon is recon
        assert recon.public_nmap_controls._runtime is recon.nmap_runtime
        assert recon.authorized_nmap_controls._runtime is recon.nmap_runtime
    finally:
        recon.close()
        tools.close()
        tools.deleteLater()
        recon.deleteLater()
        qapp.processEvents()


def test_tools_creates_no_parallel_runtime_or_inventory(qapp, monkeypatch, tmp_path):
    from core.recon import nmap_profile_store
    from core.recon.inventory import AssetInventory
    from core.recon.nmap_runtime import NmapRuntime
    from core.recon.process_supervisor import ProcessSupervisor
    from core.recon.subfinder_runtime import SubfinderRuntime
    from mainwindow import MainWindow

    constructed = {AssetInventory: [], NmapRuntime: [], SubfinderRuntime: [], ProcessSupervisor: []}
    for cls in constructed:
        original_init = cls.__init__

        def tracked_init(instance, *args, _cls=cls, _init=original_init, **kwargs):
            _init(instance, *args, **kwargs)
            constructed[_cls].append(instance)

        monkeypatch.setattr(cls, "__init__", tracked_init)
    monkeypatch.setattr(nmap_profile_store, "default_profile_path", lambda: tmp_path / "profiles.json")
    window = MainWindow()
    try:
        recon = window.recon_tab
        assert constructed[NmapRuntime] == [recon.nmap_runtime]
        assert constructed[SubfinderRuntime] == [recon.subfinder_runtime]
        assert constructed[AssetInventory] == [recon.asset_inventory]
        assert constructed[ProcessSupervisor] == [
            recon.nmap_runtime._supervisor, recon.subfinder_runtime._supervisor,
        ]
        assert window.findChildren(NmapRuntime) == [recon.nmap_runtime]
        assert window.findChildren(SubfinderRuntime) == [recon.subfinder_runtime]
        assert recon.nmap_runtime.parent() is recon
        assert recon.subfinder_runtime.parent() is recon
        assert recon.nmap_runtime._inventory is recon.asset_inventory
        assert recon.subfinder_runtime._inventory is recon.asset_inventory
        assert recon.nmap_runtime._supervisor is not recon.subfinder_runtime._supervisor
        assert recon.nmap_runtime._supervisor._jobs == {}
        assert recon.subfinder_runtime._supervisor._jobs == {}
    finally:
        window.scraper_tab.task_manager.shutdown(timeout_ms=1000)
        window.close()
        window.deleteLater()
        qapp.processEvents()


def test_profile_manager_reuses_store_dialog_and_reload_signals(tools_window, qapp):
    from dialogs.nmap_profiles_dialog import NmapProfilesDialog

    window = tools_window
    recon, tools = window.recon_tab, window.tools_tab
    window.ui.tabWidget.setCurrentWidget(tools)
    ui = recon.ui
    ui.nmapScopeInput.setPlainText("127.0.0.1")
    ui.btnNmapScopePreflight.click()
    assert recon.authorized_nmap_controls.preflight.scope is not None
    ui.nmapScopeApproval.setChecked(True)
    initial_count = ui.nmapProfileSelector.count()
    ui.btnManageNmapProfiles.click()
    qapp.processEvents()
    dialog = recon._nmap_profiles_dialog
    assert isinstance(dialog, NmapProfilesDialog)
    assert dialog.isVisible()
    assert dialog.store is recon.nmap_profile_store
    dialog.ui.btnDuplicate.click()
    dialog.ui.nameInput.setText("Tools saved profile")
    dialog.ui.btnSave.click()
    profile, = recon.nmap_profile_store.profiles
    assert profile.name == "Tools saved profile"
    assert ui.nmapProfileSelector.count() == initial_count + 1
    assert ui.nmapProfileSelector.findData(profile.profile_id) >= 0
    assert recon.authorized_nmap_controls.preflight.scope is None
    assert not ui.nmapScopeApproval.isChecked()
    assert recon.nmap_profile_store.path.exists()
    dialog.ui.btnClose.click()
    qapp.processEvents()
    ui.btnManageNmapProfiles.click()
    qapp.processEvents()
    assert recon._nmap_profiles_dialog is dialog
    assert len(recon.findChildren(NmapProfilesDialog)) == 1
    assert dialog.isVisible()
    dialog.ui.btnClose.click()
    assert not recon.nmap_runtime.busy
    assert not recon.subfinder_runtime.busy


def test_checked_recon_targets_feed_tools_without_granting_scope(tools_window, qapp):
    from PySide6.QtCore import Qt

    window = tools_window
    recon, ui = window.recon_tab, window.recon_tab.ui
    window.ui.tabWidget.setCurrentWidget(recon)
    ui.pasteInput.setPlainText("checked.example.test\nunchecked.example.test")
    ui.btnAddPaste.click()
    recon.target_model.setData(recon.target_model.index(0, 0), Qt.Checked, Qt.CheckStateRole)
    ui.targetTable.selectRow(1)
    window.ui.tabWidget.setCurrentWidget(window.tools_tab)
    qapp.processEvents()
    ui.btnNmapUseSelected.click()
    assert ui.nmapScopeInput.toPlainText() == "checked.example.test"
    assert recon.target_model.selected_count == 1
    assert recon.authorized_nmap_controls.preflight.scope is None
    assert not ui.nmapScopeApproval.isChecked()
    assert not ui.btnNmapAuthorizedRun.isEnabled()
    assert recon.target_model.data(recon.target_model.index(0, recon.target_model.SCOPE)) == "Unreviewed"
    assert not recon.nmap_runtime.busy
    assert not recon.subfinder_runtime.busy


def test_tools_stop_cancels_runtime_and_pending_scope_review(tools_window, qapp, monkeypatch):
    from core.recon.process_supervisor import JobSnapshot, JobState

    window = tools_window
    recon, runtime = window.recon_tab, window.recon_tab.nmap_runtime
    window.ui.tabWidget.setCurrentWidget(window.tools_tab)
    runtime._job_id, runtime._phase = "offline-nmap-job", "scan"
    cancelled = []
    monkeypatch.setattr(runtime._supervisor, "cancel", lambda job_id: cancelled.append(job_id) or True)
    runtime.changed.emit()
    assert recon.ui.btnStopNmap.isEnabled()
    recon.ui.btnStopNmap.click()
    assert cancelled == ["offline-nmap-job"]
    assert runtime._stop_requested
    assert recon.ui.nmapStatusLabel.text() == "Stopping Nmap…"
    runtime._supervisor.job_finished.emit(JobSnapshot(
        "offline-nmap-job", "nmap.local-self-test", JobState.CANCELLED, b"", b""))
    assert not runtime.busy
    assert "cancelled" in recon.ui.nmapStatusLabel.text()
    assert not recon.ui.btnStopNmap.isEnabled()

    preflight = recon.authorized_nmap_controls.preflight
    lookups = []

    def pending_lookup(parent):
        lookup = PendingLookup(parent)
        lookups.append(lookup)
        return lookup

    preflight._factory = pending_lookup
    recon.ui.nmapScopeInput.setPlainText("pending.example.test")
    recon.ui.btnNmapScopePreflight.click()
    qapp.processEvents()
    assert preflight.busy and len(lookups) == 2
    assert recon.ui.btnStopNmap.isEnabled()
    recon.ui.btnStopNmap.click()
    assert not preflight.busy
    assert preflight.scope is None
    assert all(lookup.aborted for lookup in lookups)
    assert not recon.ui.btnStopNmap.isEnabled()
    assert not recon.ui.nmapScopeApproval.isChecked()
    assert recon.asset_model.rowCount() == 0
    assert recon.asset_inventory.import_history == ()


def test_both_existing_runtimes_refresh_shared_inventory_and_run_history(tools_window, qapp):
    from core.recon.process_supervisor import JobSnapshot, JobState

    window = tools_window
    recon = window.recon_tab
    runtime = recon.nmap_runtime
    window.ui.tabWidget.setCurrentWidget(window.tools_tab)
    runtime._job_id, runtime._phase = "offline-nmap-success", "scan"
    runtime._supervisor.job_finished.emit(JobSnapshot(
        "offline-nmap-success", "nmap.local-self-test", JobState.SUCCEEDED,
        LOOPBACK_XML, b"", exit_code=0))
    assert "succeeded" in recon.ui.nmapStatusLabel.text()
    assert recon.asset_model.rowCount() == 2
    assert recon.ui.importHistory.count() == 2
    assert recon.ui.sourceFilter.findData("nmap") > 0
    assert recon.asset_inventory.import_history[0].format_name == "Nmap live XML"
    assert any(asset.value == "127.0.0.1" and asset.port == 8080 for asset in recon.asset_inventory.assets)

    subfinder = recon.subfinder_runtime
    subfinder._job_id, subfinder._phase = "offline-subfinder-success", "discovery"
    subfinder._root_domain = "example.test"
    subfinder._supervisor.job_finished.emit(JobSnapshot(
        "offline-subfinder-success", "subfinder.passive-standard", JobState.SUCCEEDED,
        b'{"host":"api.example.test","input":"example.test","sources":["crtsh"]}\n',
        b"", exit_code=0))
    qapp.processEvents()
    assert "succeeded" in subfinder.status
    assert recon.asset_model.rowCount() == 3
    assert recon.ui.importHistory.count() == 3
    assert recon.ui.sourceFilter.findData("subfinder") > 0
    assert recon.ui.importHistory.currentData() == ""
    assert [entry.format_name for entry in recon.asset_inventory.import_history] == [
        "Nmap live XML", "Subfinder live JSONL",
    ]
    assert recon.target_model.rowCount() == 0
    window.ui.tabWidget.setCurrentWidget(recon)
    recon.ui.reconPages.setCurrentIndex(1)
    qapp.processEvents()
    assert recon.ui.assetTable.isVisible()
    assert recon.asset_model.rowCount() == 3


def test_inspector_switches_keep_tools_controls_visible_and_unique(tools_window, qapp):
    window = tools_window
    recon, tools = window.recon_tab, window.tools_tab
    assert recon.ui.toolSelector.currentData() == "subfinder"
    assert {recon.ui.toolSelector.itemData(i) for i in range(recon.ui.toolSelector.count())} == {
        "nmap", "subfinder", "httpx", "ffuf",
    }
    for tool_id in ("subfinder", "httpx", "ffuf", "nmap", "subfinder"):
        window.ui.tabWidget.setCurrentWidget(recon)
        recon.ui.toolSelector.setCurrentIndex(recon.ui.toolSelector.findData(tool_id))
        qapp.processEvents()
        for name in EXECUTION_BUTTONS:
            button = getattr(recon.ui, name)
            assert not recon.isAncestorOf(button), name
            assert not button.isVisible(), name
            assert [candidate for area in (recon, tools) for candidate in area.findChildren(QPushButton)
                    if candidate.text() == button.text()] == [button], name
        window.ui.tabWidget.setCurrentWidget(tools)
        qapp.processEvents()
        for name in EXECUTION_BUTTONS:
            button = getattr(recon.ui, name)
            assert tools.ui.nmapInfo.isAncestorOf(button), name
            assert button.isVisible(), (tool_id, name)


@pytest.mark.parametrize("size", [(1366, 768), (1024, 700)])
def test_nmap_controls_fit_workspace_width_and_scroll_to_results(tools_window, qapp, size):
    from PySide6.QtCore import QPoint

    window = tools_window
    tools, ui = window.tools_tab, window.recon_tab.ui
    # Scraper already imposes a 1326px main-window minimum. Exercise Tools at
    # both requested widths without changing that unrelated existing layout.
    tools.setParent(None)
    try:
        tools.resize(*size)
        tools.show()
        qapp.processEvents()
        scroll = tools.ui.nmapScroll
        assert tools.width() == size[0]
        assert scroll.widgetResizable()
        assert not scroll.horizontalScrollBar().isVisible()
        assert scroll.verticalScrollBar().isVisible()
        assert scroll.viewport().width() >= tools.width() - 100
        for name in (*EXECUTION_BUTTONS, "nmapScopeInput", "nmapProfileSelector", "nmapConcreteScope"):
            control = getattr(ui, name)
            scroll.ensureWidgetVisible(control)
            qapp.processEvents()
            origin = control.mapTo(scroll.viewport(), QPoint(0, 0))
            assert 0 <= origin.x()
            assert origin.x() + control.width() <= scroll.viewport().width()
            assert control.isVisible()
        scroll.ensureWidgetVisible(ui.btnNmapAuthorizedResults)
        qapp.processEvents()
        assert scroll.verticalScrollBar().value() > 0
    finally:
        tools.close()
        tools.setParent(window)


def test_closing_main_window_cleans_up_original_runtimes_and_scope(tools_window, qapp):
    window = tools_window
    recon = window.recon_tab
    window.ui.tabWidget.setCurrentWidget(window.tools_tab)
    recon.ui.nmapScopeInput.setPlainText("127.0.0.1")
    recon.ui.btnNmapScopePreflight.click()
    preflight = recon.authorized_nmap_controls.preflight
    assert preflight.scope is not None
    assert preflight._expiry_timer.isActive()
    window.close()
    qapp.processEvents()
    assert recon.nmap_runtime._closing
    assert recon.subfinder_runtime._closing
    assert recon.nmap_runtime._supervisor._closing
    assert recon.subfinder_runtime._supervisor._closing
    assert preflight.scope is None
    assert not preflight.busy
    assert not preflight._expiry_timer.isActive()
