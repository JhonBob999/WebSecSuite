"""Offline Recon workflows must preserve the existing Scraper workspace."""
import os
import socket
import subprocess

import pytest
from PySide6.QtCore import QProcess
from PySide6.QtWidgets import QLabel, QMessageBox, QTableView


@pytest.fixture
def recon_window(qapp, monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Recon startup and target management must stay offline")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    monkeypatch.setattr(os, "system", blocked)
    monkeypatch.setattr(QProcess, "start", blocked)
    monkeypatch.setattr(QProcess, "startDetached", blocked)

    from mainwindow import MainWindow

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


def test_recon_replaces_only_its_placeholder_and_starts_empty(recon_window, qapp):
    window = recon_window
    tabs = window.ui.tabWidget
    assert [tabs.tabText(i) for i in range(tabs.count())] == [
        "Scraper", "Recon", "JS / Frontend", "Candidates", "Validation",
        "CVE / Exploits", "Bots", "Logs / Artifacts",
    ]
    assert hasattr(window, "recon_tab"), "Recon must expose its integrated target manager"
    recon = window.recon_tab
    assert tabs.widget(1) is recon
    tabs.setCurrentWidget(recon)
    qapp.processEvents()
    assert recon.isVisible()
    assert isinstance(recon.ui.targetTable, QTableView)
    assert recon.ui.targetTable.model() is recon.target_model
    assert recon.target_model.rowCount() == 0
    assert recon.target_model.selected_count == 0
    assert "0" in recon.ui.countLabel.text()
    visible_text = " ".join(
        label.text() for label in recon.findChildren(QLabel) if label.isVisible()
    ).lower()
    assert "setup required" in visible_text
    assert not recon.ui.btnNmapSelfTest.isEnabled()
    assert window.scraper_tab.ui.taskTable.rowCount() == 0
    assert window.scraper_tab.task_manager.get_all_tasks() == []
    assert window.scraper_tab.task_manager.is_idle()


def test_offline_recon_controls_preserve_scraper_results_and_viewer(
    recon_window, qapp, monkeypatch,
):
    from dialogs.results_viewer_dialog import UniversalViewerDialog

    window = recon_window
    assert hasattr(window, "recon_tab"), "Recon target management is missing"
    recon, scraper = window.recon_tab, window.scraper_tab
    window.ui.tabWidget.setCurrentWidget(recon)
    recon.ui.manualInput.setText("manual.example.test")
    recon.ui.btnAddTarget.click()
    recon.ui.pasteInput.setPlainText("api.example.test\npaste.example.test")
    recon.ui.btnAddPaste.click()
    qapp.processEvents()
    assert recon.target_model.rowCount() == 3
    recon.ui.manualInput.setText("https://manual.example.test/login?next=%2Fdashboard")
    recon.ui.btnAddTarget.click()
    assert recon.target_model.rowCount() == 3
    assert recon.issue_model.rowCount() == 1
    recon.ui.btnSelectAll.click()
    assert recon.target_model.selected_count == 3
    selected_text = recon.ui.countLabel.text()
    assert "3" in selected_text
    recon.ui.btnDeselectAll.click()
    assert recon.target_model.selected_count == 0
    assert recon.ui.countLabel.text() != selected_text
    assert "0" in recon.ui.countLabel.text()
    assert scraper.ui.taskTable.rowCount() == 0
    assert scraper.task_manager.get_all_tasks() == []
    assert scraper.task_results == {}

    window.ui.tabWidget.setCurrentWidget(scraper)
    scraper.add_task_row("https://scraper.example.test")
    task_id = scraper.table_ctl.task_id_by_row(0)
    payload = {
        "url": "https://scraper.example.test", "status_code": 200,
        "title": "Local fixture", "content_len": 2048,
        "timings": {"request_ms": 12},
        "request_recipe": {"method": "GET", "url": "https://scraper.example.test"},
        "response_snapshot": {"body_preview": "offline evidence"},
        "custom": {"preserve": [1, 2, 3]},
    }
    scraper.on_task_result(task_id, payload)
    assert scraper.task_results[task_id] == payload
    viewed = []
    monkeypatch.setattr(UniversalViewerDialog, "exec", lambda dialog: viewed.append(dialog._payload))
    scraper.open_results_viewer_for_row(0)
    assert viewed == [payload]
    assert scraper.task_manager.is_idle()

    window.ui.tabWidget.setCurrentWidget(recon)
    assert recon.target_model.rowCount() == 3
    recon.ui.btnSelectAll.click()
    recon.ui.btnRemoveSelected.click()
    assert recon.target_model.rowCount() == 0
    assert recon.target_model.selected_count == 0
    recon.ui.manualInput.setText("clear.example.test")
    recon.ui.btnAddTarget.click()
    assert recon.target_model.rowCount() == 1
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.Yes)
    recon.ui.btnClearTargets.click()
    assert recon.target_model.rowCount() == 0
    assert recon.target_model.selected_count == 0
    assert scraper.ui.taskTable.rowCount() == 1
    assert scraper.table_ctl.task_id_by_row(0) == task_id
    assert scraper.task_results[task_id] == payload
    assert scraper.task_manager.is_idle()


def test_offline_asset_inventory_preserves_targets_scraper_and_full_viewer_payload(
    recon_window, qapp, monkeypatch, tmp_path,
):
    from pathlib import Path

    from PySide6.QtWidgets import QFileDialog

    from dialogs.results_viewer_dialog import UniversalViewerDialog

    window = recon_window
    recon, scraper = window.recon_tab, window.scraper_tab
    scraper.add_task_row("https://scraper.example.test")
    task_id = scraper.table_ctl.task_id_by_row(0)
    payload = {
        "url": "https://scraper.example.test", "status_code": 200,
        "request_recipe": {"method": "GET", "url": "https://scraper.example.test"},
        "response_snapshot": {"body_preview": "preserved offline evidence"},
        "custom": {"preserve": [1, 2, 3]},
    }
    scraper.on_task_result(task_id, payload)
    window.ui.tabWidget.setCurrentWidget(recon)
    recon.ui.manualInput.setText("target.example.test")
    recon.ui.btnAddTarget.click()
    recon.ui.btnSelectAll.click()
    recon.ui.reconPages.setCurrentIndex(1)
    qapp.processEvents()
    assert recon.ui.assetTable.isVisible()
    fixture = Path(__file__).parents[1] / "fixtures" / "recon_observations_v1.json"
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: (str(fixture), ""))
    recon.ui.btnImportObservations.click()
    assert recon.asset_model.rowCount() == 6
    recon.ui.assetSearch.setText("EXAMPLE.COM")
    recon.ui.assetTypeFilter.setCurrentIndex(recon.ui.assetTypeFilter.findData("hostname"))
    recon.ui.sourceFilter.setCurrentIndex(recon.ui.sourceFilter.findData("synthetic-import"))
    assert recon.asset_proxy.rowCount() == 1
    recon.ui.assetTable.selectRow(0)
    viewed = []
    monkeypatch.setattr(UniversalViewerDialog, "exec", lambda dialog: viewed.append(dialog._payload))
    recon.ui.btnAssetDetails.click()
    assert viewed[0]["value"] == "example.com"
    assert set(viewed[0]["sources"]) == {"synthetic-dns", "synthetic-import"}
    assert len(viewed[0]["observations"]) == 2
    assert viewed[0]["observations"][0]["evidence"]
    invalid = tmp_path / "invalid-observations.json"
    invalid.write_text("not json", encoding="utf-8")
    assert not recon.import_observations_file(invalid)
    assert recon.asset_model.rowCount() == 6
    assert recon.asset_proxy.rowCount() == 1
    assert recon.ui.btnAssetDetails.isEnabled()
    assert recon.target_model.rowCount() == recon.target_model.selected_count == 1
    assert recon.target_model.data(recon.target_model.index(0, recon.target_model.SCOPE)) == "Unreviewed"
    recon.ui.reconPages.setCurrentIndex(0)
    qapp.processEvents()
    assert recon.ui.targetTable.isVisible()
    recon.ui.btnRemoveSelected.click()
    assert recon.target_model.rowCount() == 0
    assert recon.asset_model.rowCount() == 6
    recon.ui.manualInput.setText("clear.example.test")
    recon.ui.btnAddTarget.click()
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.Yes)
    recon.ui.btnClearTargets.click()
    assert recon.target_model.rowCount() == 0
    assert recon.asset_model.rowCount() == 6
    assert recon.asset_proxy.rowCount() == 1
    assert scraper.ui.taskTable.rowCount() == 1
    assert scraper.table_ctl.task_id_by_row(0) == task_id
    assert scraper.task_results[task_id] == payload
    assert scraper.task_manager.is_idle()
    scraper.open_results_viewer_for_row(0)
    assert viewed[-1] == payload


def test_offline_nmap_import_preserves_scraper_results_and_unreviewed_targets(
    recon_window, qapp, monkeypatch,
):
    from pathlib import Path

    from PySide6.QtWidgets import QFileDialog

    from dialogs.results_viewer_dialog import UniversalViewerDialog

    window = recon_window
    recon, scraper = window.recon_tab, window.scraper_tab
    scraper.add_task_row("https://scraper.example.test")
    task_id = scraper.table_ctl.task_id_by_row(0)
    payload = {"url": "https://scraper.example.test", "status_code": 200,
               "custom": {"preserve": "offline Nmap import"}}
    scraper.on_task_result(task_id, payload)
    window.ui.tabWidget.setCurrentWidget(recon)
    recon.ui.manualInput.setText("keep.example.test")
    recon.ui.btnAddTarget.click()
    recon.ui.btnSelectAll.click()
    recon.ui.reconPages.setCurrentIndex(1)
    qapp.processEvents()
    assert recon.ui.btnImportNmap.isVisible()
    fixture = Path(__file__).parents[1] / "fixtures" / "nmap" / "recon.xml"
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: (str(fixture), ""))
    recon.ui.btnImportNmap.click()
    assert recon.asset_model.rowCount() > 0
    assert recon.ui.sourceFilter.findData("nmap") > 0
    assert recon.target_model.rowCount() == recon.target_model.selected_count == 1
    assert recon.target_model.data(recon.target_model.index(0, recon.target_model.SCOPE)) == "Unreviewed"
    assert scraper.ui.taskTable.rowCount() == 1
    assert scraper.table_ctl.task_id_by_row(0) == task_id
    assert scraper.task_results[task_id] == payload
    assert scraper.task_manager.is_idle()
    viewed = []
    monkeypatch.setattr(UniversalViewerDialog, "exec", lambda dialog: viewed.append(dialog._payload))
    scraper.open_results_viewer_for_row(0)
    assert viewed == [payload]


def test_tool_refresh_and_responsive_tab_switches_preserve_offline_workspaces(
    recon_window, qapp, monkeypatch,
):
    from pathlib import Path

    from PySide6.QtCore import QThreadPool, QTimer
    from PySide6.QtWidgets import QPushButton

    window = recon_window
    recon, scraper = window.recon_tab, window.scraper_tab
    recon.ui.manualInput.setText("scope.example.test")
    recon.ui.btnAddTarget.click()
    recon.ui.btnSelectAll.click()
    fixtures = Path(__file__).parents[1] / "fixtures"
    assert recon.import_observations_file(fixtures / "recon_observations_v1.json")
    assert recon.import_nmap_file(fixtures / "nmap" / "recon.xml")
    assets = tuple(recon.asset_inventory.observations)
    scraper.add_task_row("https://scraper.example.test")
    task_id = scraper.table_ctl.task_id_by_row(0)
    payload = {"url": "https://scraper.example.test", "custom": "retained during detection"}
    scraper.on_task_result(task_id, payload)
    pool_limit = QThreadPool.globalInstance().maxThreadCount()
    refreshed = []
    discover = recon.tool_discovery.discover
    monkeypatch.setattr(recon.tool_discovery, "discover", lambda: refreshed.append(True) or discover())
    events = []
    for page in (0, 1, 0):
        window.ui.tabWidget.setCurrentWidget(recon)
        recon.ui.reconPages.setCurrentIndex(page)
        QTimer.singleShot(0, lambda: events.append(True))
        recon.ui.btnRefreshDetection.click()
        qapp.processEvents()
        window.ui.tabWidget.setCurrentWidget(scraper)
        qapp.processEvents()
        assert scraper.isVisible()
    assert len(events) == len(refreshed) == 3
    assert tuple(recon.asset_inventory.observations) == assets
    assert recon.target_model.rowCount() == recon.target_model.selected_count == 1
    assert recon.target_model.data(recon.target_model.index(0, recon.target_model.SCOPE)) == "Unreviewed"
    assert scraper.task_results[task_id] == payload
    assert scraper.task_manager.is_idle()
    assert QThreadPool.globalInstance().maxThreadCount() == pool_limit
    assert [button.text() for button in recon.ui.toolManager.findChildren(QPushButton)] == [
        "Refresh Detection", "Choose Subfinder…", "Choose official archive…",
        "Verify / approve executable", "Manage Scan Profiles…", "Public Target Preflight",
        "Use checked targets", "Review concrete scope", "Inspect capabilities", "Choose Nmap…",
        "Local Self-Test", "Stop", "Public Scan", "Run Selected Profile…", "Run Authorized Profile…",
        "Run Passive Discovery", "Stop Subfinder", "Open results / evidence", "Run / Import History",
    ]
    assert not recon.ui.btnNmapSelfTest.isEnabled()
    assert not recon.ui.btnStopNmap.isEnabled()
