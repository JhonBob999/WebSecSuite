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
    assert "unavailable" in visible_text
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
