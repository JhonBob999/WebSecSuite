"""Actual application startup and Subfinder inspection never launch work."""

import os
from pathlib import Path
import socket
import subprocess
import sys

from PySide6.QtCore import QProcess, QThread, QThreadPool, Qt
from PySide6.QtGui import QDesktopServices, QFont, QFontDatabase
from PySide6.QtNetwork import QDnsLookup


def test_actual_mainwindow_subfinder_startup_is_offline_and_idle(qapp, monkeypatch):
    from core.recon.subfinder_runtime import SubfinderRuntime
    from core.recon.windows_process import WindowsJobProcess

    attempts = []

    def blocked(label):
        def reject(*args, **kwargs):
            attempts.append(label)
            raise AssertionError(f"Startup must not perform {label}.")
        return reject

    for name in ("connect", "connect_ex", "sendto", "send", "sendall"):
        monkeypatch.setattr(socket.socket, name, blocked(f"socket.{name}"))
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
        monkeypatch.setattr(socket, name, blocked(f"DNS.{name}"))
    for name in ("start", "startDetached", "execute", "open", "startCommand"):
        monkeypatch.setattr(QProcess, name, blocked(f"QProcess.{name}"))
    for name in ("system", "popen", "startfile"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, blocked(f"os.{name}"))
    monkeypatch.setattr(subprocess, "Popen", blocked("subprocess.Popen"))
    monkeypatch.setattr(WindowsJobProcess, "start", blocked("native process start"))
    monkeypatch.setattr(QDnsLookup, "lookup", blocked("QDnsLookup.lookup"))
    monkeypatch.setattr(QDesktopServices, "openUrl", blocked("open URL"))
    monkeypatch.setattr(QThread, "start", blocked("QThread.start"))
    monkeypatch.setattr(QThreadPool, "start", blocked("QThreadPool.start"))
    monkeypatch.setattr(QThreadPool, "tryStart", blocked("QThreadPool.tryStart"))

    original_font, font_ids = qapp.font(), []
    if sys.platform == "win32" and not QFontDatabase.families():
        font_dir = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
        for filename in ("segoeui.ttf", "segoeuib.ttf"):
            font_id = QFontDatabase.addApplicationFont(str(font_dir / filename))
            if font_id >= 0:
                font_ids.append(font_id)
        if font_ids:
            qapp.setFont(QFont("Segoe UI", 9))

    from mainwindow import MainWindow

    window = MainWindow()
    recon, scraper = window.recon_tab, window.scraper_tab
    try:
        assert type(recon.subfinder_runtime) is SubfinderRuntime
        window.resize(1366, 768)
        window.show()
        window.ui.tabWidget.setCurrentWidget(recon)
        recon.ui.toolSelector.setCurrentIndex(recon.ui.toolSelector.findData("subfinder"))
        recon.ui.manualInput.setText("example.test")
        recon.ui.btnAddTarget.click()
        recon.target_model.setData(recon.target_model.index(0, 0), Qt.Checked, Qt.CheckStateRole)
        qapp.processEvents()
        assert recon.target_model.selected_count == 1
        assert recon.target_model.index(0, recon.target_model.SCOPE).data() == "Unreviewed"
        assert not recon.ui.btnApproveSubfinder.isEnabled()
        assert not recon.ui.btnRunSubfinder.isEnabled()
        assert not recon.ui.btnStopSubfinder.isEnabled()
        recon.subfinder_controls._confirm_discovery()
        assert not recon.subfinder_runtime.busy
        assert not recon.nmap_runtime.busy
        assert recon.subfinder_runtime._supervisor._jobs == {}
        assert recon.nmap_runtime._supervisor._jobs == {}

        width = recon.ui.reconSplitter.sizes()[1]
        recon.ui.btnToolInspectorToggle.click()
        assert recon.ui.toolManager.isHidden()
        recon.ui.btnToolInspectorToggle.click()
        qapp.processEvents()
        assert not recon.ui.toolManager.isHidden()
        assert abs(recon.ui.reconSplitter.sizes()[1] - width) <= 3
        scroll = recon.ui.toolInspectorScroll
        scroll.ensureWidgetVisible(recon.ui.btnSubfinderHistory)
        qapp.processEvents()
        assert not scroll.horizontalScrollBar().isVisible()
        scroll.verticalScrollBar().setValue(0)
        qapp.processEvents()
        screenshot = os.environ.get("WEBSECSUITE_STARTUP_SCREENSHOT")
        if screenshot:
            assert Path(screenshot).is_absolute()
            assert window.grab().save(screenshot)

        window.ui.tabWidget.setCurrentWidget(scraper)
        qapp.processEvents()
        assert scraper.isVisible()
        assert scraper.task_manager.get_all_tasks() == []
        assert scraper.task_manager.is_idle()
        assert QThreadPool.globalInstance().activeThreadCount() == 0
    finally:
        assert scraper.task_manager.shutdown(timeout_ms=1000) == {"stopped": 0, "joined": 0, "left": []}
        recon.close()
        window.close()
        window.deleteLater()
        qapp.processEvents()
        if font_ids:
            qapp.setFont(original_font)
            for font_id in font_ids:
                QFontDatabase.removeApplicationFont(font_id)
    assert attempts == []
