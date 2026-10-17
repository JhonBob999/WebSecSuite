import os
import socket
import subprocess
import sys

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6 import QtCore
from PySide6.QtCore import QProcess, QSettings
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QApplication


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Tests must stay offline and must not launch external processes")

    for name in ("connect", "connect_ex", "sendto", "send", "sendall"):
        monkeypatch.setattr(socket.socket, name, blocked)
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
        monkeypatch.setattr(socket, name, blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    for name in ("system", "popen", "startfile", "fork", "forkpty", "posix_spawn", "posix_spawnp",
                 "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
                 "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, blocked)
    for name in ("start", "startDetached", "execute", "open", "startCommand"):
        monkeypatch.setattr(QProcess, name, blocked)
    monkeypatch.setattr(QDesktopServices, "openUrl", blocked)


@pytest.fixture(scope="session")
def qapp(tmp_path_factory):
    settings_dir = tmp_path_factory.mktemp("qt_settings")

    class IsolatedSettings(QSettings):
        def __init__(self, organization="Test", application="Test"):
            path = settings_dir / organization / f"{application}.ini"
            super().__init__(str(path), QSettings.IniFormat)

    patch = pytest.MonkeyPatch()
    patch.setattr(QtCore, "QSettings", IsolatedSettings)
    for name in ("ui.table_controller", "ui.panels.scraper_tab"):
        if name in sys.modules:
            patch.setattr(sys.modules[name], "QSettings", IsolatedSettings)
    app = QApplication.instance() or QApplication([])
    yield app
    patch.undo()


@pytest.fixture
def scraper(qapp):
    from ui.panels.scraper_tab import ScraperTabController

    widget = ScraperTabController()
    yield widget
    widget.task_manager.shutdown(timeout_ms=1000)
    widget.close()
    widget.deleteLater()
    qapp.processEvents()
