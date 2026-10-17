import os
import socket
import sys

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6 import QtCore
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Tests must not make real network connections")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)


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
