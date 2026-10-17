"""Public Nmap UI gates use injected offline DNS and process state."""

import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QObject, QPoint, QRect, Qt, Signal
from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QMessageBox


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


class PreflightDouble(QObject):
    changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.observation = None
        self.busy = False
        self.is_fresh = False
        self.status = "Select ginandjuice.shop and start preflight."
        self.warnings = ()
        self.starts = []

    def start(self, selected_targets):
        self.starts.append(selected_targets)
        self.busy = True
        self.status = "Resolving selected hostname…"
        self.changed.emit()

    def finish(self, addresses=("8.8.8.8", "1.1.1.1")):
        self.observation = SimpleNamespace(
            hostname="ginandjuice.shop", ipv4_addresses=addresses,
            cnames=("shared.example.test",), observed_at="2026-10-17T12:00:00Z",
            resolver="Injected offline resolver",
        )
        self.busy, self.is_fresh = False, True
        self.status = "DNS complete. Select one IP and confirm authorized scope."
        self.warnings = ("Multiple addresses may indicate shared infrastructure; this is not authoritative.",)
        self.changed.emit()

    def clear(self):
        self.observation = None
        self.busy = self.is_fresh = False
        self.warnings = ()
        self.status = "Preflight required."
        self.changed.emit()


class RuntimeDouble(QObject):
    changed = Signal()
    inventory_changed = Signal()

    def __init__(self, inventory, parent=None):
        super().__init__(parent)
        self.public_preflight = PreflightDouble(self)
        self.public_preflight.changed.connect(self.changed)
        self.busy = False
        self.can_run = True
        self.status = "Ready for confirmed Nmap run."
        self.executable_path = "C:/Tools/Nmap/nmap.exe"
        self.version = "7.95"
        self.safety_reason = ""
        self.executions = []
        self.start_error = None

    def start_public_scan(self, selected_targets, *, address, scope_confirmed, confirmed):
        if self.start_error:
            raise self.start_error
        self.executions.append((selected_targets, address, scope_confirmed, confirmed))
        self.public_preflight.clear()
        self.busy, self.can_run = True, False
        self.status = "Quick Network Discovery running."
        self.changed.emit()
        return "public-run-1"

    def approve_executable(self, path):
        pass

    def start_self_test(self, **kwargs):
        pass

    def stop(self):
        pass

    def shutdown(self, immediate=False):
        pass


@pytest.fixture
def recon(qapp, monkeypatch):
    from ui.panels import recon_tab

    monkeypatch.setattr(recon_tab, "NmapRuntime", RuntimeDouble)
    panel = recon_tab.ReconTab()
    panel.resize(1366, 768)
    panel.show()
    yield panel
    panel.close()
    panel.deleteLater()
    qapp.processEvents()


def select_target(recon, hostname="ginandjuice.shop"):
    recon.ui.manualInput.setText(hostname)
    recon.ui.btnAddTarget.click()
    row = recon.target_model.rowCount() - 1
    recon.target_model.setData(recon.target_model.index(row, 0), Qt.Checked, Qt.CheckStateRole)


def preflight(recon, addresses=("8.8.8.8", "1.1.1.1")):
    select_target(recon)
    recon.ui.btnNmapPreflight.click()
    recon.nmap_runtime.public_preflight.finish(addresses)


def approve_ip(recon, index=1):
    recon.ui.nmapPublicIp.setCurrentIndex(index)
    recon.ui.nmapPublicScope.setChecked(True)


def test_dns_only_starts_from_explicit_preflight_and_checked_exact_target(recon):
    ui, service = recon.ui, recon.nmap_runtime.public_preflight
    assert not ui.btnNmapPreflight.isEnabled()
    assert not ui.btnNmapPublicScan.isEnabled()
    select_target(recon, "other.example.test")
    assert not ui.btnNmapPreflight.isEnabled()
    recon.target_model.set_all_selected(False)
    select_target(recon)
    ui.targetTable.selectRow(0)  # Highlighting another row is not checked selection.
    assert ui.btnNmapPreflight.isEnabled()
    assert service.starts == []
    ui.btnNmapPreflight.click()
    assert service.starts == [("ginandjuice.shop",)]
    assert not ui.btnNmapPreflight.isEnabled()
    assert not ui.btnNmapPublicScan.isEnabled()


@pytest.mark.parametrize("addresses", [("8.8.8.8",), ("8.8.8.8", "1.1.1.1")])
def test_dns_never_chooses_an_ip_or_approves_scope_automatically(recon, addresses):
    preflight(recon, addresses)
    ui = recon.ui
    assert ui.nmapPublicIp.currentData() is None
    assert ui.nmapPublicIp.count() == len(addresses) + 1
    assert not ui.nmapPublicScope.isChecked()
    assert not ui.btnNmapPublicScan.isEnabled()
    ui.nmapPublicIp.setCurrentIndex(1)
    assert not ui.btnNmapPublicScan.isEnabled()
    ui.nmapPublicScope.setChecked(True)
    assert ui.btnNmapPublicScan.isEnabled()
    assert "ginandjuice.shop" in ui.nmapPublicTarget.text()
    assert all(address in ui.nmapPublicDns.text() for address in addresses)
    assert "shared.example.test" in ui.nmapPublicDns.text()
    assert "not authoritative" in ui.nmapPublicWarning.text()


def test_ip_change_and_target_change_clear_scope_and_preflight(recon):
    preflight(recon)
    approve_ip(recon)
    recon.ui.nmapPublicIp.setCurrentIndex(2)
    assert not recon.ui.nmapPublicScope.isChecked()
    assert not recon.ui.btnNmapPublicScan.isEnabled()
    approve_ip(recon)
    recon.target_model.set_all_selected(False)
    assert recon.nmap_runtime.public_preflight.observation is None
    assert recon.ui.nmapPublicIp.currentData() is None
    assert not recon.ui.nmapPublicScope.isChecked()
    assert not recon.ui.btnNmapPublicScan.isEnabled()


def test_multiple_selected_targets_and_expired_preflight_block_execution(recon):
    preflight(recon)
    approve_ip(recon)
    recon.nmap_runtime.public_preflight.is_fresh = False
    recon.nmap_runtime.public_preflight.changed.emit()
    assert not recon.ui.btnNmapPublicScan.isEnabled()
    select_target(recon, "other.example.test")
    assert not recon.ui.btnNmapPreflight.isEnabled()
    assert not recon.ui.btnNmapPublicScan.isEnabled()


def test_public_confirmation_is_default_no_and_decline_requires_new_scope_check(recon, monkeypatch):
    preflight(recon)
    approve_ip(recon)
    prompts = []
    monkeypatch.setattr(QMessageBox, "question", lambda *args: prompts.append(args) or QMessageBox.No)
    recon.ui.btnNmapPublicScan.click()
    assert recon.nmap_runtime.executions == []
    assert prompts[0][-1] == QMessageBox.No
    for text in ("ginandjuice.shop", "8.8.8.8", "Quick Network Discovery", "80, 443, 8080, 8443", "TCP connect"):
        assert text in prompts[0][2]
    assert not recon.ui.nmapPublicScope.isChecked()
    assert not recon.ui.btnNmapPublicScan.isEnabled()


def test_confirmed_public_scan_passes_exact_selection_and_one_ip_once(recon, monkeypatch):
    preflight(recon)
    approve_ip(recon)
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.Yes)
    recon.ui.btnNmapPublicScan.click()
    assert recon.nmap_runtime.executions == [(("ginandjuice.shop",), "8.8.8.8", True, True)]
    assert not recon.ui.nmapPublicScope.isChecked()
    assert not recon.ui.btnNmapPublicScan.isEnabled()
    assert recon.ui.btnStopNmap.isEnabled()
    assert recon.target_model.index(0, recon.target_model.SCOPE).data() == "Unreviewed"


def test_target_change_inside_confirmation_cannot_launch(recon, monkeypatch):
    preflight(recon)
    approve_ip(recon)

    def change_then_confirm(*args):
        recon.target_model.set_all_selected(False)
        return QMessageBox.Yes

    monkeypatch.setattr(QMessageBox, "question", change_then_confirm)
    recon.ui.btnNmapPublicScan.click()
    assert recon.nmap_runtime.executions == []
    assert not recon.ui.btnNmapPublicScan.isEnabled()


def test_public_controls_survive_inspector_toggle_and_are_hidden_for_other_tools(recon, qapp):
    preflight(recon)
    approve_ip(recon)
    for tool in ("subfinder", "httpx", "ffuf"):
        recon.ui.toolSelector.setCurrentIndex(recon.ui.toolSelector.findData(tool))
        assert not recon.ui.nmapPublicSetup.isVisible()
        assert not recon.ui.btnNmapPublicScan.isVisible()
        assert not recon.ui.nmapPublicSummary.isVisible()
    recon.ui.toolSelector.setCurrentIndex(recon.ui.toolSelector.findData("nmap"))
    recon.ui.btnToolInspectorToggle.click()
    recon.ui.btnToolInspectorToggle.click()
    qapp.processEvents()
    assert recon.ui.btnNmapPublicScan.isEnabled()
    assert recon.nmap_runtime.public_preflight.starts == [("ginandjuice.shop",)]
    assert recon.nmap_runtime.executions == []


def test_public_runtime_rejection_resets_scope_and_shows_error(recon, monkeypatch):
    preflight(recon)
    approve_ip(recon)
    recon.nmap_runtime.start_error = ValueError("Executable changed; verify again.")
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.Yes)
    recon.ui.btnNmapPublicScan.click()
    assert recon.nmap_runtime.executions == []
    assert not recon.ui.nmapPublicScope.isChecked()
    assert "Executable changed" in recon.ui.nmapPublicStatus.text()


def test_failed_dns_and_missing_verified_runtime_keep_public_scan_disabled(recon):
    select_target(recon)
    recon.ui.btnNmapPreflight.click()
    service = recon.nmap_runtime.public_preflight
    service.busy = False
    service.status = "DNS resolution failed; no IP is authorized."
    service.changed.emit()
    assert "DNS resolution failed" in recon.ui.nmapPublicStatus.text()
    assert not recon.ui.btnNmapPublicScan.isEnabled()
    service.finish()
    approve_ip(recon)
    recon.nmap_runtime.can_run = False
    recon.nmap_runtime.changed.emit()
    assert not recon.ui.btnNmapPublicScan.isEnabled()
    assert recon.nmap_runtime.executions == []


def test_new_dns_answer_requires_new_ip_selection_and_scope_confirmation(recon):
    preflight(recon)
    approve_ip(recon)
    recon.nmap_runtime.public_preflight.finish(("9.9.9.9",))
    assert recon.ui.nmapPublicIp.currentData() is None
    assert not recon.ui.nmapPublicScope.isChecked()
    assert not recon.ui.btnNmapPublicScan.isEnabled()


def test_ip_change_inside_confirmation_cannot_launch(recon, monkeypatch):
    preflight(recon)
    approve_ip(recon)

    def change_then_confirm(*args):
        recon.ui.nmapPublicIp.setCurrentIndex(2)
        recon.ui.nmapPublicScope.setChecked(True)
        return QMessageBox.Yes

    monkeypatch.setattr(QMessageBox, "question", change_then_confirm)
    recon.ui.btnNmapPublicScan.click()
    assert recon.nmap_runtime.executions == []
    assert not recon.ui.nmapPublicScope.isChecked()


def test_public_preflight_wraps_in_narrow_inspector_and_actions_remain_reachable(recon, qapp):
    preflight(recon)
    service = recon.nmap_runtime.public_preflight
    service.observation.cnames = ("long-cname-component." * 8 + "example.test",)
    service.changed.emit()
    recon.ui.reconSplitter.moveSplitter(recon.ui.reconSplitter.width() - 206, 1)
    qapp.processEvents()
    ui, scroll = recon.ui, recon.ui.toolInspectorScroll
    assert not scroll.horizontalScrollBar().isVisible(), [
        (name, getattr(ui, name).minimumSizeHint().toTuple(), getattr(ui, name).size().toTuple())
        for name in ("nmapPublicSetup", "nmapPublicDns", "nmapPublicIp", "nmapPublicScope", "btnNmapPreflight")
    ]
    labels = (ui.nmapPublicTarget, ui.nmapPublicDns, ui.nmapPublicSelectedIp,
              ui.nmapPublicWarning, ui.nmapPublicScopeStatus, ui.nmapPublicStatus,
              ui.nmapPublicSummary)
    for label in labels:
        assert label.textFormat() == Qt.PlainText
        assert label.wordWrap()
        assert label.height() >= label.heightForWidth(label.width())
        scroll.ensureWidgetVisible(label)
        qapp.processEvents()
        rectangle = QRect(label.mapTo(scroll.viewport(), QPoint()), label.size())
        assert scroll.viewport().rect().intersects(rectangle)
    for action in (ui.btnNmapPreflight, ui.nmapPublicIp, ui.nmapPublicScope, ui.btnNmapPublicScan):
        scroll.ensureWidgetVisible(action)
        qapp.processEvents()
        rectangle = QRect(action.mapTo(scroll.viewport(), QPoint()), action.size())
        assert scroll.viewport().rect().contains(rectangle)
