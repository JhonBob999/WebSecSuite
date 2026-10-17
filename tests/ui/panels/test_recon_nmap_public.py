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
        self.profile_executions = []
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

    def start_profile_scan(self, selected_targets, *, profile, profile_store,
                           address, scope_confirmed, confirmed):
        if self.start_error:
            raise self.start_error
        self.profile_executions.append((selected_targets, profile, profile_store,
                                        address, scope_confirmed, confirmed))
        self.public_preflight.clear()
        self.busy, self.can_run = True, False
        self.status = "Selected profile running."
        self.changed.emit()
        return "profile-run-1"

    def start_self_test(self, **kwargs):
        pass

    def stop(self):
        pass

    def shutdown(self, immediate=False):
        pass


@pytest.fixture
def recon(qapp, monkeypatch, tmp_path):
    from ui.panels import recon_tab
    from core.recon.nmap_profile_store import NmapProfileStore

    monkeypatch.setattr(recon_tab, "NmapRuntime", RuntimeDouble)
    monkeypatch.setattr(recon_tab, "NmapProfileStore", lambda: NmapProfileStore(tmp_path / "profiles.json"))
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


def select_profile(recon, profile_id="web-services"):
    combo = recon.ui.nmapProfileSelector
    index = combo.findData(profile_id)
    assert index >= 0
    combo.setCurrentIndex(index)


def saved_custom(recon, **changes):
    from dataclasses import replace
    from core.recon.nmap_profiles import BUILTIN_PROFILES, duplicate_profile

    profile = replace(duplicate_profile(BUILTIN_PROFILES[1]), name="Saved bounded custom", **changes)
    recon.nmap_profile_store.save(profile)
    recon.public_nmap_controls.reload_profiles()
    return profile


def ready_profile(recon, profile_id="web-services"):
    preflight(recon)
    select_profile(recon, profile_id)
    approve_ip(recon)


def test_profile_selector_summary_and_eligibility_stay_offline(recon):
    ui = recon.ui
    assert ui.nmapProfileSelector.count() == 4
    assert not ui.btnNmapRunProfile.isEnabled()
    assert "Public Scan" in ui.nmapProfileEligibility.text()
    select_profile(recon)
    text = ui.nmapProfileSummary.text()
    for expected in ("Web Services", "eight common", "8", "80,443,8000,8080-8081,8443,8888,9443",
                     "TCP connect", "10", "1", "45 s", "60 s", "disabled", "Network impact"):
        assert expected in text
    assert "Eligible" in ui.nmapProfileEligibility.text()
    assert not ui.btnNmapRunProfile.isEnabled()
    assert recon.nmap_runtime.profile_executions == []
    assert recon.nmap_runtime.public_preflight.starts == []


@pytest.mark.parametrize("profile_id", ["standard-tcp", "deep-service-review"])
def test_configuration_only_presets_are_explained_and_disabled(recon, profile_id):
    ready_profile(recon, profile_id)
    assert not recon.ui.btnNmapRunProfile.isEnabled()
    assert "Not executable in R7B-1" in recon.ui.nmapProfileEligibility.text()
    assert recon.ui.btnNmapPublicScan.isEnabled()  # Legacy Quick action remains independent.


@pytest.mark.parametrize("changes", [{"ports": tuple(range(1, 18))}, {"version_detection": True},
                                      {"max_rate": 11}, {"max_retries": 2},
                                      {"host_timeout_seconds": 61, "execution_timeout_seconds": 80},
                                      {"execution_timeout_seconds": 91}])
def test_saved_ineligible_profiles_remain_listed_and_editable(recon, changes):
    profile = saved_custom(recon, **changes)
    ready_profile(recon, profile.profile_id)
    assert recon.ui.nmapProfileSelector.currentText() == profile.name
    assert not recon.ui.btnNmapRunProfile.isEnabled()
    assert "Not executable in R7B-1" in recon.ui.nmapProfileEligibility.text()
    assert recon.nmap_profile_store.profiles == (profile,)


@pytest.mark.parametrize("custom", [False, True])
def test_confirmed_profile_uses_exact_selected_snapshot_once(recon, monkeypatch, custom):
    profile = saved_custom(recon) if custom else None
    ready_profile(recon, profile.profile_id if custom else "web-services")
    prompts = []
    monkeypatch.setattr(QMessageBox, "question", lambda *args: prompts.append(args) or QMessageBox.Yes)
    recon.ui.btnNmapRunProfile.click()
    assert len(recon.nmap_runtime.profile_executions) == 1
    targets, snapshot, store, address, scope, confirmed = recon.nmap_runtime.profile_executions[0]
    assert targets == ("ginandjuice.shop",)
    assert snapshot.profile_id == (profile.profile_id if custom else "web-services")
    assert store is recon.nmap_profile_store
    assert (address, scope, confirmed) == ("8.8.8.8", True, True)
    assert prompts[0][-1] == QMessageBox.No
    for expected in ("ginandjuice.shop", "8.8.8.8", snapshot.name, "8", "45 s", "60 s",
                     "Network impact", "authorized scanning scope"):
        assert expected in prompts[0][2]
    assert not recon.ui.nmapPublicScope.isChecked()
    assert not recon.ui.btnNmapRunProfile.isEnabled()
    assert recon.ui.btnStopNmap.isEnabled()
    assert recon.nmap_runtime.executions == []


def test_profile_decline_clears_scope_and_does_not_run(recon, monkeypatch):
    ready_profile(recon)
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.No)
    recon.ui.btnNmapRunProfile.click()
    assert not recon.ui.nmapPublicScope.isChecked()
    assert recon.nmap_runtime.profile_executions == []


@pytest.mark.parametrize("change", ["profile", "profile-and-back", "ip", "ip-and-back",
                                    "target", "dns-expired", "dns-replaced"])
def test_changed_profile_confirmation_is_never_accepted(recon, monkeypatch, change):
    ready_profile(recon)

    def change_then_confirm(*args):
        if change.startswith("profile"):
            select_profile(recon, "quick-network-discovery")
            if change.endswith("and-back"):
                select_profile(recon)
        elif change.startswith("ip"):
            recon.ui.nmapPublicIp.setCurrentIndex(2)
            if change.endswith("and-back"):
                recon.ui.nmapPublicIp.setCurrentIndex(1)
        elif change == "target":
            recon.target_model.set_all_selected(False)
        elif change == "dns-expired":
            recon.nmap_runtime.public_preflight.is_fresh = False
        else:
            recon.nmap_runtime.public_preflight.finish()
        recon.ui.nmapPublicScope.setChecked(True)
        return QMessageBox.Yes

    monkeypatch.setattr(QMessageBox, "question", change_then_confirm)
    recon.ui.btnNmapRunProfile.click()
    assert recon.nmap_runtime.profile_executions == []
    assert not recon.ui.nmapPublicScope.isChecked()
    assert "changed or expired" in recon.ui.nmapPublicStatus.text()


@pytest.mark.parametrize("change", ["modify", "delete", "corrupt"])
def test_persisted_custom_change_during_confirmation_rejects_run(recon, monkeypatch, change):
    from dataclasses import replace
    from core.recon.nmap_profile_store import NmapProfileStore

    profile = saved_custom(recon)
    ready_profile(recon, profile.profile_id)

    def change_then_confirm(*args):
        disk_store = NmapProfileStore(recon.nmap_profile_store.path)
        if change == "modify":
            disk_store.save(replace(profile, max_rate=9))
        elif change == "delete":
            disk_store.delete(profile.profile_id)
        else:
            disk_store.path.write_text("{}", encoding="utf-8")
        return QMessageBox.Yes

    monkeypatch.setattr(QMessageBox, "question", change_then_confirm)
    recon.ui.btnNmapRunProfile.click()
    assert recon.nmap_runtime.profile_executions == []
    assert not recon.ui.nmapPublicScope.isChecked()
    assert "changed" in recon.ui.nmapPublicStatus.text()


def test_manager_save_refreshes_selector_without_starting_scan(recon, qapp):
    recon.ui.btnManageNmapProfiles.click()
    manager = recon._nmap_profiles_dialog
    manager.ui.btnDuplicate.click()
    manager.ui.nameInput.setText("Saved from manager")
    manager.ui.btnSave.click()
    qapp.processEvents()
    profile = recon.nmap_profile_store.profiles[0]
    assert recon.ui.nmapProfileSelector.findData(profile.profile_id) >= 0
    assert recon.nmap_runtime.profile_executions == []
    assert recon.nmap_runtime.executions == []
    manager.close()


def test_profile_controls_hide_with_tool_and_wrap_in_narrow_inspector(recon, qapp):
    ready_profile(recon)
    ui, scroll = recon.ui, recon.ui.toolInspectorScroll
    ui.reconSplitter.moveSplitter(ui.reconSplitter.width() - 206, 1)
    qapp.processEvents()
    assert not scroll.horizontalScrollBar().isVisible()
    for label in (ui.nmapProfileSummary, ui.nmapProfileEligibility):
        assert label.textFormat() == Qt.PlainText
        assert label.wordWrap()
        assert label.height() >= label.heightForWidth(label.width())
    scroll.ensureWidgetVisible(ui.btnNmapRunProfile)
    qapp.processEvents()
    rectangle = QRect(ui.btnNmapRunProfile.mapTo(scroll.viewport(), QPoint()), ui.btnNmapRunProfile.size())
    assert scroll.viewport().rect().contains(rectangle)
    ui.toolSelector.setCurrentIndex(ui.toolSelector.findData("subfinder"))
    assert not ui.nmapProfileSetup.isVisible()
    assert not ui.btnNmapRunProfile.isVisible()
