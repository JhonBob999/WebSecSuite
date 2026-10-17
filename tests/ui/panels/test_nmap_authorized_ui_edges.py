"""Authorized scan UI rejects stale capabilities and preserves rejection context."""

from dataclasses import replace
from types import SimpleNamespace

import pytest


@pytest.fixture
def prepared_panel(qapp, tmp_path, monkeypatch):
    from core.recon.nmap_capabilities import NmapCapabilities
    from core.recon.nmap_profile_store import NmapProfileStore
    from core.recon.nmap_profiles import configuration_arguments
    from core.recon import nmap_runtime
    from ui.panels import recon_tab

    monkeypatch.setattr(recon_tab, "NmapProfileStore", lambda: NmapProfileStore(tmp_path / "profiles.json"))
    monkeypatch.setattr(nmap_runtime, "process_safety_status", lambda: (True, ""))
    panel = recon_tab.ReconTab()
    runtime = panel.nmap_runtime
    runtime._tool = SimpleNamespace(executable_path="C:/Tools/Nmap/nmap.exe", version="7.95", sha256="a" * 64)
    monkeypatch.setattr(runtime, "capabilities", lambda: NmapCapabilities(True, True, runtime.version, False, False, True, False))
    monkeypatch.setattr(runtime, "authorized_arguments", lambda scope, profile: (*configuration_arguments(profile), *scope.targets))
    controls = panel.authorized_nmap_controls
    controls._inspect_capabilities()
    panel.ui.nmapScopeInput.setPlainText("127.0.0.1")
    controls._preflight()
    panel.ui.nmapScopeApproval.setChecked(True)
    assert panel.ui.btnNmapAuthorizedRun.isEnabled()
    yield panel
    panel.close()
    panel.deleteLater()
    qapp.processEvents()


def test_executable_change_requires_new_capability_inspection(prepared_panel):
    panel = prepared_panel
    runtime = panel.nmap_runtime
    runtime._tool = SimpleNamespace(executable_path="C:/Other/Nmap/nmap.exe", version="7.96", sha256="b" * 64)
    runtime.changed.emit()
    assert not panel.ui.btnNmapAuthorizedRun.isEnabled()
    assert not panel.ui.nmapScopeApproval.isChecked()
    assert panel.authorized_nmap_controls._caps is None
    assert "7.95" not in panel.ui.nmapCapabilities.text()


def test_reverification_same_path_and_version_still_requires_fresh_capabilities(prepared_panel):
    panel = prepared_panel
    panel.nmap_runtime._tool = SimpleNamespace(executable_path="C:/Tools/Nmap/nmap.exe", version="7.95", sha256="b" * 64)
    panel.nmap_runtime.changed.emit()
    assert not panel.ui.btnNmapAuthorizedRun.isEnabled()
    assert panel.authorized_nmap_controls._caps is None


def test_legacy_action_cannot_silently_execute_syn_as_connect():
    from core.recon.nmap_profiles import BUILTIN_PROFILES, duplicate_profile
    from core.recon.nmap_profile_execution import execution_reasons

    profile = replace(duplicate_profile(BUILTIN_PROFILES[0]), technique="tcp-syn")
    assert any("TCP Connect" in reason or "TCP connect" in reason for reason in execution_reasons(profile))


def test_scope_changed_during_confirmation_does_not_launch_and_keeps_reason(prepared_panel, monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    panel = prepared_panel

    def changed_while_prompt_open(*args):
        panel.ui.nmapScopeInput.setPlainText("127.0.0.2")
        return QMessageBox.Yes

    monkeypatch.setattr(QMessageBox, "question", changed_while_prompt_open)
    monkeypatch.setattr(panel.nmap_runtime, "start_authorized_scan", lambda *a, **k: pytest.fail("Changed scope must not execute"))
    panel.authorized_nmap_controls._confirm()
    assert "rejected" in panel.ui.nmapAuthorizedStatus.text().lower()
    assert "changed" in panel.ui.nmapAuthorizedStatus.text().lower()
    assert panel.authorized_nmap_controls.preflight.scope is None


def test_changed_saved_profile_rejection_survives_preflight_cleanup(prepared_panel, monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    panel = prepared_panel
    monkeypatch.setattr(QMessageBox, "question", lambda *a: QMessageBox.Yes)

    def changed_profile(profile):
        raise ValueError("Saved profile changed during confirmation.")

    monkeypatch.setattr(panel.public_nmap_controls, "_saved_profile_unchanged", changed_profile)
    monkeypatch.setattr(panel.nmap_runtime, "start_authorized_scan", lambda *a, **k: pytest.fail("Changed saved profile must not execute"))
    panel.authorized_nmap_controls._confirm()
    assert "Saved profile changed" in panel.ui.nmapAuthorizedStatus.text()
    assert panel.authorized_nmap_controls.preflight.scope is None


def test_version_probes_need_their_explicit_warning_confirmation(prepared_panel, monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    panel = prepared_panel
    panel.ui.nmapProfileSelector.setCurrentIndex(panel.ui.nmapProfileSelector.findData("deep-service-review"))
    panel.authorized_nmap_controls._preflight()
    panel.ui.nmapScopeApproval.setChecked(True)
    assert panel.ui.btnNmapAuthorizedRun.isEnabled()
    prompts = []
    monkeypatch.setattr(panel.nmap_runtime, "implicit_version_scripts",
        lambda: (SimpleNamespace(script_id="version-test", high_impact=False),))
    monkeypatch.setattr(QMessageBox, "warning", lambda *args: prompts.append(args[2]) or QMessageBox.No)
    monkeypatch.setattr(QMessageBox, "question", lambda *a: pytest.fail("Declined probes must not proceed"))
    monkeypatch.setattr(panel.nmap_runtime, "start_authorized_scan", lambda *a, **k: pytest.fail("Declined probes must not execute"))
    panel.authorized_nmap_controls._confirm()
    assert len(prompts) == 1 and "NSE version engine" in prompts[0]
    assert "version-test" in prompts[0]
    assert not panel.ui.nmapScopeApproval.isChecked()
