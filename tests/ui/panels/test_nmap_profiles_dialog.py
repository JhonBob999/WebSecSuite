"""Nmap profile editing stays offline and separate from executable runtimes."""

import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

import pytest
from PySide6.QtCore import QProcess, QThread, QThreadPool, Qt
from PySide6.QtGui import QDesktopServices, QFont, QFontDatabase
from PySide6.QtNetwork import QDnsLookup
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QPushButton, QScrollArea, QSplitter


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


def make_dialog(tmp_path):
    assert importlib.util.find_spec("dialogs.nmap_profiles_dialog"), "Profile manager dialog is missing"
    from core.recon.nmap_profile_store import NmapProfileStore
    from dialogs.nmap_profiles_dialog import NmapProfilesDialog

    store = NmapProfileStore(tmp_path / "profiles.json")
    return NmapProfilesDialog(store), store


@pytest.fixture
def manager(qapp, tmp_path):
    dialog, store = make_dialog(tmp_path)
    dialog.show()
    qapp.processEvents()
    yield dialog, store
    dialog.ui.btnClose.click()
    if dialog.ui.unsavedPrompt.isVisible():
        dialog.ui.btnDiscardEdits.click()
    dialog.deleteLater()
    qapp.processEvents()


def select(dialog, profile_id):
    tree = dialog.ui.profileList
    for group_index in range(tree.topLevelItemCount()):
        group = tree.topLevelItem(group_index)
        for index in range(group.childCount()):
            item = group.child(index)
            if item.data(0, Qt.UserRole) == profile_id:
                tree.setCurrentItem(item)
                return
    pytest.fail(f"Missing profile {profile_id}")


def test_builtins_are_read_only_and_preview_is_illustrative(manager, qapp):
    dialog, store = manager
    ui = dialog.ui
    assert isinstance(ui.profileSplitter, QSplitter)
    assert isinstance(ui.fieldsScroll, QScrollArea)
    assert ui.profileList.topLevelItem(0).childCount() == 4
    assert ui.nameInput.text() == "Quick Network Discovery"
    assert ui.nameInput.isEnabled() and ui.nameInput.isReadOnly()
    assert ui.portsInput.isEnabled() and ui.portsInput.isReadOnly()
    assert ui.descriptionInput.isEnabled() and ui.descriptionInput.isReadOnly()
    assert ui.networkImpactInput.isEnabled() and ui.networkImpactInput.isReadOnly()
    assert ui.maxRateInput.isEnabled() and ui.maxRateInput.isReadOnly()
    assert not ui.storageNotice.isVisible()
    ui.nameInput.setFocus()
    QTest.keyClicks(ui.nameInput, "Edited built-in")
    ui.portsInput.setFocus()
    QTest.keyClicks(ui.portsInput, "22")
    ui.maxRateInput.setFocus()
    QTest.keyClick(ui.maxRateInput, Qt.Key_Up)
    assert ui.nameInput.text() == "Quick Network Discovery"
    assert ui.portsInput.text() == "80,443,8080,8443"
    assert ui.maxRateInput.value() == 10
    assert not ui.versionDetection.isEnabled()
    assert not ui.btnSave.isEnabled()
    assert not ui.btnDelete.isEnabled()
    assert ui.preview.isReadOnly()
    assert "<approved-ip>" in ui.preview.toPlainText()
    assert "80,443,8080,8443" in ui.preview.toPlainText()
    assert "configuration-only" in ui.configurationNotice.text().lower()
    assert "existing Quick Network Discovery" in ui.configurationNotice.text()
    assert not any("run" == button.text().lower() for button in dialog.findChildren(QPushButton))
    select(dialog, "deep-service-review")
    qapp.processEvents()
    assert ui.versionDetection.isChecked()
    assert "-sV" in ui.preview.toPlainText()
    assert "R7B" in ui.versionNotice.text()
    assert "--max-rate" in ui.versionNotice.text()
    assert store.profiles == ()


def test_duplicate_save_rename_reload_and_delete_custom(manager, tmp_path):
    dialog, store = manager
    ui = dialog.ui
    ui.btnDuplicate.click()
    assert ui.nameInput.isEnabled()
    assert not ui.nameInput.isReadOnly()
    assert not ui.maxRateInput.isReadOnly()
    assert ui.btnSave.isEnabled()
    assert not ui.btnDelete.isEnabled()
    assert store.profiles == ()
    ui.nameInput.setText("My Web Review")
    ui.portsInput.setText("8443,80,443,80")
    ui.btnSave.click()
    assert len(store.profiles) == 1
    saved = store.profiles[0]
    assert saved.name == "My Web Review"
    assert saved.ports == (80, 443, 8443)
    assert not saved.is_builtin
    assert ui.portsInput.text() == "80,443,8443"
    assert ui.btnDelete.isEnabled()
    ui.nameInput.setText("Renamed Web Review")
    ui.btnSave.click()
    assert store.profiles[0].profile_id == saved.profile_id
    assert store.profiles[0].name == "Renamed Web Review"
    from core.recon.nmap_profile_store import NmapProfileStore
    assert NmapProfileStore(tmp_path / "profiles.json").profiles == store.profiles
    ui.btnDelete.click()
    assert store.profiles == ()
    assert ui.nameInput.text() == "Quick Network Discovery"
    assert ui.nameInput.isReadOnly()


@pytest.mark.parametrize("bad_ports", ["", "0", "--script vuln", "80;echo injected", "1-1025"])
def test_invalid_ports_clear_preview_and_disable_save(manager, bad_ports):
    dialog, store = manager
    dialog.ui.btnDuplicate.click()
    dialog.ui.portsInput.setText(bad_ports)
    assert dialog.ui.validationLabel.text()
    assert not dialog.ui.btnSave.isEnabled()
    assert "<approved-ip>" not in dialog.ui.preview.toPlainText()
    assert store.profiles == ()


def test_name_and_timeout_errors_use_inline_validation(manager):
    dialog, store = manager
    ui = dialog.ui
    ui.btnDuplicate.click()
    ui.nameInput.setText("")
    assert ui.validationLabel.text()
    assert not ui.btnSave.isEnabled()
    ui.nameInput.setText("Valid name")
    ui.hostTimeoutInput.setValue(40)
    ui.executionTimeoutInput.setValue(40)
    assert ui.validationLabel.text()
    assert not ui.btnSave.isEnabled()
    ui.executionTimeoutInput.setValue(41)
    assert not ui.validationLabel.text()
    assert ui.btnSave.isEnabled()
    assert store.profiles == ()


def test_unsaved_selection_reset_and_close_require_an_explicit_choice(manager, qapp):
    dialog, store = manager
    ui = dialog.ui
    ui.btnDuplicate.click()
    ui.btnSave.click()
    saved = store.profiles[0]
    ui.portsInput.setText("22,443")
    select(dialog, "web-services")
    qapp.processEvents()
    assert ui.unsavedPrompt.isVisible()
    assert ui.portsInput.text() == "22,443"
    assert ui.profileList.currentItem().data(0, Qt.UserRole) == saved.profile_id
    ui.btnKeepEditing.click()
    assert not ui.unsavedPrompt.isVisible()
    ui.btnReset.click()
    assert ui.unsavedPrompt.isVisible()
    ui.btnDiscardEdits.click()
    assert ui.portsInput.text() == "80,443,8080,8443"
    assert not ui.btnReset.isEnabled()
    ui.nameInput.setText("Keep this draft")
    dialog.close()
    qapp.processEvents()
    assert dialog.isVisible()
    assert ui.unsavedPrompt.isVisible()
    ui.btnKeepEditing.click()
    assert dialog.isVisible()
    ui.btnClose.click()
    ui.btnSaveEdits.click()
    qapp.processEvents()
    assert not dialog.isVisible()
    assert store.profiles[0].name == "Keep this draft"


def test_discard_on_selection_preserves_saved_profile_and_escape_protects_draft(manager, qapp):
    dialog, store = manager
    ui = dialog.ui
    ui.btnDuplicate.click()
    ui.nameInput.setText("Saved custom")
    ui.btnSave.click()
    saved = store.profiles[0]
    ui.nameInput.setText("Unsaved rename")
    select(dialog, "web-services")
    ui.btnDiscardEdits.click()
    assert ui.nameInput.text() == "Web Services"
    assert store.profiles[0] == saved
    ui.btnDuplicate.click()
    dialog.reject()
    qapp.processEvents()
    assert dialog.isVisible()
    assert ui.unsavedPrompt.isVisible()
    ui.btnDiscardEdits.click()
    qapp.processEvents()
    assert not dialog.isVisible()
    assert store.profiles == (saved,)


def test_corrupt_storage_keeps_builtins_and_edit_preview_without_writes(qapp, tmp_path):
    path = tmp_path / "profiles.json"
    path.write_bytes(b"broken config")
    dialog, store = make_dialog(tmp_path)
    try:
        assert not store.writable
        assert dialog.ui.storageNotice.text()
        assert not dialog.ui.storageNotice.isHidden()
        assert dialog.ui.profileList.topLevelItem(0).childCount() == 4
        dialog.ui.btnDuplicate.click()
        dialog.ui.portsInput.setText("443")
        assert "<approved-ip>" in dialog.ui.preview.toPlainText()
        assert not dialog.ui.btnSave.isEnabled()
        assert not dialog.ui.btnDelete.isEnabled()
        assert path.read_bytes() == b"broken config"
    finally:
        dialog.deleteLater()
        qapp.processEvents()


def test_discarded_draft_cannot_reappear_when_cached_manager_reopens(manager, qapp):
    dialog, store = manager
    ui = dialog.ui
    ui.btnDuplicate.click()
    ui.nameInput.setText("Discard this unsaved copy")
    ui.btnClose.click()
    ui.btnDiscardEdits.click()
    dialog.show()
    qapp.processEvents()
    assert not ui.unsavedPrompt.isVisible()
    assert ui.profileList.currentItem() is not None
    assert ui.nameInput.text() == "Quick Network Discovery"
    assert ui.nameInput.isReadOnly()
    assert not ui.btnDelete.isEnabled()
    assert store.profiles == ()


def test_ordinary_save_clears_pending_choice_before_reopening(manager, qapp):
    dialog, store = manager
    ui = dialog.ui
    ui.btnDuplicate.click()
    ui.nameInput.setText("Saved draft")
    select(dialog, "web-services")
    assert ui.unsavedPrompt.isVisible()
    ui.btnSave.click()
    assert not ui.unsavedPrompt.isVisible()
    assert ui.nameInput.text() == "Saved draft"
    ui.btnClose.click()
    dialog.show()
    qapp.processEvents()
    assert not ui.unsavedPrompt.isVisible()
    assert ui.nameInput.text() == "Saved draft"
    assert store.profiles[0].name == "Saved draft"


def test_storage_write_failure_keeps_edits_visible_and_blocks_pending_close(manager, monkeypatch, qapp):
    from core.recon.nmap_profile_store import ProfileStorageError

    dialog, store = manager
    ui = dialog.ui
    ui.btnDuplicate.click()
    ui.nameInput.setText("Do not lose these edits")

    def fail_save(profile):
        raise ProfileStorageError("Local profile directory is not writable.")

    monkeypatch.setattr(store, "save", fail_save)
    ui.btnClose.click()
    ui.btnSaveEdits.click()
    qapp.processEvents()
    assert dialog.isVisible()
    assert ui.unsavedPrompt.isVisible()
    assert "not writable" in ui.storageNotice.text()
    assert ui.nameInput.text() == "Do not lose these edits"
    assert ui.btnSave.isEnabled()
    assert store.profiles == ()


def test_empty_storage_notice_is_hidden_and_success_clears_errors(manager, monkeypatch):
    from core.recon.nmap_profile_store import ProfileStorageError

    dialog, store = manager
    ui = dialog.ui
    assert ui.storageNotice.isHidden()
    save = store.save

    def fail_save(profile):
        raise ProfileStorageError("Temporary write failure.")

    ui.btnDuplicate.click()
    monkeypatch.setattr(store, "save", fail_save)
    ui.btnSave.click()
    assert ui.storageNotice.isVisible()
    monkeypatch.setattr(store, "save", save)
    ui.btnSave.click()
    assert len(store.profiles) == 1
    assert ui.storageNotice.isHidden()


def test_narrow_layout_keeps_actions_visible_and_fields_scrollable(manager, qapp):
    dialog, _ = manager
    ui = dialog.ui
    assert ui.configurationNotice.height() <= ui.configurationNotice.heightForWidth(ui.configurationNotice.width()) + 2
    screenshot_dir = os.environ.get("NMAP_PROFILES_SCREENSHOT_DIR")
    if screenshot_dir:
        folder = Path(screenshot_dir)
        folder.mkdir(parents=True, exist_ok=True)
        assert dialog.grab().save(str(folder / "nmap-profiles.png"))
    dialog.resize(700, 480)
    qapp.processEvents()
    assert dialog.width() == 700
    assert not ui.fieldsScroll.horizontalScrollBar().isVisible()
    assert ui.fieldsScroll.verticalScrollBar().isVisible()
    for button in (ui.btnDuplicate, ui.btnSave, ui.btnDelete, ui.btnReset, ui.btnClose):
        assert button.isVisible()
        assert dialog.rect().contains(button.geometry())
    ui.fieldsScroll.ensureWidgetVisible(ui.preview)
    qapp.processEvents()
    assert ui.fieldsScroll.verticalScrollBar().value() > 0
    if screenshot_dir:
        assert dialog.grab().save(str(folder / "nmap-profiles-narrow.png"))


def test_profile_startup_and_editing_never_start_threads_or_runtimes(qapp, tmp_path, monkeypatch):
    assert importlib.util.find_spec("core.recon.nmap_profile_store"), "Profile store is missing"
    from core.recon import nmap_profile_store
    from core.recon.nmap_profiles import BUILTIN_PROFILES, duplicate_profile
    from core.recon.process_supervisor import ProcessSupervisor
    from core.recon.windows_process import WindowsJobProcess
    from mainwindow import MainWindow

    config_path = tmp_path / "startup-profiles.json"
    nmap_profile_store.NmapProfileStore(config_path).save(duplicate_profile(BUILTIN_PROFILES[0], "Startup custom"))
    monkeypatch.setattr(nmap_profile_store, "default_profile_path", lambda: config_path)

    attempts = []

    def blocked(label):
        def reject(*args, **kwargs):
            attempts.append(label)
            raise AssertionError(f"Profile startup and editing must not perform {label}.")
        return reject

    for target, names in (
        (socket.socket, ("connect", "connect_ex", "sendto", "send", "sendall")),
        (socket, ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr")),
        (subprocess, ("Popen",)),
        (os, ("system", "popen", "startfile")),
        (QProcess, ("start", "startDetached", "execute", "open", "startCommand")),
        (QDnsLookup, ("lookup",)), (QDesktopServices, ("openUrl",)),
        (WindowsJobProcess, ("start",)), (QThread, ("start",)),
        (QThreadPool, ("start", "tryStart")), (threading.Thread, ("start",)),
        (ProcessSupervisor, ("submit",)),
    ):
        for name in names:
            if hasattr(target, name):
                monkeypatch.setattr(target, name, blocked(f"{target.__name__}.{name}"))
    window = MainWindow()
    try:
        window.show()
        window.ui.tabWidget.setCurrentWidget(window.recon_tab)
        qapp.processEvents()
        recon = window.recon_tab
        assert recon.nmap_profile_store.profiles[0].name == "Startup custom"
        assert not recon.nmap_runtime.busy
        assert not recon.subfinder_runtime.busy
        assert not recon.nmap_runtime.public_preflight.busy
        assert window.scraper_tab.task_manager.is_idle()
        assert window.scraper_tab.task_manager.get_all_tasks() == []
        ui = recon.ui
        assert ui.btnManageNmapProfiles.isVisible()
        ui.btnManageNmapProfiles.click()
        qapp.processEvents()
        from dialogs.nmap_profiles_dialog import NmapProfilesDialog
        manager = recon.findChild(NmapProfilesDialog)
        assert manager is not None and manager.isVisible()
        assert manager.store is recon.nmap_profile_store
        manager.ui.btnDuplicate.click()
        manager.ui.portsInput.setText("443,8443")
        manager.ui.btnSave.click()
        manager.ui.btnClose.click()
        qapp.processEvents()
        assert not manager.isVisible()
        for tool_id in ("subfinder", "httpx", "ffuf", "nmap"):
            ui.toolSelector.setCurrentIndex(ui.toolSelector.findData(tool_id))
            qapp.processEvents()
            assert ui.btnManageNmapProfiles.isVisible() == (tool_id == "nmap")
        assert not recon.nmap_runtime.busy
        assert not recon.subfinder_runtime.busy
        assert window.scraper_tab.task_manager.is_idle()
        assert QThreadPool.globalInstance().activeThreadCount() == 0
    finally:
        window.scraper_tab.task_manager.shutdown(timeout_ms=1000)
        window.close()
        window.deleteLater()
        qapp.processEvents()
    assert attempts == []
