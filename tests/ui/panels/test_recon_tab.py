import pytest
from PySide6.QtWidgets import QFileDialog, QInputDialog, QMessageBox, QTableView


@pytest.fixture
def recon(qapp):
    from ui.panels.recon_tab import ReconTab

    panel = ReconTab()
    yield panel
    panel.close()
    panel.deleteLater()
    qapp.processEvents()


def test_manual_paste_and_invalid_row_feedback(recon):
    recon.ui.manualInput.setText(" EXAMPLE.test ")
    recon.ui.btnAddTarget.click()
    recon.ui.pasteInput.setPlainText("other.test\n--help\nexample.test\n\nthird.test")
    recon.ui.btnAddPaste.click()
    assert isinstance(recon.ui.targetTable, QTableView)
    assert recon.target_model.rowCount() == 3
    assert recon.target_model.selected_count == 0
    assert "Total: 3" in recon.ui.countLabel.text()
    assert "Selected: 0" in recon.ui.countLabel.text()
    assert recon.issue_model.rowCount() == 2
    assert recon.issue_model.data(recon.issue_model.index(0, 0)) == 2
    assert recon.issue_model.data(recon.issue_model.index(1, 0)) == 4
    assert "Duplicates: 1" in recon.ui.importSummary.text()
    assert "Invalid: 2" in recon.ui.importSummary.text()


def test_txt_picker_and_utf8_import(recon, tmp_path, monkeypatch):
    path = tmp_path / "targets.txt"
    path.write_text("EXAMPLE.test\nbücher.de\nhttps://bad.test/path", encoding="utf-8-sig")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: (str(path), ""))
    recon.ui.btnImportTxt.click()
    assert recon.target_model.rowCount() == 2
    assert recon.issue_model.rowCount() == 1
    assert recon.target_model.data(recon.target_model.index(0, recon.target_model.SOURCE)) == "TXT"


def test_csv_requires_explicit_column_choice(recon, tmp_path, monkeypatch):
    path = tmp_path / "targets.csv"
    path.write_text("notes,scope_name\nignore,EXAMPLE.test\nother,other.test", encoding="utf-8")
    choices = []

    def choose(parent, title, label, columns, current, editable):
        choices.append(columns)
        assert not editable
        return "scope_name", True

    monkeypatch.setattr(QInputDialog, "getItem", choose)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: (str(path), ""))
    recon.ui.btnImportCsv.click()
    assert choices == [["notes", "scope_name"]]
    assert recon.target_model.rowCount() == 2
    assert recon.target_model.data(recon.target_model.index(0, recon.target_model.SOURCE)) == "CSV"


def test_csv_column_cancel_and_file_picker_cancel_preserve_targets(recon, tmp_path, monkeypatch):
    recon.ui.manualInput.setText("keep.test")
    recon.ui.btnAddTarget.click()
    path = tmp_path / "targets.csv"
    path.write_text("host\nnew.test", encoding="utf-8")
    monkeypatch.setattr(QInputDialog, "getItem", lambda *args: ("host", False))
    recon.import_file(path, "csv")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: ("", ""))
    recon.ui.btnImportTxt.click()
    assert recon.target_model.rowCount() == 1
    assert recon.target_model.data(recon.target_model.index(0, recon.target_model.HOSTNAME)) == "keep.test"


def test_empty_and_unreadable_imports_do_not_crash(recon, tmp_path):
    for suffix in ("txt", "csv"):
        path = tmp_path / f"empty.{suffix}"
        path.write_text("", encoding="utf-8")
        recon.import_file(path, suffix)
        assert recon.target_model.rowCount() == 0
        assert "Added: 0" in recon.ui.importSummary.text()
    recon.import_file(tmp_path / "missing.txt", "txt")
    assert recon.target_model.rowCount() == 0
    assert recon.issue_model.rowCount() == 1
    assert "Invalid: 1" in recon.ui.importSummary.text()


def test_csv_remote_path_is_rejected_before_header_read(recon, monkeypatch):
    def unexpected_read(*args, **kwargs):
        raise AssertionError("Remote CSV must be rejected before file access")

    monkeypatch.setattr("pathlib.Path.read_text", unexpected_read)
    recon.import_file(r"\\server\share\targets.csv", "csv")
    assert recon.target_model.rowCount() == 0
    assert recon.issue_model.rowCount() == 1


def test_manual_input_cannot_add_multiple_domains_at_once(recon):
    recon.ui.manualInput.setText("one.test\ntwo.test")
    recon.ui.btnAddTarget.click()
    assert recon.target_model.rowCount() == 0
    assert recon.issue_model.rowCount() == 1


def test_clear_requires_confirmation_and_remove_uses_checkboxes(recon, monkeypatch):
    recon.ui.pasteInput.setPlainText("one.test\ntwo.test")
    recon.ui.btnAddPaste.click()
    recon.ui.btnSelectAll.click()
    assert "Selected: 2" in recon.ui.countLabel.text()
    recon.ui.btnDeselectAll.click()
    recon.ui.btnRemoveSelected.click()
    assert recon.target_model.rowCount() == 2
    prompts = []
    monkeypatch.setattr(QMessageBox, "question", lambda *args:
                        prompts.append(args) or QMessageBox.No)
    recon.ui.btnClearTargets.click()
    assert prompts and recon.target_model.rowCount() == 2
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.Yes)
    recon.ui.btnClearTargets.click()
    assert recon.target_model.rowCount() == recon.target_model.selected_count == 0


def test_tool_manager_has_only_unavailable_tools_and_no_run_controls(recon):
    from PySide6.QtWidgets import QLabel, QPushButton

    labels = "\n".join(label.text() for label in recon.findChildren(QLabel))
    for name in ("Subfinder", "ProjectDiscovery httpx", "Nmap", "FFUF"):
        assert f"{name} — Unavailable / not connected" in labels
    assert "authorization" in labels.lower()
    assert "discovered assets" in labels.lower()
    assert not any(button.text().lower() in {"run", "scan", "start"}
                   for button in recon.findChildren(QPushButton))
