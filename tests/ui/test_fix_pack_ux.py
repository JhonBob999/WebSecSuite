import json
from pathlib import Path

import pytest
from PySide6.QtWidgets import QFileDialog, QMessageBox

from core.metadata import build_task_entity_key
from core.paths import project_root
from dialogs.data_preview_dialog import DataPreviewDialog
from dialogs.results_viewer_dialog import UniversalViewerDialog
from ui.constants import Col


def test_startup_has_empty_task_table(scraper):
    assert scraper.ui.taskTable.rowCount() == 0
    assert scraper.task_manager.get_all_tasks() == []
    assert scraper.task_results == {}
    assert scraper.task_manager.is_idle()


def test_results_summary_does_not_serialize_full_payload(scraper):
    class Evidence:
        def __str__(self):
            raise AssertionError("Full payload was serialized for a tooltip")

    scraper.add_task_row("https://example.test")
    row = scraper.ui.taskTable.rowCount() - 1
    scraper.table_ctl.set_results_cell(row, payload={
        "status_code": 200, "content_len": 2048,
        "timings": {"request_ms": 12}, "redirect_chain": [], "evidence": Evidence(),
    })
    item = scraper.ui.taskTable.item(row, Col.Results)
    assert item.text() == "200 · 2.0KB · 12 ms · r=0"
    assert item.toolTip() == ""


def test_data_cell_tooltips_clear_while_url_annotations_survive(scraper):
    scraper.add_task_row("https://example.test")
    table = scraper.ui.taskTable
    row = table.rowCount() - 1
    task_id = scraper.table_ctl.task_id_by_row(row)
    scraper.annotation_store.upsert_annotation(build_task_entity_key(task_id), note="review endpoint")
    scraper.actions.refresh_task_annotation_visuals()
    for col in range(1, table.columnCount()):
        scraper.table_ctl.ensure_item(row, col).setToolTip("old large tooltip")
    scraper.set_status_cell(row, "Done")
    scraper.set_code_cell(row, 200)
    scraper.set_time_cell(row, 12)
    scraper.table_ctl.set_results_cell(row, summary="summary", payload_short="large details")
    scraper.set_cookies_cell(row, {"cookies_count": 2})
    scraper.set_params_cell(row, "GET")
    assert "review endpoint" in table.item(row, Col.URL).toolTip()
    assert "https://example.test" in table.item(row, Col.URL).toolTip()
    assert all(table.item(row, col).toolTip() == "" for col in range(1, table.columnCount()))


def test_live_result_update_skips_payload_tooltip_serialization_and_keeps_viewer(scraper, monkeypatch):
    scraper.add_task_row("https://example.test")
    task_id = scraper.table_ctl.task_id_by_row(0)
    payload = {
        "url": "https://example.test", "status_code": 200, "title": "Example",
        "content_len": 2048, "timings": {"request_ms": 12}, "evidence": "keep details",
    }
    serialized = []
    real_dumps = json.dumps

    def record_dumps(value, *args, **kwargs):
        if value is payload:
            serialized.append(value)
        return real_dumps(value, *args, **kwargs)

    monkeypatch.setattr(json, "dumps", record_dumps)
    scraper.on_task_result(task_id, payload)
    assert serialized == []
    assert scraper.task_results[task_id] == payload
    assert "Status: 200" in scraper.ui.taskTable.item(0, Col.Results).text()
    assert all(scraper.ui.taskTable.item(0, col).toolTip() == ""
               for col in range(1, scraper.ui.taskTable.columnCount()))
    viewed = []
    monkeypatch.setattr(UniversalViewerDialog, "exec", lambda dialog: viewed.append(dialog._payload))
    scraper.open_results_viewer_for_row(0)
    assert viewed == [payload]


@pytest.mark.parametrize("fmt", ["json", "csv", "xlsx"])
def test_preview_export_confirms_and_emits_without_open_picker(qapp, tmp_path, monkeypatch, fmt):
    records = [{"url": "https://example.test", "status_code": 200}]
    dialog = DataPreviewDialog()
    dialog.set_records(records)
    target = tmp_path / f"preview.{fmt}"
    monkeypatch.setattr(dialog, "_ask_export_path", lambda: (str(target), fmt))
    confirmations, emitted, pickers = [], [], []
    monkeypatch.setattr(QMessageBox, "information", lambda parent, title, text: confirmations.append(text))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: pickers.append(args) or ("", ""))
    dialog.export_done.connect(lambda path, count: emitted.append((path, count)))
    dialog.on_export_clicked()
    assert target.exists()
    assert str(target) in confirmations[0]
    assert emitted == [(str(target), 1)]
    assert pickers == []
    if fmt == "json":
        exported = json.loads(target.read_text(encoding="utf-8"))
        assert len(exported) == 1
        assert exported[0]["url"] == "https://example.test"
        assert exported[0]["status_code"] == 200
        assert exported[0]["_raw_result"] == records[0]
    dialog.close()


@pytest.mark.parametrize("operation", ["full", "selection", "matches"])
def test_viewer_default_export_paths_ignore_cwd(qapp, tmp_path, monkeypatch, operation):
    monkeypatch.chdir(tmp_path)
    dialog = UniversalViewerDialog(content="needle first\nsecond needle", default_save_stem="test")
    suggestions = []
    custom = tmp_path / "chosen" / f"{operation}.txt"

    def choose(parent, title, suggested, filters):
        suggestions.append(Path(suggested))
        return str(custom), "Text files (*.txt)"

    monkeypatch.setattr(QFileDialog, "getSaveFileName", choose)
    if operation == "full":
        dialog._save_to_file()
    elif operation == "selection":
        dialog.viewer.selectAll()
        dialog._save_selected_text()
    else:
        dialog.search_input.setText("needle")
        dialog._export_search_matches()
    assert len(suggestions) == 1
    assert suggestions[0].is_absolute()
    assert suggestions[0].parent == project_root() / "data" / "exports"
    assert "needle" in custom.read_text(encoding="utf-8")
    dialog.close()


def test_preview_default_export_path_ignores_cwd(qapp, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    suggestions = []
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda parent, title, path, filters:
                        suggestions.append(Path(path)) or ("", ""))
    dialog = DataPreviewDialog()
    assert dialog._ask_export_path() == ("", "")
    assert suggestions[0].parent == project_root() / "data" / "exports"
    assert not (tmp_path / "data").exists()
    dialog.close()


@pytest.mark.parametrize("cookie_file, suffix", [
    (None, "cookies_example.test.json"), ("custom.json", "custom.json"),
])
def test_cookie_paths_ignore_cwd(scraper, tmp_path, monkeypatch, cookie_file, suffix):
    monkeypatch.chdir(tmp_path)
    path = scraper._cookie_path_for("https://example.test/a", cookie_file)
    assert path == project_root() / "data" / "cookies" / suffix
    absolute = tmp_path / "elsewhere" / "chosen.json"
    assert scraper._cookie_path_for("https://example.test", str(absolute)) == absolute


def test_scraper_export_defaults_ignore_cwd_and_preserve_custom_dir(scraper, tmp_path, monkeypatch):
    from PySide6.QtCore import QSettings

    monkeypatch.chdir(tmp_path)
    settings = QSettings("WebSecSuite", "Scraper")
    settings.remove("export/last_dir")
    suggestions = []
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda parent, title, path, filters:
                        suggestions.append(Path(path)) or ("", ""))
    scraper._ask_export_path("all")
    scraper._ask_export_path_log()
    assert all(p.parent == project_root() / "data" / "exports" for p in suggestions)
    custom = tmp_path / "custom-export"
    settings.setValue("export/last_dir", str(custom))
    scraper._ask_export_path("all")
    assert suggestions[-1].parent == custom
    settings.setValue("export/last_dir", "data/exports")
    scraper._ask_export_path("all")
    assert suggestions[-1].parent == project_root() / "data" / "exports"


def test_main_window_initializes_offline_from_another_cwd(qapp, tmp_path, monkeypatch):
    from mainwindow import MainWindow

    monkeypatch.chdir(tmp_path)
    window = MainWindow()
    try:
        window.show()
        qapp.processEvents()
        assert window.isVisible()
        assert window.windowTitle() == "WebSecSuite"
        assert window.ui.tabWidget.indexOf(window.scraper_tab) >= 0
        assert window.scraper_tab.ui.taskTable.rowCount() == 0
        assert window.scraper_tab.task_manager.is_idle()
        window.scraper_tab.start_all_tasks()
        assert window.scraper_tab.task_manager.is_idle()
        assert not (tmp_path / "data").exists()
    finally:
        window.scraper_tab.task_manager.shutdown(timeout_ms=1000)
        window.close()
        window.deleteLater()
        qapp.processEvents()
