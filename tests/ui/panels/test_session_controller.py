"""
Tests for the pure helper methods on SessionController (status/progress
normalization). These don't touch self.parent/self.table_ctl/self.task_manager,
so the controller is instantiated with None dependencies -- exercising the
Qt-free logic extracted from ScraperTabController's former inline methods.
"""
from ui.panels.session_controller import SessionController

from copy import deepcopy

import pytest
from PySide6.QtWidgets import QMessageBox

from core.metadata import build_task_entity_key
from core.scraper.task_types import TaskStatus
from core.session_persistence import build_scraper_session, load_session
from ui.constants import Col


def _controller() -> SessionController:
    return SessionController(parent=None, table_ctl=None, task_manager=None, log_panel=None)


def test_session_status_key_strips_enum_prefix_and_progress_suffix():
    sc = _controller()
    assert sc._session_status_key("TaskStatus.Running 42%") == "running"
    assert sc._session_status_key("Done") == "done"
    assert sc._session_status_key("") == ""


def test_session_progress_value_clamps_and_defaults():
    sc = _controller()
    assert sc._session_progress_value("150") == 100
    assert sc._session_progress_value("-5") == 0
    assert sc._session_progress_value("abc") == 0
    assert sc._session_progress_value(42) == 42


def test_session_snapshot_progress_forces_100_for_done_status():
    sc = _controller()
    assert sc._session_snapshot_progress(50, status_text="Done") == 100


def test_session_snapshot_progress_keeps_raw_value_for_running_status():
    sc = _controller()
    assert sc._session_snapshot_progress(50, status_text="Running") == 50


def test_session_result_looks_successful():
    sc = _controller()
    assert sc._session_result_looks_successful({"error": "boom"}) is False
    assert sc._session_result_looks_successful({"status": "failed"}) is False
    assert sc._session_result_looks_successful({"status": "ok"}) is True
    assert sc._session_result_looks_successful(None) is False


def test_coerce_loaded_session_status_maps_transient_states_to_terminal():
    sc = _controller()
    # Running/Paused loaded from a session file is stale by definition -> Stopped
    assert sc._coerce_loaded_session_status("Running") == "Stopped"
    assert sc._coerce_loaded_session_status("Paused") == "Stopped"
    assert sc._coerce_loaded_session_status("Done") == "Done"
    assert sc._coerce_loaded_session_status("bogus") == "Pending"


def test_parse_session_created_at_handles_z_suffix_and_invalid_input():
    sc = _controller()
    parsed = sc._parse_session_created_at("2026-01-01T00:00:00Z")
    assert parsed is not None
    assert parsed.year == 2026 and parsed.month == 1 and parsed.day == 1
    assert sc._parse_session_created_at("not-a-date") is None
    assert sc._parse_session_created_at("") is None


def test_session_row_value_falls_back_to_minus_one():
    sc = _controller()
    assert sc._session_row_value("7") == 7
    assert sc._session_row_value("x") == -1
    assert sc._session_row_value(None) == -1


def _session(*, params=None, result=None, status="Done"):
    return build_scraper_session(tasks=[{
        "id": "restored", "url": "https://restored.test", "params": params or {},
        "status": status, "progress": 42, "result": result,
    }], selected_task_id="restored", current_row=0)


def _workspace(scraper):
    # Existing pending tasks, result, annotation and non-first-row selection.
    scraper.add_task_row("https://keep-one.test")
    scraper.add_task_row("https://keep-two.test")
    table = scraper.ui.taskTable
    row = table.rowCount() - 1
    task_id = scraper.table_ctl.task_id_by_row(row)
    task = scraper.task_manager.get_task(task_id)
    task.result = {"status_code": 200, "title": "keep"}
    scraper.task_results[task_id] = task.result
    scraper.table_ctl.set_results_cell(row, payload=task.result)
    scraper.annotation_store.upsert_annotation(build_task_entity_key(task_id), note="keep this note", bookmark=True)
    scraper.actions.refresh_task_annotation_visuals()
    table.setCurrentCell(row, Col.URL)
    table.selectRow(row)
    return scraper.session_ctl.collect_snapshot(), [
        [table.item(r, c).clone() if table.item(r, c) else None
         for c in range(table.columnCount())]
        for r in range(table.rowCount())
    ]


def _assert_workspace(scraper, before, cells):
    after = scraper.session_ctl.collect_snapshot()
    after.pop("saved_at")
    before = deepcopy(before)
    before.pop("saved_at")
    assert after == before
    table = scraper.ui.taskTable
    assert table.currentRow() == before["workspace"]["current_row"]
    for row, items in enumerate(cells):
        for col, item in enumerate(items):
            current = table.item(row, col)
            if item is not None:
                assert current is not None
                assert current.text() == item.text()
                assert current.toolTip() == item.toolTip()
    assert not table.signalsBlocked()
    assert table.updatesEnabled()


@pytest.mark.parametrize("params", [
    {"headers": None}, {"headers": []}, {"headers": "bad"},
    {"cookie_mode": []}, {"cookie_file": 42}, {"cookies_count": "bad"},
    {"proxy": {"https": "bad"}}, {"user_agent": []},
])
def test_invalid_nested_params_preserve_workspace(scraper, params):
    before, cells = _workspace(scraper)
    with pytest.raises(ValueError, match="(?i)(session|task|params)"):
        scraper.session_ctl.restore_snapshot(_session(params=params))
    _assert_workspace(scraper, before, cells)


@pytest.mark.parametrize("mutation", ["bad_entry", "missing_id", "bad_params", "duplicate_id", "bad_timings"])
def test_invalid_session_never_silently_partially_restores(scraper, mutation):
    before, cells = _workspace(scraper)
    session = _session()
    if mutation == "bad_entry":
        session["tasks"].append(None)
    elif mutation == "missing_id":
        session["tasks"].append({"url": "https://invalid.test"})
    elif mutation == "bad_params":
        session["tasks"][0]["params"] = []
    elif mutation == "duplicate_id":
        session["tasks"].append(deepcopy(session["tasks"][0]))
    else:
        session["tasks"][0]["result"] = {"timings": [1]}
    with pytest.raises(ValueError):
        scraper.session_ctl.restore_snapshot(session)
    _assert_workspace(scraper, before, cells)


@pytest.mark.parametrize("failure_stage", ["cell", "annotations", "inspector"])
def test_restore_commit_failure_rolls_back_workspace(scraper, monkeypatch, failure_stage):
    before, cells = _workspace(scraper)
    owner, method = {
        "cell": (scraper, "set_cookies_cell"),
        "annotations": (scraper.actions, "refresh_task_annotation_visuals"),
        "inspector": (scraper, "_refresh_task_inspector_for_current"),
    }[failure_stage]

    def fail(*args, **kwargs):
        raise RuntimeError("Simulated commit failure")

    monkeypatch.setattr(owner, method, fail)
    with pytest.raises(Exception, match="(?i)(restore|session|commit)"):
        scraper.session_ctl.restore_snapshot(_session(result={"status_code": 201}))
    _assert_workspace(scraper, before, cells)


@pytest.mark.parametrize("status, expected", [("Running", TaskStatus.STOPPED), ("Paused", TaskStatus.STOPPED), ("Done", TaskStatus.DONE)])
def test_valid_session_restore_preserves_data_and_normalizes_status(scraper, status, expected):
    _workspace(scraper)
    result = {"status_code": 200, "timings": {"request_ms": 12}, "custom": {"keep": [1, 2]}}
    params = {"headers": {"Authorization": "test-token"}, "proxy": "http://user:pass@proxy.test:80"}
    session = _session(params=params, result=result, status=status)
    assert scraper.session_ctl.restore_snapshot(session) == 1
    task = scraper.task_manager.get_task("restored")
    assert task.status == expected
    assert task.progress == 42
    assert task.to_params()["headers"] == params["headers"]
    assert task.proxy == params["proxy"]
    assert task.result == result
    assert scraper.task_results == {"restored": result}
    assert scraper.ui.taskTable.rowCount() == 1
    assert scraper.table_ctl.task_id_by_row(scraper.ui.taskTable.currentRow()) == "restored"


def test_restore_is_blocked_while_tasks_are_active(scraper):
    before, cells = _workspace(scraper)
    scraper.task_manager.get_all_tasks()[0].status = TaskStatus.RUNNING
    before["tasks"][0]["status"] = "Running"
    with pytest.raises(ValueError, match="(?i)(running|active)"):
        scraper.session_ctl.restore_snapshot(_session())
    _assert_workspace(scraper, before, cells)


@pytest.mark.parametrize("answer", [QMessageBox.Cancel, QMessageBox.Save])
@pytest.mark.parametrize("params", [
    {"headers": {"Authorization": "private-test-value"}},
    {"headers": {"Cookie": "private-test-value"}},
    {"headers": {"X-API-Key": "private-test-value"}},
    {"proxy": "http://user:private-test-value@proxy.test:80"},
])
def test_sensitive_save_requires_confirmation_without_exposing_secrets(scraper, tmp_path, monkeypatch, params, answer):
    scraper.session_ctl.restore_snapshot(_session(params=params))
    path = tmp_path / "session.json"
    path.write_text("previous session", encoding="utf-8")
    monkeypatch.setattr(scraper.session_ctl, "ask_save_path", lambda: str(path))
    warnings = []

    def warning(parent, title, text, *args, **kwargs):
        warnings.append(text)
        return answer

    monkeypatch.setattr(QMessageBox, "warning", warning)
    monkeypatch.setattr(QMessageBox, "information", lambda *args: QMessageBox.Ok)
    scraper.session_ctl.on_save_clicked()
    assert len(warnings) == 1
    assert "plaintext" in warnings[0].lower()
    assert "private-test-value" not in warnings[0]
    assert "private-test-value" not in scraper.ui.logOutput.toPlainText()
    if answer == QMessageBox.Cancel:
        assert path.read_text(encoding="utf-8") == "previous session"
    else:
        assert load_session(path)["tasks"][0]["params"] == scraper.session_ctl.collect_snapshot()["tasks"][0]["params"]


def test_non_sensitive_save_needs_no_confirmation(scraper, tmp_path, monkeypatch):
    scraper.session_ctl.restore_snapshot(_session(params={"headers": {"Accept": "text/html"}}))
    target = tmp_path / "normal.json"
    monkeypatch.setattr(scraper.session_ctl, "ask_save_path", lambda: str(target))

    def unexpected_warning(*args, **kwargs):
        pytest.fail("Normal session save should not ask for sensitive-data confirmation")

    monkeypatch.setattr(QMessageBox, "warning", unexpected_warning)
    monkeypatch.setattr(QMessageBox, "information", lambda *args: QMessageBox.Ok)
    scraper.session_ctl.on_save_clicked()
    assert load_session(target)["tasks"][0]["id"] == "restored"


def test_load_null_headers_file_reports_error_and_keeps_workspace(scraper, tmp_path, monkeypatch):
    import json

    before, cells = _workspace(scraper)
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(_session(params={"headers": None})), encoding="utf-8")
    monkeypatch.setattr(scraper.session_ctl, "ask_load_path", lambda: str(path))
    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", lambda parent, title, text: warnings.append(text))
    scraper.session_ctl.on_load_clicked()
    assert len(warnings) == 1
    assert "params.headers" in warnings[0]
    _assert_workspace(scraper, before, cells)
