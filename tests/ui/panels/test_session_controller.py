"""
Tests for the pure helper methods on SessionController (status/progress
normalization). These don't touch self.parent/self.table_ctl/self.task_manager,
so the controller is instantiated with None dependencies -- exercising the
Qt-free logic extracted from ScraperTabController's former inline methods.
"""
from ui.panels.session_controller import SessionController


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
