"""New handoff actions read current task identities and leave Scraper intact."""

from copy import deepcopy

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMenu, QMessageBox

from core.scraper.task_types import ScrapeTask, TaskStatus
from ui.constants import Col


def add_completed(scraper, url="https://example.test/private?token=secret", task_id=None):
    if task_id:
        scraper.task_manager._tasks[task_id] = ScrapeTask(id=task_id, url=url)
    scraper.add_task_row(url, task_id=task_id)
    row = scraper.ui.taskTable.rowCount() - 1
    task_id = scraper.table_ctl.task_id_by_row(row)
    task = scraper.task_manager.get_task(task_id)
    task.status = TaskStatus.DONE
    task.result = {
        "status_code": 200, "final_url": url,
        "request_recipe": {"timestamp": "2026-10-17T12:00:00Z"},
        "response_snapshot": {"status_code": 200},
    }
    scraper.task_results[task_id] = deepcopy(task.result)
    scraper.ui.taskTable.selectRow(row)
    return task


def test_actions_emit_only_sanitized_payloads_and_preserve_task_selection(scraper):
    task = add_completed(scraper)
    before = deepcopy(task)
    cached = deepcopy(scraper.task_results)
    targets, batches = [], []
    scraper.reconTargetRequested.connect(targets.append)
    scraper.reconObservationRequested.connect(batches.append)
    scraper.actions._acts["send_recon_target"].trigger()
    scraper.actions._acts["send_recon_inventory"].trigger()
    assert targets == ["example.test"]
    assert len(batches) == 1
    assert batches[0].observations[0].value == "example.test"
    assert scraper.table_ctl.selected_rows() == [0]
    assert scraper.task_manager.get_all_tasks() == [before]
    assert scraper.task_results == cached
    assert scraper.task_manager.is_idle()


@pytest.mark.parametrize("state", ["failed", "reset", "done_without_result"])
def test_stale_success_cache_cannot_become_observation(scraper, monkeypatch, state):
    task = add_completed(scraper)
    if state == "failed":
        task.status = TaskStatus.FAILED
        task.result = {"error": "secret-network-error"}
    elif state == "reset":
        scraper.task_manager.reset_task(task.id)
    else:
        task.result = None
    messages, batches = [], []
    monkeypatch.setattr(QMessageBox, "information", lambda *args: messages.append(args[-1]))
    scraper.reconObservationRequested.connect(batches.append)
    assert not scraper.send_task_to_recon_inventory(task.id)
    assert batches == []
    assert messages and "completed HTTP response" in messages[0]
    assert "secret-network-error" not in messages[0]
    assert task.id in scraper.task_results


def test_context_uses_clicked_sorted_hex_id_without_changing_selection(scraper, monkeypatch):
    first = add_completed(scraper, "https://a.example.test/", "a" * 32)
    clicked = add_completed(scraper, "https://z.example.test/?token=secret", "b" * 32)
    table = scraper.ui.taskTable
    table.setSortingEnabled(True)
    table.sortItems(Col.URL, Qt.DescendingOrder)
    selected_row = scraper.table_ctl.row_by_task_id(first.id)
    clicked_row = scraper.table_ctl.row_by_task_id(clicked.id)
    table.selectRow(selected_row)
    targets, batches = [], []
    scraper.reconTargetRequested.connect(targets.append)
    scraper.reconObservationRequested.connect(batches.append)

    def choose(menu, *_args):
        actions = {action.text(): action for action in menu.actions()}
        target = actions["Send to Recon Target Manager"]
        inventory = actions["Send to Recon Asset Inventory"]
        assert target.isEnabled() and inventory.isEnabled()
        target.trigger()
        inventory.trigger()

    class ContextMenu(QMenu):
        def exec(self, *_args):
            choose(self)

    monkeypatch.setattr("ui.panels.scraper_actions.QMenu", ContextMenu)
    item = table.item(clicked_row, Col.URL)
    scraper.actions.on_context_menu(table.visualItemRect(item).center())
    assert targets == ["z.example.test"]
    assert batches[0].observations[0].value == "z.example.test"
    assert scraper.table_ctl.selected_rows() == [selected_row]
    assert scraper.actions._context_task_id is None


def test_invalid_target_and_pending_response_actions_are_explained(scraper, monkeypatch):
    scraper.add_task_row("https://127.0.0.1/?token=secret")
    table = scraper.ui.taskTable
    table.selectRow(0)

    def inspect(menu, *_args):
        assert menu.toolTipsVisible()
        actions = {action.text(): action for action in menu.actions()}
        for label in ("Send to Recon Target Manager", "Send to Recon Asset Inventory"):
            assert not actions[label].isEnabled()
            assert actions[label].toolTip()
            assert "secret" not in actions[label].toolTip()

    class ContextMenu(QMenu):
        def exec(self, *_args):
            inspect(self)

    monkeypatch.setattr("ui.panels.scraper_actions.QMenu", ContextMenu)
    scraper.actions.on_context_menu(table.visualItemRect(table.item(0, Col.URL)).center())


def test_queued_rerun_with_previous_done_result_cannot_transfer(scraper, monkeypatch):
    task = add_completed(scraper)
    monkeypatch.setattr(scraper.task_manager, "is_running", lambda task_id: True)
    messages, batches = [], []
    monkeypatch.setattr(QMessageBox, "information", lambda *args: messages.append(args[-1]))
    scraper.reconObservationRequested.connect(batches.append)
    assert not scraper.send_task_to_recon_inventory(task.id)
    scraper.actions._update_recon_handoff_actions()
    action = scraper.actions._acts["send_recon_inventory"]
    assert not action.isEnabled()
    assert action.toolTip()
    assert batches == [] and messages
