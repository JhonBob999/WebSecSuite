"""Exercise the two handoff signals through the actual application wiring."""

from copy import deepcopy

import pytest
from PySide6.QtCore import Qt

from core.scraper.task_types import TaskStatus
from ui.constants import Col


@pytest.fixture
def handoff_window(qapp):
    from mainwindow import MainWindow

    window = MainWindow()
    yield window
    window.scraper_tab.task_manager.shutdown(timeout_ms=1000)
    window.close()
    window.deleteLater()
    qapp.processEvents()


def test_actual_signals_reuse_recon_dedup_history_and_unreviewed_scope(handoff_window):
    scraper, recon = handoff_window.scraper_tab, handoff_window.recon_tab
    scraper.add_task_row("https://EXAMPLE.test/private?access_token=secret")
    task_id = scraper.table_ctl.task_id_by_row(0)
    task = scraper.task_manager.get_task(task_id)
    task.status = TaskStatus.DONE
    task.result = {
        "final_url": task.url, "status_code": 401,
        "request_recipe": {"timestamp": "2026-10-17T12:00:00Z", "headers": {"Cookie": "secret"}},
        "response_snapshot": {"status_code": 401, "body_preview": "secret"},
    }
    scraper.task_results[task_id] = deepcopy(task.result)
    scraper.ui.taskTable.selectRow(0)
    before = deepcopy(task)
    cached = deepcopy(scraper.task_results)
    selected = scraper.table_ctl.selected_rows()

    for _ in range(2):
        scraper.actions._acts["send_recon_target"].trigger()
        scraper.actions._acts["send_recon_inventory"].trigger()

    assert recon.target_model.rowCount() == 1
    assert recon.target_model.data(recon.target_model.index(0, recon.target_model.HOSTNAME)) == "example.test"
    assert recon.target_model.data(recon.target_model.index(0, recon.target_model.SOURCE)) == "Scraper"
    assert recon.target_model.data(recon.target_model.index(0, recon.target_model.SCOPE)) == "Unreviewed"
    assert recon.target_model.data(recon.target_model.index(0, recon.target_model.SELECT), Qt.CheckStateRole) == Qt.Unchecked
    assert "Duplicates: 1" in recon.ui.importSummary.text()
    assert len(recon.asset_inventory.assets) == len(recon.asset_inventory.observations) == 1
    assert len(recon.asset_inventory.import_history) == 1
    assert recon.ui.importHistory.count() == 2
    assert recon.ui.importHistory.itemText(0) == "All Assets"
    assert "Scraper" in recon.ui.importHistory.itemText(1)
    assert "Duplicates: 1" in recon.ui.assetStatusLabel.text()
    recon.ui.importHistory.setCurrentIndex(1)
    assert recon.asset_proxy.rowCount() == 1
    asset = recon.asset_model.asset_at(0)
    assert asset.entity_key == "recon:hostname:example.test"
    assert asset.sources == ("Scraper",)
    assert asset.observations[0].evidence[0].metadata == {"http_status": 401}
    assert scraper.task_manager.get_all_tasks() == [before]
    assert scraper.task_results == cached
    assert scraper.table_ctl.selected_rows() == selected
    assert scraper.ui.taskTable.rowCount() == 1
    assert scraper.task_manager.is_idle()
