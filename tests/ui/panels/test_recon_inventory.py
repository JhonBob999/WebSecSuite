"""Offline Asset Inventory controls stay separate from imported targets."""

import json

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QFileDialog, QTabWidget, QTableView


@pytest.fixture
def recon(qapp):
    from ui.panels.recon_tab import ReconTab

    panel = ReconTab()
    yield panel
    panel.close()
    panel.deleteLater()
    qapp.processEvents()


def test_asset_inventory_starts_empty_and_target_manager_remains_default(recon):
    assert isinstance(recon.ui.reconPages, QTabWidget)
    assert recon.ui.reconPages.currentIndex() == 0
    assert [recon.ui.reconPages.tabText(index) for index in range(2)] == [
        "Target Manager", "Asset Inventory",
    ]
    assert recon.ui.targetTable.model() is recon.target_model
    assert isinstance(recon.ui.assetTable, QTableView)
    assert recon.ui.assetTable.model() is recon.asset_proxy
    assert recon.ui.assetTable.editTriggers() == QAbstractItemView.NoEditTriggers
    assert recon.asset_model.rowCount() == recon.asset_proxy.rowCount() == 0
    assert not recon.ui.btnAssetDetails.isEnabled()
    assert "Total: 0" in recon.ui.assetCountLabel.text()
    assert "Filtered: 0" in recon.ui.assetCountLabel.text()


@pytest.fixture
def observations_file(tmp_path):
    path = tmp_path / "observations.json"
    path.write_text(json.dumps({
        "schema": "websecsuite.recon.observations", "version": 1, "run_id": "gui-fixture",
        "observations": [
            {"id": "api-host", "type": "hostname", "value": "api.example.test", "source": "alpha",
             "confidence": 0.8, "evidence": [{"ref": "fixture:api", "metadata": {"line": 1}}]},
            {"id": "www-host", "type": "hostname", "value": "www.example.test", "source": "beta",
             "confidence": 0.7, "evidence": [{"ref": "fixture:www", "metadata": {"line": 2}}]},
            {"id": "ip", "type": "ip", "value": "192.0.2.7", "source": "alpha",
             "evidence": [{"ref": "fixture:ip"}]},
            {"id": "service", "type": "service", "host": "api.example.test", "transport": "tcp",
             "port": 443, "source": "beta", "evidence": [{"ref": "fixture:service"}]},
        ],
    }), encoding="utf-8")
    return path


def choose_filter(combo, value):
    index = combo.findData(value)
    assert index >= 0
    combo.setCurrentIndex(index)


def test_json_file_picker_imports_assets_without_selecting_targets(recon, observations_file, monkeypatch):
    recon.ui.manualInput.setText("target.example.test")
    recon.ui.btnAddTarget.click()
    recon.ui.btnSelectAll.click()
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: (str(observations_file), ""))
    recon.ui.btnImportObservations.click()
    assert recon.asset_model.rowCount() == recon.asset_proxy.rowCount() == 4
    assert "Added: 4" in recon.ui.assetStatusLabel.text()
    assert "Duplicates: 0" in recon.ui.assetStatusLabel.text()
    assert "Assets: 4" in recon.ui.assetStatusLabel.text()
    assert "Total: 4" in recon.ui.assetCountLabel.text()
    assert recon.target_model.rowCount() == recon.target_model.selected_count == 1
    assert recon.ui.assetStatusLabel.textFormat() == Qt.PlainText
    assert not recon.ui.btnAssetDetails.isEnabled()


def test_cancel_and_invalid_import_preserve_inventory_filters_and_selection(
    recon, observations_file, tmp_path, monkeypatch,
):
    assert recon.import_observations_file(observations_file)
    choose_filter(recon.ui.sourceFilter, "alpha")
    recon.ui.assetTable.selectRow(0)
    before = recon.asset_inventory.assets
    selected = recon.ui.assetTable.selectionModel().selectedRows()[0]
    status = recon.ui.assetStatusLabel.text()
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: ("", ""))
    recon.ui.btnImportObservations.click()
    assert recon.ui.assetStatusLabel.text() == status
    assert recon.ui.assetTable.selectionModel().selectedRows() == [selected]
    broken = tmp_path / "invalid.json"
    broken.write_text('{"schema": "<b>unsupported</b>", "version": 1}', encoding="utf-8")
    assert not recon.import_observations_file(broken)
    assert recon.asset_inventory.assets == before
    assert recon.asset_model.rowCount() == 4
    assert recon.asset_proxy.rowCount() == 2
    assert recon.ui.sourceFilter.currentData() == "alpha"
    assert recon.ui.assetTable.selectionModel().selectedRows() == [selected]
    assert recon.ui.btnAssetDetails.isEnabled()
    assert "Import failed:" in recon.ui.assetStatusLabel.text()
    assert not recon.import_observations_file(tmp_path / "missing.json")
    assert recon.asset_inventory.assets == before


def test_repeated_import_is_idempotent_and_refresh_preserves_source_filter(recon, observations_file):
    assert recon.import_observations_file(observations_file)
    choose_filter(recon.ui.sourceFilter, "beta")
    recon.ui.assetTable.selectRow(0)
    assert recon.ui.btnAssetDetails.isEnabled()
    assert recon.import_observations_file(observations_file)
    assert recon.asset_model.rowCount() == 4
    assert recon.ui.sourceFilter.currentData() == "beta"
    assert recon.asset_proxy.rowCount() == 2
    assert "Added: 0" in recon.ui.assetStatusLabel.text()
    assert "Duplicates: 4" in recon.ui.assetStatusLabel.text()
    assert not recon.ui.assetTable.selectionModel().selectedRows()
    assert not recon.ui.btnAssetDetails.isEnabled()


def test_combined_filters_update_counts_and_invalidate_details_selection(recon, observations_file):
    assert recon.import_observations_file(observations_file)
    recon.ui.assetTable.selectRow(0)
    recon.ui.assetSearch.setText("EXAMPLE.TEST")
    assert recon.asset_proxy.rowCount() == 3
    assert not recon.ui.btnAssetDetails.isEnabled()
    choose_filter(recon.ui.assetTypeFilter, "hostname")
    choose_filter(recon.ui.sourceFilter, "beta")
    assert recon.asset_proxy.rowCount() == 1
    assert recon.asset_proxy.data(recon.asset_proxy.index(0, 0)) == "www.example.test"
    assert "Total: 4" in recon.ui.assetCountLabel.text()
    assert "Filtered: 1" in recon.ui.assetCountLabel.text()
    recon.ui.assetSearch.setText("absent")
    assert recon.asset_proxy.rowCount() == 0
    assert not recon.ui.btnAssetDetails.isEnabled()
    recon.ui.assetSearch.clear()
    choose_filter(recon.ui.assetTypeFilter, "")
    choose_filter(recon.ui.sourceFilter, "")
    assert recon.asset_proxy.rowCount() == 4


def test_details_use_sorted_proxy_row_and_preserve_complete_evidence(recon, observations_file, monkeypatch):
    from dialogs.results_viewer_dialog import UniversalViewerDialog

    assert recon.import_observations_file(observations_file)
    recon.ui.assetSearch.setText("example.test")
    choose_filter(recon.ui.assetTypeFilter, "hostname")
    recon.ui.assetTable.sortByColumn(0, Qt.DescendingOrder)
    recon.ui.assetTable.selectRow(0)
    viewed = []
    monkeypatch.setattr(UniversalViewerDialog, "exec", lambda dialog: viewed.append(dialog))
    recon.ui.btnAssetDetails.click()
    assert len(viewed) == 1
    dialog = viewed[0]
    assert dialog._payload["value"] == "www.example.test"
    assert dialog._payload["entity_type"] == "hostname"
    assert dialog._payload["sources"] == ["beta"]
    assert dialog._payload["observations"][0]["confidence"] == 0.7
    assert dialog._payload["observations"][0]["evidence"][0]["metadata"] == {"line": 2}
    assert dialog.summary_label is None
    assert dialog.parent() is recon
    assert dialog._default_save_stem == "recon_asset"
    recon.ui.assetTable.doubleClicked.emit(recon.asset_proxy.index(0, 0))
    assert len(viewed) == 2
    assert viewed[1]._payload == dialog._payload
