"""Offline Nmap imports share the existing Recon inventory and viewer."""

import json
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog


NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" start="1735689600">
  <host>
    <status state="up" reason="user-set"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="example.com" type="user"/>
      <hostname name="api.example.com" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.9" conf="10"/>
      </port>
      <port protocol="tcp" portid="443"><state state="open"/>
        <service name="https" product="nginx" version="1.26" conf="10"/>
      </port>
      <port protocol="udp" portid="443"><state state="open"/>
        <service name="quic" conf="3"/>
      </port>
      <port protocol="tcp" portid="80"><state state="filtered"/></port>
    </ports>
  </host>
  <runstats><finished time="1735689605"/></runstats>
</nmaprun>
"""
JSON_FIXTURE = Path(__file__).parents[2] / "fixtures" / "recon_observations_v1.json"


@pytest.fixture
def recon(qapp):
    from ui.panels.recon_tab import ReconTab

    panel = ReconTab()
    yield panel
    panel.close()
    panel.deleteLater()
    qapp.processEvents()


@pytest.fixture
def nmap_file(tmp_path):
    path = tmp_path / "offline-scan.xml"
    path.write_text(NMAP_XML, encoding="utf-8")
    return path


def test_nmap_picker_imports_xml_using_native_dialog_defaults(recon, nmap_file, monkeypatch):
    def choose(parent, title, directory, file_filter, **options):
        assert parent is recon
        assert "Nmap" in title
        assert directory == ""
        assert "*.xml" in file_filter
        assert not options.get("options", QFileDialog.Options(0)) & QFileDialog.DontUseNativeDialog
        return str(nmap_file), file_filter

    monkeypatch.setattr(QFileDialog, "getOpenFileName", choose)
    recon.ui.btnImportNmap.click()
    assert recon.asset_model.rowCount() == 6
    assert recon.ui.sourceFilter.findData("nmap") > 0
    assert "Added: 6" in recon.ui.assetStatusLabel.text()
    assert "New assets: 6" in recon.ui.assetStatusLabel.text()
    assert "Merged assets: 0" in recon.ui.assetStatusLabel.text()


def test_nmap_merges_existing_assets_and_repeat_import_deduplicates(recon, nmap_file):
    assert recon.import_observations_file(JSON_FIXTURE)
    recon.ui.manualInput.setText("selected.example.test")
    recon.ui.btnAddTarget.click()
    recon.ui.btnSelectAll.click()
    recon.ui.assetTable.selectRow(0)
    assert recon.import_nmap_file(nmap_file)
    assert recon.asset_model.rowCount() == 8
    assert "Added: 6" in recon.ui.assetStatusLabel.text()
    assert "Duplicates: 0" in recon.ui.assetStatusLabel.text()
    assert "New assets: 2" in recon.ui.assetStatusLabel.text()
    assert "Merged assets: 4" in recon.ui.assetStatusLabel.text()
    assert not recon.ui.assetTable.selectionModel().selectedRows()
    assert not recon.ui.btnAssetDetails.isEnabled()
    recon.ui.assetTable.selectRow(0)
    assert recon.import_nmap_file(nmap_file)
    assert recon.asset_model.rowCount() == 8
    assert "Added: 0" in recon.ui.assetStatusLabel.text()
    assert "Duplicates: 6" in recon.ui.assetStatusLabel.text()
    assert "New assets: 0" in recon.ui.assetStatusLabel.text()
    assert "Merged assets: 0" in recon.ui.assetStatusLabel.text()
    assert not recon.ui.assetTable.selectionModel().selectedRows()
    assert recon.target_model.rowCount() == recon.target_model.selected_count == 1
    assert recon.target_model.data(recon.target_model.index(0, recon.target_model.SCOPE)) == "Unreviewed"


def test_nmap_filters_sort_and_existing_viewer_keep_service_evidence(
    recon, nmap_file, monkeypatch,
):
    from dialogs.results_viewer_dialog import UniversalViewerDialog

    assert recon.import_observations_file(JSON_FIXTURE)
    recon.ui.assetSearch.setText("192.0.2.10")
    recon.ui.assetTypeFilter.setCurrentIndex(recon.ui.assetTypeFilter.findData("service"))
    recon.ui.assetTable.sortByColumn(recon.asset_model.SERVICE, Qt.DescendingOrder)
    assert recon.import_nmap_file(nmap_file)
    recon.ui.sourceFilter.setCurrentIndex(recon.ui.sourceFilter.findData("nmap"))
    assert recon.asset_proxy.rowCount() == 3
    assert recon.asset_proxy.sortColumn() == recon.asset_model.SERVICE
    assert recon.asset_proxy.sortOrder() == Qt.DescendingOrder
    assert [recon.asset_proxy.index(row, 0).data(recon.asset_model.AssetRole).port
            for row in range(3)] == [443, 443, 22]
    row = next(row for row in range(3)
               if recon.asset_proxy.index(row, 0).data(recon.asset_model.EntityKeyRole)
               == "recon:service:tcp:192.0.2.10:22")
    recon.ui.assetTable.selectRow(row)
    viewed = []
    monkeypatch.setattr(UniversalViewerDialog, "exec", lambda dialog: viewed.append(dialog._payload))
    recon.ui.btnAssetDetails.click()
    assert viewed[0]["entity_key"] == "recon:service:tcp:192.0.2.10:22"
    assert viewed[0]["sources"] == ["nmap"]
    assert viewed[0]["observations"][0]["evidence"]
    assert "OpenSSH" in json.dumps(viewed[0])
    assert recon.import_nmap_file(nmap_file)
    assert recon.ui.sourceFilter.currentData() == "nmap"
    assert recon.ui.assetSearch.text() == "192.0.2.10"
    assert recon.ui.assetTypeFilter.currentData() == "service"
    assert recon.asset_proxy.rowCount() == 3


@pytest.mark.parametrize("content", [
    "<nmaprun><host>",
    "<other/>",
    '<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "https://example.test/evil">]><nmaprun>&x;</nmaprun>',
])
def test_failed_nmap_import_preserves_inventory_filters_sort_and_selection(recon, tmp_path, content):
    assert recon.import_observations_file(JSON_FIXTURE)
    recon.ui.assetSearch.setText("192.0.2.10")
    recon.ui.assetTypeFilter.setCurrentIndex(recon.ui.assetTypeFilter.findData("service"))
    recon.ui.sourceFilter.setCurrentIndex(recon.ui.sourceFilter.findData("synthetic-services"))
    recon.ui.assetTable.sortByColumn(recon.asset_model.SERVICE, Qt.DescendingOrder)
    recon.ui.assetTable.selectRow(0)
    before = recon.asset_inventory.assets
    selected_key = recon.ui.assetTable.selectionModel().selectedRows()[0].data(recon.asset_model.EntityKeyRole)
    path = tmp_path / "invalid.xml"
    path.write_text(content, encoding="utf-8")
    assert not recon.import_nmap_file(path)
    assert recon.asset_inventory.assets is before
    assert recon.asset_model.rowCount() == 6
    assert recon.asset_proxy.rowCount() == 2
    assert recon.ui.assetSearch.text() == "192.0.2.10"
    assert recon.ui.assetTypeFilter.currentData() == "service"
    assert recon.ui.sourceFilter.currentData() == "synthetic-services"
    assert recon.asset_proxy.sortOrder() == Qt.DescendingOrder
    assert recon.ui.assetTable.selectionModel().selectedRows()[0].data(recon.asset_model.EntityKeyRole) == selected_key
    assert recon.ui.btnAssetDetails.isEnabled()
    assert recon.ui.assetStatusLabel.textFormat() == Qt.PlainText
    assert "failed" in recon.ui.assetStatusLabel.text().lower()


def test_nmap_picker_cancel_preserves_selection_and_status(recon, monkeypatch):
    assert recon.import_observations_file(JSON_FIXTURE)
    recon.ui.assetTable.selectRow(0)
    status = recon.ui.assetStatusLabel.text()
    selected_key = recon.ui.assetTable.selectionModel().selectedRows()[0].data(recon.asset_model.EntityKeyRole)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: ("", ""))
    recon.ui.btnImportNmap.click()
    assert recon.asset_model.rowCount() == 6
    assert recon.ui.assetStatusLabel.text() == status
    assert recon.ui.assetTable.selectionModel().selectedRows()[0].data(recon.asset_model.EntityKeyRole) == selected_key
    assert recon.ui.btnAssetDetails.isEnabled()
