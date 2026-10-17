"""R4.1 inventory history, reset actions and stable context selection, offline."""

import json

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMenu


@pytest.fixture
def recon(qapp):
    from ui.panels.recon_tab import ReconTab

    panel = ReconTab()
    yield panel
    panel.close()
    panel.deleteLater()
    qapp.processEvents()


def import_bundle(recon, tmp_path, run_id, hosts, source="native", filename="assets.json"):
    folder = tmp_path / run_id
    folder.mkdir(exist_ok=True)
    path = folder / filename
    path.write_text(json.dumps({
        "schema": "websecsuite.recon.observations", "version": 1, "run_id": run_id,
        "observations": [
            {"id": str(i), "type": "hostname", "value": host, "source": source}
            for i, host in enumerate(hosts)
        ],
    }), encoding="utf-8")
    assert recon.import_observations_file(path)
    return path


def values(recon):
    return [recon.asset_proxy.data(recon.asset_proxy.index(i, 0))
            for i in range(recon.asset_proxy.rowCount())]


def choose(combo, value):
    index = combo.findData(value)
    assert index >= 0
    combo.setCurrentIndex(index)


def action(menu, text):
    return next(item for item in menu.actions() if item.text() == text)


def test_history_selects_overlapping_imports_and_distinguishes_same_filename(recon, tmp_path):
    first = import_bundle(recon, tmp_path, "run-one", ["shared.example.test", "a.example.test"])
    import_bundle(recon, tmp_path, "run-two", ["shared.example.test", "z.example.test"], "other")
    history = recon.ui.importHistory
    assert history.currentData() == ""
    assert history.count() == 3
    assert history.itemText(1) != history.itemText(2)
    assert "assets.json" in history.itemText(1) and "JSON" in history.itemText(1)
    assert len(values(recon)) == 3
    entries = recon.asset_inventory.import_history
    choose(history, entries[0].import_id)
    assert set(values(recon)) == {"shared.example.test", "a.example.test"}
    assert "Total: 3" in recon.ui.assetCountLabel.text()
    assert "Import: 2 assets / 2 observations" in recon.ui.assetCountLabel.text()
    choose(recon.ui.sourceFilter, "other")
    assert values(recon) == []  # the shared asset's other-source observation is in run-two
    choose(recon.ui.sourceFilter, "")
    choose(history, entries[1].import_id)
    assert set(values(recon)) == {"shared.example.test", "z.example.test"}
    assert recon.import_observations_file(first)
    assert history.count() == 3
    assert history.currentData() == entries[1].import_id
    choose(history, "")
    assert len(values(recon)) == 3


def test_reset_filters_preserves_sort_reset_view_restores_inventory_order(recon, tmp_path):
    import_bundle(recon, tmp_path, "run-one", ["a.example.test", "z.example.test"])
    xml = tmp_path / "scan.xml"
    xml.write_text('<nmaprun scanner="nmap"><host><address addr="192.0.2.2" '
                   'addrtype="ipv4"/></host></nmaprun>', encoding="utf-8")
    assert recon.import_nmap_file(xml)
    before = recon.asset_inventory.observations
    recon.ui.assetTable.sortByColumn(0, Qt.DescendingOrder)
    choose(recon.ui.importHistory, recon.asset_inventory.import_history[0].import_id)
    recon.ui.assetSearch.setText("a.example")
    choose(recon.ui.assetTypeFilter, "hostname")
    choose(recon.ui.sourceFilter, "native")
    recon.ui.btnResetFilters.click()
    assert recon.ui.assetSearch.text() == ""
    assert recon.ui.assetTypeFilter.currentData() == recon.ui.sourceFilter.currentData() == ""
    assert recon.ui.importHistory.currentData() == ""
    assert recon.asset_proxy.sortColumn() == 0
    assert recon.asset_proxy.sortOrder() == Qt.DescendingOrder
    assert values(recon) == sorted(values(recon), reverse=True)
    recon.ui.btnResetView.click()
    assert recon.asset_proxy.sortColumn() == -1
    assert recon.ui.assetTable.horizontalHeader().sortIndicatorSection() == -1
    assert values(recon) == [asset.value for asset in recon.asset_inventory.assets]
    assert recon.asset_inventory.observations is before


def test_same_filename_same_run_distinct_datasets_have_distinct_labels(recon, tmp_path):
    import_bundle(recon, tmp_path, "same-run", ["shared.example.test"], "one")
    import_bundle(recon, tmp_path, "same-run", ["shared.example.test"], "two")
    history = recon.ui.importHistory
    assert history.count() == 3
    assert history.itemText(1) != history.itemText(2)
    assert recon.asset_model.rowCount() == 1


def test_context_menu_captures_sorted_asset_and_reuses_viewer_and_target_rules(recon, tmp_path, monkeypatch):
    from dialogs.results_viewer_dialog import UniversalViewerDialog

    import_bundle(recon, tmp_path, "menu-run", ["a.example.test", "z.example.test"])
    recon.ui.assetTable.sortByColumn(0, Qt.DescendingOrder)
    recon.ui.assetTable.selectRow(1)
    menu = recon._asset_context_menu(recon.asset_proxy.index(0, 0))
    assert isinstance(menu, QMenu)
    # Re-sort after menu creation: actions must retain the clicked entity, never its row.
    recon.ui.assetTable.sortByColumn(0, Qt.AscendingOrder)
    viewed = []
    monkeypatch.setattr(UniversalViewerDialog, "exec", lambda dialog: viewed.append(dialog._payload))
    action(menu, "Open Asset Details").trigger()
    assert viewed[-1]["value"] == "z.example.test"
    action(menu, "Copy Asset Identity").trigger()
    assert QApplication.clipboard().text() == "recon:hostname:z.example.test"
    action(menu, "Add to Target Manager").trigger()
    action(menu, "Add to Target Manager").trigger()
    model = recon.target_model
    assert model.rowCount() == 1 and model.selected_count == 0
    assert model.data(model.index(0, model.HOSTNAME)) == "z.example.test"
    assert model.data(model.index(0, model.SCOPE)) == "Unreviewed"
    action(menu, "Filter by Type").trigger()
    assert recon.ui.assetTypeFilter.currentData() == "hostname"
    source_action = action(menu, "Filter by Source")
    source_menu = source_action.menu()
    action(source_menu, "native").trigger()
    assert recon.ui.sourceFilter.currentData() == "native"
    provenance_action = action(menu, "Show related Import / Provenance")
    provenance = provenance_action.menu()
    action(provenance, "Open Provenance").trigger()
    assert viewed[-1]["entity_key"] == "recon:hostname:z.example.test"
    assert viewed[-1]["imports"][0]["run_id"] == "menu-run"
    provenance.actions()[-1].trigger()
    assert recon.ui.importHistory.currentData() == recon.asset_inventory.import_history[0].import_id


def test_ip_context_disables_target_action_with_reason(recon, tmp_path):
    xml = tmp_path / "ip.xml"
    xml.write_text('<nmaprun scanner="nmap"><host><address addr="192.0.2.2" '
                   'addrtype="ipv4"/></host></nmaprun>', encoding="utf-8")
    assert recon.import_nmap_file(xml)
    menu = recon._asset_context_menu(recon.asset_proxy.index(0, 0))
    target = action(menu, "Add to Target Manager")
    assert not target.isEnabled()
    assert target.toolTip() and "hostname" in target.toolTip().lower()
    assert recon._asset_context_menu(recon.asset_proxy.index(-1, 0)) is None


def test_receiver_validates_hostname_deduplicates_and_preserves_scope(recon):
    assert recon.receive_target_hostname("API.Example.test.")
    assert recon.receive_target_hostname("api.example.test")
    assert not recon.receive_target_hostname("192.0.2.1")
    assert recon.target_model.rowCount() == 1
    assert recon.target_model.selected_count == 0
    assert recon.target_model.data(recon.target_model.index(0, recon.target_model.SCOPE)) == "Unreviewed"
