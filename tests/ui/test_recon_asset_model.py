"""Read-only inventory projection, literal search, and structured filters."""

import importlib
import json

import pytest
from PySide6.QtCore import QModelIndex, Qt


def models():
    return importlib.import_module("ui.recon_asset_model")


def inventory():
    from core.recon.inventory import AssetInventory

    store = AssetInventory()
    store.import_json(json.dumps({
        "schema": "websecsuite.recon.observations", "version": 1, "run_id": "model-tests",
        "observations": [
            {"id": "host-a", "type": "hostname", "value": "API.Example.test.",
             "source": "fixture-a", "evidence": [{"ref": "note:host"}]},
            {"id": "host-b", "type": "hostname", "value": "api.example.test",
             "source": "fixture-b"},
            {"id": "ip", "type": "ip", "value": "2001:0db8::1", "source": "fixture-a"},
            {"id": "dns", "type": "service", "host": "192.0.2.10", "transport": "udp",
             "port": 53, "service_name": "dns", "source": "fixture-b"},
            {"id": "https", "type": "service", "host": "api.example.test", "transport": "tcp",
             "port": 443, "service_name": "https", "source": "fixture-a",
             "evidence": [{"ref": "note:service"}, {"ref": "note:port"}]},
        ],
    }))
    return store


def test_empty_model_is_read_only_and_has_no_child_tables(qapp):
    model = models().ReconAssetModel()
    assert model.rowCount() == 0
    assert model.columnCount() == 5
    assert model.data(QModelIndex()) is None
    assert model.flags(QModelIndex()) == Qt.NoItemFlags
    assert model.asset_at(-1) is None
    assert model.asset_at(0) is None


def test_model_projects_sources_service_and_evidence_without_editing(qapp):
    module = models()
    store = inventory()
    assets = store.assets
    model = module.ReconAssetModel()
    model.set_assets(assets)
    assert model.rowCount() == 4
    row = next(i for i, asset in enumerate(assets) if asset.entity_type == "hostname")
    assert [model.data(model.index(row, column)) for column in range(5)] == [
        "api.example.test", "Hostname", "", "fixture-a, fixture-b", 1,
    ]
    index = model.index(row, 0)
    assert model.data(index, model.EntityKeyRole) == "recon:hostname:api.example.test"
    assert model.data(index, model.AssetRole) is assets[row]
    assert not model.flags(index) & (Qt.ItemIsEditable | Qt.ItemIsUserCheckable)
    assert not model.setData(index, "changed.test")
    assert model.asset_at(row).value == "api.example.test"
    assert model.rowCount(index) == model.columnCount(index) == 0
    service_row = next(i for i, asset in enumerate(assets) if asset.port == 443)
    assert model.data(model.index(service_row, 2)) == "https · tcp/443"
    assert model.data(model.index(service_row, 4)) == 2


def test_filters_combine_literal_case_insensitive_text_with_exact_type_source(qapp):
    module = models()
    model = module.ReconAssetModel()
    model.set_assets(inventory().assets)
    proxy = module.ReconAssetFilterProxy()
    proxy.setSourceModel(model)
    proxy.set_search_text(" API.EXAMPLE ")
    assert proxy.rowCount() == 2
    proxy.set_entity_type("hostname")
    assert proxy.rowCount() == 1
    proxy.set_source("fixture-b")
    assert proxy.rowCount() == 1
    proxy.set_source("fixture")
    assert proxy.rowCount() == 0
    proxy.set_source("")
    proxy.set_entity_type("")
    proxy.set_search_text("https")
    assert proxy.rowCount() == 1
    proxy.set_search_text("[.*")
    assert proxy.rowCount() == 0
    proxy.set_search_text("")
    assert proxy.rowCount() == 4


@pytest.mark.parametrize("column, expected", [
    (2, [53, 443]),
    (4, [53, 443]),
])
def test_service_and_evidence_sorting_use_numbers_and_map_to_correct_asset(qapp, column, expected):
    module = models()
    model = module.ReconAssetModel()
    model.set_assets(inventory().assets)
    proxy = module.ReconAssetFilterProxy()
    proxy.setSourceModel(model)
    proxy.set_entity_type("service")
    proxy.sort(column, Qt.AscendingOrder)
    actual = [model.asset_at(proxy.mapToSource(proxy.index(i, 0)).row()).port
              for i in range(proxy.rowCount())]
    assert actual == expected


def test_model_refresh_reapplies_filters_without_changing_domain_inventory(qapp):
    module = models()
    store = inventory()
    model = module.ReconAssetModel()
    proxy = module.ReconAssetFilterProxy()
    proxy.setSourceModel(model)
    proxy.set_source("fixture-b")
    model.set_assets(store.assets)
    assert proxy.rowCount() == 2
    original_keys = [asset.entity_key for asset in store.assets]
    model.set_assets(())
    assert proxy.rowCount() == model.rowCount() == 0
    assert [asset.entity_key for asset in store.assets] == original_keys
