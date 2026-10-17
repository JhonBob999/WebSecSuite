"""Atomic imports and provenance-preserving asset aggregation."""

import importlib
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest


def api():
    return importlib.import_module("core.recon.inventory")


def envelope(*records, run_id="run-1"):
    return json.dumps({"schema": "websecsuite.recon.observations", "version": 1,
                       "run_id": run_id, "observations": list(records)})


def host(id="h-1", value="example.com", source="fixture", **changes):
    return {"id": id, "type": "hostname", "source": source, "value": value, **changes}


def service(id="s-1", transport="tcp", port=443, name="https", **changes):
    return {"id": id, "type": "service", "source": "fixture", "host": "192.0.2.10",
            "transport": transport, "port": port, "service_name": name, **changes}


def test_normalized_inventory_deduplicates_assets_and_preserves_all_provenance():
    inventory = api().AssetInventory()
    evidence = {"ref": "capture:one", "metadata": {"status": 200}}
    result = inventory.import_json(envelope(host(value="EXAMPLE.COM.", evidence=[evidence]),
        host(id="h-2", source="another", confidence=0.7, evidence=[evidence]),
        host(id="h-3", value="other.example")))
    assert (result.added_observations, result.duplicates, result.total_assets, result.run_id) == (3, 0, 2, "run-1")
    assert [asset.entity_key for asset in inventory.assets] == ["recon:hostname:example.com", "recon:hostname:other.example"]
    first = inventory.assets[0]
    assert first.sources == ("another", "fixture")
    assert first.evidence_count == 1
    assert (first.entity_type, first.value, first.transport, first.port, first.service_names) == ("hostname", "example.com", None, None, ())
    assert {observation.id for observation in first.observations} == {"h-1", "h-2"}
    assert first.to_dict()["observations"][0]["run_id"] == "run-1"
    assert len(inventory.observations) == 3


def test_repeated_imports_and_input_duplicates_are_idempotent():
    inventory = api().AssetInventory()
    text = envelope(host(), host(value="EXAMPLE.COM."))
    first = inventory.import_json(text)
    assert (first.added_observations, first.duplicates, first.total_assets) == (1, 1, 1)
    before = inventory.assets
    second = inventory.import_json(text)
    assert (second.added_observations, second.duplicates, second.total_assets) == (0, 2, 1)
    assert inventory.assets == before
    assert len(inventory.observations) == 1


def test_new_run_enriches_same_asset_without_adding_asset_rows():
    inventory = api().AssetInventory()
    inventory.import_json(envelope(host(evidence=[{"ref": "one"}])))
    result = inventory.import_json(envelope(host(evidence=[{"ref": "two"}]), run_id="run-2"))
    assert (result.added_observations, result.total_assets) == (1, 1)
    asset = inventory.assets[0]
    assert asset.evidence_count == 2
    assert {item.run_id for item in asset.observations} == {"run-1", "run-2"}


def test_service_identity_includes_host_transport_port_and_excludes_service_name():
    inventory = api().AssetInventory()
    inventory.import_json(envelope(service(), service(id="s-2", name="tls"),
        service(id="s-3", transport="udp", name="quic"), service(id="s-4", port=8443),
        service(id="s-5", host="other.example"), service(id="s-6", transport="sctp")))
    assert len(inventory.assets) == 5
    asset = next(item for item in inventory.assets if item.entity_key == "recon:service:tcp:192.0.2.10:443")
    assert asset.service_names == ("https", "tls")
    assert len(asset.observations) == 2
    assert all(item.entity_type == "service" for item in inventory.assets)


def test_hostnames_sharing_ip_evidence_remain_distinct_without_derived_relations():
    inventory = api().AssetInventory()
    evidence = [{"ref": "dns:fixture", "metadata": {"address": "192.0.2.10"}}]
    inventory.import_json(envelope(host(evidence=evidence), host(id="h-2", value="other.example", evidence=evidence)))
    assert [asset.value for asset in inventory.assets] == ["example.com", "other.example"]
    assert all(asset.entity_type == "hostname" for asset in inventory.assets)
    assert all("relations" not in asset.to_dict() for asset in inventory.assets)


@pytest.mark.parametrize("failure", ["invalid_record", "batch_conflict", "stored_conflict"])
def test_import_failure_is_atomic_including_conflicts_against_existing_store(failure):
    inventory = api().AssetInventory()
    inventory.import_json(envelope(host()))
    before_assets, before_observations = inventory.assets, inventory.observations
    records = [host(id="new", value="new.example")]
    if failure == "invalid_record":
        records.append(host(id="bad", value="bad/path"))
    elif failure == "batch_conflict":
        records.extend([host(id="duplicate", value="a.example"), host(id="duplicate", value="b.example")])
    else:
        records.append(host(value="changed.example"))
    with pytest.raises(ValueError, match=r"(?i)observation [234]"):
        inventory.import_json(envelope(*records))
    assert inventory.assets == before_assets
    assert inventory.observations == before_observations


def test_stored_conflict_reports_original_record_index_after_input_duplicates():
    inventory = api().AssetInventory()
    inventory.import_json(envelope(host()))
    with pytest.raises(ValueError, match=r"(?i)observation 3.*conflict"):
        inventory.import_json(envelope(host(id="new"), host(id="new"), host(value="changed.example")))
    assert len(inventory.observations) == 1


def test_evidence_uniqueness_uses_reference_kind_and_complete_metadata():
    inventory = api().AssetInventory()
    inventory.import_json(envelope(host(evidence=[{"ref": "same", "metadata": {"a": 1, "b": 2}},
        {"ref": "same", "metadata": {"b": 2, "a": 1}}, {"ref": "same", "metadata": {"a": 2}},
        {"ref": "same", "kind": "capture", "metadata": {"a": 1, "b": 2}}])))
    assert inventory.assets[0].evidence_count == 3
    assert len(inventory.assets[0].to_dict()["observations"][0]["evidence"]) == 4


def test_inventory_snapshots_are_immutable_and_details_do_not_mutate_store():
    inventory = api().AssetInventory()
    inventory.import_json(envelope(host(evidence=[{"ref": "x", "metadata": {"a": [1]}}])))
    snapshot = inventory.assets
    assert isinstance(snapshot, tuple)
    assert isinstance(inventory.observations, tuple)
    with pytest.raises(FrozenInstanceError):
        snapshot[0].value = "changed.example"
    details = snapshot[0].to_dict()
    details["observations"][0]["evidence"][0]["metadata"]["a"].append(2)
    inventory.import_json(envelope(host(id="h-2", value="new.example")))
    assert len(snapshot) == 1
    assert inventory.assets[0].to_dict()["observations"][0]["evidence"][0]["metadata"] == {"a": [1]}
    assert json.loads(json.dumps(inventory.assets[0].to_dict()))["entity_key"] == "recon:hostname:example.com"


def test_empty_import_keeps_inventory_and_reports_zero_additions():
    inventory = api().AssetInventory()
    inventory.import_json(envelope(host()))
    before = inventory.assets
    result = inventory.import_json(envelope(run_id="empty-run"))
    assert (result.added_observations, result.duplicates, result.total_assets, result.run_id) == (0, 0, 1, "empty-run")
    assert inventory.assets == before


def test_local_fixture_import_exercises_native_schema_and_idempotence():
    inventory = api().AssetInventory()
    path = Path(__file__).parents[2] / "fixtures" / "recon_observations_v1.json"
    result = inventory.import_file(path)
    assert (result.added_observations, result.total_assets, result.run_id) == (7, 6, "synthetic-run-1")
    assert {asset.value for asset in inventory.assets if asset.entity_type == "ip"} == {"192.0.2.10", "2001:db8::10"}
    assert {asset.value for asset in inventory.assets if asset.entity_type == "hostname"} == {"example.com", "xn--bcher-kva.example"}
    assert inventory.import_file(path).added_observations == 0
