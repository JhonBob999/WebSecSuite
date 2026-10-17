"""Offline dataset history preserves selectable, immutable import provenance."""

import json
from dataclasses import FrozenInstanceError, replace

import pytest

from core.recon.inventory import AssetInventory
from core.recon.observations import ObservationBatch, ObservationImportError, parse_observations_json


def document(*records, run_id="run-1"):
    return json.dumps({"schema": "websecsuite.recon.observations", "version": 1,
                       "run_id": run_id, "observations": list(records)})


def hostname(record_id="host-1", value="example.test", source="fixture"):
    return {"id": record_id, "type": "hostname", "source": source, "value": value}


def xml(start="1"):
    return (f'<nmaprun scanner="nmap" start="{start}"><host>'
            '<hostnames><hostname name="EXAMPLE.TEST."/></hostnames>'
            '</host></nmaprun>')


def test_history_uses_normalized_stored_provenance_and_dataset_counts():
    inventory = AssetInventory()
    inventory.import_json(document(hostname(value="EXAMPLE.TEST."),
        hostname("host-2", source="other"), hostname(value="EXAMPLE.TEST.")), label="Dataset A")

    entry, = inventory.import_history
    assert (entry.label, entry.run_id, entry.format_name, entry.filename) == (
        "Dataset A", "run-1", "Native JSON", None)
    assert entry.observation_identities == (("run-1", "fixture", "host-1"), ("run-1", "other", "host-2"))
    assert entry.entity_keys == ("recon:hostname:example.test",)
    assert (entry.observation_count, entry.asset_count) == (2, 1)
    assert all(identity in {item.identity for item in inventory.observations}
               for identity in entry.observation_identities)
    assert entry.import_id


def test_normalized_duplicate_dataset_does_not_add_history_or_assets():
    inventory = AssetInventory()
    inventory.import_json(document(hostname("host-2", source="other"), hostname(value="EXAMPLE.TEST.")),
                          label="First label")
    before = inventory.import_history, inventory.assets, inventory.observations
    result = inventory.import_json(document(hostname(), hostname("host-2", source="other"), hostname()),
                                   label="Renamed copy")

    assert (result.added_observations, result.duplicates) == (0, 3)
    assert inventory.import_history is before[0]
    assert inventory.assets is before[1] and inventory.observations is before[2]
    assert inventory.import_history[0].label == "First label"


@pytest.mark.parametrize("kind", ["native", "nmap"])
def test_file_basename_is_metadata_and_renamed_copy_is_idempotent(kind, tmp_path):
    inventory = AssetInventory()
    first = tmp_path / ("first.json" if kind == "native" else "first.xml")
    copied = tmp_path / ("copy.json" if kind == "native" else "copy.xml")
    content = document(hostname()) if kind == "native" else xml()
    first.write_text(content, encoding="utf-8")
    copied.write_text(content, encoding="utf-8")
    importer = inventory.import_file if kind == "native" else inventory.import_nmap_file
    importer(first)
    before = inventory.import_history, inventory.assets
    result = importer(copied)

    entry, = inventory.import_history
    assert (entry.label, entry.filename) == (first.name, first.name)
    assert entry.format_name == ("Native JSON" if kind == "native" else "Nmap XML")
    assert result.added_observations == 0
    assert inventory.import_history is before[0] and inventory.assets is before[1]
    assert str(tmp_path) not in repr(entry)


@pytest.mark.parametrize("kind", ["native", "nmap"])
def test_same_basename_different_runs_have_distinct_history_and_correlate_asset(kind, tmp_path):
    inventory = AssetInventory()
    for index in (1, 2):
        folder = tmp_path / str(index)
        folder.mkdir()
        path = folder / ("results.json" if kind == "native" else "results.xml")
        path.write_text(document(hostname(), run_id=f"run-{index}") if kind == "native" else xml(str(index)),
                        encoding="utf-8")
        (inventory.import_file if kind == "native" else inventory.import_nmap_file)(path)

    one, two = inventory.import_history
    assert one.label == two.label
    assert one.run_id != two.run_id and one.import_id != two.import_id
    assert one.entity_keys == two.entity_keys == ("recon:hostname:example.test",)
    assert len(inventory.assets) == 1 and len(inventory.assets[0].observations) == 2


def test_native_nmap_and_scraper_batches_share_assets_and_keep_separate_dataset_provenance():
    inventory = AssetInventory()
    inventory.import_json(document(hostname()))
    nmap = inventory.import_nmap_xml(xml(), label="Offline XML")
    scraper_batch = parse_observations_json(document(hostname(source="scraper"), run_id="scraper-run"))
    inventory.import_batch(scraper_batch)

    native, nmap_entry, scraper_entry = inventory.import_history
    assert [entry.format_name for entry in inventory.import_history] == ["Native JSON", "Nmap XML", "Scraper"]
    assert nmap_entry.run_id == nmap.run_id
    assert scraper_entry.label == "Scraper" and scraper_entry.filename is None
    assert scraper_entry.observation_identities == (("scraper-run", "scraper", "host-1"),)
    assert all(entry.entity_keys == ("recon:hostname:example.test",) for entry in inventory.import_history)
    assert len(inventory.assets) == 1
    assert inventory.assets[0].sources == ("fixture", "nmap", "scraper")
    assert len({native.import_id, nmap_entry.import_id, scraper_entry.import_id}) == 3


def test_overlapping_import_history_includes_existing_members_and_distinct_subsets():
    inventory = AssetInventory()
    inventory.import_json(document(hostname()))
    inventory.import_json(document(hostname(), hostname("second", "other.test")), label="Expanded")
    inventory.import_json(document(hostname("second", "other.test")), label="Subset")

    first, expanded, subset = inventory.import_history
    assert expanded.observation_identities == (("run-1", "fixture", "host-1"), ("run-1", "fixture", "second"))
    assert expanded.entity_keys == ("recon:hostname:example.test", "recon:hostname:other.test")
    assert (expanded.observation_count, subset.observation_count) == (2, 1)
    assert len({first.import_id, expanded.import_id, subset.import_id}) == 3
    assert len(inventory.assets) == 2 and len(inventory.observations) == 2


@pytest.mark.parametrize("failure", ["invalid", "within_batch", "stored_conflict"])
def test_failed_import_preserves_history_inventory_and_snapshot_identity(failure):
    inventory = AssetInventory()
    inventory.import_json(document(hostname()))
    before = inventory.import_history, inventory.assets, inventory.observations
    records = [hostname("new", "new.test")]
    if failure == "invalid":
        records.append(hostname("bad", "bad/path"))
    elif failure == "within_batch":
        records.extend([hostname("same", "one.test"), hostname("same", "two.test")])
    else:
        records.append(hostname(value="changed.test"))

    with pytest.raises(ObservationImportError):
        inventory.import_json(document(*records), label="Failed dataset")

    assert inventory.import_history is before[0]
    assert inventory.assets is before[1] and inventory.observations is before[2]


def test_history_entries_and_old_snapshots_remain_immutable():
    inventory = AssetInventory()
    inventory.import_json(document(hostname()))
    snapshot = inventory.import_history
    assert isinstance(snapshot, tuple)
    with pytest.raises(FrozenInstanceError):
        snapshot[0].label = "Modified"
    with pytest.raises(TypeError):
        snapshot[0].observation_identities[0] = ("wrong", "wrong", "wrong")
    inventory.import_json(document(hostname(), run_id="later"))
    assert len(snapshot) == 1 and len(inventory.import_history) == 2
    assert snapshot[0].run_id == "run-1"


def test_empty_dataset_history_is_idempotent_and_retains_run_identity():
    inventory = AssetInventory()
    inventory.import_json(document(run_id="empty-one"))
    inventory.import_json(document(run_id="empty-one"), label="Copy")
    inventory.import_json(document(run_id="empty-two"))
    one, two = inventory.import_history
    assert (one.observation_count, one.asset_count, one.observation_identities, one.entity_keys) == (0, 0, (), ())
    assert one.import_id != two.import_id
    assert not inventory.assets and not inventory.observations


def test_public_batch_preserves_duplicate_accounting_and_original_conflict_index():
    inventory = AssetInventory()
    inventory.import_json(document(hostname(source="scraper")))
    batch = parse_observations_json(document(hostname("new", "new.test", "scraper"),
        hostname("new", "new.test", "scraper"), hostname(value="changed.test", source="scraper")))
    before = inventory.import_history, inventory.assets, inventory.observations
    with pytest.raises(ObservationImportError, match="Observation 3.*conflict"):
        inventory.import_batch(batch, label="Scraper run")
    assert inventory.import_history is before[0]
    assert inventory.assets is before[1] and inventory.observations is before[2]

    valid = parse_observations_json(document(hostname(source="scraper"), hostname(source="scraper")))
    result = inventory.import_batch(valid, label="Scraper run", format_name="Scraper")
    assert (result.added_observations, result.duplicates, result.total_assets) == (0, 2, 1)
    assert len(inventory.import_history) == 1


@pytest.mark.parametrize("malformed", ["wrong_type", "run_mismatch", "entity_key", "record_indices", "duplicates"])
def test_public_batch_rejects_invalid_provenance_without_mutating_inventory(malformed):
    inventory = AssetInventory()
    inventory.import_json(document(hostname()))
    before = inventory.import_history, inventory.assets, inventory.observations
    valid = parse_observations_json(document(hostname("new", "new.test"), run_id="new-run"))
    if malformed == "wrong_type":
        batch = object()
    elif malformed == "run_mismatch":
        batch = replace(valid, run_id="wrong-run")
    elif malformed == "entity_key":
        batch = replace(valid, observations=(replace(valid.observations[0], entity_key="recon:hostname:forged.test"),))
    elif malformed == "record_indices":
        batch = replace(valid, record_indices=(0,))
    else:
        batch = replace(valid, duplicates=-1)

    with pytest.raises(ObservationImportError):
        inventory.import_batch(batch)
    assert inventory.import_history is before[0]
    assert inventory.assets is before[1] and inventory.observations is before[2]


def test_public_batch_allows_missing_optional_record_indices():
    inventory = AssetInventory()
    parsed = parse_observations_json(document(hostname(), run_id="scraper-run"))
    result = inventory.import_batch(ObservationBatch(parsed.run_id, parsed.observations))
    assert result.added_observations == 1
    assert inventory.import_history[0].observation_identities == (("scraper-run", "fixture", "host-1"),)


@pytest.mark.parametrize("field,value", [("label", []), ("label", ""), ("format_name", {}), ("format_name", " ")])
def test_history_metadata_rejects_mutable_or_empty_labels_atomically(field, value):
    inventory = AssetInventory()
    batch = parse_observations_json(document(hostname()))
    with pytest.raises(ObservationImportError):
        inventory.import_batch(batch, **{field: value})
    assert inventory.import_history == () and inventory.assets == () and inventory.observations == ()
