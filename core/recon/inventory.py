"""In-memory, provenance-preserving normalized asset inventory."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from core.recon.nmap_import import parse_nmap_xml, read_nmap_file
from core.recon.observations import (
    MAX_OBSERVATIONS, SCHEMA, VERSION,
    Observation, ObservationBatch, ObservationImportError,
    parse_observations_json, read_observations_file,
)


@dataclass(frozen=True)
class Asset:
    entity_key: str
    entity_type: str
    value: str
    transport: str | None
    port: int | None
    service_names: tuple[str, ...]
    sources: tuple[str, ...]
    evidence_count: int
    observations: tuple[Observation, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_key": self.entity_key, "entity_type": self.entity_type,
            "value": self.value, "transport": self.transport, "port": self.port,
            "service_names": list(self.service_names), "sources": list(self.sources),
            "evidence_count": self.evidence_count,
            "observations": [observation.to_dict() for observation in self.observations],
        }


@dataclass(frozen=True)
class InventoryImportResult:
    added_observations: int
    duplicates: int
    total_assets: int
    run_id: str


@dataclass(frozen=True)
class InventoryImportEntry:
    """One dataset's stored provenance; labels never define dataset identity."""

    import_id: str
    label: str
    run_id: str
    format_name: str
    filename: str | None
    observation_identities: tuple[tuple[str, str, str], ...]
    entity_keys: tuple[str, ...]

    @property
    def observation_count(self) -> int:
        return len(self.observation_identities)

    @property
    def asset_count(self) -> int:
        return len(self.entity_keys)


def _validated_batch(batch: ObservationBatch) -> ObservationBatch:
    """Keep the public in-memory adapter behind the native validation gate."""
    if not isinstance(batch, ObservationBatch) or not isinstance(batch.observations, tuple):
        raise ObservationImportError("Expected an immutable observation batch.")
    if len(batch.observations) > MAX_OBSERVATIONS:
        raise ObservationImportError("observations exceeds the 10,000 record import limit.")
    if type(batch.duplicates) is not int or batch.duplicates < 0:
        raise ObservationImportError("Observation batch duplicates must be a nonnegative integer.")
    if (not isinstance(batch.record_indices, tuple) or
            (batch.record_indices and (
                len(batch.record_indices) != len(batch.observations) or
                any(type(index) is not int or index < 1 for index in batch.record_indices) or
                tuple(sorted(set(batch.record_indices))) != batch.record_indices))):
        raise ObservationImportError("Observation batch record indices are invalid.")
    records = []
    try:
        for observation in batch.observations:
            if not isinstance(observation, Observation) or observation.run_id != batch.run_id:
                raise ObservationImportError("Observation batch run_id does not match its records.")
            record = observation.to_dict()
            record.pop("run_id")
            record.pop("entity_key")
            records.append(record)
        validated = parse_observations_json(json.dumps({
            "schema": SCHEMA, "version": VERSION, "run_id": batch.run_id, "observations": records,
        }, ensure_ascii=False, allow_nan=False))
    except (AttributeError, TypeError, ValueError, OverflowError, RecursionError) as error:
        if isinstance(error, ObservationImportError):
            raise
        raise ObservationImportError("Invalid observation batch: " + " ".join(str(error).split())) from None
    if validated.observations != batch.observations:
        raise ObservationImportError("Observation batch records must be normalized and unique.")
    return ObservationBatch(validated.run_id, validated.observations, batch.duplicates,
                            batch.record_indices or validated.record_indices)


def _assets(observations: tuple[Observation, ...]) -> tuple[Asset, ...]:
    grouped: dict[str, list[Observation]] = defaultdict(list)
    for observation in observations:
        grouped[observation.entity_key].append(observation)
    assets = []
    for entity_key, members in sorted(grouped.items()):
        first = members[0]
        assets.append(Asset(
            entity_key, first.entity_type, first.value, first.transport, first.port,
            tuple(sorted({item.service_name for item in members if item.service_name is not None})),
            tuple(sorted({item.source for item in members})),
            len({reference for item in members for reference in item.evidence}), tuple(members),
        ))
    return tuple(assets)


class AssetInventory:
    """Atomic native imports with immutable, deterministic inventory snapshots."""

    def __init__(self) -> None:
        self._by_identity: dict[tuple[str, str, str], Observation] = {}
        self._observations: tuple[Observation, ...] = ()
        self._assets: tuple[Asset, ...] = ()
        self._import_history: tuple[InventoryImportEntry, ...] = ()

    @property
    def assets(self) -> tuple[Asset, ...]:
        return self._assets

    @property
    def observations(self) -> tuple[Observation, ...]:
        return self._observations

    @property
    def import_history(self) -> tuple[InventoryImportEntry, ...]:
        return self._import_history

    def import_json(self, text: str, *, label: str = "Native JSON") -> InventoryImportResult:
        return self._import_batch(parse_observations_json(text), label=label, format_name="Native JSON")

    def import_file(self, path: str | Path, *, label: str | None = None) -> InventoryImportResult:
        batch = read_observations_file(path)
        filename = Path(path).name
        return self._import_batch(batch, label=filename if label is None else label,
                                  format_name="Native JSON", filename=filename)

    def import_nmap_xml(self, content: bytes | str, *, label: str = "Nmap XML") -> InventoryImportResult:
        return self._import_batch(parse_nmap_xml(content), label=label, format_name="Nmap XML")

    def import_nmap_file(self, path: str | Path, *, label: str | None = None) -> InventoryImportResult:
        batch = read_nmap_file(path)
        filename = Path(path).name
        return self._import_batch(batch, label=filename if label is None else label,
                                  format_name="Nmap XML", filename=filename)

    def import_batch(self, batch: ObservationBatch, *, label: str = "Scraper",
                     format_name: str = "Scraper") -> InventoryImportResult:
        """Atomically import a validated in-memory dataset without file access."""
        return self._import_batch(_validated_batch(batch), label=label, format_name=format_name)

    def _import_batch(self, batch: ObservationBatch, *, label: str = "Native JSON",
                      format_name: str = "Native JSON", filename: str | None = None) -> InventoryImportResult:
        if not isinstance(label, str) or not label.strip():
            raise ObservationImportError("Import label must be nonempty text.")
        if not isinstance(format_name, str) or not format_name.strip():
            raise ObservationImportError("Import format name must be nonempty text.")
        planned = self._by_identity.copy()
        added, duplicates = 0, batch.duplicates
        for index, observation in enumerate(batch.observations, 1):
            previous = planned.get(observation.identity)
            if previous is not None:
                if previous != observation:
                    record_index = batch.record_indices[index - 1]
                    raise ObservationImportError(
                        f"Observation {record_index}: conflicting stored record shares run_id, source, and id."
                    )
                duplicates += 1
            else:
                planned[observation.identity] = observation
                added += 1
        observations, assets = self._observations, self._assets
        if added:
            observations = tuple(planned[identity] for identity in sorted(planned))
            assets = _assets(observations)
        identities = tuple(sorted({item.identity for item in batch.observations}))
        members = tuple(planned[identity] for identity in identities)
        digest = hashlib.sha256(json.dumps((batch.run_id, identities), ensure_ascii=False,
                                          separators=(",", ":")).encode("utf-8")).hexdigest()
        import_id = f"recon:import:sha256:{digest}"
        history = self._import_history
        if not any(entry.import_id == import_id for entry in history):
            entry = InventoryImportEntry(import_id, label, batch.run_id, format_name, filename,
                                         tuple(item.identity for item in members),
                                         tuple(sorted({item.entity_key for item in members})))
            history = (*history, entry)
        self._by_identity, self._observations, self._assets, self._import_history = (
            planned, observations, assets, history)
        return InventoryImportResult(added, duplicates, len(assets), batch.run_id)


__all__ = ["Asset", "AssetInventory", "InventoryImportEntry", "InventoryImportResult"]
