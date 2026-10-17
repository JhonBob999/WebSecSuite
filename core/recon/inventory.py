"""In-memory, provenance-preserving normalized asset inventory."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.recon.observations import (
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

    @property
    def assets(self) -> tuple[Asset, ...]:
        return self._assets

    @property
    def observations(self) -> tuple[Observation, ...]:
        return self._observations

    def import_json(self, text: str) -> InventoryImportResult:
        return self._import_batch(parse_observations_json(text))

    def import_file(self, path: str | Path) -> InventoryImportResult:
        return self._import_batch(read_observations_file(path))

    def _import_batch(self, batch: ObservationBatch) -> InventoryImportResult:
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
        if added:
            observations = tuple(planned[identity] for identity in sorted(planned))
            assets = _assets(observations)
            self._by_identity, self._observations, self._assets = planned, observations, assets
        return InventoryImportResult(added, duplicates, len(self._assets), batch.run_id)


__all__ = ["Asset", "AssetInventory", "InventoryImportResult"]
