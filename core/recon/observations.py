"""Bounded native observation imports; values and evidence are never fetched."""

from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.recon.targets import normalize_hostname


SCHEMA = "websecsuite.recon.observations"
VERSION = 1
MAX_IMPORT_BYTES = 8 * 1024 * 1024
MAX_OBSERVATIONS = 10_000
MAX_EVIDENCE = 32
MAX_METADATA_BYTES = 4096
MAX_METADATA_DEPTH = 8


class ObservationImportError(ValueError):
    """A native observation document or its local file cannot be imported."""


@dataclass(frozen=True)
class EvidenceRef:
    """An inert reference with immutable JSON metadata storage."""

    ref: str
    kind: str | None = None
    _metadata_json: str | None = None

    @property
    def metadata(self) -> dict[str, Any] | None:
        return None if self._metadata_json is None else json.loads(self._metadata_json)

    def to_dict(self) -> dict[str, Any]:
        details: dict[str, Any] = {"ref": self.ref}
        if self.kind is not None:
            details["kind"] = self.kind
        if self._metadata_json is not None:
            details["metadata"] = self.metadata
        return details


@dataclass(frozen=True)
class Observation:
    """One normalized source observation, preserving its import provenance."""

    run_id: str
    id: str
    source: str
    entity_key: str
    entity_type: str
    value: str
    transport: str | None = None
    port: int | None = None
    service_name: str | None = None
    confidence: float | None = None
    evidence: tuple[EvidenceRef, ...] = ()

    @property
    def identity(self) -> tuple[str, str, str]:
        return self.run_id, self.source, self.id

    def to_dict(self) -> dict[str, Any]:
        details: dict[str, Any] = {
            "run_id": self.run_id, "id": self.id, "source": self.source,
            "type": self.entity_type, "entity_key": self.entity_key,
        }
        if self.entity_type == "service":
            details.update(host=self.value, transport=self.transport, port=self.port)
            if self.service_name is not None:
                details["service_name"] = self.service_name
        else:
            details["value"] = self.value
        if self.confidence is not None:
            details["confidence"] = self.confidence
        details["evidence"] = [item.to_dict() for item in self.evidence]
        return details


@dataclass(frozen=True)
class ObservationBatch:
    run_id: str
    observations: tuple[Observation, ...]
    duplicates: int = 0
    record_indices: tuple[int, ...] = ()


class _JSONObject(dict):
    """Keep duplicate-key information until a record index is available."""

    def __init__(self, pairs):
        super().__init__()
        self.duplicate_keys = []
        for key, value in pairs:
            if key in self:
                self.duplicate_keys.append(key)
            self[key] = value


def _one_line(value: object) -> str:
    return " ".join(str(value).split())


def _validate_json_values(value: Any, context: str, depth: int = 0) -> None:
    if depth > 16:
        raise ObservationImportError(f"{context}: JSON nesting is too deep.")
    if isinstance(value, _JSONObject):
        if value.duplicate_keys:
            raise ObservationImportError(f"{context}: duplicate JSON object keys are ambiguous.")
        for item in value.values():
            _validate_json_values(item, context, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _validate_json_values(item, context, depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ObservationImportError(f"{context}: nonfinite JSON numbers are not supported.")
    elif isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeError:
            raise ObservationImportError(f"{context}: text contains an invalid Unicode character.") from None


def _text(value: Any, label: str, limit: int = 128) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be nonempty text.")
    if len(value) > limit:
        raise ValueError(f"{label} must contain at most {limit} characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{label} must not contain control characters.")
    return value


def _ip(value: Any) -> str:
    value = _text(value, "IP value", 128).strip()
    if "%" in value:
        raise ValueError("Scoped IP addresses are ambiguous and are not supported.")
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        raise ValueError("IP value must be an unscoped IPv4 or IPv6 address.") from None


def _host(value: Any) -> str:
    value = _text(value, "Service host", 1024).strip()
    if "%" in value:
        raise ValueError("Scoped IP addresses are ambiguous and are not supported.")
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return normalize_hostname(value)


def _metadata_depth(value: Any, depth: int = 1) -> None:
    if not isinstance(value, (dict, list)):
        return
    if depth > MAX_METADATA_DEPTH:
        raise ValueError(f"Evidence metadata exceeds depth {MAX_METADATA_DEPTH}.")
    values = value.values() if isinstance(value, dict) else value
    for item in values:
        _metadata_depth(item, depth + 1)


def _evidence(value: Any) -> tuple[EvidenceRef, ...]:
    if not isinstance(value, list):
        raise ValueError("evidence must be an array.")
    if len(value) > MAX_EVIDENCE:
        raise ValueError(f"evidence must contain at most {MAX_EVIDENCE} references.")
    references = []
    for index, item in enumerate(value, 1):
        label = f"Evidence {index}"
        if not isinstance(item, dict):
            raise ValueError(f"{label} must be an object.")
        if set(item) - {"ref", "kind", "metadata"}:
            raise ValueError(f"{label} contains unsupported fields.")
        ref = _text(item.get("ref"), f"{label} ref", 1024)
        kind = _text(item["kind"], f"{label} kind") if "kind" in item else None
        metadata_json = None
        if "metadata" in item:
            if not isinstance(item["metadata"], dict):
                raise ValueError(f"{label} metadata must be a JSON object.")
            _metadata_depth(item["metadata"])
            metadata_json = json.dumps(item["metadata"], ensure_ascii=False, sort_keys=True,
                                       separators=(",", ":"), allow_nan=False)
            if len(metadata_json.encode("utf-8")) > MAX_METADATA_BYTES:
                raise ValueError(f"{label} metadata exceeds {MAX_METADATA_BYTES} encoded bytes.")
        references.append(EvidenceRef(ref, kind, metadata_json))
    return tuple(references)


def _observation(record: Any, run_id: str) -> Observation:
    if not isinstance(record, dict):
        raise ValueError("Record must be a JSON object.")
    entity_type = record.get("type")
    if entity_type not in ("hostname", "ip", "service"):
        raise ValueError("type must be hostname, ip, or service.")
    allowed = {"id", "type", "source", "confidence", "evidence"}
    allowed.update({"host", "transport", "port", "service_name"} if entity_type == "service" else {"value"})
    if set(record) - allowed:
        raise ValueError("Record contains unsupported fields.")
    record_id = _text(record.get("id"), "id")
    source = _text(record.get("source"), "source")
    confidence = None
    if "confidence" in record:
        raw_confidence = record["confidence"]
        if (type(raw_confidence) not in (int, float) or
                not 0 <= raw_confidence <= 1 or not math.isfinite(raw_confidence)):
            raise ValueError("confidence must be a finite number between 0 and 1.")
        confidence = float(raw_confidence)
    transport, port, service_name = None, None, None
    if entity_type == "hostname":
        value = normalize_hostname(_text(record.get("value"), "Hostname value", 1024))
    elif entity_type == "ip":
        value = _ip(record.get("value"))
    else:
        value = _host(record.get("host"))
        transport = _text(record.get("transport"), "transport").strip().lower()
        if transport not in {"tcp", "udp", "sctp"}:
            raise ValueError("transport must be tcp, udp, or sctp.")
        port = record.get("port")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("port must be an integer between 1 and 65535.")
        if "service_name" in record:
            service_name = _text(record["service_name"], "service_name")
    if entity_type == "service":
        key_host = f"[{value}]" if ":" in value else value
        entity_key = f"recon:service:{transport}:{key_host}:{port}"
    else:
        entity_key = f"recon:{entity_type}:{value}"
    return Observation(run_id, record_id, source, entity_key, entity_type, value,
                       transport, port, service_name, confidence, _evidence(record.get("evidence", [])))


def parse_observations_json(text: str) -> ObservationBatch:
    """Validate the complete native document before returning normalized records."""
    if not isinstance(text, str):
        raise ObservationImportError("Observation JSON must be UTF-8 text.")
    try:
        if len(text) > MAX_IMPORT_BYTES or len(text.encode("utf-8")) > MAX_IMPORT_BYTES:
            raise ObservationImportError("Observation JSON exceeds the 8 MiB import limit.")
        document = json.loads(text.removeprefix("\ufeff"), object_pairs_hook=_JSONObject)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        if isinstance(error, ObservationImportError):
            raise
        raise ObservationImportError("Malformed observation JSON: " + _one_line(error)) from None
    if not isinstance(document, dict):
        raise ObservationImportError("Observation JSON envelope must be an object.")
    if document.duplicate_keys:
        raise ObservationImportError("Observation envelope contains duplicate JSON keys.")
    if set(document) != {"schema", "version", "run_id", "observations"}:
        raise ObservationImportError("Observation envelope requires only schema, version, run_id, and observations.")
    if document["schema"] != SCHEMA or type(document["version"]) is not int or document["version"] != VERSION:
        raise ObservationImportError("Unsupported observation schema or version; expected native version 1.")
    try:
        run_id = _text(document["run_id"], "run_id")
        _validate_json_values(run_id, "Observation envelope")
    except ValueError as error:
        raise ObservationImportError(_one_line(error)) from None
    records = document["observations"]
    if not isinstance(records, list):
        raise ObservationImportError("observations must be an array.")
    if len(records) > MAX_OBSERVATIONS:
        raise ObservationImportError("observations exceeds the 10,000 record import limit.")
    seen: dict[tuple[str, str, str], Observation] = {}
    record_indices = []
    duplicates = 0
    for index, record in enumerate(records, 1):
        context = f"Observation {index}"
        try:
            _validate_json_values(record, context)
            observation = _observation(record, run_id)
            previous = seen.get(observation.identity)
            if previous is not None:
                if previous != observation:
                    raise ValueError("Conflicting records share the same run_id, source, and id.")
                duplicates += 1
            else:
                seen[observation.identity] = observation
                record_indices.append(index)
        except ObservationImportError:
            raise
        except (ValueError, TypeError, OverflowError, RecursionError) as error:
            raise ObservationImportError(f"{context}: {_one_line(error)}") from None
    return ObservationBatch(run_id, tuple(seen.values()), duplicates, tuple(record_indices))


def _local_json_path(path: str | Path) -> Path:
    path_text = str(path)
    normalized = path_text.replace("\\", "/")
    has_scheme = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", path_text)
    drive_absolute = re.match(r"^[A-Za-z]:[/\\]", path_text)
    device_names = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                    *(f"LPT{i}" for i in range(1, 10))}
    if (normalized.startswith(("//", "/??/", "/Device/")) or
            (has_scheme and not drive_absolute) or
            any(part.rstrip(" .").split(".")[0].upper() in device_names for part in normalized.split("/"))):
        raise ObservationImportError("Choose a local JSON file; remote and device paths are not supported.")
    file_path = Path(path_text)
    if file_path.suffix.lower() != ".json":
        raise ObservationImportError("Unsupported file type; choose a local JSON file.")
    return file_path


def read_observations_file(path: str | Path) -> ObservationBatch:
    """Read a bounded local UTF-8 JSON file; never follow evidence references."""
    file_path = _local_json_path(path)
    try:
        with file_path.open("rb") as handle:
            content = handle.read(MAX_IMPORT_BYTES + 1)
        if len(content) > MAX_IMPORT_BYTES:
            raise ObservationImportError("Observation file exceeds the 8 MiB import limit.")
        text = content.decode("utf-8-sig")
    except UnicodeError:
        raise ObservationImportError("Observation file must contain valid UTF-8 JSON text.") from None
    except (OSError, ValueError) as error:
        if isinstance(error, ObservationImportError):
            raise
        raise ObservationImportError("Could not read observation file: " + _one_line(error)) from None
    return parse_observations_json(text)


__all__ = ["EvidenceRef", "Observation", "ObservationBatch", "ObservationImportError",
           "parse_observations_json", "read_observations_file"]
