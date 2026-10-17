"""Bounded, atomic imports of the passive Subfinder ``-oJ -cs`` output path.

The supported schema is the official v2.17.0 ``writeSourceJSONHost`` path:
https://github.com/projectdiscovery/subfinder/blob/v2.17.0/pkg/runner/outputter.go
Its encoder emits host, input, and sources, followed by a newline per record.
Alternate output modes and future schema changes require explicit review.
This adapter performs no DNS, file access, or execution authorization.
"""

from __future__ import annotations

import hashlib
import json
import re

from core.recon.observations import (
    MAX_EVIDENCE, MAX_OBSERVATIONS, SCHEMA, VERSION, ObservationBatch,
    ObservationImportError, parse_observations_json,
)
from core.recon.process_supervisor import JobSnapshot, JobState
from core.recon.targets import normalize_hostname


MAX_SUBFINDER_OUTPUT_BYTES = 1_048_576
MAX_SUBFINDER_LINE_BYTES = 16_384
MAX_SUBFINDER_RECORDS = MAX_OBSERVATIONS
MAX_SUBFINDER_SOURCES = MAX_EVIDENCE - 1
_ADAPTER_ID = "subfinder.passive-standard"
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_PROVIDER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def _identity(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTITY.fullmatch(value) is None:
        raise ObservationImportError(f"Subfinder {label} must be a bounded inert run identifier.")
    return value


def _hostname(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) > 1024:
        raise ObservationImportError(f"Subfinder {label} must be bounded hostname text.")
    try:
        return normalize_hostname(value)
    except (TypeError, ValueError, UnicodeError):
        raise ObservationImportError(f"Subfinder {label} must be a valid R1 hostname.") from None


def _context(result: JobSnapshot, root_domain: str, run_id: str) -> tuple[str, str]:
    if (type(result) is not JobSnapshot or result.adapter_id != _ADAPTER_ID
            or type(result.state) is not JobState or result.state is not JobState.SUCCEEDED
            or type(result.exit_code) is not int or result.exit_code != 0
            or type(result.stdout_truncated) is not bool or result.stdout_truncated
            or type(result.stderr_truncated) is not bool or result.stderr_truncated):
        raise ObservationImportError("Only complete successful Passive Standard Subfinder jobs can be imported.")
    if (type(result.stdout) is not bytes or type(result.stderr) is not bytes
            or len(result.stdout) + len(result.stderr) > MAX_SUBFINDER_OUTPUT_BYTES):
        raise ObservationImportError("Subfinder process output exceeds its bounded byte format.")
    _identity(result.job_id, "job identity")
    return _hostname(root_domain, "root domain"), _identity(run_id, "run identity")


def _object(pairs: list[tuple[str, object]]) -> dict:
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("Duplicate JSON object keys are not supported.")
        document[key] = value
    return document


def _nonfinite(value: str) -> None:
    raise ValueError("Nonfinite JSON values are not supported.")


def _record(line: bytes, index: int, root_domain: str) -> tuple[str, set[str]]:
    label = f"Subfinder record {index}"
    if not line or len(line) > MAX_SUBFINDER_LINE_BYTES:
        raise ObservationImportError(f"{label} is empty or exceeds the line byte limit.")
    try:
        document = json.loads(line.decode("utf-8"), object_pairs_hook=_object, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError):
        raise ObservationImportError(f"{label} must contain one complete valid UTF-8 JSON object.") from None
    if type(document) is not dict or set(document) != {"host", "input", "sources"}:
        raise ObservationImportError(f"{label} requires only host, input, and sources for the passive profile.")
    host = _hostname(document["host"], f"record {index} host")
    if _hostname(document["input"], f"record {index} input") != root_domain:
        raise ObservationImportError(f"{label} input does not match the captured root domain.")
    sources = document["sources"]
    if type(sources) is not list or not 1 <= len(sources) <= MAX_SUBFINDER_SOURCES:
        raise ObservationImportError(f"{label} sources must be a nonempty bounded provider array.")
    providers = set()
    for source in sources:
        if not isinstance(source, str) or _PROVIDER.fullmatch(source) is None:
            raise ObservationImportError(f"{label} contains an invalid provider name.")
        providers.add(source.lower())
    return host, providers


def parse_subfinder_output(result: JobSnapshot, *, root_domain: str, run_id: str) -> ObservationBatch:
    """Validate the complete successful job before returning hostname observations.

    A repeated hostname combines its provider references. Out-of-root names are
    excluded by label boundaries, after validating their complete record. Neither
    a provider result nor root membership asserts scope, resolution, or reachability.
    All diagnostics omit raw tool output and rejected values.
    """
    root_domain, run_id = _context(result, root_domain, run_id)
    content = result.stdout
    if content and not content.endswith(b"\n"):
        raise ObservationImportError("Subfinder JSONL is incomplete: the final record has no encoder newline.")
    lines = content.split(b"\n")[:-1] if content else []
    if len(lines) > MAX_SUBFINDER_RECORDS:
        raise ObservationImportError("Subfinder JSONL exceeds the record limit.")
    hosts: dict[str, set[str]] = {}
    record_indices = []
    duplicates = out_of_root = 0
    for index, line in enumerate(lines, 1):
        host, providers = _record(line.removesuffix(b"\r"), index, root_domain)
        if host != root_domain and not host.endswith("." + root_domain):
            out_of_root += 1
            continue
        if host in hosts:
            combined = hosts[host] | providers
            if len(combined) > MAX_SUBFINDER_SOURCES:
                raise ObservationImportError(f"Subfinder record {index} exceeds the combined provider limit.")
            hosts[host] = combined
            duplicates += 1
        else:
            hosts[host] = providers
            record_indices.append(index)
    metadata = {
        "adapter_id": _ADAPTER_ID, "job_id": result.job_id,
        "root_domain": root_domain, "profile": "Passive Standard", "execution_mode": "passive",
        "stdout_sha256": hashlib.sha256(content).hexdigest(), "stdout_bytes": len(content),
        "subfinder_discovery": {
            "discovered_hostnames": len(hosts), "duplicate_records": duplicates,
            "out_of_root_records": out_of_root,
        },
    }
    records = []
    for host, providers in hosts.items():
        records.append({
            "id": "hostname:" + hashlib.sha256(host.encode("ascii")).hexdigest(),
            "type": "hostname", "source": "subfinder", "value": host,
            "evidence": [{"ref": run_id + ":run", "kind": "subfinder-run", "metadata": metadata}, *(
                {"ref": run_id + ":source:" + provider, "kind": "subfinder-source",
                 "metadata": {"provider": provider}} for provider in sorted(providers)
            )],
        })
    # The native gate enforces the shared inventory contract and evidence bounds
    # before any caller can add observations or history to its inventory.
    batch = parse_observations_json(json.dumps({
        "schema": SCHEMA, "version": VERSION, "run_id": run_id, "observations": records,
    }, ensure_ascii=False, allow_nan=False))
    return ObservationBatch(batch.run_id, batch.observations, duplicates, tuple(record_indices))


__all__ = ["parse_subfinder_output"]
