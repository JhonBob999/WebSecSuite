"""Strict, bounded, offline version-1 observation imports."""

import importlib
import io
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest


def api():
    return importlib.import_module("core.recon.observations")


def envelope(*records, **changes):
    document = {
        "schema": "websecsuite.recon.observations", "version": 1,
        "run_id": "run-1", "observations": list(records),
    }
    document.update(changes)
    return json.dumps(document, ensure_ascii=False)


def hostname(**changes):
    record = {"id": "h-1", "type": "hostname", "source": "fixture", "value": "EXAMPLE.COM."}
    record.update(changes)
    return record


@pytest.mark.parametrize(("record", "entity_type", "value", "key"), [
    (hostname(), "hostname", "example.com", "recon:hostname:example.com"),
    (hostname(value="BÜCHER.example."), "hostname", "xn--bcher-kva.example", "recon:hostname:xn--bcher-kva.example"),
    ({"id": "ip-1", "type": "ip", "source": "fixture", "value": "192.0.2.10"}, "ip", "192.0.2.10", "recon:ip:192.0.2.10"),
    ({"id": "ip-2", "type": "ip", "source": "fixture", "value": "2001:0DB8:0:0::10"}, "ip", "2001:db8::10", "recon:ip:2001:db8::10"),
    ({"id": "s-1", "type": "service", "source": "fixture", "host": "EXAMPLE.COM.", "transport": "TCP", "port": 443}, "service", "example.com", "recon:service:tcp:example.com:443"),
    ({"id": "s-2", "type": "service", "source": "fixture", "host": "2001:0db8::10", "transport": "udp", "port": 53}, "service", "2001:db8::10", "recon:service:udp:[2001:db8::10]:53"),
])
def test_normalizes_records_with_stable_namespaced_keys(record, entity_type, value, key):
    batch = api().parse_observations_json(envelope(record))
    observation = batch.observations[0]
    assert (batch.run_id, batch.duplicates) == ("run-1", 0)
    assert (observation.entity_type, observation.value, observation.entity_key) == (entity_type, value, key)
    assert (observation.run_id, observation.source, observation.id) == ("run-1", "fixture", record["id"])


def test_observations_preserve_evidence_metadata_and_return_defensive_json_details():
    evidence = {"ref": "file:///inert/evidence.json", "kind": "synthetic", "metadata": {
        "nested": [None, True, 1, 1.5, {"label": "bücher"}], "command": "do not execute",
    }}
    batch = api().parse_observations_json(envelope(hostname(confidence=0.8, evidence=[evidence])))
    observation = batch.observations[0]
    details = observation.to_dict()
    assert details["evidence"] == [evidence]
    assert details["confidence"] == 0.8
    assert details["entity_key"] == "recon:hostname:example.com"
    assert details["run_id"] == "run-1"
    details["evidence"][0]["metadata"]["nested"].append("changed")
    assert observation.to_dict()["evidence"] == [evidence]
    with pytest.raises(FrozenInstanceError):
        observation.value = "changed.example"
    assert isinstance(batch.observations, tuple)


def test_exact_repeated_identity_coalesces_after_normalization():
    batch = api().parse_observations_json(envelope(hostname(), hostname(value="example.com"), hostname(id="h-2")))
    assert [item.id for item in batch.observations] == ["h-1", "h-2"]
    assert batch.duplicates == 1


@pytest.mark.parametrize("change", [
    {"value": "other.example"}, {"confidence": 0.9}, {"evidence": [{"ref": "another"}]},
])
def test_conflicting_identity_rejects_whole_batch_with_record_index(change):
    with pytest.raises(api().ObservationImportError, match=r"(?i)observation 2.*conflict"):
        api().parse_observations_json(envelope(hostname(), hostname(**change)))


def test_distinct_sources_and_runs_preserve_observation_identity():
    batch = api().parse_observations_json(envelope(hostname(), hostname(source="another")))
    assert len(batch.observations) == 2
    other = api().parse_observations_json(envelope(hostname(), run_id="run-2"))
    assert other.observations[0].run_id == "run-2"


@pytest.mark.parametrize("changes", [
    {"schema": "external-export"}, {"version": 2}, {"version": True},
    {"version": "1"}, {"observations": {}}, {"run_id": ""}, {"run_id": "x" * 129},
    {"extra": "unsupported"},
])
def test_rejects_unsupported_or_malformed_envelopes(changes):
    with pytest.raises(api().ObservationImportError):
        api().parse_observations_json(envelope(**changes))


@pytest.mark.parametrize("text", ["", " ", "{", "[]", "null", '{"schema":"one","schema":"two"}'])
def test_malformed_json_or_duplicate_envelope_keys_are_readable_errors(text):
    with pytest.raises(api().ObservationImportError) as error:
        api().parse_observations_json(text)
    assert str(error.value).strip()
    assert "\n" not in str(error.value)


@pytest.mark.parametrize("record", [
    None, [], {}, hostname(id=""), hostname(id=1), hostname(source=False),
    hostname(source="x" * 129), hostname(value="https://example.com"),
    hostname(value="192.0.2.10"), hostname(type="url"), hostname(extra="ignored?"),
    hostname(confidence=True), hostname(confidence=None), hostname(confidence=-0.1),
    hostname(confidence=1.1), hostname(confidence=float("nan")), hostname(confidence=float("inf")),
    hostname(evidence=None), hostname(evidence=["reference"]), hostname(evidence=[{}]),
    hostname(evidence=[{"ref": "x", "extra": 1}]), hostname(evidence=[{"ref": "x", "metadata": []}]),
    hostname(evidence=[{"ref": "x", "metadata": {"bad": float("nan")}}]),
])
def test_invalid_record_is_rejected_with_one_based_record_index(record):
    with pytest.raises(api().ObservationImportError, match=r"(?i)observation 2"):
        api().parse_observations_json(envelope(hostname(id="good"), record))


@pytest.mark.parametrize("value", ["fe80::1%eth0", "fe80::1%3", "[2001:db8::1]", "192.168.001.1", "example.com", ""])
def test_ip_records_reject_scoped_or_ambiguous_addresses(value):
    with pytest.raises(api().ObservationImportError, match=r"(?i)observation 1"):
        api().parse_observations_json(envelope({"id": "ip", "type": "ip", "source": "fixture", "value": value}))


@pytest.mark.parametrize(("field", "value"), [
    ("port", 0), ("port", 65536), ("port", True), ("port", 443.0), ("port", "443"),
    ("transport", "icmp"), ("host", "fe80::1%eth0"), ("host", "https://example.com"),
    ("service_name", None),
])
def test_service_validation_rejects_invalid_port_protocol_or_host(field, value):
    record = {"id": "s-1", "type": "service", "source": "fixture", "host": "example.com", "transport": "tcp", "port": 443}
    record[field] = value
    with pytest.raises(api().ObservationImportError, match=r"(?i)observation 1"):
        api().parse_observations_json(envelope(record))


@pytest.mark.parametrize("fragment", [
    '"id":"h-1","id":"h-2","type":"hostname","source":"fixture","value":"example.com"',
    '"id":"h-1","type":"hostname","source":"fixture","value":"example.com","evidence":[{"ref":"x","metadata":{"a":1,"a":2}}]',
])
def test_ambiguous_nested_duplicate_keys_report_record_index(fragment):
    text = '{"schema":"websecsuite.recon.observations","version":1,"run_id":"run-1","observations":[{' + fragment + '}]}'
    with pytest.raises(api().ObservationImportError, match=r"(?i)observation 1.*duplicate"):
        api().parse_observations_json(text)


def test_empty_observation_array_is_a_valid_no_op():
    batch = api().parse_observations_json(envelope())
    assert (batch.run_id, batch.observations, batch.duplicates) == ("run-1", (), 0)


def test_record_count_limit_includes_repeated_records():
    with pytest.raises(api().ObservationImportError, match="10,000"):
        api().parse_observations_json(envelope(*([hostname()] * 10001)))


@pytest.mark.parametrize("record", [
    hostname(evidence=[{"ref": str(index)} for index in range(33)]),
    hostname(evidence=[{"ref": "r" * 1025}]),
    hostname(evidence=[{"ref": "x", "metadata": {"text": "x" * 4096}}]),
])
def test_evidence_count_reference_and_metadata_byte_limits(record):
    with pytest.raises(api().ObservationImportError, match=r"(?i)observation 1"):
        api().parse_observations_json(envelope(record))


def test_metadata_depth_limit_rejects_deep_json_without_crashing():
    metadata = {}
    cursor = metadata
    for _ in range(8):
        cursor["nested"] = {}
        cursor = cursor["nested"]
    with pytest.raises(api().ObservationImportError, match=r"(?i)observation 1.*depth"):
        api().parse_observations_json(envelope(hostname(evidence=[{"ref": "x", "metadata": metadata}])))


def test_file_import_decodes_utf8_bom_and_rejects_bad_utf8(tmp_path):
    path = tmp_path / "observations.JSON"
    path.write_text(envelope(hostname(value="bücher.example")), encoding="utf-8-sig")
    assert api().read_observations_file(path).observations[0].value == "xn--bcher-kva.example"
    path.write_bytes(b"\xff\xfe{}")
    with pytest.raises(api().ObservationImportError, match="UTF-8"):
        api().read_observations_file(path)


@pytest.mark.parametrize("path", [
    r"\\server\share\records.json", "//server/share/records.json", r"\/server/share/records.json",
    "https://example.com/records.json", "file://server/share/records.json", "file:/tmp/records.json",
    r"\\?\C:\records.json", r"\\.\pipe\records.json", r"\??\C:\records.json", "NUL.json",
])
def test_remote_and_device_paths_are_rejected_before_access(path, monkeypatch):
    def unexpected_open(*args, **kwargs):
        raise AssertionError("Rejected paths must never be opened")

    monkeypatch.setattr(Path, "open", unexpected_open)
    with pytest.raises(api().ObservationImportError, match="local"):
        api().read_observations_file(path)


def test_file_format_and_missing_file_errors_are_wrapped(tmp_path):
    with pytest.raises(api().ObservationImportError, match="JSON"):
        api().read_observations_file(tmp_path / "records.xml")
    with pytest.raises(api().ObservationImportError, match="read"):
        api().read_observations_file(tmp_path / "missing.json")


def test_invalid_local_file_path_is_wrapped_as_an_import_error():
    with pytest.raises(api().ObservationImportError):
        api().read_observations_file("bad\x00name.json")


def test_byte_limit_applies_to_text_and_file_reads_are_bounded(monkeypatch):
    oversized = b" " * (8 * 1024 * 1024 + 1)
    with pytest.raises(api().ObservationImportError, match="8 MiB"):
        api().parse_observations_json(oversized.decode("ascii"))

    class BoundedRead(io.BytesIO):
        def read(self, size=-1):
            assert size == 8 * 1024 * 1024 + 1
            return super().read(size)

    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: BoundedRead(oversized))
    with pytest.raises(api().ObservationImportError, match="8 MiB"):
        api().read_observations_file("local.json")


def test_normalization_and_evidence_are_inert_without_network_or_subprocess(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Observation imports must remain offline and inert")

    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    monkeypatch.setattr("socket.gethostbyname", forbidden)
    monkeypatch.setattr("socket.socket", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    record = hostname(evidence=[{"ref": "https://example.invalid/evidence", "metadata": {"command": "curl example.invalid"}}])
    batch = api().parse_observations_json(envelope(record))
    assert batch.observations[0].to_dict()["evidence"][0]["ref"] == "https://example.invalid/evidence"
