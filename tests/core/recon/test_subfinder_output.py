"""Synthetic, offline Subfinder JSONL validation and inventory integration."""

import hashlib
import importlib
import json
import socket

import pytest

from core.recon.inventory import AssetInventory
from core.recon.observations import ObservationImportError
from core.recon.process_supervisor import JobSnapshot, JobState


RUN_ID = "subfinder:passive:synthetic-run-1"
ROOT = "example.test"
_DEFAULT_SOURCES = object()


def api():
    return importlib.import_module("core.recon.subfinder_output")


def record(host="api.example.test", sources=_DEFAULT_SOURCES, **changes):
    values = {"host": host, "input": ROOT, "sources": ["crtsh"] if sources is _DEFAULT_SOURCES else sources}
    values.update(changes)
    return values


def output(*records):
    return b"".join((json.dumps(item, ensure_ascii=False) + "\n").encode("utf-8") for item in records)


def result(raw=None, **changes):
    values = dict(job_id="synthetic-job-1", adapter_id="subfinder.passive-standard",
                  state=JobState.SUCCEEDED, stdout=output(record()) if raw is None else raw,
                  stderr=b"", exit_code=0)
    values.update(changes)
    return JobSnapshot(**values)


def parse(raw=None, *, root_domain=ROOT, run_id=RUN_ID, **changes):
    return api().parse_subfinder_output(result(raw, **changes), root_domain=root_domain, run_id=run_id)


def run_metadata(batch):
    return next(item.metadata for item in batch.observations[0].evidence if item.kind == "subfinder-run")


def test_successful_jsonl_normalizes_hostnames_and_keeps_only_passive_bounded_provenance(monkeypatch):
    def no_dns(*args, **kwargs):
        pytest.fail("A passive output import must not resolve DNS.")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    raw = output(record("API.EXAMPLE.TEST."), record("b\u00fccher.example.test", ["alienvault", "crtsh"]))
    batch = parse(raw, stderr=b"private diagnostic and token=do-not-store",
                  diagnostic="C:\\private\\provider-config.yaml")
    assert batch.run_id == RUN_ID
    assert [(item.source, item.entity_type, item.value) for item in batch.observations] == [
        ("subfinder", "hostname", "api.example.test"),
        ("subfinder", "hostname", "xn--bcher-kva.example.test"),
    ]
    assert all(item.port is None and item.transport is None and item.confidence is None
               for item in batch.observations)
    metadata = run_metadata(batch)
    assert metadata == {
        "adapter_id": "subfinder.passive-standard", "job_id": "synthetic-job-1",
        "root_domain": ROOT, "profile": "Passive Standard", "execution_mode": "passive",
        "stdout_sha256": hashlib.sha256(raw).hexdigest(), "stdout_bytes": len(raw),
        "subfinder_discovery": {"discovered_hostnames": 2, "duplicate_records": 0, "out_of_root_records": 0},
    }
    assert [(item.kind, item.metadata) for item in batch.observations[1].evidence[1:]] == [
        ("subfinder-source", {"provider": "alienvault"}), ("subfinder-source", {"provider": "crtsh"}),
    ]
    assert all(item.ref.startswith(RUN_ID + ":") for host in batch.observations for item in host.evidence)
    serialized = json.dumps([item.to_dict() for item in batch.observations])
    assert "private" not in serialized and "token" not in serialized and "provider-config" not in serialized
    assert all(name not in metadata for name in ("in_scope", "reachable", "dns", "ip", "authorized"))


def test_duplicates_combine_provider_references_and_out_of_root_records_are_excluded():
    batch = parse(output(record("badexample.test"), record("API.EXAMPLE.TEST.", ["crtsh", "crtsh"]),
                         record("example.test.attacker.test"), record("api.example.test", ["alienvault"]),
                         record("example.test", ["crtsh"])))
    assert [item.value for item in batch.observations] == ["api.example.test", "example.test"]
    assert batch.duplicates == 1 and batch.record_indices == (2, 5)
    assert run_metadata(batch)["subfinder_discovery"] == {
        "discovered_hostnames": 2, "duplicate_records": 1, "out_of_root_records": 2,
    }
    providers = [item.metadata["provider"] for item in batch.observations[0].evidence if item.kind == "subfinder-source"]
    assert providers == ["alienvault", "crtsh"]
    assert len({item.ref for item in batch.observations[0].evidence}) == 3


def test_root_input_and_provider_case_use_canonical_normalization():
    batch = parse(output(record("API.EXAMPLE.TEST.", ["CRTSh", "crtsh"], input="EXAMPLE.TEST.")),
                  root_domain="EXAMPLE.TEST.")
    assert batch.observations[0].value == "api.example.test"
    assert run_metadata(batch)["root_domain"] == ROOT
    assert batch.observations[0].evidence[-1].metadata == {"provider": "crtsh"}


@pytest.mark.parametrize("state", [JobState.QUEUED, JobState.STARTING, JobState.RUNNING,
                                  JobState.FAILED, JobState.CANCELLED, JobState.TIMED_OUT])
def test_only_successful_terminal_jobs_can_be_imported(state):
    with pytest.raises(ObservationImportError):
        parse(state=state)


@pytest.mark.parametrize("changes", [
    {"adapter_id": "nmap.localhost"}, {"adapter_id": "subfinder.other-profile"},
    {"exit_code": None}, {"exit_code": 1}, {"exit_code": True},
    {"stdout_truncated": True}, {"stderr_truncated": True},
    {"stdout_truncated": 0}, {"stderr_truncated": None}, {"state": "SUCCEEDED"},
    {"job_id": ""}, {"job_id": "a" * 129}, {"job_id": "secret\nnext-line"},
    {"job_id": "https://example.test/?token=secret"}, {"stderr": "not bytes"},
])
def test_incomplete_mismatched_or_unbounded_process_context_is_rejected(changes):
    with pytest.raises(ObservationImportError):
        parse(**changes)


@pytest.mark.parametrize("value", [None, {}, object()])
def test_snapshot_type_is_required(value):
    with pytest.raises(ObservationImportError):
        api().parse_subfinder_output(value, root_domain=ROOT, run_id=RUN_ID)


@pytest.mark.parametrize("root_domain", ["", "127.0.0.1", "*.example.test", "https://example.test",
                                        "singlelabel", "bad\u200b.example.test", "a" * 1025, None])
def test_invalid_root_context_cannot_be_imported(root_domain):
    with pytest.raises(ObservationImportError):
        parse(root_domain=root_domain)


@pytest.mark.parametrize("run_id", ["", "a" * 129, "run\nprivate", "https://example.test/?token=secret", None])
def test_run_identity_is_bounded_and_inert(run_id):
    with pytest.raises(ObservationImportError):
        parse(run_id=run_id)


@pytest.mark.parametrize("item", [
    None, [], "api.example.test", 3,
    {"host": "api.example.test", "input": ROOT},
    {"host": "api.example.test", "sources": ["crtsh"]},
    {"input": ROOT, "sources": ["crtsh"]},
    record(source="crtsh"), record(ip="192.0.2.1"), record(wildcard_certificate=True),
    record(unexpected={"token": "secret"}), record(input="other.test"),
    record(host=None), record(host=[]), record(host="bad/path"), record(host="*.example.test"),
    record(host="192.0.2.1"), record(host="bad\u200b.example.test"), record(host="a" * 1025),
    record(sources=None), record(sources="crtsh"), record(sources=[]), record(sources=[None]),
    record(sources=[{}]), record(sources=[""]), record(sources=["source/token=secret"]),
    record(sources=["line\nbreak"]), record(sources=["a" * 65]),
])
def test_unexpected_json_schema_values_and_provider_secrets_fail_the_whole_import(item):
    # A valid first row must not be returned when the following row is invalid.
    with pytest.raises(ObservationImportError) as error:
        parse(output(record(), item))
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("raw", [
    b'{"host":"api.example.test","input":"example.test","sources":["crtsh"]}',
    b'{"host":"api.example.test"\n', b'\xff\n', b'\xef\xbb\xbf{}\n',
    b'\n', b' \n', b'{}\r', b'{}\n\n', b'{}\x00\n',
    b'{"host":"api.example.test","host":"evil.example.test","input":"example.test","sources":["crtsh"]}\n',
    b'{"host":"api.example.test","input":"example.test","sources":[NaN]}\n',
    b'{"host":"api.example.test","input":"example.test","sources":["\\ud800"]}\n',
    b'[' * 1200 + b'0' + b']' * 1200 + b'\n', "not bytes", bytearray(b"{}\n"),
])
def test_malformed_duplicate_key_non_utf8_blank_and_unfinished_jsonl_is_rejected(raw):
    with pytest.raises(ObservationImportError):
        parse(raw)


def test_crlf_jsonl_records_are_accepted_as_complete_lines():
    assert parse(output(record()).replace(b"\n", b"\r\n")).observations[0].value == "api.example.test"


def test_output_byte_line_record_and_source_limits_reject_without_partial_results(monkeypatch):
    parser = api()
    with pytest.raises(ObservationImportError):
        parse(b"x" * (parser.MAX_SUBFINDER_OUTPUT_BYTES + 1))
    with pytest.raises(ObservationImportError):
        parse(b" " * (parser.MAX_SUBFINDER_LINE_BYTES + 1) + b"\n")
    with pytest.raises(ObservationImportError):
        parse(output(record(sources=[f"source{index}" for index in range(parser.MAX_SUBFINDER_SOURCES + 1)])))
    monkeypatch.setattr(parser, "MAX_SUBFINDER_RECORDS", 2)
    with pytest.raises(ObservationImportError):
        parse(output(record(), record(), record()))


def test_provider_union_across_duplicate_records_is_bounded():
    limit = api().MAX_SUBFINDER_SOURCES
    with pytest.raises(ObservationImportError):
        parse(output(record(sources=[f"source{index}" for index in range(limit)]),
                     record(sources=["extra"])))


def test_invalid_out_of_root_records_are_not_silently_skipped():
    with pytest.raises(ObservationImportError):
        parse(output(record("outside.test", sources=["https://provider.test/?token=secret"])))


def test_parser_batch_merges_with_native_assets_keeps_history_and_reimport_is_idempotent():
    inventory = AssetInventory()
    inventory.import_json(json.dumps({
        "schema": "websecsuite.recon.observations", "version": 1, "run_id": "native-run",
        "observations": [{"id": "host-1", "source": "fixture", "type": "hostname", "value": "api.example.test"}],
    }))
    batch = parse(output(record(), record(sources=["alienvault"])))
    first = inventory.import_batch(batch, label="Subfinder Passive Standard — example.test",
                                   format_name="Subfinder JSONL")
    assert (first.added_observations, first.duplicates, first.total_assets) == (1, 1, 1)
    assert inventory.assets[0].sources == ("fixture", "subfinder")
    before = inventory.assets, inventory.observations, inventory.import_history
    second = inventory.import_batch(batch, label="Copy", format_name="Subfinder JSONL")
    assert (second.added_observations, second.duplicates, second.total_assets) == (0, 2, 1)
    assert all(current is old for current, old in zip(
        (inventory.assets, inventory.observations, inventory.import_history), before))
    inventory.import_batch(parse(run_id="subfinder:passive:synthetic-run-2"), format_name="Subfinder JSONL")
    assert len(inventory.assets) == 1 and len(inventory.assets[0].observations) == 3
    assert [entry.run_id for entry in inventory.import_history] == [
        "native-run", RUN_ID, "subfinder:passive:synthetic-run-2",
    ]


@pytest.mark.parametrize("raw", [b"", output(record("outside.test"))])
def test_empty_successful_discovery_keeps_distinct_idempotent_history_without_assets(raw):
    inventory = AssetInventory()
    first = parse(raw)
    assert first.observations == () and first.duplicates == 0 and first.run_id == RUN_ID
    inventory.import_batch(first, label="Subfinder Passive Standard — example.test", format_name="Subfinder JSONL")
    inventory.import_batch(first, label="Copied zero result", format_name="Subfinder JSONL")
    inventory.import_batch(parse(raw, run_id="subfinder:passive:empty-two"), format_name="Subfinder JSONL")
    assert not inventory.assets and not inventory.observations
    assert len(inventory.import_history) == 2
    assert inventory.import_history[0].run_id == RUN_ID
    assert inventory.import_history[0].label == "Subfinder Passive Standard — example.test"


@pytest.mark.parametrize("failure", ["bad_tail", "truncated", "stored_conflict"])
def test_import_failure_keeps_inventory_and_history_unchanged(failure):
    inventory = AssetInventory()
    inventory.import_batch(parse(), format_name="Subfinder JSONL")
    before = inventory.assets, inventory.observations, inventory.import_history
    with pytest.raises(ObservationImportError):
        if failure == "bad_tail":
            batch = parse(output(record("new.example.test")) + b'{"host":\n')
        elif failure == "truncated":
            batch = parse(output(record("new.example.test")), stdout_truncated=True)
        else:
            batch = parse(output(record("new.example.test"), record(sources=["alienvault"])))
        inventory.import_batch(batch, format_name="Subfinder JSONL")
    assert all(current is old for current, old in zip(
        (inventory.assets, inventory.observations, inventory.import_history), before))
