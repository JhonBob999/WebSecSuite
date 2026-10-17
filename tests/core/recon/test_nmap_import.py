"""Synthetic, completely offline Nmap XML adapter and atomic inventory imports."""

import hashlib
import importlib
import json
from pathlib import Path

import pytest

from core.recon.inventory import AssetInventory
from core.recon.observations import MAX_METADATA_BYTES, ObservationImportError


FIXTURES = Path(__file__).parents[2] / "fixtures" / "nmap"


def adapter():
    return importlib.import_module("core.recon.nmap_import")


def report(body="", attributes='scanner="nmap" version="7.95" start="1"'):
    return f"<nmaprun {attributes}>{body}</nmaprun>"


def host(ports="", address="192.0.2.10", extra=""):
    address_type = "ipv6" if ":" in address else "ipv4"
    return (f'<host><address addr="{address}" addrtype="{address_type}"/>'
            f'{extra}<ports>{ports}</ports></host>')


def port(number=443, transport="tcp", state="open", service=""):
    return (f'<port protocol="{transport}" portid="{number}">'
            f'<state state="{state}"/>{service}</port>')


def metadata(observation, kind):
    return next(item.metadata for item in observation.evidence if item.kind == kind)


def test_nmap_fixture_imports_into_existing_r2_inventory():
    inventory = AssetInventory()
    result = inventory.import_nmap_file(FIXTURES / "recon.xml")
    assert (result.added_observations, result.duplicates, result.total_assets) == (10, 0, 10)
    assert {item.source for item in inventory.observations} == {"nmap"}
    assert {a.value for a in inventory.assets if a.entity_type == "hostname"} == {
        "api.example.test", "www.example.test",
    }
    assert {a.value for a in inventory.assets if a.entity_type == "ip"} == {
        "192.0.2.10", "2001:db8::10", "198.51.100.20", "203.0.113.30",
    }
    services = [a for a in inventory.assets if a.entity_type == "service"]
    assert {(a.value, a.transport, a.port) for a in services} == {
        ("192.0.2.10", "tcp", 22), ("192.0.2.10", "tcp", 443),
        ("192.0.2.10", "udp", 443), ("2001:db8::10", "tcp", 443),
    }


def test_supported_fields_and_scan_provenance_are_bounded_evidence():
    batch = adapter().read_nmap_file(FIXTURES / "recon.xml")
    ssh = next(o for o in batch.observations if o.port == 22)
    assert ssh.service_name == "ssh"
    assert ssh.confidence == 1.0
    assert metadata(ssh, "nmap-service") == {
        "state": "open", "name": "ssh", "product": "OpenSSH", "version": "9.9",
        "extrainfo": "synthetic", "conf": "10", "method": "probed",
    }
    run = metadata(ssh, "nmap-run")
    content = (FIXTURES / "recon.xml").read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    assert batch.run_id == f"nmap:sha256:{digest}"
    assert run["file_sha256"] == digest
    assert run["file_size"] == len(content)
    assert run["scanner"] == "nmap" and run["scanner_version"] == "7.95"
    assert run["start"] == "1767225600" and run["finished"] == "1767225612"
    assert run["startstr"] and run["finished_timestr"]
    details = metadata(ssh, "nmap-host")
    assert details["state"] == "up"
    assert details["starttime"] == "1767225601" and details["endtime"] == "1767225610"
    assert details["addresses"] == ["192.0.2.10"]
    assert details["hostnames"] == ["api.example.test", "www.example.test"]
    assert "CVE-2099" not in json.dumps([o.to_dict() for o in batch.observations])
    for observation in batch.observations:
        for reference in observation.evidence:
            assert len(json.dumps(reference.metadata, ensure_ascii=False, separators=(",", ":")).encode()) <= MAX_METADATA_BYTES


def test_non_open_states_are_only_host_evidence_and_never_confirmed_services():
    batch = adapter().read_nmap_file(FIXTURES / "recon.xml")
    address = next(o for o in batch.observations if o.value == "192.0.2.10" and o.entity_type == "ip")
    details = metadata(address, "nmap-port-states")
    assert details["non_open_port_count"] == 4
    assert {item["state"] for item in details["non_open_ports"]} == {"closed", "filtered", "open|filtered", "unknown"}
    assert details["extraports"] == [{"state": "filtered", "count": "995"}]
    states = {o.value: metadata(o, "nmap-host")["state"] for o in batch.observations if o.entity_type == "ip"}
    assert states["198.51.100.20"] == "down"
    assert states["203.0.113.30"] == "unknown"


def test_optional_fields_do_not_invent_service_or_hostname_information():
    batch = adapter().parse_nmap_xml(report(host(port(), extra="<status/>"), attributes=""))
    assert len(batch.observations) == 2
    service = next(o for o in batch.observations if o.entity_type == "service")
    assert service.service_name is None and service.confidence is None
    assert metadata(service, "nmap-host")["state"] == "unknown"
    assert "scanner_version" not in metadata(service, "nmap-run")
    assert not any(o.entity_type == "hostname" for o in batch.observations)


@pytest.mark.parametrize("state", ["closed", "filtered", "open|filtered", "closed|filtered",
    "unfiltered", "unknown", "OPEN", " open ", "", "open&#10;"])
def test_only_exact_explicit_open_state_creates_services(state):
    batch = adapter().parse_nmap_xml(report(host(port(state=state))))
    assert all(o.entity_type != "service" for o in batch.observations)


def test_missing_port_state_and_service_element_never_imply_open():
    batch = adapter().parse_nmap_xml(report(host('<port protocol="tcp" portid="443"><service name="https"/></port>')))
    assert [o.entity_type for o in batch.observations] == ["ip"]


def test_hostname_only_and_multiple_addresses_use_one_explicit_service_host():
    body = ('<host><hostnames><hostname name="a.example.test"/><hostname name="b.example.test"/></hostnames>'
            f'<ports>{port()}</ports></host>')
    batch = adapter().parse_nmap_xml(report(body))
    assert [o.value for o in batch.observations if o.entity_type == "service"] == ["a.example.test"]
    body = host(port(), extra='<address addr="2001:db8::1" addrtype="ipv6"/>')
    batch = adapter().parse_nmap_xml(report(body))
    assert {o.value for o in batch.observations if o.entity_type == "ip"} == {"192.0.2.10", "2001:db8::1"}
    assert [o.value for o in batch.observations if o.entity_type == "service"] == ["192.0.2.10"]


def test_exact_reimport_and_renamed_copy_are_idempotent(tmp_path):
    inventory = AssetInventory()
    first = inventory.import_nmap_file(FIXTURES / "recon.xml")
    copy = tmp_path / "renamed.xml"
    copy.write_bytes((FIXTURES / "recon.xml").read_bytes())
    before = inventory.assets
    repeated = inventory.import_nmap_file(copy)
    assert repeated.run_id == first.run_id
    assert (repeated.added_observations, repeated.duplicates, repeated.total_assets) == (0, 10, 10)
    assert inventory.assets is before


def test_different_scans_and_native_json_enrich_same_assets_without_schema_change():
    inventory = AssetInventory()
    inventory.import_json(json.dumps({"schema": "websecsuite.recon.observations", "version": 1,
        "run_id": "native", "observations": [{"id": "ip", "source": "fixture", "type": "ip", "value": "192.0.2.10"}]}))
    one = inventory.import_nmap_xml(report(host(port())))
    two = inventory.import_nmap_xml(report(host(port()), attributes='scanner="nmap" start="2"'))
    assert one.run_id != two.run_id
    assert two.total_assets == 2
    assert len(inventory.observations) == 5
    assert inventory.assets[0].sources == ("fixture", "nmap")


@pytest.mark.parametrize("name", ["truncated.xml", "wrong_root.xml", "entity_attack.xml"])
def test_failed_file_import_preserves_existing_inventory(name):
    inventory = AssetInventory()
    inventory.import_nmap_file(FIXTURES / "recon.xml")
    assets, observations = inventory.assets, inventory.observations
    with pytest.raises(ObservationImportError):
        inventory.import_nmap_file(FIXTURES / name)
    assert inventory.assets is assets and inventory.observations is observations


def test_stored_identity_conflict_rolls_back_all_other_nmap_additions():
    xml = report(host(port()))
    batch = adapter().parse_nmap_xml(xml)
    conflicting = batch.observations[-1].to_dict()
    conflicting.pop("entity_key")
    conflicting.pop("run_id")
    conflicting["service_name"] = "conflicting"
    inventory = AssetInventory()
    inventory.import_json(json.dumps({"schema": "websecsuite.recon.observations", "version": 1,
                                      "run_id": batch.run_id, "observations": [conflicting]}))
    before = inventory.assets, inventory.observations
    with pytest.raises(ObservationImportError, match="conflict"):
        inventory.import_nmap_xml(xml)
    assert (inventory.assets, inventory.observations) == before


@pytest.mark.parametrize("xml", [
    "", "not XML", "<nmaprun>", "<nmaprun></nmaprun><nmaprun/>", "<html/>",
    '<nmaprun xmlns="urn:other"/>', '<nmaprun scanner="masscan"/>',
    '<!DOCTYPE nmaprun><nmaprun/>',
    '<!DOCTYPE nmaprun SYSTEM "https://example.invalid/nmap.dtd"><nmaprun/>',
    '<!DOCTYPE nmaprun [<!ENTITY a "expanded">]><nmaprun>&a;</nmaprun>',
    '<!DOCTYPE nmaprun [<!ENTITY % a SYSTEM "file:///C:/secret">%a;]><nmaprun/>',
    '<nmaprun>&undefined;</nmaprun>',
])
def test_malformed_wrong_scanner_root_dtd_and_entities_are_rejected(xml):
    with pytest.raises(ObservationImportError):
        adapter().parse_nmap_xml(xml)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-be"])
def test_entity_rejection_is_encoding_independent(encoding):
    xml = '<!DOCTYPE nmaprun [<!ENTITY a "expanded">]><nmaprun>&a;</nmaprun>'
    with pytest.raises(ObservationImportError, match="DTD|entit"):
        adapter().parse_nmap_xml(xml.encode(encoding))


@pytest.mark.parametrize("bad", [
    host(port(number=0)), host(port(number=65536)), host(port(number="oops")),
    host(port(), address="not-an-ip"), host(port(), address="fe80::1%eth0"),
    host(extra='<hostnames><hostname name="bad/name"/></hostnames>'),
])
def test_late_normalization_failure_is_atomic(bad):
    inventory = AssetInventory()
    inventory.import_nmap_file(FIXTURES / "recon.xml")
    before = inventory.assets, inventory.observations
    with pytest.raises(ObservationImportError):
        inventory.import_nmap_xml(report(host(address="192.0.2.99") + bad))
    assert (inventory.assets, inventory.observations) == before


@pytest.mark.parametrize("confidence", ["-1", "11", "NaN", "bad", ""])
def test_unusable_optional_confidence_is_omitted(confidence):
    batch = adapter().parse_nmap_xml(report(host(port(service=f'<service conf="{confidence}"/>'))))
    assert next(o for o in batch.observations if o.entity_type == "service").confidence is None


def test_oversized_input_and_bounded_file_read(tmp_path):
    path = tmp_path / "oversized.xml"
    path.write_bytes(b" " * (adapter().MAX_IMPORT_BYTES + 1))
    with pytest.raises(ObservationImportError, match="8 MiB"):
        adapter().read_nmap_file(path)
    with pytest.raises(ObservationImportError, match="8 MiB"):
        adapter().parse_nmap_xml(path.read_bytes())


def test_reader_requests_only_the_bounded_input_size(monkeypatch):
    import io

    requested = []

    class BoundedInput(io.BytesIO):
        def read(self, size=-1):
            requested.append(size)
            return super().read(size)

    monkeypatch.setattr(Path, "open", lambda *args: BoundedInput(b"<nmaprun/>"))
    assert adapter().read_nmap_file("local.xml").observations == ()
    assert requested == [adapter().MAX_IMPORT_BYTES + 1]


def test_stylesheets_scripts_schema_and_evidence_references_are_inert(monkeypatch):
    import builtins

    module = adapter()

    def forbidden(*args, **kwargs):
        pytest.fail("XML content must never cause file access")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    xml = ('<?xml-stylesheet href="file:///C:/secret"?>' + report(host(port(service=
        '<service name="http"/><script id="vuln" output="execute.exe; CVE-2099-0000"/>')),
        attributes='scanner="nmap" schemaLocation="https://example.invalid/schema" args="execute.exe"'))
    batch = module.parse_nmap_xml(xml)
    details = json.dumps([o.to_dict() for o in batch.observations])
    assert "CVE-2099" not in details and "execute.exe" not in details
    with pytest.raises(ObservationImportError, match="DTD|entit"):
        module.parse_nmap_xml('<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///C:/secret">]><nmaprun>&x;</nmaprun>')


@pytest.mark.parametrize("limit,xml", [
    ("MAX_OBSERVATIONS", report(host() + host(address="192.0.2.11"))),
    ("MAX_XML_ELEMENTS", report("<host/><host/><host/>")),
    ("MAX_XML_DEPTH", report("<a><b><c><d/></c></b></a>")),
    ("MAX_XML_STRING", report('<host note="abcd"/>')),
    ("MAX_HOSTS", report("<host/><host/><host/><host/>")),
    ("MAX_PORTS", report(host(port(1) + port(2) + port(3) + port(4)))),
])
def test_limits_reject_before_mutation(limit, xml, monkeypatch):
    inventory = AssetInventory()
    inventory.import_nmap_file(FIXTURES / "recon.xml")
    before = inventory.assets, inventory.observations
    monkeypatch.setattr(adapter(), limit, 1 if limit == "MAX_OBSERVATIONS" else 3)
    with pytest.raises(ObservationImportError, match="limit|depth|length"):
        inventory.import_nmap_xml(xml)
    assert (inventory.assets, inventory.observations) == before


def test_evidence_and_optional_strings_are_bounded_with_omission_counts():
    states = "".join(port(i, state="filtered") for i in range(1, 100))
    service = '<service name="http" product="' + ("界" * 1000) + '"/>'
    batch = adapter().parse_nmap_xml(report(host(states + port(service=service))))
    address = next(o for o in batch.observations if o.entity_type == "ip")
    details = metadata(address, "nmap-port-states")
    assert details["non_open_port_count"] == 99
    assert len(details["non_open_ports"]) == adapter().MAX_STATE_SAMPLES
    assert details["non_open_ports_omitted"] == 99 - adapter().MAX_STATE_SAMPLES
    observed = next(o for o in batch.observations if o.entity_type == "service")
    assert len(metadata(observed, "nmap-service")["product"]) <= 128


def test_mac_only_host_and_unsupported_transport_do_not_invent_services():
    xml = report('<host><address addr="00:00:5e:00:53:01" addrtype="mac"/>'
                 f'<ports>{port()}</ports></host>' + host(port(transport="sctp")))
    batch = adapter().parse_nmap_xml(xml)
    assert len(batch.observations) == 1
    assert batch.observations[0].entity_type == "ip"


@pytest.mark.parametrize("xml", [
    report('<host><address addr="192.0.2.1" addrtype="ipv6"/></host>'),
    report('<host ' + ' '.join(f'a{i}="v"' for i in range(33)) + '/>'),
    report(host(port(state="x" * 129))),
])
def test_invalid_address_type_and_attribute_state_limits(xml):
    with pytest.raises(ObservationImportError):
        adapter().parse_nmap_xml(xml)


@pytest.mark.parametrize("value", [None, 123, "\ud800", b'<?xml version="1.0" encoding="made-up"?><nmaprun/>'])
def test_bad_types_unicode_and_encodings_are_friendly_errors(value):
    with pytest.raises(ObservationImportError):
        adapter().parse_nmap_xml(value)


def test_unreadable_file_is_a_friendly_import_error(tmp_path):
    with pytest.raises(ObservationImportError, match="Could not read"):
        adapter().read_nmap_file(tmp_path / "missing.xml")


@pytest.mark.parametrize("path", ["https://example.test/report.xml", r"\\server\share\report.xml",
    r"\\?\C:\report.xml", "NUL.xml", "NUL .xml", "COM¹.xml",
    "C:/data/report.xml:stream.xml", "report.json"])
def test_remote_device_and_wrong_extension_paths_rejected_without_open(path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Unsafe paths must be rejected before file access")
    monkeypatch.setattr(Path, "open", forbidden)
    with pytest.raises(ObservationImportError):
        adapter().read_nmap_file(path)
