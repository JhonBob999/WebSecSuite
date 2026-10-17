"""Offline approved-public XML validation and atomic provenance integration."""

import hashlib
import importlib

import pytest

from core.recon.inventory import AssetInventory
from core.recon.observations import MAX_IMPORT_BYTES, ObservationImportError


ADDRESS = "8.8.8.8"
RUN_ID = "nmap:public:synthetic-run-1"


def api():
    return importlib.import_module("core.recon.nmap_public_output")


def observation(**changes):
    from core.recon.public_target import PublicTargetObservation

    values = dict(hostname="ginandjuice.shop", ipv4_addresses=(ADDRESS, "1.1.1.1"),
                  cnames=("edge.example.test",), observed_at="2026-10-17T10:00:00+00:00",
                  resolver="system IPv4 resolver")
    values.update(changes)
    return PublicTargetObservation(**values)


def report(*, ports=None, extra_host="", extra_root="", doctype=b"<!DOCTYPE nmaprun>"):
    if ports is None:
        ports = ('<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>'
                 '<service name="https" method="table" conf="3"/></port>'
                 '<port protocol="tcp" portid="80"><state state="closed" reason="conn-refused"/></port>'
                 '<extraports state="filtered" count="2"><extrareasons reason="no-responses" count="2"/></extraports>')
    body = ('<nmaprun scanner="nmap" version="7.95" start="1">'
            '<scaninfo type="connect" protocol="tcp" numservices="4" services="80,443,8080,8443"/>'
            f'<host><status state="up" reason="user-set"/><address addr="{ADDRESS}" addrtype="ipv4"/>'
            f'{extra_host}<ports>{ports}</ports></host>{extra_root}'
            '<runstats><finished exit="success" time="2"/><hosts up="1" down="0" total="1"/></runstats>'
            '</nmaprun>')
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + doctype + body.encode()


def parse(content=None, **changes):
    parser = api().parse_public_nmap_output
    values = dict(observation=observation(), address=ADDRESS, run_id=RUN_ID)
    values.update(changes)
    return parser(report() if content is None else content, **values)


def evidence(item, kind):
    return next(value.metadata for value in item.evidence if value.kind == kind)


def test_complete_public_report_keeps_scanned_ip_and_time_specific_dns_provenance():
    raw = report()
    batch = parse(raw)
    assert batch.run_id == RUN_ID
    assert [(item.entity_type, item.value, item.port) for item in batch.observations] == [
        ("ip", ADDRESS, None), ("service", ADDRESS, 443),
    ]
    assert {item.source for item in batch.observations} == {"nmap"}
    run = evidence(batch.observations[0], "nmap-run")
    assert run["file_sha256"] == hashlib.sha256(raw).hexdigest()
    assert run["file_size"] == len(raw) and run["doctype_normalized"] is True
    assert run["profile"] == "Quick Network Discovery"
    assert run["target"] == ADDRESS and run["approved_hostname"] == "ginandjuice.shop"
    assert run["ports"] == [80, 443, 8080, 8443]
    assert run["technique"] == "tcp-connect"
    assert run["dns_observation"] == {
        "hostname": "ginandjuice.shop", "selected_ipv4": ADDRESS,
        "ipv4_addresses": [ADDRESS, "1.1.1.1"], "cnames": ["edge.example.test"],
        "observed_at": "2026-10-17T10:00:00+00:00", "resolver": "system IPv4 resolver",
        "association": "preflight-observation", "ownership_verified": False,
    }
    assert all(reference.ref.startswith(RUN_ID) for item in batch.observations for reference in item.evidence)


def test_closed_and_filtered_outcomes_remain_evidence_without_inventing_services():
    batch = parse()
    states = evidence(batch.observations[0], "nmap-port-states")
    assert states["non_open_ports"] == [{"transport": "tcp", "port": 80, "state": "closed"}]
    assert states["extraports"] == [{"state": "filtered", "count": "2"}]


def test_normal_inert_nmap_task_timing_and_table_service_metadata_are_accepted():
    raw = report().replace(
        b'<host>',
        b'<verbose level="0"/><debugging level="0"/>'
        b'<taskbegin task="Connect Scan" time="1"/>'
        b'<taskprogress task="Connect Scan" time="1" percent="50.00"/>'
        b'<taskend task="Connect Scan" time="2"/><host starttime="1" endtime="2">',
    ).replace(b'<ports>', b'<hostnames/><ports>').replace(
        b'</ports></host>', b'</ports><times srtt="1000" rttvar="5000" to="100000"/></host>',
    )
    batch = parse(raw)
    assert [(item.entity_type, item.port) for item in batch.observations] == [("ip", None), ("service", 443)]
    assert evidence(batch.observations[-1], "nmap-service")["method"] == "table"


def test_aggregate_reason_metadata_cannot_assign_one_port_conflicting_states():
    ports = ('<port protocol="tcp" portid="443"><state state="open"/></port>'
             '<port protocol="tcp" portid="80"><state state="closed"/></port>'
             '<extraports state="closed" count="1"><extrareasons reason="conn-refused" count="1" '
             'proto="tcp" ports="8080"/></extraports>'
             '<extraports state="filtered" count="1"><extrareasons reason="no-responses" count="1" '
             'proto="tcp" ports="8080"/></extraports>')
    with pytest.raises(ObservationImportError):
        parse(report(ports=ports))


@pytest.mark.parametrize("ports", [
    '<extraports state="closed" count="4"/>',
    '<extraports state="filtered" count="4"/>',
    '<extraports state="closed" count="2"/><extraports state="filtered" count="2"/>',
])
def test_zero_open_ports_is_a_successful_scanned_ip_observation(ports):
    batch = parse(report(ports=ports))
    assert [(item.entity_type, item.value) for item in batch.observations] == [("ip", ADDRESS)]


@pytest.mark.parametrize("change", [
    lambda raw: raw.replace(b'scanner="nmap"', b'scanner="masscan"'),
    lambda raw: raw.replace(b'scanner="nmap"', b''),
    lambda raw: raw.replace(b'exit="success"', b'exit="error"'),
    lambda raw: raw.replace(b'<finished exit="success" time="2"/>', b''),
    lambda raw: raw.replace(b'<finished exit="success" time="2"/>', b'<finished exit="success"/><finished exit="success"/>'),
    lambda raw: raw.replace(b'<host>', b'<host timedout="true">'),
    lambda raw: raw.replace(b'<status state="up"', b'<status state="down"'),
    lambda raw: raw.replace(b'<status state="up" reason="user-set"/>', b'<status state="up"/><status state="up"/>'),
    lambda raw: raw.replace(b'total="1"', b'total="2"'),
    lambda raw: raw.replace(b'addr="8.8.8.8"', b'addr="1.1.1.1"'),
    lambda raw: raw.replace(b'addrtype="ipv4"', b'addrtype="ipv6"'),
    lambda raw: raw.replace(b'type="connect"', b'type="syn"'),
    lambda raw: raw.replace(b'protocol="tcp"', b'protocol="udp"'),
    lambda raw: raw.replace(b'services="80,443,8080,8443"', b'services="1-4"'),
    lambda raw: raw.replace(b'numservices="4"', b'numservices="5"'),
    lambda raw: raw.replace(b'portid="443"', b'portid="22"'),
    lambda raw: raw.replace(b'<state state="open" reason="syn-ack"/>', b''),
    lambda raw: raw.replace(b'<state state="open" reason="syn-ack"/>', b'<state state="open"/><state state="closed"/>'),
    lambda raw: raw.replace(b'state="open"', b'state="unknown"'),
    lambda raw: raw.replace(b'state="open"', b'state="open|filtered"'),
    lambda raw: raw.replace(b'<extraports state="filtered" count="2">', b'<extraports state="open" count="2">'),
    lambda raw: raw.replace(b'<extraports state="filtered" count="2">', b'<extraports state="filtered" count="1">'),
    lambda raw: raw.replace(b'portid="80"', b'portid="443"'),
    lambda raw: raw.replace(b'<extrareasons reason="no-responses" count="2"/>', b'<extrareasons reason="no-responses" count="3"/>'),
    lambda raw: raw.replace(b'<service name="https" method="table"', b'<service name="https" method="probed"'),
])
def test_incomplete_unexpected_and_off_profile_reports_are_rejected(change):
    with pytest.raises(ObservationImportError):
        parse(change(report()))


@pytest.mark.parametrize("extra_host,extra_root", [
    ('<address addr="1.1.1.1" addrtype="ipv4"/>', ''),
    ('<address addr="2001:4860:4860::8888" addrtype="ipv6"/>', ''),
    ('<hostnames><hostname name="ginandjuice.shop"/></hostnames>', ''),
    ('<script id="unexpected" output="inert"/>', ''),
    ('<os><osmatch name="unexpected"/></os>', ''),
    ('<trace/>', ''),
    ('', '<hosthint><address addr="1.1.1.1" addrtype="ipv4"/></hosthint>'),
    ('', '<host><status state="up"/><address addr="8.8.8.8" addrtype="ipv4"/></host>'),
    ('', '<prescript><script id="unexpected"/></prescript>'),
])
def test_extra_target_identity_and_excluded_scan_features_cannot_import(extra_host, extra_root):
    with pytest.raises(ObservationImportError):
        parse(report(extra_host=extra_host, extra_root=extra_root))


@pytest.mark.parametrize("doctype", [
    b'<!DOCTYPE nmaprun SYSTEM "https://example.invalid/nmap.dtd">',
    b'<!DOCTYPE nmaprun [<!ENTITY a "expanded">]>',
    b'<!DOCTYPE nmaprun []>', b'<!DOCTYPE  nmaprun>', b'<!DOCTYPE nmaprun >',
    b'<!-- <!DOCTYPE nmaprun> -->',
])
def test_public_parser_keeps_existing_strict_declaration_rules(doctype):
    with pytest.raises(ObservationImportError):
        parse(report(doctype=doctype))


@pytest.mark.parametrize("raw", [b'', b'<nmaprun>', b'x' * (MAX_IMPORT_BYTES + 1),
    b'<nmaprun>\x00</nmaprun>', 'not bytes'], ids=["empty", "truncated", "oversized", "nul", "text"])
def test_empty_truncated_oversized_and_non_utf8_output_is_rejected(raw):
    with pytest.raises(ObservationImportError):
        parse(raw)


@pytest.mark.parametrize("changes", [
    {"hostname": "other.example"}, {"hostname": "GINANDJUICE.SHOP"},
    {"ipv4_addresses": ("1.1.1.1",)}, {"ipv4_addresses": (ADDRESS, "127.0.0.1")},
    {"ipv4_addresses": [ADDRESS]}, {"cnames": ("bad/name",)},
    {"cnames": tuple(f"a{number}.example.test" for number in range(33))},
    {"observed_at": "not a timestamp"}, {"resolver": "x" * 129},
])
def test_unbounded_or_mismatched_dns_provenance_is_rejected(changes):
    with pytest.raises(ObservationImportError):
        parse(observation=observation(**changes))


@pytest.mark.parametrize("changes", [
    {"address": "1.1.1.1"}, {"address": "127.0.0.1"}, {"address": "192.0.2.1"},
    {"run_id": ""}, {"run_id": "nmap:public:"}, {"run_id": "x" * 129},
    {"run_id": "nmap:public:line\nbreak"}, {"observation": object()},
])
def test_parser_cannot_substitute_scan_context(changes):
    with pytest.raises(ObservationImportError):
        parse(**changes)


def test_public_runs_merge_assets_keep_distinct_history_and_preserve_inventory_on_failure():
    inventory = AssetInventory()
    first = parse()
    inventory.import_batch(first, label="Nmap Quick Network Discovery", format_name="Nmap live XML")
    second = parse(run_id="nmap:public:synthetic-run-2")
    inventory.import_batch(second, label="Nmap Quick Network Discovery", format_name="Nmap live XML")
    assert len(inventory.assets) == 2 and len(inventory.observations) == 4
    assert len(inventory.import_history) == 2
    assert [entry.run_id for entry in inventory.import_history] == [RUN_ID, "nmap:public:synthetic-run-2"]
    assert inventory.assets[0].sources == ("nmap",)
    assert all(evidence(item, "nmap-run")["target"] == ADDRESS for item in inventory.observations)
    before = inventory.assets, inventory.observations, inventory.import_history
    with pytest.raises(ObservationImportError):
        inventory.import_batch(parse(report().replace(b'addr="8.8.8.8"', b'addr="1.1.1.1"')))
    assert all(current is old for current, old in zip(
        (inventory.assets, inventory.observations, inventory.import_history), before))


def test_local_validator_remains_bound_to_127_0_0_1():
    from core.recon.nmap_adapter import parse_trusted_nmap_output

    with pytest.raises(ObservationImportError):
        parse_trusted_nmap_output(report())
    local = report().replace(b'addr="8.8.8.8"', b'addr="127.0.0.1"')
    assert parse_trusted_nmap_output(local).observations[0].value == "127.0.0.1"
