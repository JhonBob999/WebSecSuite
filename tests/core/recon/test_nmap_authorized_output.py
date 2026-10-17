"""Offline advanced reports cannot expand approved hosts or scan settings."""

from dataclasses import replace
import hashlib
import importlib
import json
from types import SimpleNamespace

import pytest

from core.recon.inventory import AssetInventory
from core.recon.nmap_profiles import BUILTIN_PROFILES
from core.recon.observations import ObservationImportError


def profile(**changes):
    values = dict(ports=(80, 443), technique="tcp-connect", udp_ports=(), udp_scan=False,
                  port_mode="explicit", top_ports=100, discovery="none", dns_mode="never",
                  version_detection=False, os_detection=False, traceroute=False,
                  script_ids=(), script_arguments=())
    values.update(changes)
    return replace(BUILTIN_PROFILES[1], **values)


def scope(*targets):
    return SimpleNamespace(targets=targets or ("192.0.2.10",), inputs=targets or ("192.0.2.10",), dns_observations=())


def port(number=80, protocol="tcp", state="open", body=""):
    return f'<port protocol="{protocol}" portid="{number}"><state state="{state}"/>{body}</port>'


def host(body=None, address="192.0.2.10", state="up", extra=""):
    body = port(80) + port(443, state="closed") if body is None else body
    family = "ipv6" if ":" in address else "ipv4"
    return (f'<host><status state="{state}"/><address addr="{address}" addrtype="{family}"/>'
            + extra + (f"<ports>{body}</ports>" if body else "") + "</host>")


def report(hosts=None, scaninfo=None, total=1, up=1, exit="success", extra=""):
    if hosts is None:
        hosts = host()
    if scaninfo is None:
        scaninfo = '<scaninfo type="connect" protocol="tcp" numservices="2" services="80,443"/>'
    return ('<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" version="7.95" start="1">'
            + scaninfo + hosts + extra + f'<runstats><finished exit="{exit}" time="2" elapsed="1.0"/>'
            f'<hosts up="{up}" down="{total-up}" total="{total}"/></runstats></nmaprun>').encode()


def parse(raw=None, **changes):
    options = dict(scope=scope(), profile=profile(), executable_version="7.95",
                   run_id="nmap:authorized:fixture", arguments=("-sT", "--script-args", "token=secret", "192.0.2.10"),
                   executable_sha256="a" * 64)
    options.update(changes)
    return importlib.import_module("core.recon.nmap_authorized_output").parse_authorized_nmap_output(
        report() if raw is None else raw, **options)


def details(observation, kind):
    return [item.metadata for item in observation.evidence if item.kind == kind]


def test_completed_report_imports_atomically_with_original_digest_and_redacted_args():
    raw = report()
    batch = parse(raw)
    inventory = AssetInventory()
    inventory.import_batch(batch)
    assert {(item.entity_type, item.port) for item in batch.observations} == {("ip", None), ("service", 80)}
    metadata = details(batch.observations[0], "nmap-run")[0]
    assert metadata["file_sha256"] == hashlib.sha256(raw).hexdigest()
    assert metadata["scanner_version"] == "7.95"
    assert metadata["executable_sha256"] == "a" * 64
    assert "token=secret" not in json.dumps([item.to_dict() for item in batch.observations])


@pytest.mark.parametrize("technique,scan_type", [
    ("tcp-connect", "connect"), ("tcp-syn", "syn"), ("tcp-ack", "ack"), ("tcp-window", "window"),
    ("tcp-fin", "fin"), ("tcp-null", "null"), ("tcp-xmas", "xmas"), ("tcp-maimon", "maimon"),
])
def test_scan_technique_is_bound_to_scaninfo(technique, scan_type):
    scaninfo = f'<scaninfo type="{scan_type}" protocol="tcp" numservices="2" services="80,443"/>'
    assert parse(report(scaninfo=scaninfo), profile=profile(technique=technique)).observations
    with pytest.raises(ObservationImportError):
        parse(report(scaninfo=scaninfo.replace(f'type="{scan_type}"', 'type="udp"')), profile=profile(technique=technique))


def test_combined_tcp_udp_ipv6_results_preserve_service_cpe_os_trace_and_nse():
    scaninfo = ('<scaninfo type="syn" protocol="tcp" numservices="2" services="80,443"/>'
                '<scaninfo type="udp" protocol="udp" numservices="1" services="53"/>')
    service = ('<service name="domain" product="DNS" version="1" method="probed" conf="10">'
               '<cpe>cpe:/a:example:dns:1</cpe></service>'
               '<script id="dns-recursion" output="Recursion observed"><table key="result"><elem key="enabled">true</elem></table></script>')
    extra = ('<os><osmatch name="Example OS" accuracy="93"><osclass vendor="Example" accuracy="93" osfamily="Unix">'
             '<cpe>cpe:/o:example:unix</cpe></osclass></osmatch></os>'
             '<trace proto="udp" port="53"><hop ttl="1" ipaddr="2001:db8::1" rtt="1.2"/></trace><times srtt="1200"/>')
    batch = parse(report(hosts=host(port(80)+port(443,state="filtered")+port(53,"udp",body=service),
                                  address="2001:db8::10", extra=extra), scaninfo=scaninfo),
                  scope=scope("2001:db8::10"), profile=profile(technique="tcp-syn", udp_scan=True, udp_ports=(53,),
                      version_detection=True, os_detection=True, traceroute=True, script_ids=("dns-recursion",)))
    udp = next(item for item in batch.observations if item.transport == "udp")
    assert details(udp, "nmap-service")[0]["cpe"] == ["cpe:/a:example:dns:1"]
    assert details(udp, "nmap-nse")[0]["structured"][0]["children"][0]["text"] == "true"
    ip = next(item for item in batch.observations if item.entity_type == "ip")
    assert details(ip, "nmap-os")[0]["matches"][0]["accuracy"] == 93
    assert details(ip, "nmap-os")[0]["classification"] == "guess"
    assert details(ip, "nmap-trace")[0]["hops"][0]["ipaddr"] == "2001:db8::1"


@pytest.mark.parametrize("change", [
    lambda raw: raw.replace(b'addr="192.0.2.10"', b'addr="192.0.2.11"'),
    lambda raw: raw.replace(b'portid="443"', b'portid="444"'),
    lambda raw: raw.replace(b'portid="443"', b'portid="80"'),
    lambda raw: raw.replace(b'numservices="2"', b'numservices="3"'),
    lambda raw: raw.replace(b'version="7.95"', b'version="7.94"'),
    lambda raw: raw.replace(b'exit="success"', b'exit="error"'),
    lambda raw: raw.replace(b'<host>', b'<host timedout="true">'),
    lambda raw: raw.replace(b'total="1"', b'total="2"'),
    lambda raw: raw.replace(b'</ports>', b'</ports><ports/>'),
    lambda raw: raw[:-20],
])
def test_inconsistent_or_partial_results_cannot_mutate_inventory(change):
    inventory = AssetInventory()
    inventory.import_batch(parse())
    before = inventory.assets, inventory.observations, inventory.import_history
    with pytest.raises(ObservationImportError):
        inventory.import_batch(parse(change(report())))
    assert all(current is previous for current, previous in zip(
        (inventory.assets, inventory.observations, inventory.import_history), before))


def test_zero_open_ports_and_discovery_only_and_list_only_remain_useful():
    batch = parse(report(hosts=host('<extraports state="filtered" count="2"/>')))
    assert [item.entity_type for item in batch.observations] == ["ip"]
    for mode, state in (("only", "down"), ("list", "unknown")):
        batch = parse(report(hosts=host("", state=state), scaninfo="", up=0), profile=profile(discovery=mode))
        assert details(batch.observations[0], "nmap-host")[0]["state"] == state


def test_every_explicit_non_open_outcome_survives_beyond_legacy_samples():
    outcomes = "".join(port(number, state="closed") for number in range(1, 41))
    outcomes += port(443, state="unfiltered") + port(8080, state="filtered")
    raw = report(hosts=host(outcomes), scaninfo='<scaninfo type="ack" protocol="tcp" numservices="42" services="1-40,443,8080"/>')
    batch = parse(raw, profile=profile(ports=(*range(1, 41), 443, 8080), technique="tcp-ack"))
    ip = batch.observations[0]
    # The compatibility samples remain intentionally unchanged.
    assert details(ip, "nmap-port-states")[0]["non_open_ports_omitted"] == 26
    groups = [group for metadata in details(ip, "nmap-port-outcomes") for group in metadata["outcomes"]]
    assert {tuple(group[key] for key in ("protocol", "state", "ports", "count")) for group in groups} == {
        ("tcp", "closed", "1-40", 40), ("tcp", "unfiltered", "443", 1), ("tcp", "filtered", "8080", 1),
    }


def test_complete_aggregate_evidence_keeps_counts_and_only_reported_port_identities():
    outcomes = ('<extraports state="closed" count="3"><extrareasons reason="reset" count="3" proto="tcp" ports="1-3"/></extraports>'
                '<extraports state="filtered" count="2"/>')
    raw = report(hosts=host(outcomes), scaninfo='<scaninfo type="connect" protocol="tcp" numservices="5" services="1-5"/>')
    batch = parse(raw, profile=profile(ports=(1, 2, 3, 4, 5)))
    groups = [group for metadata in details(batch.observations[0], "nmap-aggregate-outcomes") for group in metadata["outcomes"]]
    assert groups == [
        {"state": "closed", "count": 3, "reasons": [{"reason": "reset", "count": 3, "proto": "tcp", "ports": "1-3"}]},
        {"state": "filtered", "count": 2, "reasons": []},
    ]


def test_multitarget_results_cannot_omit_an_approved_host_or_invent_hostname_assets():
    approved = scope("192.0.2.10", "192.0.2.11")
    raw = report(hosts=host() + host("", address="192.0.2.11", state="down"), total=2, up=1)
    assert len(parse(raw, scope=approved).observations) == 3
    with pytest.raises(ObservationImportError):
        parse(report(), scope=approved)
    raw = report(hosts=host(extra='<hostnames><hostname name="outside.example"/></hostnames>'))
    batch = parse(raw)
    assert all(item.entity_type != "hostname" for item in batch.observations)


def test_reverse_dns_names_remain_inert_even_when_not_valid_target_hostnames():
    raw = report(hosts=host(extra='<hostnames><hostname name="foo_bar.example.test" type="PTR"/></hostnames>'))
    batch = parse(raw, profile=profile(dns_mode="reverse"))
    assert {(item.entity_type, item.value) for item in batch.observations} == {
        ("ip", "192.0.2.10"), ("service", "192.0.2.10"),
    }
    ip = next(item for item in batch.observations if item.entity_type == "ip")
    metadata = details(ip, "nmap-hostnames")[0]
    assert metadata["names"] == [{"name": "foo_bar.example.test", "type": "PTR"}]
    assert metadata["authorization"] is False
    assert details(ip, "nmap-run")[0]["file_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("body", [
    '<script id="unexpected" output="hello"/>', '<os><osmatch name="Guess" accuracy="90"/></os>',
    '<trace><hop ttl="1" ipaddr="192.0.2.1"/></trace>',
])
def test_unrequested_active_features_are_rejected(body):
    with pytest.raises(ObservationImportError):
        parse(report(hosts=host(extra=body)))


def test_nse_output_and_nested_text_are_inert_bounded_and_safe_for_shared_viewer():
    script = '<script id="http-title" output="&lt;img src=x&gt;&#10;hello"><elem key="data">&lt;b&gt;text&lt;/b&gt;</elem></script>'
    batch = parse(report(hosts=host(port(80, body=script)+port(443,state="closed"))),
                  profile=profile(script_ids=("http-title",)))
    service = next(item for item in batch.observations if item.entity_type == "service")
    assert details(service, "nmap-nse")[0]["output"] == "<img src=x>\nhello"
    assert details(service, "nmap-nse")[0]["structured"][0]["text"] == "<b>text</b>"
    with pytest.raises(ObservationImportError):
        parse(report(hosts=host(extra='<hostscript>'+script.replace('http-title','other')+'</hostscript>')),
              profile=profile(script_ids=("http-title",)))


@pytest.mark.parametrize("xml", [
    b'<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///C:/secret">]><nmaprun>&x;</nmaprun>',
    b'<nmaprun>'+b'<x>'*33+b'</x>'*33+b'</nmaprun>',
    b'<nmaprun>'+b' '* (8*1024*1024)+b'</nmaprun>',
], ids=["entity", "depth", "size"])
def test_secure_xml_limits_and_entities_remain_enforced(xml):
    with pytest.raises(ObservationImportError):
        parse(xml)


def test_omitted_hosts_have_no_confirmed_individual_state():
    batch = parse(report(total=2), scope=scope("192.0.2.10", "192.0.2.11"))
    absent = next(item for item in batch.observations if item.value == "192.0.2.11")
    assert details(absent, "nmap-host")[0]["state"] == "not-reported"
    assert details(absent, "nmap-host")[0]["individual_state_confirmed"] is False


def test_top_ports_require_exact_ports_from_the_approved_distribution():
    with pytest.raises(ObservationImportError, match="trusted"):
        parse(profile=profile(port_mode="top", top_ports=2))
    assert parse(profile=profile(port_mode="top", top_ports=2), expected_ports=(("tcp", (80, 443)),)).observations
    with pytest.raises(ObservationImportError):
        parse(profile=profile(port_mode="top", top_ports=2), expected_ports=(("tcp", (22, 443)),))


def test_top_request_above_database_size_uses_exact_available_trusted_ports():
    batch = parse(profile=profile(port_mode="top", top_ports=65535), expected_ports=(("tcp", (80, 443)),))
    assert len(batch.observations) == 2


def test_all_ports_accepts_complete_aggregate_without_creating_open_services():
    raw = report(scaninfo='<scaninfo type="connect" protocol="tcp" numservices="65535" services="1-65535"/>',
                 hosts=host('<extraports state="closed" count="65535"/>'))
    assert [item.entity_type for item in parse(raw, profile=profile(port_mode="all")).observations] == ["ip"]


def test_closed_port_script_output_is_retained_on_host_evidence():
    raw = report(hosts=host(port(80, state="closed", body='<script id="http-title" output="closed test"/>') + port(443,state="closed")))
    batch = parse(raw, profile=profile(script_ids=("http-title",)))
    assert details(batch.observations[0], "nmap-nse")[0]["output"] == "closed test"


def test_dns_preflight_provenance_does_not_expose_script_argument_values():
    snapshot = scope()
    snapshot.inputs = ("example.test",)
    snapshot.dns_observations = (("example.test", ("192.0.2.10", "192.0.2.11")),)
    snapshot.observed_at = "2026-10-17T10:00:00Z"
    batch = parse(scope=snapshot, profile=profile(script_ids=("http-title",), script_arguments=(("token", "secret"),)))
    dns = details(batch.observations[0], "nmap-dns")[0]
    assert dns["hostname"] == "example.test"
    assert dns["addresses"] == ["192.0.2.10", "192.0.2.11"]
    assert dns["ownership_verified"] is False
    assert "secret" not in json.dumps([item.to_dict() for item in batch.observations])


def test_large_nse_is_chunked_and_total_output_limit_remains_enforced():
    script = '<script id="http-title" output="' + "x" * 4096 + '"/>'
    batch = parse(report(hosts=host(port(80, body=script)+port(443,state="closed"))), profile=profile(script_ids=("http-title",)))
    service = next(item for item in batch.observations if item.entity_type == "service")
    chunks = details(service, "nmap-nse")
    assert all(item["encoding"] == "json-chunks" for item in chunks)
    assert json.loads("".join(item["text"] for item in chunks))["output"] == "x" * 4096
    scripts = script * 17
    with pytest.raises(ObservationImportError, match="64 KiB"):
        parse(report(hosts=host(extra="<hostscript>"+scripts+"</hostscript>")), profile=profile(script_ids=("http-title",)))


@pytest.mark.parametrize("position", ["before-root", "inside-root"])
def test_xml_formatting_whitespace_does_not_consume_retained_nse_text_budget(position):
    raw = report()
    if position == "before-root":
        raw = raw.replace(b'<!DOCTYPE nmaprun>', b' ' * 71680 + b'<!DOCTYPE nmaprun>')
    else:
        raw = raw.replace(b'start="1">', b'start="1">' + b' ' * 71680)
    batch = parse(raw)
    assert details(batch.observations[0], "nmap-run")[0]["file_sha256"] == hashlib.sha256(raw).hexdigest()


def test_actual_nse_element_text_still_obeys_the_64kib_limit():
    script = '<script id="http-title"><elem key="large">' + 'x' * 65537 + '</elem></script>'
    with pytest.raises(ObservationImportError, match="64 KiB"):
        parse(report(hosts=host(port(80,body=script)+port(443,state="closed"))), profile=profile(script_ids=("http-title",)))


def test_service_version_output_must_be_requested_even_on_closed_ports():
    raw = report(hosts=host(port(80,state="closed",body='<service name="http" method="probed"/>')+port(443,state="closed")))
    with pytest.raises(ObservationImportError, match="Unrequested"):
        parse(raw)


def test_run_level_nse_survives_when_no_hosts_are_reported():
    raw = report(hosts="", up=0, extra='<prescript><script id="http-title" output="pre-run observation"/></prescript>')
    batch = parse(raw, profile=profile(script_ids=("http-title",)))
    assert details(batch.observations[0], "nmap-nse")[0]["output"] == "pre-run observation"


def test_service_vendor_device_and_os_details_are_inert_evidence():
    service = '<service name="http" product="Example" devicetype="router" ostype="Example OS" hostname="inferred.example" method="probed" conf="8"/>'
    batch = parse(report(hosts=host(port(80,body=service)+port(443,state="closed"))), profile=profile(version_detection=True))
    observed = next(item for item in batch.observations if item.entity_type == "service")
    metadata = details(observed, "nmap-service")[0]
    assert metadata["devicetype"] == "router"
    assert metadata["ostype"] == "Example OS"
    assert observed.confidence == 0.8


def test_explicit_nse_can_set_service_version_without_sV():
    service = '<service name="http" product="Example" method="probed" conf="3"/>'
    script = '<script id="http-server-header" output="Example"/>'
    batch = parse(report(hosts=host(port(80,body=service+script)+port(443,state="closed"))),
                  profile=profile(script_ids=("http-server-header",)))
    observed = next(item for item in batch.observations if item.entity_type == "service")
    assert details(observed, "nmap-service")[0]["detection_source"] == "approved-nse"


def test_selected_script_hashes_and_implicit_version_engine_survive_without_output():
    selected = (
        SimpleNamespace(script_id="http-title", categories=("default", "safe"), sha256="1" * 64),
        SimpleNamespace(script_id="http-server-header", categories=("version",), sha256="2" * 64),
    )
    batch = parse(profile=profile(version_detection=True, script_ids=("http-title",)), scripts=selected)
    ip = next(item for item in batch.observations if item.entity_type == "ip")
    manifest = [item for metadata in details(ip, "nmap-script-selection") for item in metadata["scripts"]]
    assert manifest == [
        {"id": "http-title", "categories": ["default", "safe"], "sha256": "1" * 64, "implicit_version": False},
        {"id": "http-server-header", "categories": ["version"], "sha256": "2" * 64, "implicit_version": True},
    ]
    provenance = details(ip, "nmap-run")[0]
    assert provenance["script_selection_count"] == 2
    assert len(provenance["script_selection_sha256"]) == 64
    assert not details(ip, "nmap-nse")


def test_string_script_selection_fixtures_retain_ids_without_invented_hashes():
    batch = parse(profile=profile(version_detection=True), scripts=("http-server-header",))
    ip = next(item for item in batch.observations if item.entity_type == "ip")
    assert details(ip, "nmap-script-selection")[0]["scripts"] == [
        {"id": "http-server-header", "implicit_version": True},
    ]


def test_full_bounded_ipv6_scope_and_sixty_four_dns_inputs_fit_native_evidence():
    targets = tuple("2001:db8::" + format(number, "x") for number in range(1, 257))
    snapshot = scope(*targets)
    snapshot.inputs = tuple(f"host-{number}.example.test" for number in range(64))
    snapshot.dns_observations = tuple((name, targets) for name in snapshot.inputs)
    raw = report(hosts="".join(host('<extraports state="closed" count="2"/>', address=address) for address in targets), total=256, up=256)
    batch = parse(raw, scope=snapshot, arguments=("-sT", "-Pn", *targets))
    assert len(batch.observations) == 256
    inventory = AssetInventory()
    assert inventory.import_batch(batch).total_assets == 256


@pytest.mark.parametrize("raw", [
    report(hosts=host("", state="unknown"), scaninfo="", up=0).replace(b'down="1"', b'down="2"'),
    report(hosts=host("", state="up"), scaninfo="", up=1),
], ids=["wrong-count", "invented-up-state"])
def test_list_only_cannot_claim_live_hosts_or_inconsistent_statistics(raw):
    with pytest.raises(ObservationImportError):
        parse(raw, profile=profile(discovery="list"))


@pytest.mark.parametrize("fragment", [
    '<service name="http" method="invalid"/>', '<service name="http" conf="11"/>',
    '<service name="http" conf="nan"/>',
])
def test_invalid_service_detection_contract_is_rejected(fragment):
    with pytest.raises(ObservationImportError):
        parse(report(hosts=host(port(80,body=fragment)+port(443,state="closed"))))
