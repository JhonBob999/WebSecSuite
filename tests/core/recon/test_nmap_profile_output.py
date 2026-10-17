"""Offline bounded profile XML, provenance, and atomic inventory regressions."""

from dataclasses import replace
import hashlib
import json

import pytest

from core.recon.inventory import AssetInventory
from core.recon.nmap_profiles import BUILTIN_PROFILES, duplicate_profile
from core.recon.nmap_public_output import parse_public_nmap_output
from core.recon.observations import MAX_IMPORT_BYTES, MAX_METADATA_BYTES, ObservationImportError
from core.recon.public_target import PublicTargetObservation


ADDRESS = "8.8.8.8"
WEB = BUILTIN_PROFILES[1]
CUSTOM = replace(duplicate_profile(WEB, "Sixteen ports"), ports=tuple(range(8000, 8016)))
RUN_ID = "nmap:public:profile-fixture-1"


def observation():
    return PublicTargetObservation(
        "ginandjuice.shop", (ADDRESS,), (), "2026-10-17T10:00:00+00:00", "offline fixture resolver",
    )


def report(profile=WEB, *, services=None, ports=None, doctype=b"<!DOCTYPE nmaprun>"):
    if services is None:
        services = ",".join(str(port) for port in profile.ports)
    if ports is None:
        ports = "".join(
            f'<port protocol="tcp" portid="{port}"><state state="open" reason="syn-ack"/>'
            '<service name="http" method="table" conf="3"/></port>' for port in profile.ports
        )
    body = (
        '<nmaprun scanner="nmap" version="7.95" start="1">'
        f'<scaninfo type="connect" protocol="tcp" numservices="{len(profile.ports)}" services="{services}"/>'
        f'<host><status state="up"/><address addr="{ADDRESS}" addrtype="ipv4"/>'
        f'<hostnames/><ports>{ports}</ports></host>'
        '<runstats><finished exit="success" time="2"/><hosts up="1" down="0" total="1"/></runstats>'
        '</nmaprun>'
    )
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + doctype + body.encode()


def parse(raw=None, *, profile=WEB, executable_version="7.95", **changes):
    values = dict(observation=observation(), address=ADDRESS, run_id=RUN_ID,
                  profile=profile, executable_version=executable_version)
    values.update(changes)
    return parse_public_nmap_output(report(profile) if raw is None else raw, **values)


def metadata(item, kind="nmap-run"):
    return next(evidence.metadata for evidence in item.evidence if evidence.kind == kind)


@pytest.mark.parametrize("profile", [WEB, CUSTOM], ids=["eight-web-ports", "sixteen-custom-ports"])
def test_valid_profile_xml_imports_exact_selected_tcp_services(profile):
    batch = parse(profile=profile)
    assert batch.run_id == RUN_ID
    assert batch.observations[0].value == ADDRESS
    assert [item.port for item in batch.observations[1:]] == list(profile.ports)
    assert all(item.transport == "tcp" for item in batch.observations[1:])


@pytest.mark.parametrize("services,profile", [
    ("80,443,8000,8080-8081,8443,8888,9443", WEB), ("8000-8015", CUSTOM),
])
def test_nmap_compact_scaninfo_port_ranges_match_the_exact_profile_set(services, profile):
    assert len(parse(report(profile, services=services), profile=profile).observations) == len(profile.ports) + 1


def test_profile_provenance_records_arguments_settings_version_and_original_digest():
    raw = report()
    batch = parse(raw)
    run = metadata(batch.observations[0])
    assert run["profile"] == run["profile_name"] == "Web Services"
    assert run["profile_id"] == "web-services"
    assert run["ports"] == [80, 443, 8000, 8080, 8081, 8443, 8888, 9443]
    assert run["effective_arguments"] == [
        "-sT", "-Pn", "-n", "-p", "80,443,8000,8080-8081,8443,8888,9443",
        "--max-retries", "1", "--max-rate", "10", "--host-timeout", "45s",
        "--no-stylesheet", "-oX", "-", ADDRESS,
    ]
    assert {key: run[key] for key in (
        "max_rate", "max_retries", "host_timeout_seconds", "execution_timeout_seconds", "version_detection",
    )} == {"max_rate": 10, "max_retries": 1, "host_timeout_seconds": 45,
           "execution_timeout_seconds": 60, "version_detection": False}
    assert run["executable_version"] == "7.95"
    assert run["file_sha256"] == hashlib.sha256(raw).hexdigest()
    assert run["approved_hostname"] == "ginandjuice.shop" and run["target"] == ADDRESS
    assert run["dns_observation"]["association"] == "preflight-observation"
    assert run["dns_observation"]["ownership_verified"] is False
    assert all(item.ref.startswith(RUN_ID) for item in batch.observations for item in item.evidence)
    assert len(json.dumps(run, ensure_ascii=False).encode()) < MAX_METADATA_BYTES


@pytest.mark.parametrize("ports", [
    '<extraports state="closed" count="8"/>',
    '<extraports state="filtered" count="8"/>',
    '<extraports state="closed" count="3"/><extraports state="filtered" count="5"/>',
])
def test_zero_open_ports_are_successfully_importable_profile_results(ports):
    batch = parse(report(ports=ports))
    assert [(item.entity_type, item.value) for item in batch.observations] == [("ip", ADDRESS)]


def test_sixteen_port_aggregate_accounting_accepts_explicit_reason_ranges():
    ports = ('<extraports state="closed" count="12"><extrareasons reason="conn-refused" count="12" '
             'proto="tcp" ports="8000-8011"/></extraports>'
             '<extraports state="filtered" count="4"><extrareasons reason="no-responses" count="4" '
             'proto="tcp" ports="8012-8015"/></extraports>')
    batch = parse(report(CUSTOM, services="8000-8015", ports=ports), profile=CUSTOM)
    states = metadata(batch.observations[0], "nmap-port-states")
    assert states["extraports"] == [{"state": "closed", "count": "12"}, {"state": "filtered", "count": "4"}]


def test_individual_closed_filtered_and_open_states_with_aggregate_reasons_are_preserved():
    ports = ('<port protocol="tcp" portid="80"><state state="closed"/></port>'
             '<port protocol="tcp" portid="443"><state state="filtered"/></port>'
             '<port protocol="tcp" portid="8000"><state state="open"/></port>'
             '<extraports state="closed" count="5"><extrareasons reason="conn-refused" count="5" '
             'proto="tcp" ports="8080-8081,8443,8888,9443"/></extraports>')
    batch = parse(report(ports=ports))
    assert [(item.entity_type, item.port) for item in batch.observations] == [("ip", None), ("service", 8000)]
    assert metadata(batch.observations[0], "nmap-port-states")["non_open_ports"] == [
        {"transport": "tcp", "port": 80, "state": "closed"},
        {"transport": "tcp", "port": 443, "state": "filtered"},
    ]


@pytest.mark.parametrize("ports", [
    '<extraports state="closed" count="7"/>',
    '<extraports state="closed" count="9"/>',
    '<extraports state="closed" count="0"/><extraports state="filtered" count="8"/>',
    '<extraports state="closed" count="08"/>',
    '<extraports state="open" count="8"/>',
    '<extraports state="open|filtered" count="8"/>',
    '<extraports state="closed" count="4"/><extraports state="closed" count="4"/>',
    '<extraports state="closed" count="8"><extrareasons count="7"/></extraports>',
    '<extraports state="closed" count="8"><extrareasons count="8" proto="udp"/></extraports>',
    '<extraports state="closed" count="8"><extrareasons count="8" ports="1-8"/></extraports>',
    '<extraports state="closed" count="8"><extrareasons count="8" '
    'ports="80,443,8000,8080,8081,8443,8888,8888"/></extraports>',
    '<extraports state="closed" count="8"><extrareasons count="8" ports="1-65535"/></extraports>',
    '<extraports state="closed" count="8"><extrareasons count="8" ports="8001-8000"/></extraports>',
    '<port protocol="tcp" portid="80"><state state="closed"/></port>'
    '<extraports state="closed" count="7"><extrareasons count="7" '
    'ports="80,443,8000,8080,8081,8443,8888"/></extraports>',
    '<extraports state="closed" count="4"><extrareasons count="4" ports="80,443,8000,8080"/></extraports>'
    '<extraports state="filtered" count="4"><extrareasons count="4" ports="8080,8443,8888,9443"/></extraports>',
])
def test_profile_aggregate_results_cannot_omit_duplicate_or_substitute_ports(ports):
    with pytest.raises(ObservationImportError):
        parse(report(ports=ports))


@pytest.mark.parametrize("change", [
    lambda raw: raw.replace(b'<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>'
                            b'<service name="http" method="table" conf="3"/></port>', b''),
    lambda raw: raw.replace(b'portid="80"', b'portid="443"'),
    lambda raw: raw.replace(b'portid="80"', b'portid="22"'),
    lambda raw: raw.replace(b'portid="80"', b'portid="080"'),
    lambda raw: raw.replace(b'protocol="tcp"', b'protocol="udp"'),
    lambda raw: raw.replace(b'scanner="nmap"', b'scanner="other"'),
    lambda raw: raw.replace(b'addr="8.8.8.8"', b'addr="1.1.1.1"'),
    lambda raw: raw.replace(b'<hostnames/>', b'<hostnames><hostname name="ginandjuice.shop"/></hostnames>'),
    lambda raw: raw.replace(b'<host>', b'<host timedout="true">'),
    lambda raw: raw.replace(b'exit="success"', b'exit="error"'),
    lambda raw: raw.replace(b'total="1"', b'total="2"'),
    lambda raw: raw.replace(b'type="connect"', b'type="syn"'),
    lambda raw: raw.replace(b'numservices="8"', b'numservices="9"'),
    lambda raw: raw.replace(b'method="table"', b'method="probed"'),
    lambda raw: raw.replace(b'<state state="open" reason="syn-ack"/>', b'<state state="unknown"/>'),
    lambda raw: raw.replace(b'<state state="open" reason="syn-ack"/>', b'<state state="open"/><state state="closed"/>'),
    lambda raw: raw.replace(b'<ports>', b'<ports><script id="unexpected"/>'),
])
def test_profile_xml_keeps_strict_scanner_completion_identity_and_outcome_checks(change):
    with pytest.raises(ObservationImportError):
        parse(change(report()))


@pytest.mark.parametrize("services", [
    "80,443,8000,8080,8081,8443,8888", "80,443,8000,8080,8081,8443,8888,22",
    "80,443,8000,8080,8081,8443,8888,8888", "443,80,8000,8080,8081,8443,8888,9443",
    "080,443,8000,8080-8081,8443,8888,9443", "80,443,8000,8080 - 8081,8443,8888,9443",
    "1-65535", "", "80,443,8000,8081-8080,8443,8888,9443",
])
def test_profile_scaninfo_requires_the_exact_bounded_canonical_port_set(services):
    with pytest.raises(ObservationImportError):
        parse(report(services=services))


@pytest.mark.parametrize("doctype", [
    b'<!DOCTYPE nmaprun SYSTEM "https://example.invalid/nmap.dtd">',
    b'<!DOCTYPE nmaprun [<!ENTITY a "expanded">]>', b'<!DOCTYPE nmaprun []>',
    b'<!DOCTYPE  nmaprun>', b'<!DOCTYPE nmaprun >', b'<!-- <!DOCTYPE nmaprun> -->',
])
def test_profile_xml_does_not_relax_the_strict_dtd_and_entity_rules(doctype):
    with pytest.raises(ObservationImportError):
        parse(report(doctype=doctype))


@pytest.mark.parametrize("raw", [b'', b'<nmaprun>', b'x' * (MAX_IMPORT_BYTES + 1), b'<nmaprun>\x00</nmaprun>', 'text'],
                         ids=["empty", "truncated", "oversized", "nul", "text"])
def test_profile_xml_rejects_partial_oversized_and_non_utf8_output(raw):
    with pytest.raises(ObservationImportError):
        parse(raw)


@pytest.mark.parametrize("profile", [
    BUILTIN_PROFILES[2], BUILTIN_PROFILES[3], replace(CUSTOM, ports=tuple(range(8000, 8017))),
    replace(CUSTOM, version_detection=True), replace(CUSTOM, max_rate=11),
])
def test_profile_output_cannot_bypass_the_separate_execution_eligibility_gate(profile):
    with pytest.raises(ObservationImportError):
        parse(profile=profile)


@pytest.mark.parametrize("executable_version", [None, "", " ", "x" * 65, "7.95\nother", "7.95\x00", object()])
def test_profile_provenance_rejects_unbounded_or_ambiguous_executable_versions(executable_version):
    with pytest.raises(ObservationImportError):
        parse(executable_version=executable_version)


@pytest.mark.parametrize("change", [
    lambda raw: raw.replace(b'version="7.95"', b'version="7.94"'),
    lambda raw: raw.replace(b' version="7.95"', b''),
])
def test_profile_report_scanner_version_must_match_the_verified_executable(change):
    with pytest.raises(ObservationImportError):
        parse(change(report()))


def test_profile_evidence_still_passes_the_final_native_metadata_bound_before_import():
    inventory = AssetInventory()
    inventory.import_batch(parse())
    before = inventory.assets, inventory.observations, inventory.import_history
    oversized = replace(observation(), cnames=tuple(
        f"a{number}." + ".".join(("a" * 63, "b" * 63, "c" * 63, "test")) for number in range(32)
    ))
    with pytest.raises(ObservationImportError, match="metadata exceeds"):
        inventory.import_batch(parse(observation=oversized, run_id="nmap:public:too-much-evidence"))
    assert all(current is previous for current, previous in zip(
        (inventory.assets, inventory.observations, inventory.import_history), before,
    ))


def test_profile_results_merge_into_existing_inventory_and_rejected_output_is_atomic():
    inventory = AssetInventory()
    inventory.import_batch(parse(), label="Nmap Web Services", format_name="Nmap live XML")
    inventory.import_batch(parse(run_id="nmap:public:profile-fixture-2"), label="Nmap Web Services", format_name="Nmap live XML")
    assert len(inventory.assets) == 9 and len(inventory.observations) == 18
    assert [item.run_id for item in inventory.import_history] == [RUN_ID, "nmap:public:profile-fixture-2"]
    before = inventory.assets, inventory.observations, inventory.import_history
    with pytest.raises(ObservationImportError):
        inventory.import_batch(parse(report().replace(b'portid="80"', b'portid="443"')))
    assert all(current is previous for current, previous in zip(
        (inventory.assets, inventory.observations, inventory.import_history), before,
    ))
