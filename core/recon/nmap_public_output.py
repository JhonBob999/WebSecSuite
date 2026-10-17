"""Bounded XML validation for approved, narrowly scoped public scan profiles.

The runtime must first require complete, successful process execution. This
module validates the report against that run's captured preflight observation;
it neither resolves DNS nor creates or restores execution authorization.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import re
from xml.etree.ElementTree import Element

from core.recon.nmap_adapter import _normalize_local_xml
from core.recon.nmap_import import _xml_root, parse_nmap_xml
from core.recon.nmap_profiles import NmapScanProfile
from core.recon.observations import (
    MAX_IMPORT_BYTES, SCHEMA, VERSION, ObservationBatch, ObservationImportError,
    parse_observations_json,
)
from core.recon.public_target import (
    PUBLIC_HOSTNAME, PUBLIC_PORTS, PUBLIC_PROFILE, PublicTargetObservation,
    validate_public_address,
)
from core.recon.targets import normalize_hostname


_PORT_IDS = {str(value) for value in PUBLIC_PORTS}
_ALLOWED_CHILDREN = {
    "nmaprun": {"scaninfo", "verbose", "debugging", "taskbegin", "taskend", "taskprogress", "host", "runstats"},
    "host": {"status", "address", "hostnames", "ports", "times"},
    "hostnames": set(),
    "ports": {"port", "extraports"},
    "port": {"state", "service"},
    "extraports": {"extrareasons"},
    "runstats": {"finished", "hosts"},
}


def _context(observation: PublicTargetObservation, address: str, run_id: str) -> dict:
    """Validate inert, bounded provenance without treating DNS as ownership."""
    if type(observation) is not PublicTargetObservation or observation.hostname != PUBLIC_HOSTNAME:
        raise ObservationImportError("Public Nmap results require the exact R5B preflight hostname.")
    if (not isinstance(run_id, str) or len(run_id) > 128 or
            re.fullmatch(r"nmap:public:[A-Za-z0-9][A-Za-z0-9._:-]*", run_id) is None):
        raise ObservationImportError("Public Nmap results require a distinct bounded public run identity.")
    try:
        selected = validate_public_address(address)
        addresses = observation.ipv4_addresses
        cnames = observation.cnames
        if (selected != address or type(addresses) is not tuple or not 1 <= len(addresses) <= 32
                or any(validate_public_address(value) != value for value in addresses)
                or len(set(addresses)) != len(addresses) or address not in addresses
                or type(cnames) is not tuple or len(cnames) > 32
                or any(normalize_hostname(value) != value for value in cnames)
                or len(set(cnames)) != len(cnames)):
            raise ValueError("The selected IP must match bounded canonical preflight DNS results.")
        for value, limit in ((observation.observed_at, 64), (observation.resolver, 128)):
            if (not isinstance(value, str) or not value.strip() or len(value) > limit
                    or any(ord(character) < 32 or ord(character) == 127 for character in value)):
                raise ValueError("DNS provenance text is missing or exceeds its bounds.")
        timestamp = datetime.fromisoformat(observation.observed_at)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("The preflight observation must include a time zone.")
    except (TypeError, ValueError, OverflowError) as error:
        raise ObservationImportError("Invalid public Nmap preflight observation: " + str(error)) from None
    return {
        "hostname": PUBLIC_HOSTNAME, "selected_ipv4": address,
        "ipv4_addresses": list(addresses), "cnames": list(cnames),
        "observed_at": observation.observed_at, "resolver": observation.resolver,
        "association": "preflight-observation", "ownership_verified": False,
    }


def _structure(root: Element) -> None:
    # A narrow tree rejects hosthint/alternate addresses, hostname assertions,
    # scripts, OS/version probes and hidden duplicate metadata before R3's more
    # permissive offline importer can ignore unsupported nodes.
    for node in root.iter():
        if any(child.tag not in _ALLOWED_CHILDREN.get(node.tag, set()) for child in node):
            raise ObservationImportError("Public Nmap XML contains unexpected scan or target metadata.")


def _port_ids(text: str, limit: int) -> tuple[str, ...]:
    """Expand bounded Nmap numeric lists/ranges without accepting CLI syntax."""
    if type(text) is not str or not text or len(text) > 192:
        raise ObservationImportError("The public report has invalid bounded TCP port identities.")
    values = []
    for term in text.split(","):
        match = re.fullmatch(r"([1-9][0-9]{0,4})(?:-([1-9][0-9]{0,4}))?", term)
        if match is None:
            raise ObservationImportError("The public report has invalid TCP port range notation.")
        first, last = int(match[1]), int(match[2] or match[1])
        if not 1 <= first <= last <= 65535 or last - first + 1 > limit:
            raise ObservationImportError("The public report has unbounded TCP port range notation.")
        values.extend(str(number) for number in range(first, last + 1))
        if len(values) > limit:
            raise ObservationImportError("The public report exceeds the selected TCP port count.")
    if len(values) != len(set(values)) or values != sorted(values, key=int):
        raise ObservationImportError("The public report has duplicate or noncanonical TCP port identities.")
    return tuple(values)


def _profile(root: Element, address: str, expected_ports: tuple[int, ...] | None = None) -> Element:
    _structure(root)
    if root.get("scanner") != "nmap":
        raise ObservationImportError("The public report must identify the Nmap scanner.")
    runs = root.findall("runstats")
    finished = root.findall("runstats/finished")
    if len(runs) != 1 or len(finished) != 1 or finished[0].get("exit") != "success":
        raise ObservationImportError("Nmap did not report a complete successful public scan.")
    hosts = root.findall("host")
    if len(hosts) != 1:
        raise ObservationImportError("The public report must contain exactly one approved host.")
    host = hosts[0]
    statuses, summaries = host.findall("status"), root.findall("runstats/hosts")
    if (host.get("timedout") not in {None, "false"} or len(statuses) != 1
            or statuses[0].get("state") != "up" or len(summaries) != 1
            or any(summaries[0].get(name) != value for name, value in
                   (("up", "1"), ("down", "0"), ("total", "1")))):
        raise ObservationImportError("The approved public host did not complete successfully.")
    addresses = host.findall("address")
    if (len(addresses) != 1 or addresses[0].get("addrtype") != "ipv4"
            or addresses[0].get("addr") != address):
        raise ObservationImportError("The public report contains an unexpected target address.")
    scans = root.findall("scaninfo")
    ports = PUBLIC_PORTS if expected_ports is None else expected_ports
    if (len(scans) != 1 or scans[0].get("type") != "connect" or scans[0].get("protocol") != "tcp"
            or scans[0].get("numservices") != str(len(ports))):
        raise ObservationImportError("The public report has an unexpected Nmap profile.")
    services = scans[0].get("services", "")
    matches = (services == "80,443,8080,8443" if expected_ports is None else
               _port_ids(services, len(ports)) == tuple(str(port) for port in ports))
    if not matches:
        raise ObservationImportError("The public report has an unexpected Nmap profile.")
    return host


def _port_outcomes(host: Element, expected_ports: tuple[int, ...] | None = None) -> None:
    port_ids = _PORT_IDS if expected_ports is None else {str(port) for port in expected_ports}
    port_count = len(port_ids)
    containers = host.findall("ports")
    if len(containers) != 1:
        raise ObservationImportError("The public report is missing complete port results.")
    container, seen_ports = containers[0], set()
    for port in container.findall("port"):
        number, states, services = port.get("portid"), port.findall("state"), port.findall("service")
        if (port.get("protocol") != "tcp" or number not in port_ids or number in seen_ports
                or len(states) != 1 or states[0].get("state") not in {"open", "closed", "filtered"}
                or len(services) > 1 or any(service.get("method") not in {None, "table"} for service in services)):
            raise ObservationImportError("The public report has unexpected or incomplete TCP port outcomes.")
        seen_ports.add(number)
    reported, seen_states, reason_ports = len(seen_ports), set(), set()

    def valid_count(value):
        if expected_ports is None:
            return re.fullmatch(r"[1-4]", value) is not None
        return re.fullmatch(r"[1-9][0-9]?", value) is not None and int(value) <= port_count

    for extra in container.findall("extraports"):
        state, count = extra.get("state"), extra.get("count", "")
        if (state not in {"closed", "filtered"} or state in seen_states
                or not valid_count(count)):
            raise ObservationImportError("The public report has invalid aggregate port outcomes.")
        seen_states.add(state)
        reported += int(count)
        reasons, reason_count = extra.findall("extrareasons"), 0
        for reason in reasons:
            raw_count = reason.get("count", "")
            if (not valid_count(raw_count) or reason.get("proto") not in {None, "tcp"}):
                raise ObservationImportError("The public report has invalid aggregate port reason metadata.")
            reason_count += int(raw_count)
            if reason.get("ports") is not None:
                values = (reason.get("ports", "").split(",") if expected_ports is None else
                          _port_ids(reason.get("ports", ""), port_count))
                if (len(values) != int(raw_count) or len(set(values)) != len(values)
                        or any(value not in port_ids or value in seen_ports or value in reason_ports for value in values)):
                    raise ObservationImportError("The public report has unexpected aggregate port identities.")
                reason_ports.update(values)
        if reasons and reason_count != int(count):
            raise ObservationImportError("The public report has incomplete aggregate port reasons.")
    if reported != port_count:
        raise ObservationImportError("The public scan did not report all four approved ports." if expected_ports is None
                                     else "The public scan did not report all selected approved ports.")


def parse_public_nmap_output(content: bytes, *, observation: PublicTargetObservation,
                             address: str, run_id: str, profile: NmapScanProfile | None = None,
                             executable_version: str = "") -> ObservationBatch:
    """Return a validated batch tied to one completed public run and scanned IP."""
    dns_observation = _context(observation, address, run_id)
    selected_profile, profile_metadata = None, {}
    if profile is not None:
        # Configuration validity never grants execution eligibility. Revalidate
        # even a frozen profile before using its port set or enriching evidence.
        from core.recon.nmap_profile_execution import (
            ProfileExecutionError, profile_arguments, validate_executable_profile,
        )
        try:
            selected_profile = validate_executable_profile(profile)
            arguments = profile_arguments(selected_profile, address)
        except (ProfileExecutionError, TypeError, ValueError) as error:
            raise ObservationImportError("Invalid public Nmap execution profile: " + str(error)) from None
        if (type(executable_version) is not str or not executable_version.strip() or len(executable_version) > 64
                or any(ord(character) < 32 or ord(character) == 127 for character in executable_version)):
            raise ObservationImportError("The public Nmap executable version must be bounded single-line text.")
        profile_metadata = {
            "profile_id": selected_profile.profile_id, "profile_name": selected_profile.name,
            "effective_arguments": list(arguments), "max_rate": selected_profile.max_rate,
            "max_retries": selected_profile.max_retries,
            "host_timeout_seconds": selected_profile.host_timeout_seconds,
            "execution_timeout_seconds": selected_profile.execution_timeout_seconds,
            "version_detection": selected_profile.version_detection, "executable_version": executable_version,
        }
    if type(content) is not bytes or not content or len(content) > MAX_IMPORT_BYTES:
        raise ObservationImportError("Complete bounded public Nmap XML process output is required.")
    if b"\x00" in content:
        raise ObservationImportError("Trusted Nmap output must use its UTF-8 XML format.")
    normalized, declaration_removed = _normalize_local_xml(content)
    root = _xml_root(normalized)
    if selected_profile is not None and root.get("version") != executable_version:
        raise ObservationImportError("The public report scanner version differs from the verified Nmap executable.")
    expected_ports = None if selected_profile is None else selected_profile.ports
    _port_outcomes(_profile(root, address, expected_ports), expected_ports)
    batch = parse_nmap_xml(normalized)
    digest = hashlib.sha256(content).hexdigest()
    records = []
    for observation_record in batch.observations:
        record = observation_record.to_dict()
        record.pop("run_id")
        record.pop("entity_key")
        for item in record["evidence"]:
            item["ref"] = item["ref"].replace(batch.run_id, run_id, 1)
            if item["kind"] == "nmap-run":
                item["metadata"].update({
                    "file_sha256": digest, "file_size": len(content), "doctype_normalized": declaration_removed,
                    "execution_mode": "authorized-public",
                    "profile": PUBLIC_PROFILE if selected_profile is None else selected_profile.name, "target": address,
                    "approved_hostname": PUBLIC_HOSTNAME,
                    "ports": list(PUBLIC_PORTS if selected_profile is None else selected_profile.ports),
                    "technique": "tcp-connect", "dns_observation": dns_observation, **profile_metadata,
                })
        records.append(record)
    # The final native gate bounds enriched evidence and normalizes every field
    # before an inventory import can change assets or history.
    return parse_observations_json(json.dumps({
        "schema": SCHEMA, "version": VERSION, "run_id": run_id, "observations": records,
    }, ensure_ascii=False, allow_nan=False))


__all__ = ["parse_public_nmap_output"]
