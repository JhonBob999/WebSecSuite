"""Offline Nmap XML adapter to the native R2 observation contract.

XML, evidence references, scanner arguments and script output are never executed
or fetched. A content digest identifies the source file independently of its path.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from xml.etree.ElementTree import Element, TreeBuilder
from xml.parsers import expat

from core.recon.observations import (
    MAX_IMPORT_BYTES, MAX_METADATA_BYTES, MAX_OBSERVATIONS, SCHEMA, VERSION,
    ObservationBatch, ObservationImportError, parse_observations_json,
)
from core.recon.targets import normalize_hostname


MAX_XML_ELEMENTS = 100_000
MAX_XML_DEPTH = 32
MAX_XML_STRING = 4096
MAX_HOSTS = 10_000
MAX_PORTS = 50_000
MAX_STATE_SAMPLES = 16
MAX_HOST_SAMPLES = 4


def _reject_declaration(*_args):
    raise ObservationImportError("Nmap XML DTD and entity declarations are not allowed.")


def _xml_root(content: bytes | str) -> Element:
    """Parse with explicit declaration denial and bounds before building nodes."""
    builder = TreeBuilder()
    parser = expat.ParserCreate(namespace_separator="}")
    depth, elements = 0, 0

    def start(name, attributes):
        nonlocal depth, elements
        depth += 1
        elements += 1
        if depth > MAX_XML_DEPTH:
            raise ObservationImportError("Nmap XML exceeds the nesting depth limit.")
        if elements > MAX_XML_ELEMENTS:
            raise ObservationImportError("Nmap XML exceeds the element count limit.")
        if len(attributes) > 32:
            raise ObservationImportError("Nmap XML exceeds the attribute count limit.")
        if (len(name) > MAX_XML_STRING or any(
                len(key) > MAX_XML_STRING or len(value) > MAX_XML_STRING
                for key, value in attributes.items())):
            raise ObservationImportError("Nmap XML exceeds the string length limit.")
        if elements == 1 and name != "nmaprun":
            raise ObservationImportError("Expected an unnamespaced nmaprun XML root.")
        builder.start(name, attributes)

    def end(name):
        nonlocal depth
        builder.end(name)
        depth -= 1

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.StartDoctypeDeclHandler = _reject_declaration
    parser.EntityDeclHandler = _reject_declaration
    parser.ExternalEntityRefHandler = _reject_declaration
    parser.SkippedEntityHandler = _reject_declaration
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    # No character-data or processing-instruction handler: text (including NSE
    # output), stylesheet instructions and comments are not retained or followed.
    try:
        parser.Parse(content, True)
        return builder.close()
    except (expat.ExpatError, LookupError, ValueError) as error:
        if isinstance(error, ObservationImportError):
            raise
        raise ObservationImportError("Malformed or truncated Nmap XML: " + str(error)) from None


def _optional(node: Element | None, name: str) -> str | None:
    if node is None:
        return None
    value = " ".join(node.get(name, "").split())
    if len(value) > 128:
        value = value[:127] + "…"
    # XML character references can contain controls not accepted by R2.
    value = "".join(character for character in value if ord(character) >= 32 and ord(character) != 127)
    return value or None


def _fields(node: Element | None, names: tuple[str, ...]) -> dict:
    return {name: value for name in names if (value := _optional(node, name)) is not None}


def _state(node: Element | None) -> str:
    # Missing state remains unknown; never infer open from a service element.
    value = node.get("state", "") if node is not None else ""
    if len(value) > 128:
        raise ObservationImportError("Nmap state exceeds the 128 character length limit.")
    return value or "unknown"


def _size(metadata: dict) -> int:
    return len(json.dumps(metadata, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _host_identity(node: Element) -> tuple[list[str], list[str]]:
    addresses, hostnames = [], []
    seen_addresses, seen_hostnames = set(), set()
    for address in node.findall("address"):
        if address.get("addrtype") not in {"ipv4", "ipv6"}:
            continue
        raw = address.get("addr", "")
        try:
            if "%" in raw:
                raise ValueError("Scoped IP addresses are not supported.")
            value = ipaddress.ip_address(raw)
            expected = 4 if address.get("addrtype") == "ipv4" else 6
            if value.version != expected:
                raise ValueError("IP address does not match addrtype.")
        except ValueError as error:
            raise ObservationImportError("Invalid Nmap host address: " + str(error)) from None
        if value.compressed not in seen_addresses:
            seen_addresses.add(value.compressed)
            addresses.append(value.compressed)
    for hostname in node.findall("hostnames/hostname"):
        raw = hostname.get("name", "")
        if not raw.strip():
            continue
        try:
            value = normalize_hostname(raw)
        except ValueError as error:
            raise ObservationImportError("Invalid Nmap hostname: " + str(error)) from None
        if value not in seen_hostnames:
            seen_hostnames.add(value)
            hostnames.append(value)
    return addresses, hostnames


def _port_states(ports: list[Element], host: Element) -> dict:
    non_open = []
    for port in ports:
        state = _state(port.find("state"))
        if state != "open":
            non_open.append({"transport": port.get("protocol"), "port": int(port.get("portid")), "state": state})
    metadata = {"non_open_port_count": len(non_open), "non_open_ports": non_open[:MAX_STATE_SAMPLES],
                "non_open_ports_omitted": max(0, len(non_open) - MAX_STATE_SAMPLES)}
    extras = host.findall("ports/extraports")
    metadata["extraports"] = [_fields(item, ("state", "count")) for item in extras[:MAX_STATE_SAMPLES]]
    metadata["extraports_omitted"] = max(0, len(extras) - MAX_STATE_SAMPLES)
    # Unusual state labels remain verbatim in the retained samples. Drop trailing
    # samples with explicit omission counts instead of exceeding R2 metadata size.
    while _size(metadata) > MAX_METADATA_BYTES:
        if metadata["extraports"]:
            metadata["extraports"].pop()
            metadata["extraports_omitted"] += 1
        else:
            metadata["non_open_ports"].pop()
            metadata["non_open_ports_omitted"] += 1
    return metadata


def _host_records(host: Element, index: int, run_ref: str, run_metadata: dict) -> list[dict]:
    addresses, hostnames = _host_identity(host)
    host_metadata = {"state": _state(host.find("status")), **_fields(host, ("starttime", "endtime")),
                     "addresses": addresses[:MAX_HOST_SAMPLES], "hostnames": hostnames[:MAX_HOST_SAMPLES],
                     "addresses_omitted": max(0, len(addresses) - MAX_HOST_SAMPLES),
                     "hostnames_omitted": max(0, len(hostnames) - MAX_HOST_SAMPLES)}
    ports = []
    for item in host.findall("ports/port"):
        if item.get("protocol") not in {"tcp", "udp"}:
            continue
        try:
            raw = item.get("portid", "")
            if not re.fullmatch(r"[0-9]{1,5}", raw) or not 1 <= int(raw) <= 65535:
                raise ValueError
        except ValueError:
            raise ObservationImportError(f"Nmap host {index}: portid must be an integer from 1 to 65535.") from None
        ports.append(item)
    host_ref = f"{run_ref}#host-{index}"
    common_evidence = [
        {"ref": run_ref, "kind": "nmap-run", "metadata": run_metadata},
        {"ref": host_ref, "kind": "nmap-host", "metadata": host_metadata},
    ]
    host_evidence = [*common_evidence, {"ref": host_ref + "/ports", "kind": "nmap-port-states",
                                     "metadata": _port_states(ports, host)}]
    records = []
    for entity_type, values in (("ip", addresses), ("hostname", hostnames)):
        for offset, value in enumerate(values, 1):
            records.append({"id": f"host-{index}-{entity_type}-{offset}", "source": "nmap",
                            "type": entity_type, "value": value, "evidence": host_evidence})
    # The XML reports ports on a host, not proof that every name or address has
    # that service. Use the first reported IP, otherwise the first reported name.
    service_host = next(iter(addresses or hostnames), None)
    if service_host is not None:
        for offset, port in enumerate(ports, 1):
            if _state(port.find("state")) != "open":
                continue
            service = port.find("service")
            service_metadata = {"state": "open", **_fields(service, (
                "name", "product", "version", "extrainfo", "conf", "method", "tunnel"))}
            record = {"id": f"host-{index}-service-{offset}", "source": "nmap", "type": "service",
                      "host": service_host, "transport": port.get("protocol"), "port": int(port.get("portid")),
                      "evidence": [*common_evidence, {"ref": f"{host_ref}/port-{offset}",
                                   "kind": "nmap-service", "metadata": service_metadata}]}
            if name := _optional(service, "name"):
                record["service_name"] = name
            confidence = _optional(service, "conf")
            if confidence is not None and re.fullmatch(r"[0-9]{1,2}", confidence) and int(confidence) <= 10:
                record["confidence"] = int(confidence) / 10
            records.append(record)
    return records


def parse_nmap_xml(content: bytes | str) -> ObservationBatch:
    """Validate an entire bounded XML report before returning native observations."""
    if not isinstance(content, (bytes, str)):
        raise ObservationImportError("Nmap XML must be bytes or XML text.")
    try:
        if len(content) > MAX_IMPORT_BYTES:
            raise ObservationImportError("Nmap XML exceeds the 8 MiB import limit.")
        raw = content.encode("utf-8") if isinstance(content, str) else content
    except UnicodeError:
        raise ObservationImportError("Nmap XML contains invalid Unicode.") from None
    if len(raw) > MAX_IMPORT_BYTES:
        raise ObservationImportError("Nmap XML exceeds the 8 MiB import limit.")
    root = _xml_root(content)
    if (scanner := root.get("scanner")) is not None and scanner != "nmap":
        raise ObservationImportError("Expected Nmap XML; scanner identity must be nmap when present.")
    digest = hashlib.sha256(raw).hexdigest()
    run_id = f"nmap:sha256:{digest}"
    run_metadata = {"file_sha256": digest, "file_size": len(raw), **_fields(root, ("scanner", "start", "startstr"))}
    if version := _optional(root, "version"):
        run_metadata["scanner_version"] = version
    finished = root.find("runstats/finished")
    for source, target in (("time", "finished"), ("timestr", "finished_timestr"), ("exit", "exit")):
        if value := _optional(finished, source):
            run_metadata[target] = value
    hosts = root.findall("host")
    if len(hosts) > MAX_HOSTS or sum(len(host.findall("ports/port")) for host in hosts) > MAX_PORTS:
        raise ObservationImportError("Nmap XML exceeds the host or port record count limit.")
    records = []
    for index, host in enumerate(hosts, 1):
        records.extend(_host_records(host, index, run_id, run_metadata))
        if len(records) > MAX_OBSERVATIONS:
            raise ObservationImportError("Nmap XML exceeds the 10,000 observation record limit.")
    # Keep R2's schema, normalization and evidence validation as the final gate.
    return parse_observations_json(json.dumps({"schema": SCHEMA, "version": VERSION,
                                              "run_id": run_id, "observations": records}))


def _local_xml_path(path: str | Path) -> Path:
    text = str(path)
    normalized = text.replace("\\", "/")
    drive = re.match(r"^[A-Za-z]:/", normalized)
    tail = normalized[2:] if drive else normalized
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
                *(f"COM{i}" for i in "123456789¹²³"), *(f"LPT{i}" for i in "123456789¹²³")}
    if (normalized.startswith(("//", "/??/", "/Device/")) or ":" in tail or
            any(part.split(".")[0].rstrip(" ").upper() in reserved for part in normalized.split("/"))):
        raise ObservationImportError("Choose a local XML file; remote and device paths are not supported.")
    result = Path(text)
    if result.suffix.lower() != ".xml":
        raise ObservationImportError("Unsupported file type; choose a local Nmap XML file.")
    return result


def read_nmap_file(path: str | Path) -> ObservationBatch:
    """Read at most 8 MiB plus one byte from a local report, never its references."""
    file_path = _local_xml_path(path)
    try:
        with file_path.open("rb") as handle:
            content = handle.read(MAX_IMPORT_BYTES + 1)
    except (OSError, ValueError) as error:
        raise ObservationImportError("Could not read Nmap XML file: " + " ".join(str(error).split())) from None
    return parse_nmap_xml(content)


__all__ = ["parse_nmap_xml", "read_nmap_file"]
