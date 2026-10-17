"""Strict XML evidence for a completed, explicitly authorized Nmap plan.

This adapter never executes or resolves anything. Legacy local/public validators
and the offline importer retain their narrower behavior. Omitted down hosts are
represented as not-reported observations with aggregate accounting evidence.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, is_dataclass
import hashlib
import ipaddress
import json
import re
import unicodedata
from xml.etree.ElementTree import TreeBuilder, tostring
from xml.parsers import expat

from core.recon.nmap_adapter import _normalize_local_xml
from core.recon.nmap_import import _xml_root, parse_nmap_xml
from core.recon.observations import (
    MAX_EVIDENCE, MAX_IMPORT_BYTES, MAX_METADATA_BYTES, SCHEMA, VERSION,
    ObservationBatch, ObservationImportError, parse_observations_json,
)


MAX_NSE_BYTES = 65_536
_STATES = {"open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"}
_TECHNIQUES = {"tcp-connect": "connect", "tcp-syn": "syn", "tcp-ack": "ack", "tcp-window": "window",
               "tcp-fin": "fin", "tcp-null": "null", "tcp-xmas": "xmas", "tcp-maimon": "maimon"}
_CHILDREN = {
    "nmaprun": {"scaninfo", "verbose", "debugging", "taskbegin", "taskend", "taskprogress",
                "host", "hosthint", "runstats", "prescript", "postscript"},
    "host": {"status", "address", "hostnames", "ports", "times", "os", "trace", "distance",
             "uptime", "tcpsequence", "ipidsequence", "tcptssequence", "hostscript", "smurf"},
    "hosthint": {"status", "address", "hostnames"}, "hostnames": {"hostname"},
    "ports": {"port", "extraports"}, "port": {"state", "service", "script", "owner"},
    "service": {"cpe"}, "extraports": {"extrareasons"},
    "os": {"portused", "osmatch", "osfingerprint"}, "osmatch": {"osclass"}, "osclass": {"cpe"},
    "trace": {"hop"}, "hostscript": {"script"}, "prescript": {"script"}, "postscript": {"script"},
    "script": {"table", "elem"}, "table": {"table", "elem"}, "elem": set(),
    "runstats": {"finished", "hosts"},
}


def _error(message):
    raise ObservationImportError(message)


def _json(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _safe(value):
    """Keep useful literal text; shared viewers render it as plain text."""
    return "".join(character for character in value
                   if unicodedata.category(character) not in {"Cc", "Cf", "Cs"}
                   or character in "\n\t")


def _rich_root(content):
    # First use the existing security gate unchanged. Only validated normalized
    # UTF-8 is reparsed to retain bounded element text needed for CPE and NSE.
    _xml_root(content)
    builder = TreeBuilder()
    parser = expat.ParserCreate()
    text_bytes = 0
    stack = []

    def start(name, attributes):
        stack.append(name)
        builder.start(name, attributes)

    def end(name):
        builder.end(name)
        stack.pop()

    def characters(value):
        nonlocal text_bytes
        # Formatting between result elements is not evidence. Retain only the
        # text-bearing fields consumed below, keeping their independent bound.
        if not stack or stack[-1] not in {"cpe", "elem"}:
            return
        text_bytes += len(value.encode("utf-8"))
        if text_bytes > MAX_NSE_BYTES:
            _error("Nmap XML retained text exceeds the 64 KiB limit.")
        builder.data(_safe(value))

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = characters
    parser.Parse(content, True)
    return builder.close()


def _number(value, label, maximum=65535, minimum=0):
    if (type(value) is not str or re.fullmatch(r"0|[1-9][0-9]{0,9}", value) is None
            or not minimum <= int(value) <= maximum):
        _error("Invalid bounded Nmap " + label + ".")
    return int(value)


def _ports(text):
    if type(text) is not str or not text or len(text) > 65536:
        _error("Invalid bounded Nmap port list.")
    result = []
    for term in text.split(","):
        match = re.fullmatch(r"([1-9][0-9]{0,4})(?:-([1-9][0-9]{0,4}))?", term)
        if match is None:
            _error("Invalid Nmap port range notation.")
        first, last = int(match[1]), int(match[2] or match[1])
        if not 1 <= first <= last <= 65535 or len(result) + last - first + 1 > 65535:
            _error("Unbounded Nmap port range.")
        result.extend(range(first, last + 1))
    if result != sorted(set(result)):
        _error("Duplicate or noncanonical Nmap port list.")
    return tuple(result)


def _expected_scans(root, profile, expected_ports):
    discovery = getattr(profile, "discovery", "none")
    scans = root.findall("scaninfo")
    if discovery in {"only", "list"}:
        if scans:
            _error("Discovery-only report unexpectedly includes a port scan.")
        return {}
    technique = profile.technique
    protocols = {}
    if technique != "udp":
        if technique not in _TECHNIQUES:
            _error("Unsupported Nmap scan technique in captured profile.")
        protocols["tcp"] = _TECHNIQUES[technique]
    if technique == "udp" or getattr(profile, "udp_scan", False):
        protocols["udp"] = "udp"
    mode = getattr(profile, "port_mode", "explicit")
    supplied = dict(expected_ports)
    if mode == "top" and set(supplied) != set(protocols):
        _error("Top-port results require exact ports bound to the trusted services database.")
    expected = {}
    for protocol in protocols:
        if mode == "all":
            expected[protocol] = tuple(range(1, 65536))
        elif mode == "top":
            values = supplied[protocol]
            if (type(values) is not tuple or not 1 <= len(values) <= profile.top_ports
                    or values != tuple(sorted(set(values))) or any(type(p) is not int or not 1 <= p <= 65535 for p in values)):
                _error("Invalid trusted top-port identities.")
            expected[protocol] = values
        else:
            expected[protocol] = profile.ports if protocol == "tcp" else getattr(profile, "udp_ports", ())
        if not expected[protocol]:
            _error("The captured scan profile has no selected ports.")
    seen = set()
    for scan in scans:
        protocol = scan.get("protocol")
        if (protocol not in expected or protocol in seen or scan.get("type") != protocols[protocol]
                or _number(scan.get("numservices"), "scan port count") != len(expected[protocol])
                or _ports(scan.get("services")) != expected[protocol]):
            _error("The report scan technique, protocol or ports differ from the approved plan.")
        seen.add(protocol)
    if seen != set(expected):
        _error("The report is missing approved scan technique metadata.")
    return expected


def _host_address(host, targets):
    addresses = []
    for element in host.findall("address"):
        family = element.get("addrtype")
        if family == "mac":
            if re.fullmatch(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", element.get("addr", "")) is None:
                _error("Invalid Nmap MAC address metadata.")
            continue
        try:
            address = ipaddress.ip_address(element.get("addr", ""))
            if family != ("ipv4" if address.version == 4 else "ipv6") or "%" in str(address):
                raise ValueError
        except ValueError:
            _error("Invalid Nmap host address.")
        addresses.append(address.compressed)
    if len(addresses) != 1 or addresses[0] not in targets:
        _error("The report contains an unexpected or ambiguous target address.")
    return addresses[0]


def _port_outcomes(host, expected):
    containers = host.findall("ports")
    if len(containers) != 1:
        _error("The completed host is missing unambiguous port results.")
    seen = set()
    counts = {protocol: 0 for protocol in expected}
    for port in containers[0].findall("port"):
        protocol = port.get("protocol")
        number = _number(port.get("portid"), "port identity", minimum=1)
        states, services = port.findall("state"), port.findall("service")
        identity = (protocol, number)
        if (protocol not in expected or number not in expected[protocol] or identity in seen
                or len(states) != 1 or states[0].get("state") not in _STATES or len(services) > 1):
            _error("Unexpected, duplicate or incomplete Nmap port outcomes.")
        seen.add(identity)
        counts[protocol] += 1
    reported = len(seen)
    aggregate_states, reason_ids = set(), set()
    unknown_aggregate = 0
    for extra in containers[0].findall("extraports"):
        state = extra.get("state")
        count = _number(extra.get("count"), "aggregate port count", maximum=131070, minimum=1)
        if state not in _STATES - {"open"} or state in aggregate_states:
            _error("Invalid or duplicate aggregate Nmap port states.")
        aggregate_states.add(state)
        reported += count
        reasons = extra.findall("extrareasons")
        reason_count = 0
        for reason in reasons:
            amount = _number(reason.get("count"), "aggregate reason count", maximum=131070, minimum=1)
            reason_count += amount
            protocol = reason.get("proto")
            if protocol is not None and protocol not in expected:
                _error("Unexpected aggregate port protocol.")
            if reason.get("ports") is not None:
                if protocol is None and len(expected) != 1:
                    _error("Ambiguous aggregate port identities in mixed scan.")
                protocol = protocol or next(iter(expected))
                values = _ports(reason.get("ports"))
                if len(values) != amount or any((protocol, value) in seen | reason_ids
                        or value not in expected[protocol] for value in values):
                    _error("Unexpected or duplicate aggregate port identities.")
                reason_ids.update((protocol, value) for value in values)
            if protocol is not None:
                counts[protocol] += amount
            else:
                unknown_aggregate += amount
        if reasons and reason_count != count:
            _error("Incomplete aggregate Nmap port reason accounting.")
        if not reasons:
            unknown_aggregate += count
    if (reported != sum(map(len, expected.values()))
            or any(counts[protocol] > len(expected[protocol]) for protocol in expected)
            or sum(len(expected[p]) - counts[p] for p in expected) != unknown_aggregate):
        _error("Nmap did not account for every selected port.")


def _append(evidence, ref, kind, metadata):
    if len(_json(metadata).encode("utf-8")) > MAX_METADATA_BYTES:
        _error("Expanded Nmap evidence metadata exceeds the 4096 byte bound.")
    evidence.append({"ref": ref, "kind": kind, "metadata": metadata})
    if len(evidence) > MAX_EVIDENCE:
        _error("Expanded Nmap evidence exceeds the reference count bound.")


def _fields(node):
    return {key: _safe(value) for key, value in node.attrib.items()}


def _pack(evidence, ref, kind, key, items, **metadata):
    """Pack bounded lists without multiplying references per target or DNS name."""
    group, offset = [], 0
    for item in items:
        candidate = {**metadata, key: [*group, item], "offset": offset}
        if group and len(_json(candidate).encode()) > 3500:
            _append(evidence, ref + f"/{offset}", kind, {**metadata, key: group, "offset": offset})
            offset += len(group)
            group = []
        group.append(item)
    if group:
        _append(evidence, ref + f"/{offset}", kind, {**metadata, key: group, "offset": offset})


def _dns_evidence(scope, address, evidence, ref):
    groups = []
    for hostname, addresses in getattr(scope, "dns_observations", ()):
        if address not in addresses:
            continue
        shown = list(addresses) if len(addresses) <= 8 else [address]
        metadata = {"hostname": hostname, "addresses": shown,
                    "address_count": len(addresses), "addresses_omitted": len(addresses) - len(shown),
                    "addresses_sha256": hashlib.sha256(_json(addresses).encode()).hexdigest(),
                    "ownership_verified": False, "association": "preflight-observation"}
        groups.append(metadata)
    if len(groups) == 1:
        _append(evidence, ref + "/dns", "nmap-dns", {
            **groups[0], "observed_at": getattr(scope, "observed_at", ""), "authorization": False,
        })
    elif groups:
        _pack(evidence, ref + "/dns", "nmap-dns", "observations", groups,
              observed_at=getattr(scope, "observed_at", ""), authorization=False)


def _compact_port_chunks(values):
    """Retain every validated identity with compact, bounded numeric ranges."""
    values = sorted(values)
    terms = []
    first = last = values[0]
    for value in values[1:]:
        if value == last + 1:
            last = value
        else:
            terms.append((str(first) if first == last else f"{first}-{last}", last - first + 1))
            first = last = value
    terms.append((str(first) if first == last else f"{first}-{last}", last - first + 1))
    chunks, current, length, count = [], [], 0, 0
    for term, amount in terms:
        if current and length + len(term) + 1 > 2800:
            chunks.append((",".join(current), count))
            current, length, count = [], 0, 0
        current.append(term)
        length += len(term) + 1
        count += amount
    chunks.append((",".join(current), count))
    return chunks


def _complete_port_evidence(host, evidence, ref):
    """Shared results include all outcomes, beyond the legacy sample window.

    Aggregate results preserve exactly Nmap's counts/reasons. Unidentified
    aggregate ports are never expanded into invented per-port observations.
    """
    groups = {}
    for port in host.findall("ports/port"):
        key = (port.get("protocol"), port.find("state").get("state"))
        groups.setdefault(key, []).append(int(port.get("portid")))
    outcomes = []
    for (protocol, state), values in sorted(groups.items()):
        chunks = _compact_port_chunks(values)
        for index, (ports, count) in enumerate(chunks, 1):
            item = {"protocol": protocol, "state": state, "ports": ports, "count": count}
            if len(chunks) > 1:
                item.update({"part": index, "parts": len(chunks), "total_count": len(values)})
            outcomes.append(item)
    _pack(evidence, ref + "/outcomes", "nmap-port-outcomes", "outcomes", outcomes,
          complete=True, identity_basis="explicit-port-elements")
    aggregates = []
    for node in host.findall("ports/extraports"):
        reasons = []
        for reason in node.findall("extrareasons"):
            metadata = _fields(reason)
            metadata["count"] = int(reason.get("count"))
            reasons.append(metadata)
        aggregates.append({"state": node.get("state"), "count": int(node.get("count")), "reasons": reasons})
    _pack(evidence, ref + "/aggregates", "nmap-aggregate-outcomes", "outcomes", aggregates,
          complete=True, identity_basis="only-explicit-extrareasons-port-lists")


def _script_tree(node):
    value = {"type": node.tag, **_fields(node)}
    if node.text and node.text.strip():
        value["text"] = node.text
    if len(node):
        value["children"] = [_script_tree(child) for child in node]
    return value


def _script_evidence(script, evidence, ref):
    metadata = {"id": script.get("id"), "output": _safe(script.get("output", "")),
                "structured": [_script_tree(child) for child in script]}
    if len(_json(metadata).encode("utf-8")) <= MAX_METADATA_BYTES:
        _append(evidence, ref, "nmap-nse", metadata)
        return
    # Preserve complete inert output in bounded numbered JSON chunks, rather
    # than silently dropping text or increasing the shared evidence limits.
    encoded = _json(metadata)
    chunks, current, current_bytes = [], "", 0
    for character in encoded:
        encoded_bytes = len(_json(character).encode("utf-8")) - 2
        if current_bytes + encoded_bytes > 3200:
            chunks.append(current)
            current = ""
            current_bytes = 0
        current += character
        current_bytes += encoded_bytes
    if current:
        chunks.append(current)
    for index, chunk in enumerate(chunks, 1):
        _append(evidence, ref + f"/chunk-{index}", "nmap-nse", {
            "id": script.get("id"), "encoding": "json-chunks", "chunk": index,
            "chunks": len(chunks), "text": chunk,
        })


def _feature_evidence(host, evidence, ref, profile):
    # PTR answers describe the observed numeric host; they are not target
    # identities and need not satisfy the Target Manager's hostname grammar.
    names = [_fields(node) for node in host.findall("hostnames/hostname")]
    if names:
        _pack(evidence, ref + "/hostnames", "nmap-hostnames", "names", names,
              authorization=False, ownership_verified=False, association="xml-hostname-observation")
    os_nodes = host.findall("os")
    traces = host.findall("trace")
    if len(os_nodes) > 1 or len(traces) > 1:
        _error("Duplicate Nmap OS or traceroute result containers.")
    if os_nodes:
        if not getattr(profile, "os_detection", False):
            _error("Unrequested OS detection output.")
        matches = []
        for match in os_nodes[0].findall("osmatch"):
            value = {**_fields(match), "accuracy": _number(match.get("accuracy"), "OS confidence", maximum=100),
                     "classes": []}
            for item in match.findall("osclass"):
                class_value = _fields(item)
                if item.get("accuracy") is not None:
                    class_value["accuracy"] = _number(item.get("accuracy"), "OS class confidence", maximum=100)
                class_value["cpe"] = [child.text or "" for child in item.findall("cpe")]
                value["classes"].append(class_value)
            matches.append(value)
        # One reference per guess preserves bounded but complete matches.
        if not matches:
            _append(evidence, ref + "/os", "nmap-os", {"classification": "guess", "matches": []})
        for index, match in enumerate(matches):
            _append(evidence, ref + f"/os-{index}", "nmap-os", {"classification": "guess", "matches": [match]})
    if traces:
        if not getattr(profile, "traceroute", False):
            _error("Unrequested traceroute output.")
        hops = []
        for hop in traces[0].findall("hop"):
            value = _fields(hop)
            value["ttl"] = _number(hop.get("ttl"), "traceroute TTL", maximum=255, minimum=1)
            if hop.get("ipaddr") is not None:
                try:
                    value["ipaddr"] = ipaddress.ip_address(hop.get("ipaddr")).compressed
                except ValueError:
                    _error("Invalid traceroute address.")
            if hop.get("rtt") is not None and re.fullmatch(r"[0-9]{1,8}(?:\.[0-9]{1,6})?|--", hop.get("rtt")) is None:
                _error("Invalid traceroute timing.")
            hops.append(value)
        for offset in range(0, max(1, len(hops)), 8):
            _append(evidence, ref + f"/trace-{offset}", "nmap-trace", {
                **_fields(traces[0]), "hops": hops[offset:offset + 8], "total_hops": len(hops), "offset": offset,
            })
    timing = host.findall("times")
    if len(timing) > 1:
        _error("Duplicate Nmap host timing metadata.")
    if timing:
        _append(evidence, ref + "/timing", "nmap-timing", _fields(timing[0]))


def _redacted_arguments(arguments):
    redacted, hide_next = [], False
    for argument in arguments:
        if type(argument) is not str or len(argument) > 65536:
            _error("Invalid captured Nmap arguments.")
        if hide_next:
            redacted.append("[redacted]")
            hide_next = False
        elif argument == "--script-args":
            redacted.append(argument)
            hide_next = True
        elif argument.startswith("--script-args="):
            redacted.append("--script-args=[redacted]")
        else:
            redacted.append(_safe(argument))
    return redacted


def _script_selection(profile, scripts):
    """Persist approved installed identities even when their rules emit nothing."""
    explicit = tuple(getattr(profile, "script_ids", ()))
    selection, seen = [], set()
    for script in (*scripts, *explicit):
        identifier = script if isinstance(script, str) else getattr(script, "script_id", "")
        if (type(identifier) is not str or re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,99}", identifier) is None
                or ".." in identifier):
            _error("Invalid approved NSE script selection identity.")
        if identifier in seen:
            continue
        item = {"id": identifier, "implicit_version": bool(profile.version_detection and identifier not in explicit)}
        if not isinstance(script, str):
            categories, digest = getattr(script, "categories", ()), getattr(script, "sha256", "")
            if (type(categories) is not tuple or any(type(value) is not str
                    or re.fullmatch(r"[a-z][a-z-]{0,31}", value) is None for value in categories)
                    or type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
                _error("Invalid approved NSE script categories or digest.")
            item.update({"categories": list(categories), "sha256": digest})
        selection.append(item)
        seen.add(identifier)
    return selection


def parse_authorized_nmap_output(content: bytes, *, scope, profile, executable_version: str,
                                 run_id: str, arguments: tuple = (), scripts: tuple = (),
                                 executable_sha256: str = "", expected_ports: tuple = ()) -> ObservationBatch:
    """Validate all outcomes against one inert captured plan before import.

    Successful process exit and cancellation/output-limit checks remain the
    runtime's responsibility. Neither this parser nor its scope metadata grants
    authorization. Top-port identities must come from the approved distribution.
    """
    if type(content) is not bytes or not content or len(content) > MAX_IMPORT_BYTES or b"\0" in content:
        _error("Complete bounded UTF-8 Nmap XML process output is required.")
    if (type(run_id) is not str or re.fullmatch(r"nmap:authorized:[A-Za-z0-9][A-Za-z0-9._:-]{0,100}", run_id) is None
            or type(executable_version) is not str or not executable_version or len(executable_version) > 64):
        _error("A bounded authorized run identity and verified scanner version are required.")
    if executable_sha256 and re.fullmatch(r"[0-9a-f]{64}", executable_sha256) is None:
        _error("Invalid verified executable digest.")
    try:
        targets = scope.targets
        if (type(targets) is not tuple or not 1 <= len(targets) <= 256 or len(set(targets)) != len(targets)
                or any(ipaddress.ip_address(value).compressed != value or "%" in value for value in targets)):
            raise ValueError
    except (AttributeError, TypeError, ValueError):
        _error("The captured scope must contain bounded canonical concrete IP targets.")
    normalized, declaration_removed = _normalize_local_xml(content)
    root = _rich_root(normalized)
    for node in root.iter():
        if any(child.tag not in _CHILDREN.get(node.tag, set()) for child in node):
            _error("Unexpected Nmap result structure.")
    if root.get("scanner") != "nmap" or root.get("version") != executable_version:
        _error("The report scanner identity/version differs from the verified executable.")
    summaries, finished = root.findall("runstats/hosts"), root.findall("runstats/finished")
    if len(root.findall("runstats")) != 1 or len(summaries) != 1 or len(finished) != 1 or finished[0].get("exit") != "success":
        _error("Nmap did not report a complete successful authorized scan.")
    summary = {key: _number(summaries[0].get(key), "host statistics", maximum=256) for key in ("up", "down", "total")}
    discovery = getattr(profile, "discovery", "none")
    if summary["total"] != len(targets) or (discovery != "list" and summary["up"] + summary["down"] != len(targets)):
        _error("Nmap host statistics do not account for the exact approved scope.")
    if discovery == "list" and (summary["up"] != 0 or summary["down"] != len(targets)):
        _error("List-only statistics must not claim discovered live hosts.")
    expected = _expected_scans(root, profile, expected_ports)
    hosts, explicit, states = root.findall("host"), {}, {}
    for host in hosts:
        address = _host_address(host, targets)
        status = host.findall("status")
        if (address in explicit or len(status) != 1 or host.get("timedout") not in {None, "false"}
                or status[0].get("state") not in ({"unknown"} if discovery == "list" else {"up", "down"})):
            _error("Duplicate, incomplete or timed-out Nmap host results.")
        explicit[address], states[address] = host, status[0].get("state")
        if discovery in {"only", "list"} or states[address] != "up":
            if host.findall("ports"):
                _error("Unexpected port scan output for a discovery/down host.")
        else:
            _port_outcomes(host, expected)
        for service in host.findall("ports/port/service"):
            if service.get("method") not in {None, "table", "probed"}:
                _error("Invalid Nmap service detection method.")
            if service.get("conf") is not None:
                _number(service.get("conf"), "service confidence", maximum=10)
            if (service.get("method") == "probed" and not getattr(profile, "version_detection", False)
                    and not getattr(profile, "script_ids", ()) and not scripts):
                _error("Unrequested service-version detection output.")
    for hint in root.findall("hosthint"):
        _host_address(hint, targets)
    omitted = set(targets) - set(explicit)
    if (sum(state == "up" for state in states.values()) != summary["up"]
            or (discovery == "list" and omitted)
            or (discovery != "list" and sum(state == "down" for state in states.values()) + len(omitted) != summary["down"])):
        _error("Nmap explicit host outcomes disagree with the complete scope statistics.")
    script_selection = _script_selection(profile, scripts)
    selected_scripts = {item["id"] for item in script_selection}
    nse_bytes = 0
    for script in root.iter("script"):
        if script.get("id") not in selected_scripts:
            _error("Nmap returned an unrequested NSE script.")
        nse_bytes += len(_json({"attributes": _fields(script), "structured": [_script_tree(child) for child in script]}).encode())
        if nse_bytes > MAX_NSE_BYTES:
            _error("Nmap NSE output exceeds the 64 KiB bound.")
    # Preserve the original importer's services and confidence rules. Its
    # offline hostname normalization is intentionally stricter than PTR text.
    # Remove hostname assertions only from this intermediary feed; retain the
    # original tree for inert DNS evidence and the raw bytes for provenance.
    intermediary = deepcopy(root)
    for host in intermediary.findall("host"):
        for names in host.findall("hostnames"):
            host.remove(names)
    batch = parse_nmap_xml(tostring(intermediary, encoding="utf-8"))
    profile_data = asdict(profile) if is_dataclass(profile) else vars(profile).copy()
    configuration_digest = hashlib.sha256(_json(profile_data).encode()).hexdigest()
    profile_data.pop("script_arguments", None)
    profile_data.pop("description", None)
    profile_data.pop("network_impact", None)
    for field in ("ports", "udp_ports"):
        if field in profile_data:
            values = profile_data[field]
            profile_data[field] = {"count": len(values), "sha256": hashlib.sha256(_json(values).encode()).hexdigest()}
    provenance = {"file_sha256": hashlib.sha256(content).hexdigest(), "file_size": len(content),
                  "doctype_normalized": declaration_removed, "execution_mode": "authorized-scope",
                  "scanner_version": executable_version, "executable_sha256": executable_sha256,
                  "configuration_sha256": configuration_digest,
                  "arguments_sha256": hashlib.sha256(_json(arguments).encode()).hexdigest(),
                  "script_selection_sha256": hashlib.sha256(_json(script_selection).encode()).hexdigest(),
                  "script_selection_count": len(script_selection),
                  "scan_statistics": summary, "timing": _fields(finished[0])}
    common = []
    _append(common, run_id, "nmap-run", provenance)
    _append(common, run_id + "/configuration", "nmap-configuration", profile_data)
    _pack(common, run_id + "/script-selection", "nmap-script-selection", "scripts", script_selection,
          basis="approved-installed-selection", output_required=False)
    # Concrete targets are already retained in full below. Repeating hundreds
    # of target argv tokens would consume evidence references without adding
    # provenance; the full original argv remains bound by its SHA-256 above.
    prefix = arguments[:-len(targets)] if tuple(arguments[-len(targets):]) == targets else arguments
    redacted = _redacted_arguments(prefix)
    _pack(common, run_id + "/arguments", "nmap-arguments", "arguments", redacted,
          target_tokens_in_scope=len(arguments) - len(prefix),
          target_scope_sha256=hashlib.sha256(_json(targets).encode()).hexdigest())
    for offset in range(0, len(targets), 32):
        _append(common, run_id + f"/scope-{offset}", "nmap-scope", {
            "targets": list(targets[offset:offset + 32]), "target_count": len(targets),
            "offset": offset, "authorization": "explicit-per-run", "dns_is_authorization": False,
        })
    _pack(common, run_id + "/inputs", "nmap-scope-inputs", "inputs", getattr(scope, "inputs", ()),
          observed_at=getattr(scope, "observed_at", ""),
          dns_observations_sha256=hashlib.sha256(_json(getattr(scope, "dns_observations", ())).encode()).hexdigest())
    for index, script in enumerate([*root.findall("prescript/script"), *root.findall("postscript/script")]):
        _script_evidence(script, common, run_id + f"/script-{index}")
    records = []
    host_indexes = {address: index for index, address in enumerate(explicit, 1)}
    for observation in batch.observations:
        if observation.entity_type == "hostname":
            continue  # Reverse DNS names are evidence, never newly scoped assets.
        record = observation.to_dict()
        record.pop("entity_key")
        record.pop("run_id")
        address = observation.value
        host = explicit[address]
        evidence = [*common]
        for old in record["evidence"]:
            if old["kind"] == "nmap-run":
                continue
            old["ref"] = old["ref"].replace(batch.run_id, run_id, 1)
            evidence.append(old)
        ref = run_id + f"#host-{host_indexes[address]}"
        _dns_evidence(scope, address, evidence, ref)
        _feature_evidence(host, evidence, ref, profile)
        for index, script in enumerate(host.findall("hostscript/script")):
            _script_evidence(script, evidence, ref + f"/script-{index}")
        if observation.entity_type == "ip":
            _complete_port_evidence(host, evidence, ref)
            for node in host.findall("ports/port"):
                for index, script in enumerate(node.findall("script")):
                    _script_evidence(script, evidence, ref + f"/{node.get('protocol')}-{node.get('portid')}/script-{index}")
        if observation.entity_type == "service":
            node = next(node for node in host.findall("ports/port")
                        if node.get("protocol") == observation.transport and int(node.get("portid")) == observation.port)
            service = node.find("service")
            if service is not None:
                if (service.get("method") == "probed" and not getattr(profile, "version_detection", False)
                        and not selected_scripts):
                    _error("Unrequested service-version detection output.")
                service_metadata = next(item for item in evidence if item["kind"] == "nmap-service")["metadata"]
                service_metadata.update(_fields(service))
                if service.get("method") == "probed":
                    service_metadata["detection_source"] = ("version-probe-or-nse" if profile.version_detection
                                                            else "approved-nse")
                cpes = [item.text or "" for item in service.findall("cpe")]
                if cpes:
                    next(item for item in evidence if item["kind"] == "nmap-service")["metadata"]["cpe"] = cpes
            for index, script in enumerate(node.findall("script")):
                _script_evidence(script, evidence, ref + f"/port-{observation.port}/script-{index}")
        record["evidence"] = evidence
        records.append(record)
    for address in sorted(omitted):
        evidence = [*common]
        _dns_evidence(scope, address, evidence, run_id + "/not-reported/" + address)
        _append(evidence, run_id + "/not-reported/" + address, "nmap-host", {
            "state": "not-reported", "address": address, "basis": "complete-aggregate-accounting",
            "aggregate_down_count": summary["down"], "individual_state_confirmed": False,
        })
        records.append({"id": "not-reported-" + address, "source": "nmap", "type": "ip", "value": address, "evidence": evidence})
    return parse_observations_json(_json({"schema": SCHEMA, "version": VERSION, "run_id": run_id, "observations": records}))


__all__ = ["parse_authorized_nmap_output"]
