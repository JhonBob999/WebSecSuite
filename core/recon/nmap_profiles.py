"""Immutable offline Nmap configurations and inert command previews.

These values are configuration data, never execution requests or scope grants.
This module deliberately has no runtime, process, DNS, or adapter integration.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, replace
import re
import unicodedata
from uuid import uuid4


_MAX_PORTS = 1024
_MAX_PORT_TEXT = 8192
_BUILTIN_IDS = frozenset({
    "quick-network-discovery", "web-services", "standard-tcp", "deep-service-review",
})
_PROFILE_ID = re.compile(r"[a-z][a-z0-9-]{0,63}")
_PORT_TERM = re.compile(r"([0-9]{1,5})(?:-([0-9]{1,5}))?")
TECHNIQUE_FLAGS = {
    "tcp-connect": "-sT", "tcp-syn": "-sS", "tcp-ack": "-sA", "tcp-window": "-sW",
    "tcp-fin": "-sF", "tcp-null": "-sN", "tcp-xmas": "-sX", "tcp-maimon": "-sM", "udp": "-sU",
}
DISCOVERY_PROBE_FLAGS = {
    "syn": "-PS", "ack": "-PA", "udp": "-PU", "icmp-echo": "-PE",
    "icmp-timestamp": "-PP", "icmp-mask": "-PM",
}
LEGACY_PROFILE_FIELDS = frozenset({
    "profile_id", "name", "description", "is_builtin", "ports", "technique", "max_rate",
    "max_retries", "host_timeout_seconds", "execution_timeout_seconds", "version_detection", "network_impact",
})
_SCRIPT_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,99}")
_SCRIPT_ARGUMENT = re.compile(r"[a-zA-Z][a-zA-Z0-9_.-]{0,99}")
_SCRIPT_VALUE = re.compile(r"[a-zA-Z0-9 _.:/@%+?&=~-]{1,512}")

PREVIEW_NOTICE = (
    "Configuration-only preview; this is not authorization to execute a scan. "
    "Profiles do not grant target or IP scope. --max-rate limits the port scan; "
    "it does not reliably cap service-version detection, NSE or discovery probes. "
    "Capability checks and separate per-run scope approval are required before execution."
)


class ProfileValidationError(ValueError):
    """An offline profile contains unsupported, malformed, or unbounded data."""


def _canonical_ports(ports) -> tuple[int, ...]:
    if type(ports) is not tuple or not ports:
        raise ProfileValidationError("Ports must be a nonempty tuple of integer TCP ports.")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ProfileValidationError("TCP ports must be integers from 1 to 65535.")
    result = tuple(sorted(set(ports)))
    if len(result) > _MAX_PORTS:
        raise ProfileValidationError("A profile may contain at most 1024 unique TCP ports.")
    return result


def parse_ports(text: str) -> tuple[int, ...]:
    """Parse bounded ASCII port lists/ranges without accepting CLI syntax."""
    if (type(text) is not str or not text or len(text) > _MAX_PORT_TEXT
            or any(character not in "0123456789,- " for character in text)):
        raise ProfileValidationError("Enter at most 8192 characters of numeric ports and ranges.")
    ports: set[int] = set()
    for term in text.split(","):
        match = _PORT_TERM.fullmatch(term.strip(" "))
        if match is None:
            raise ProfileValidationError("Use comma-separated TCP ports or ascending numeric ranges.")
        first = int(match[1])
        last = int(match[2]) if match[2] is not None else first
        if not 1 <= first <= last <= 65535:
            raise ProfileValidationError("TCP ports must be ascending values from 1 to 65535.")
        # Validate the range length before allocating or expanding its values.
        if last - first + 1 > _MAX_PORTS:
            raise ProfileValidationError("A profile may contain at most 1024 unique TCP ports.")
        ports.update(range(first, last + 1))
        if len(ports) > _MAX_PORTS:
            raise ProfileValidationError("A profile may contain at most 1024 unique TCP ports.")
    return tuple(sorted(ports))


def format_ports(ports) -> str:
    """Return canonical ports as deterministic, compact numeric ranges."""
    values = _canonical_ports(ports)
    result = []
    first = last = values[0]
    for port in values[1:]:
        if port == last + 1:
            last = port
        else:
            result.append(str(first) if first == last else f"{first}-{last}")
            first = last = port
    result.append(str(first) if first == last else f"{first}-{last}")
    return ",".join(result)


def _controls(text: str, *, newline: bool = False) -> bool:
    return any(unicodedata.category(character) in {"Cc", "Cf", "Cs"}
               and not (newline and character == "\n") for character in text)


def _bounded_text(value, label: str, *, newline: bool = False) -> str:
    if type(value) is not str or len(value) > 2000 or _controls(value, newline=newline):
        raise ProfileValidationError(f"{label} must be bounded text without control characters.")
    return value


def _name(value) -> str:
    if type(value) is not str or _controls(value) or not 1 <= len(value.strip()) <= 80:
        raise ProfileValidationError("Profile name must contain 1 to 80 characters without controls.")
    return value.strip()


@dataclass(frozen=True, slots=True)
class NmapScanProfile:
    profile_id: str
    name: str
    description: str
    is_builtin: bool
    ports: tuple[int, ...]
    technique: str
    max_rate: int
    max_retries: int
    host_timeout_seconds: int
    execution_timeout_seconds: int
    version_detection: bool
    network_impact: str
    udp_ports: tuple[int, ...] = ()
    udp_scan: bool = False
    port_mode: str = "explicit"
    top_ports: int = 100
    discovery: str = "none"
    discovery_probes: tuple[str, ...] = ()
    dns_mode: str = "never"
    timing_template: int = 3
    min_rate: int = 0
    min_parallelism: int = 0
    max_parallelism: int = 0
    version_intensity: int = 7
    version_all: bool = False
    version_trace: bool = False
    os_detection: bool = False
    os_guess: bool = False
    os_limit: bool = False
    traceroute: bool = False
    script_ids: tuple[str, ...] = ()
    script_arguments: tuple[tuple[str, str], ...] = ()
    script_timeout_seconds: int = 30
    version_timeout_seconds: int = 0

    def __post_init__(self):
        if type(self.profile_id) is not str or _PROFILE_ID.fullmatch(self.profile_id) is None:
            raise ProfileValidationError("Profile ID must be a bounded lowercase identifier.")
        if type(self.is_builtin) is not bool or self.is_builtin != (self.profile_id in _BUILTIN_IDS):
            raise ProfileValidationError("Built-in IDs are reserved; custom profiles need their own ID.")
        object.__setattr__(self, "name", _name(self.name))
        _bounded_text(self.description, "Description", newline=True)
        _bounded_text(self.network_impact, "Network impact")
        object.__setattr__(self, "ports", _canonical_ports(self.ports))
        if type(self.technique) is not str or self.technique not in TECHNIQUE_FLAGS:
            raise ProfileValidationError("Select a supported typed scan technique.")
        for label, value, low, high in (
            ("Maximum rate", self.max_rate, 1, 100),
            ("Maximum retries", self.max_retries, 0, 3),
            ("Host timeout", self.host_timeout_seconds, 5, 600),
            ("Execution timeout", self.execution_timeout_seconds, 10, 900),
        ):
            if type(value) is not int or not low <= value <= high:
                raise ProfileValidationError(f"{label} must be an integer from {low} to {high}.")
        if self.execution_timeout_seconds <= self.host_timeout_seconds:
            raise ProfileValidationError("Execution timeout must be greater than the host timeout.")
        if type(self.version_detection) is not bool:
            raise ProfileValidationError("Version detection must be an explicit boolean.")
        for name in ("udp_scan", "version_all", "version_trace", "os_detection", "os_guess", "os_limit", "traceroute"):
            if type(getattr(self, name)) is not bool:
                raise ProfileValidationError(f"{name.replace('_', ' ').capitalize()} must be an explicit boolean.")
        if type(self.udp_ports) is not tuple:
            raise ProfileValidationError("UDP ports must be a tuple of integer ports.")
        if self.udp_ports:
            object.__setattr__(self, "udp_ports", _canonical_ports(self.udp_ports))
        for name, choices in (
            ("port_mode", {"explicit", "all", "top"}),
            ("discovery", {"none", "default", "only", "list"}),
            ("dns_mode", {"never", "reverse"}),
        ):
            if type(getattr(self, name)) is not str or getattr(self, name) not in choices:
                raise ProfileValidationError(f"Select a supported {name.replace('_', ' ')}.")
        for label, value, low, high in (
            ("Top ports", self.top_ports, 1, 65535), ("Timing template", self.timing_template, 0, 5),
            ("Minimum rate", self.min_rate, 0, 100), ("Minimum parallelism", self.min_parallelism, 0, 64),
            ("Maximum parallelism", self.max_parallelism, 0, 64), ("Version intensity", self.version_intensity, 0, 9),
            ("Script timeout", self.script_timeout_seconds, 1, 600),
            ("Version execution budget", self.version_timeout_seconds, 0, 900),
        ):
            if type(value) is not int or not low <= value <= high:
                raise ProfileValidationError(f"{label} must be an integer from {low} to {high}.")
        if self.min_rate > self.max_rate:
            raise ProfileValidationError("Minimum rate cannot exceed maximum rate.")
        if self.max_parallelism and self.min_parallelism > self.max_parallelism:
            raise ProfileValidationError("Minimum parallelism cannot exceed maximum parallelism.")
        if type(self.discovery_probes) is not tuple or len(self.discovery_probes) > len(DISCOVERY_PROBE_FLAGS):
            raise ProfileValidationError("Discovery probes must be a bounded tuple of supported choices.")
        if any(type(probe) is not str or probe not in DISCOVERY_PROBE_FLAGS for probe in self.discovery_probes):
            raise ProfileValidationError("Unknown discovery probe choice.")
        if len(set(self.discovery_probes)) != len(self.discovery_probes):
            raise ProfileValidationError("Discovery probes cannot contain duplicates.")
        if self.discovery_probes and self.discovery not in {"default", "only"}:
            raise ProfileValidationError("Discovery probes require enabled host discovery.")
        if (self.version_all or self.version_trace or self.version_intensity != 7 or self.version_timeout_seconds) and not self.version_detection:
            raise ProfileValidationError("Version options require service version detection.")
        if self.version_all and self.version_intensity != 7:
            raise ProfileValidationError("All version probes conflicts with an explicit version intensity.")
        if (self.os_guess or self.os_limit) and not self.os_detection:
            raise ProfileValidationError("OS guess and limit options require OS detection.")
        if type(self.script_ids) is not tuple or len(self.script_ids) > 32:
            raise ProfileValidationError("Select at most 32 named installed NSE scripts.")
        if any(type(value) is not str or _SCRIPT_ID.fullmatch(value) is None or ".." in value
               or value.endswith(".nse") for value in self.script_ids):
            raise ProfileValidationError("NSE scripts must be simple installed script IDs without paths or expressions.")
        if len(set(self.script_ids)) != len(self.script_ids):
            raise ProfileValidationError("NSE scripts cannot contain duplicate IDs.")
        if type(self.script_arguments) is not tuple or len(self.script_arguments) > 32:
            raise ProfileValidationError("Use at most 32 structured NSE argument pairs.")
        argument_names = set()
        for argument in self.script_arguments:
            if (type(argument) is not tuple or len(argument) != 2
                    or type(argument[0]) is not str or _SCRIPT_ARGUMENT.fullmatch(argument[0]) is None
                    or type(argument[1]) is not str or _SCRIPT_VALUE.fullmatch(argument[1]) is None
                    or argument[1].startswith("-") or argument[0] in argument_names):
                raise ProfileValidationError("NSE arguments require unique simple names and bounded scalar values; nested syntax and option injection are unsupported.")
            argument_names.add(argument[0])
        if self.script_arguments and not self.script_ids:
            raise ProfileValidationError("NSE arguments require explicitly selected scripts.")
        if self.discovery in {"only", "list"} and (
                self.technique != "tcp-connect" or self.udp_scan or self.version_detection
                or self.os_detection or self.traceroute or self.script_ids):
            raise ProfileValidationError("Host-only and list-only modes cannot include port scan, version, OS, traceroute or NSE options.")
        if (self.udp_scan or self.technique == "udp") and self.port_mode == "explicit" and not self.udp_ports:
            raise ProfileValidationError("An explicit UDP scan requires at least one UDP port.")


def _profile(value) -> NmapScanProfile:
    if type(value) is not NmapScanProfile:
        raise ProfileValidationError("A validated offline Nmap profile is required.")
    # Recheck all fields even if frozen dataclass protection was bypassed by
    # accidental in-process object.__setattr__ use. This creates no capability.
    return replace(value)


_FIELDS = frozenset(field.name for field in fields(NmapScanProfile))


def profile_from_dict(data: dict) -> NmapScanProfile:
    """Accept the complete data schema only, never execution or target fields."""
    if type(data) is not dict or frozenset(data) not in {_FIELDS, LEGACY_PROFILE_FIELDS}:
        raise ProfileValidationError("A profile must contain exactly the recognized configuration fields.")
    values = {**data, "ports": parse_ports(data["ports"])}
    if "udp_ports" in values:
        values["udp_ports"] = () if values["udp_ports"] == "" else parse_ports(values["udp_ports"])
        for name in ("discovery_probes", "script_ids", "script_arguments"):
            value = values[name]
            if type(value) is not list:
                raise ProfileValidationError(f"Serialized {name} must be a JSON list.")
            if name == "script_arguments":
                if any(type(pair) is not list for pair in value):
                    raise ProfileValidationError("Serialized script arguments must be lists of pairs.")
                values[name] = tuple(tuple(pair) for pair in value)
            else:
                values[name] = tuple(value)
    return NmapScanProfile(**values)


def profile_to_dict(profile: NmapScanProfile) -> dict:
    profile = _profile(profile)
    result = {}
    for item in fields(NmapScanProfile):
        value = getattr(profile, item.name)
        if item.name in {"ports", "udp_ports"}:
            value = format_ports(value) if value else ""
        elif item.name == "script_arguments":
            value = [list(pair) for pair in value]
        elif type(value) is tuple:
            value = list(value)
        result[item.name] = value
    return result


def duplicate_profile(profile: NmapScanProfile, name=None) -> NmapScanProfile:
    profile = _profile(profile)
    return replace(profile, profile_id="custom-" + uuid4().hex, is_builtin=False,
                   name=profile.name[:75] + " copy" if name is None else name,
                   description="Custom Nmap TCP scan profile." if profile.is_builtin else profile.description)


def rename_profile(profile: NmapScanProfile, name: str) -> NmapScanProfile:
    profile = _profile(profile)
    if profile.is_builtin:
        raise ProfileValidationError("Duplicate a built-in profile before renaming it.")
    return replace(profile, name=name)


def format_network_impact(profile: NmapScanProfile) -> str:
    """Describe validated settings without trusting saved impact prose or mutating data."""
    profile = _profile(profile)
    count = len(profile.ports)
    version = (
        "service version detection enabled (-sV); additional service probes; "
        "--max-rate does not reliably cap service-version probes."
        if profile.version_detection else
        "service version detection disabled; no service-version probes."
    )
    legacy = (
        f"{count} TCP {'port' if count == 1 else 'ports'}; {version} "
        f"--max-rate {profile.max_rate} limits the TCP port scan to {profile.max_rate} probes/s. "
        f"--max-retries {profile.max_retries} for port probes. "
        f"Host timeout: {profile.host_timeout_seconds} s. "
        f"Overall timeout: {profile.execution_timeout_seconds} s."
    )
    details = []
    if profile.discovery in {"only", "list"}:
        return (
            f"{'Host discovery probes' if profile.discovery == 'only' else 'List-only enumeration; no active host probes'}; "
            f"DNS: {profile.dns_mode}. Overall timeout: {profile.execution_timeout_seconds} s. "
            "Configuration does not grant target authorization."
        )
    if profile.technique != "tcp-connect":
        details.append(f"Scan technique: {profile.technique}; raw-packet techniques require capability approval.")
    if profile.port_mode != "explicit":
        legacy = legacy.replace(f"{count} TCP {'port' if count == 1 else 'ports'};", "Selected ports per protocol: " + (
            "all 65535;" if profile.port_mode == "all" else f"top {profile.top_ports};"))
    if profile.technique == "udp":
        legacy = legacy.replace(f"{count} TCP {'port' if count == 1 else 'ports'};", f"{len(profile.udp_ports)} UDP ports;")
        legacy = legacy.replace("limits the TCP port scan", "limits the UDP port scan")
    elif profile.udp_scan:
        selection = (f"{len(profile.udp_ports)} explicit ports" if profile.port_mode == "explicit" else
                     "all 65535 ports" if profile.port_mode == "all" else f"top {profile.top_ports} available ports")
        details.append(f"Additional UDP scan: {selection}.")
    if profile.os_detection:
        details.append("OS detection sends additional probes; results are guesses with confidence, not confirmed facts.")
    if profile.traceroute:
        details.append("Traceroute sends additional path probes.")
    if profile.script_ids:
        details.append(f"{len(profile.script_ids)} explicitly selected NSE scripts; installed-source and risk checks apply. --max-rate does not reliably cap NSE probes.")
    if profile.discovery != "none":
        details.append("Discovery probes are not reliably capped by --max-rate.")
    if profile.version_detection and profile.version_timeout_seconds:
        details.append(f"Version execution budget: {profile.version_timeout_seconds} s for the entire process; no independent per-service timeout.")
    return " ".join((legacy, *details))


def configuration_arguments(profile: NmapScanProfile) -> tuple[str, ...]:
    """Build canonical typed options, never executable text or a target grant.

    Version execution budget is enforced by the runtime as a total process
    bound. Nmap has no independent ``--version-timeout`` CLI option.
    """
    profile = _profile(profile)
    arguments = []
    scanning = profile.discovery not in {"only", "list"}
    if scanning:
        arguments.append(TECHNIQUE_FLAGS[profile.technique])
        if profile.udp_scan and profile.technique != "udp":
            arguments.append("-sU")
    elif profile.discovery == "only":
        arguments.append("-sn")
    else:
        arguments.append("-sL")
    if profile.discovery == "none":
        arguments.append("-Pn")
    arguments.append("-n" if profile.dns_mode == "never" else "-R")
    arguments.extend(DISCOVERY_PROBE_FLAGS[probe] for probe in profile.discovery_probes)
    if scanning:
        if profile.port_mode == "top":
            arguments.extend(("--top-ports", str(profile.top_ports)))
        else:
            if profile.port_mode == "all":
                ports = "1-65535"
            elif profile.technique == "udp":
                ports = format_ports(profile.udp_ports)
            elif profile.udp_scan:
                ports = f"T:{format_ports(profile.ports)},U:{format_ports(profile.udp_ports)}"
            else:
                ports = format_ports(profile.ports)
            arguments.extend(("-p", ports))
    arguments.extend(("--max-retries", str(profile.max_retries), "--max-rate", str(profile.max_rate),
                      "--host-timeout", f"{profile.host_timeout_seconds}s"))
    if profile.timing_template != 3:
        arguments.append(f"-T{profile.timing_template}")
    for option, value in (("--min-rate", profile.min_rate), ("--min-parallelism", profile.min_parallelism),
                          ("--max-parallelism", profile.max_parallelism)):
        if value:
            arguments.extend((option, str(value)))
    if profile.version_detection:
        arguments.append("-sV")
        if profile.version_all:
            arguments.append("--version-all")
        elif profile.version_intensity != 7:
            arguments.extend(("--version-intensity", str(profile.version_intensity)))
        if profile.version_trace:
            arguments.append("--version-trace")
    if profile.os_detection:
        arguments.append("-O")
        if profile.os_guess:
            arguments.append("--osscan-guess")
        if profile.os_limit:
            arguments.append("--osscan-limit")
    if profile.traceroute:
        arguments.append("--traceroute")
    if profile.script_ids:
        arguments.extend(("--script", ",".join(profile.script_ids), "--script-timeout", f"{profile.script_timeout_seconds}s"))
        if profile.script_arguments:
            arguments.extend(("--script-args", ",".join(f"{key}={value}" for key, value in profile.script_arguments)))
    return (*arguments, "--no-stylesheet", "-oX", "-")


def preview_arguments(profile: NmapScanProfile) -> tuple[str, ...]:
    """Return inert display tokens with a placeholder that grants no IP scope."""
    return (*configuration_arguments(profile), "<approved-ip>")


BUILTIN_PROFILES = (
    NmapScanProfile(
        "quick-network-discovery", "Quick Network Discovery", "Review four common web service ports.",
        True, (80, 443, 8080, 8443), "tcp-connect", 10, 1, 30, 40, False,
        "Four TCP ports; no service-version probes.",
    ),
    NmapScanProfile(
        "web-services", "Web Services", "Review eight common web service ports.",
        True, (80, 443, 8000, 8080, 8081, 8443, 8888, 9443), "tcp-connect", 10, 1, 45, 60, False,
        "Eight TCP ports; no service-version probes.",
    ),
    NmapScanProfile(
        "standard-tcp", "Standard TCP", "Review TCP ports 1 through 1000.",
        True, tuple(range(1, 1001)), "tcp-connect", 10, 1, 300, 360, False,
        "Up to 1000 TCP ports; more connections than the web service profiles.",
    ),
    NmapScanProfile(
        "deep-service-review", "Deep Service Review", "Review TCP ports 1 through 1024 with service-version detection.",
        True, tuple(range(1, 1025)), "tcp-connect", 10, 1, 600, 660, True,
        "Up to 1024 TCP ports plus service-version probes; --max-rate does not reliably cap version probes.",
    ),
)


__all__ = [
    "NmapScanProfile", "ProfileValidationError", "BUILTIN_PROFILES", "PREVIEW_NOTICE", "parse_ports",
    "format_ports", "format_network_impact", "profile_from_dict", "profile_to_dict",
    "duplicate_profile", "rename_profile", "preview_arguments", "configuration_arguments",
    "LEGACY_PROFILE_FIELDS", "TECHNIQUE_FLAGS", "DISCOVERY_PROBE_FLAGS",
]
