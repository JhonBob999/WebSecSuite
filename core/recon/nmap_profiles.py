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

PREVIEW_NOTICE = (
    "Configuration-only preview; this is not authorization to execute a scan. "
    "Profiles do not grant target or IP scope. --max-rate limits the port scan; "
    "it does not reliably cap service-version detection probes when -sV is enabled."
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

    def __post_init__(self):
        if type(self.profile_id) is not str or _PROFILE_ID.fullmatch(self.profile_id) is None:
            raise ProfileValidationError("Profile ID must be a bounded lowercase identifier.")
        if type(self.is_builtin) is not bool or self.is_builtin != (self.profile_id in _BUILTIN_IDS):
            raise ProfileValidationError("Built-in IDs are reserved; custom profiles need their own ID.")
        object.__setattr__(self, "name", _name(self.name))
        _bounded_text(self.description, "Description", newline=True)
        _bounded_text(self.network_impact, "Network impact")
        object.__setattr__(self, "ports", _canonical_ports(self.ports))
        if type(self.technique) is not str or self.technique != "tcp-connect":
            raise ProfileValidationError("Only the TCP connect technique is supported.")
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


def _profile(value) -> NmapScanProfile:
    if type(value) is not NmapScanProfile:
        raise ProfileValidationError("A validated offline Nmap profile is required.")
    # Recheck all fields even if frozen dataclass protection was bypassed by
    # accidental in-process object.__setattr__ use. This creates no capability.
    return replace(value)


_FIELDS = frozenset(field.name for field in fields(NmapScanProfile))


def profile_from_dict(data: dict) -> NmapScanProfile:
    """Accept the complete data schema only, never execution or target fields."""
    if type(data) is not dict or set(data) != _FIELDS:
        raise ProfileValidationError("A profile must contain exactly the recognized configuration fields.")
    return NmapScanProfile(**{**data, "ports": parse_ports(data["ports"])})


def profile_to_dict(profile: NmapScanProfile) -> dict:
    profile = _profile(profile)
    return {field.name: format_ports(profile.ports) if field.name == "ports" else getattr(profile, field.name)
            for field in fields(NmapScanProfile)}


def duplicate_profile(profile: NmapScanProfile, name=None) -> NmapScanProfile:
    profile = _profile(profile)
    return replace(profile, profile_id="custom-" + uuid4().hex, is_builtin=False,
                   name=profile.name[:75] + " copy" if name is None else name)


def rename_profile(profile: NmapScanProfile, name: str) -> NmapScanProfile:
    profile = _profile(profile)
    if profile.is_builtin:
        raise ProfileValidationError("Duplicate a built-in profile before renaming it.")
    return replace(profile, name=name)


def preview_arguments(profile: NmapScanProfile) -> tuple[str, ...]:
    """Return inert display tokens with a placeholder that grants no IP scope."""
    profile = _profile(profile)
    return (
        "-sT", "-Pn", "-n", "-p", format_ports(profile.ports),
        "--max-retries", str(profile.max_retries), "--max-rate", str(profile.max_rate),
        "--host-timeout", f"{profile.host_timeout_seconds}s",
        *(("-sV",) if profile.version_detection else ()),
        "--no-stylesheet", "-oX", "-", "<approved-ip>",
    )


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
    "format_ports", "profile_from_dict", "profile_to_dict", "duplicate_profile", "rename_profile", "preview_arguments",
]
