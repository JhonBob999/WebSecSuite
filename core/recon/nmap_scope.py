"""Explicit user initiated preflight for finite Nmap address selections.

DNS answers are observations. Only a separate per-run confirmation may consume
one snapshot; numeric addresses are always passed to Nmap, never hostnames.
CIDR includes every address (including IPv4 network/broadcast boundaries).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import re
import socket
from time import monotonic
from weakref import WeakKeyDictionary

from core.recon.targets import normalize_hostname


MAX_TARGETS = 256
MAX_INPUTS = 64
SCOPE_TTL_SECONDS = 300


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False)
class ScopeSnapshot:
    inputs: tuple[str, ...]
    targets: tuple[str, ...]
    dns_observations: tuple[tuple[str, tuple[str, ...]], ...]
    observed_at: str
    expires_at: float

    @property
    def target_count(self) -> int:
        return len(self.targets)

    @property
    def family(self) -> int:
        return ipaddress.ip_address(self.targets[0]).version


_SCOPES: WeakKeyDictionary = WeakKeyDictionary()


def _identity(scope):
    return (scope.inputs, scope.targets, scope.dns_observations, scope.observed_at, scope.expires_at)


def _address(value):
    if type(value) is not str or "%" in value:
        raise ValueError("Scoped IPv6 interface identifiers are not supported; choose a concrete unambiguous address.")
    address = ipaddress.ip_address(value)
    if address.is_unspecified or address.is_multicast:
        raise ValueError("Unspecified and multicast addresses are outside supported scan scope.")
    if address.version == 4 and str(address) == "255.255.255.255":
        raise ValueError("The limited broadcast address is outside supported scan scope.")
    return address


def _system_resolver(hostname):
    # Called only by resolve_scope, normally in the runtime's explicit Qt worker.
    return (entry[4][0] for entry in socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM))


def resolve_scope(inputs, resolver=None, *, family=None) -> ScopeSnapshot:
    """Resolve only explicit selections into <=256 addresses of one IP family.

    An injected resolver receives a normalized hostname and returns IP strings.
    The explicit family selector filters DNS targets while retaining every DNS
    observation; explicit numeric selections must all match that family.
    """
    if family is not None and (type(family) is not int or family not in (4, 6)):
        raise ValueError("Choose IPv4 or IPv6 explicitly for DNS preflight.")
    if type(inputs) not in (tuple, list) or not 1 <= len(inputs) <= MAX_INPUTS:
        raise ValueError("Select 1–64 explicit hostnames, IPs, CIDRs or full address ranges.")
    normalized, targets, dns = [], [], []
    resolve = resolver or _system_resolver

    def add(values):
        for value in values:
            parsed = _address(value)
            if family is not None and parsed.version != family:
                raise ValueError("An explicit target uses a different IP family from the selected run.")
            canonical = str(parsed)
            if canonical not in targets:
                if len(targets) >= MAX_TARGETS:
                    raise ValueError("Scope exceeds the limit of 256 concrete target addresses.")
                targets.append(canonical)

    for value in inputs:
        if (type(value) is not str or not 1 <= len(value) <= 253 or value != value.strip()
                or any(character.isspace() or ord(character) < 32 for character in value)
                or value.startswith("-") or any(character in value for character in "\\,%")):
            raise ValueError("Targets must be explicit hostnames, IPs, CIDRs or full address ranges without options.")
        try:
            address = _address(value)
        except ValueError:
            address = None
        if address is not None:
            normalized.append(str(address))
            add((str(address),))
        elif "/" in value:
            try:
                network = ipaddress.ip_network(value, strict=True)
            except ValueError:
                raise ValueError("CIDR must use an exact network boundary and a valid prefix.") from None
            if network.num_addresses > MAX_TARGETS:
                raise ValueError("CIDR exceeds the limit of 256 concrete target addresses.")
            normalized.append(str(network))
            add(str(item) for item in network)
        elif "-" in value and (":" in value or re.fullmatch(r"[0-9.]+-[0-9.]+", value)):
            parts = value.split("-")
            try:
                if len(parts) != 2:
                    raise ValueError
                first, last = (_address(item) for item in parts)
                if first.version != last.version or int(last) < int(first) or int(last) - int(first) + 1 > MAX_TARGETS:
                    raise ValueError
            except ValueError:
                raise ValueError("Use an ascending same-family full IP range containing at most 256 addresses.") from None
            normalized.append(str(first) + "-" + str(last))
            add(str(type(first)(number)) for number in range(int(first), int(last) + 1))
        else:
            # A rejected literal must not accidentally become a DNS lookup.
            if ":" in value or value.replace(".", "").isdigit():
                raise ValueError("Invalid or unsupported numeric target address.")
            hostname = normalize_hostname(value)
            if hostname not in normalized:
                try:
                    answers = []
                    for item in resolve(hostname):
                        answer = str(_address(item))
                        if answer not in answers:
                            answers.append(answer)
                        if len(answers) > MAX_TARGETS:
                            raise ValueError
                    if not answers:
                        raise ValueError
                except (OSError, ValueError, TypeError):
                    raise ValueError("Hostname preflight failed or returned an incomplete, unsupported or excessive address set.") from None
                dns.append((hostname, tuple(answers)))
                chosen = [item for item in answers if family is None or ipaddress.ip_address(item).version == family]
                if not chosen:
                    raise ValueError("DNS returned no addresses in the selected IP family.")
                add(chosen)
            normalized.append(hostname)
    if not targets or len({ipaddress.ip_address(item).version for item in targets}) != 1:
        raise ValueError("Choose one IP family per run; mixed IPv4/IPv6 scope is not supported.")
    snapshot = ScopeSnapshot(tuple(dict.fromkeys(normalized)), tuple(targets), tuple(dns),
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"), monotonic() + SCOPE_TTL_SECONDS)
    _SCOPES[snapshot] = [_identity(snapshot), False]
    return snapshot


def validate_scope(scope: ScopeSnapshot) -> ScopeSnapshot:
    if type(scope) is not ScopeSnapshot or scope not in _SCOPES or _identity(scope) != _SCOPES[scope][0]:
        raise ValueError("An unchanged explicit target preflight is required.")
    if monotonic() >= scope.expires_at:
        raise ValueError("Target preflight expired; review and confirm scope again.")
    return scope


def scope_is_fresh(scope) -> bool:
    try:
        validate_scope(scope)
        return not _SCOPES[scope][1]
    except ValueError:
        return False


def claim_scope(scope: ScopeSnapshot, *, scope_confirmed: bool) -> float:
    validate_scope(scope)
    if scope_confirmed is not True:
        raise ValueError("Explicit authorization covering every concrete target address is required.")
    if _SCOPES[scope][1]:
        raise ValueError("This target preflight was already used; preflight and confirm again.")
    _SCOPES[scope][1] = True
    return scope.expires_at
