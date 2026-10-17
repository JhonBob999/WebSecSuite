"""One R5B hostname, explicit DNS preflight, and ephemeral observation identity.

DNS observations are not scope grants. Only an explicit, one-use confirmation
of one public IPv4 may be consumed by the separate trusted Nmap adapter.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
from time import monotonic
from weakref import WeakKeyDictionary

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtNetwork import QDnsLookup

from core.recon.targets import normalize_hostname


PUBLIC_HOSTNAME = "ginandjuice.shop"
PUBLIC_PORTS = (80, 443, 8080, 8443)
PUBLIC_PROFILE = "Quick Network Discovery"
PREFLIGHT_TTL_SECONDS = 300
DNS_TIMEOUT_MS = 10_000
_MAX_ADDRESSES = 32
_MAX_CNAMES = 8
_RESOLVER = "Qt system DNS / A query"


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False)
class PublicTargetObservation:
    hostname: str
    ipv4_addresses: tuple[str, ...]
    cnames: tuple[str, ...]
    observed_at: str
    resolver: str


@dataclass
class _ObservationState:
    fingerprint: tuple
    expires_at: float
    used: bool = False


_OBSERVATIONS: WeakKeyDictionary = WeakKeyDictionary()


def selected_public_hostname(targets) -> str:
    if not isinstance(targets, (tuple, list)) or len(targets) != 1:
        raise ValueError("Select exactly one Target Manager hostname for public preflight.")
    hostname = normalize_hostname(targets[0])
    if hostname != PUBLIC_HOSTNAME:
        raise ValueError("R5B supports only the exact hostname ginandjuice.shop.")
    return hostname


def validate_public_address(value: str) -> str:
    try:
        if type(value) is not str or value != value.strip():
            raise ValueError
        address = ipaddress.IPv4Address(value)
        if (not address.is_global or address.is_private or address.is_loopback or address.is_link_local
                or address.is_multicast or address.is_reserved or address.is_unspecified):
            raise ValueError
        return str(address)
    except (ValueError, ipaddress.AddressValueError):
        raise ValueError("Choose a globally routable public IPv4 address returned by this preflight.") from None


def _fingerprint(observation: PublicTargetObservation) -> tuple:
    return (observation.hostname, observation.ipv4_addresses, observation.cnames,
            observation.observed_at, observation.resolver)


def validate_public_observation(observation: PublicTargetObservation) -> float:
    """Return the expiry of an unchanged, service-issued observation."""
    if type(observation) is not PublicTargetObservation or observation not in _OBSERVATIONS:
        raise ValueError("A user-initiated public DNS preflight is required.")
    state = _OBSERVATIONS[observation]
    if _fingerprint(observation) != state.fingerprint:
        raise ValueError("The public DNS observation changed; run preflight again.")
    if monotonic() >= state.expires_at:
        raise ValueError("The public DNS preflight expired; run preflight again.")
    return state.expires_at


def claim_public_observation(observation: PublicTargetObservation, address: str, *, scope_confirmed: bool) -> float:
    """Consume one explicit IP-scope confirmation; never infer it from DNS."""
    expires_at = validate_public_observation(observation)
    if scope_confirmed is not True:
        raise ValueError("Explicit approval that the selected IP is within your authorized scope is required.")
    if validate_public_address(address) not in observation.ipv4_addresses:
        raise ValueError("The selected IP was not returned by this DNS preflight.")
    state = _OBSERVATIONS[observation]
    if state.used:
        raise ValueError("This public DNS preflight was already used; run preflight and confirm again.")
    state.used = True
    return expires_at


class PublicTargetPreflight(QObject):
    """Asynchronous, bounded Qt DNS lookup. Construction never resolves a name.

    CNAME records are shown only when included by the system resolver in its
    A response. No reverse lookup, ASN query, origin discovery or follow-up
    scanning occurs. The lookup factory is injectable for offline tests.
    """

    changed = Signal()

    def __init__(self, parent=None, *, lookup_factory=None):
        super().__init__(parent)
        self._lookup_factory = lookup_factory
        self._lookup = None
        self._observation = None
        self._warnings = ()
        self._status = "Public preflight required: select ginandjuice.shop in Target Manager."
        self._timeout = QTimer(self)
        self._timeout.setSingleShot(True)
        self._timeout.timeout.connect(self._timed_out)
        self._expiry = QTimer(self)
        self._expiry.setSingleShot(True)
        self._expiry.timeout.connect(self._expired)

    @property
    def busy(self) -> bool:
        return self._lookup is not None

    @property
    def observation(self) -> PublicTargetObservation | None:
        return self._observation

    @property
    def status(self) -> str:
        return self._status

    @property
    def warnings(self) -> tuple[str, ...]:
        return self._warnings

    @property
    def is_fresh(self) -> bool:
        try:
            validate_public_observation(self._observation)
            return not _OBSERVATIONS[self._observation].used
        except ValueError:
            return False

    def clear(self) -> None:
        self._timeout.stop()
        self._expiry.stop()
        lookup, self._lookup = self._lookup, None
        if lookup is not None:
            lookup.abort()
            lookup.deleteLater()
        if self._observation is not None:
            _OBSERVATIONS.pop(self._observation, None)
        self._observation = None
        self._warnings = ()
        self._status = "Public preflight required; DNS does not authorize scanning."
        self.changed.emit()

    def start(self, selected_targets) -> None:
        # Validate before creating a resolver; malformed/unsupported selections
        # must not make even a DNS query. Invalid attempts revoke old results.
        self.clear()
        hostname = selected_public_hostname(selected_targets)
        lookup = self._lookup = (self._lookup_factory or QDnsLookup)(self)
        lookup.setType(QDnsLookup.Type.A)
        lookup.setName(hostname)
        lookup.finished.connect(lambda: self._finished(lookup))
        self._status = "Resolving ginandjuice.shop IPv4 / available CNAME records…"
        self._timeout.start(DNS_TIMEOUT_MS)
        self.changed.emit()
        try:
            lookup.lookup()
        except Exception:
            self.clear()
            self._status = "Public DNS preflight failed; no address is authorized."
            self.changed.emit()

    def _finished(self, lookup) -> None:
        if lookup is not self._lookup:
            return
        self._lookup = None
        self._timeout.stop()
        try:
            if lookup.error() != QDnsLookup.NoError:
                raise ValueError("DNS resolution failed; no address is authorized.")
            records = lookup.hostAddressRecords()
            names = lookup.canonicalNameRecords()
            if not 1 <= len(records) <= _MAX_ADDRESSES or len(names) > _MAX_CNAMES:
                raise ValueError("DNS returned no IPv4 addresses or exceeded the preflight limits.")
            addresses = tuple(dict.fromkeys(validate_public_address(record.value().toString()) for record in records))
            cnames = tuple(dict.fromkeys(normalize_hostname(record.value()) for record in names))
            observation = PublicTargetObservation(PUBLIC_HOSTNAME, addresses, cnames,
                datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"), _RESOLVER)
            _OBSERVATIONS[observation] = _ObservationState(_fingerprint(observation), monotonic() + PREFLIGHT_TTL_SECONDS)
            self._observation = observation
            warnings = ["DNS is a time-specific observation, not authorization or proof of IP ownership. "
                        "Shared hosting/CDN detection is incomplete and not authoritative."]
            if len(addresses) > 1:
                warnings.append("Multiple IPv4 answers may indicate shared hosting, load balancing or CDN infrastructure.")
            if cnames:
                warnings.append("CNAME indirection may point to shared hosting/CDN infrastructure; confirm permission for the selected IP.")
            self._warnings = tuple(warnings)
            self._status = "DNS preflight ready for explicit IP selection and scope approval (valid for 5 minutes)."
            self._expiry.start(PREFLIGHT_TTL_SECONDS * 1000)
        except (ValueError, TypeError, AttributeError):
            self._observation = None
            self._status = "Public DNS preflight failed: no complete, bounded public IPv4 answer is available."
        finally:
            lookup.deleteLater()
        self.changed.emit()

    def _timed_out(self) -> None:
        self.clear()
        self._status = "Public DNS preflight timed out; no address is authorized."
        self.changed.emit()

    def _expired(self) -> None:
        self.clear()
        self._status = "Public DNS preflight expired; resolve and confirm scope again."
        self.changed.emit()

    def take_observation(self) -> PublicTargetObservation:
        """Detach the fresh result for one scan attempt without persisting a grant."""
        if self.busy or not self.is_fresh:
            raise ValueError("A fresh public DNS preflight is required for every scan attempt.")
        observation, self._observation = self._observation, None
        self._expiry.stop()
        self._warnings = ()
        self._status = "Preflight consumed; resolve and confirm scope again for another run."
        self.changed.emit()
        return observation
