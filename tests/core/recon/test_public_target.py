"""Public scope is a user-triggered, time-specific DNS observation, never a grant."""

from types import SimpleNamespace

import pytest
from PySide6.QtCore import QObject, Signal
from PySide6.QtNetwork import QDnsLookup

from core.recon import public_target as public


class FakeLookup(QObject):
    finished = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.started = self.aborted = False
        self.addresses = ("8.8.8.8", "1.1.1.1")
        self.aliases = ()
        self.code = QDnsLookup.NoError

    def setType(self, kind):
        assert kind == QDnsLookup.Type.A

    def setName(self, name):
        self.name = name

    def lookup(self):
        self.started = True

    def abort(self):
        self.aborted = True
        self.finished.emit()

    def error(self):
        return self.code

    def hostAddressRecords(self):
        return [SimpleNamespace(value=lambda item=item: SimpleNamespace(toString=lambda: item))
                for item in self.addresses]

    def canonicalNameRecords(self):
        return [SimpleNamespace(value=lambda item=item: item) for item in self.aliases]


@pytest.fixture
def preflight(qapp):
    lookups = []

    def factory(parent):
        lookup = FakeLookup(parent)
        lookups.append(lookup)
        return lookup

    service = public.PublicTargetPreflight(lookup_factory=factory)
    yield service, lookups
    service.clear()
    service.deleteLater()
    qapp.processEvents()


@pytest.mark.parametrize("targets", [(), ("ginandjuice.shop", "ginandjuice.shop"),
    ("example.com",), ("www.ginandjuice.shop",), ("8.8.8.8",),
    ("ginandjuice.shop --script all",), ("https://ginandjuice.shop",)])
def test_only_exactly_one_supported_r1_target_can_trigger_dns(preflight, targets):
    service, lookups = preflight
    with pytest.raises(ValueError):
        service.start(targets)
    assert not lookups
    assert service.observation is None


def test_no_dns_on_construction_and_no_implicit_ip_selection_or_scope_grant(preflight):
    service, lookups = preflight
    assert not lookups and not service.is_fresh
    service.start(("GINANDJUICE.SHOP.",))
    lookup = lookups[-1]
    assert lookup.name == "ginandjuice.shop" and lookup.started
    assert service.busy and service.observation is None
    lookup.aliases = ("shared.cloudfront.net.",)
    lookup.finished.emit()
    observation = service.observation
    assert observation.hostname == "ginandjuice.shop"
    assert observation.ipv4_addresses == ("8.8.8.8", "1.1.1.1")
    assert observation.cnames == ("shared.cloudfront.net",)
    assert observation.observed_at.endswith("Z")
    assert service.is_fresh and not service.busy
    assert any("CDN" in item for item in service.warnings)
    with pytest.raises(ValueError, match="scope"):
        public.claim_public_observation(observation, "8.8.8.8", scope_confirmed=False)
    with pytest.raises(ValueError):
        public.claim_public_observation(observation, "9.9.9.9", scope_confirmed=True)
    public.claim_public_observation(observation, "8.8.8.8", scope_confirmed=True)
    with pytest.raises(ValueError, match="used"):
        public.claim_public_observation(observation, "1.1.1.1", scope_confirmed=True)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
    "169.254.1.1", "224.0.0.1", "240.0.0.1", "0.0.0.0", "100.64.0.1", "192.0.2.1",
    "198.18.0.1", "198.51.100.1", "203.0.113.1", "255.255.255.255", "::1", "8.8.8.8/32",
    "8.8.8.8 -A", "8.8.8.008", " 8.8.8.8"])
def test_nonpublic_or_ambiguous_addresses_rejected(preflight, address):
    service, lookups = preflight
    service.start((public.PUBLIC_HOSTNAME,))
    lookups[-1].addresses = ("8.8.8.8", address)
    lookups[-1].finished.emit()
    assert service.observation is None and not service.is_fresh
    with pytest.raises(ValueError):
        public.validate_public_address(address)


@pytest.mark.parametrize("mode", ["error", "empty", "too_many", "bad_cname", "timeout"])
def test_failed_dns_never_produces_approval(preflight, mode):
    service, lookups = preflight
    service.start((public.PUBLIC_HOSTNAME,))
    lookup = lookups[-1]
    if mode == "error":
        lookup.code = QDnsLookup.NotFoundError
    elif mode == "empty":
        lookup.addresses = ()
    elif mode == "too_many":
        lookup.addresses = ("8.8.8.8",) * 33
    elif mode == "bad_cname":
        lookup.aliases = ("bad --option",)
    if mode == "timeout":
        service._timeout.timeout.emit()
        assert lookup.aborted
    else:
        lookup.finished.emit()
    assert not service.busy and service.observation is None
    assert "failed" in service.status.lower() or "timed out" in service.status.lower()


def test_changed_selection_or_expiry_invalidates_observation_and_stale_callbacks(preflight, monkeypatch):
    service, lookups = preflight
    now = [1000.0]
    monkeypatch.setattr(public, "monotonic", lambda: now[0])
    service.start((public.PUBLIC_HOSTNAME,))
    lookup = lookups[-1]
    service.clear()
    assert lookup.aborted
    lookup.finished.emit()
    assert service.observation is None
    service.start((public.PUBLIC_HOSTNAME,))
    lookups[-1].finished.emit()
    observation = service.observation
    now[0] += public.PREFLIGHT_TTL_SECONDS + 1
    assert not service.is_fresh
    with pytest.raises(ValueError, match="expired"):
        public.claim_public_observation(observation, "8.8.8.8", scope_confirmed=True)


def test_only_service_issued_observations_may_authorize_and_take_requires_fresh_dns(preflight):
    service, lookups = preflight
    forged = public.PublicTargetObservation(public.PUBLIC_HOSTNAME, ("8.8.8.8",), (),
                                             "2026-10-17T00:00:00Z", "fake")
    with pytest.raises(ValueError):
        public.claim_public_observation(forged, "8.8.8.8", scope_confirmed=True)
    with pytest.raises(ValueError):
        service.take_observation()
    service.start((public.PUBLIC_HOSTNAME,))
    lookups[-1].finished.emit()
    observation = service.take_observation()
    assert service.observation is None
    public.claim_public_observation(observation, "8.8.8.8", scope_confirmed=True)
    public.validate_public_observation(observation)
    with pytest.raises(ValueError):
        service.take_observation()


def test_actual_qt_resolver_construction_and_timeout_without_lookup(qapp, monkeypatch):
    calls = []
    monkeypatch.setattr(QDnsLookup, "lookup", lambda lookup: calls.append((lookup.name(), lookup.type())))
    service = public.PublicTargetPreflight()
    try:
        service.start((public.PUBLIC_HOSTNAME,))
        assert calls == [(public.PUBLIC_HOSTNAME, QDnsLookup.Type.A)]
        assert service.busy and service._lookup.parent() is service
        service._timeout.timeout.emit()
        assert not service.busy and not service.is_fresh
        assert "timed out" in service.status
    finally:
        service.clear()
        service.deleteLater()
        qapp.processEvents()
