"""Scope authorization is explicit and invalidated by configuration changes."""

import pytest


def test_digit_prefixed_hyphenated_hostname_uses_async_dns(qapp):
    from core.recon.nmap_scope_preflight import NmapScopePreflight
    from tests.core.recon.test_public_target import FakeLookup

    queries = []

    class Lookup(FakeLookup):
        def setType(self, kind):
            self.kind = kind

    def factory(parent):
        query = Lookup(parent)
        queries.append(query)
        return query

    preflight = NmapScopePreflight(lookup_factory=factory)
    preflight.start(("1-api.example.test",), family=4)
    assert preflight.busy and len(queries) == 2
    assert all(query.started and query.name == "1-api.example.test" for query in queries)
    for query in queries:
        query.finished.emit()
    assert preflight.scope.targets == ("8.8.8.8", "1.1.1.1")
    preflight.clear()


def test_incomplete_dns_failure_cannot_authorize_partial_answer_set(qapp):
    from PySide6.QtNetwork import QDnsLookup
    from core.recon.nmap_scope_preflight import NmapScopePreflight
    from tests.core.recon.test_public_target import FakeLookup

    queries = []

    class Lookup(FakeLookup):
        def setType(self, kind):
            self.kind = kind

    def factory(parent):
        query = Lookup(parent)
        queries.append(query)
        return query

    preflight = NmapScopePreflight(lookup_factory=factory)
    preflight.start(("api.example.test",), family=4)
    queries[0].finished.emit()
    queries[1].code = QDnsLookup.ServerFailureError
    queries[1].finished.emit()
    assert preflight.scope is None
    assert not preflight.busy
    assert "incomplete" in preflight.status.lower() or "failed" in preflight.status.lower()


def test_numeric_scope_is_bounded_and_does_not_launch(qapp):
    from core.recon.nmap_scope_preflight import NmapScopePreflight

    preflight = NmapScopePreflight()
    preflight.start(("192.0.2.0/30",), family=4)
    assert preflight.scope.targets == ("192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3")
    assert not preflight.busy
    preflight.clear()
    assert preflight.scope is None


def test_scope_failure_discards_old_concrete_addresses(qapp):
    from core.recon.nmap_scope_preflight import NmapScopePreflight

    preflight = NmapScopePreflight()
    preflight.start(("127.0.0.1",), family=4)
    assert preflight.scope is not None
    preflight.start(("192.0.2.0/16",), family=4)
    assert preflight.scope is None
    assert not preflight.busy
    assert "256" in preflight.status or "bound" in preflight.status.lower()


def test_authorized_controls_start_passive_and_reset_scope_on_input(qapp, tmp_path, monkeypatch):
    from core.recon.nmap_profile_store import NmapProfileStore
    from ui.panels import recon_tab

    monkeypatch.setattr(recon_tab, "NmapProfileStore", lambda: NmapProfileStore(tmp_path / "profiles.json"))
    panel = recon_tab.ReconTab()
    try:
        controls = panel.authorized_nmap_controls
        ui = panel.ui
        assert not panel.nmap_runtime.busy
        assert not ui.btnNmapAuthorizedRun.isEnabled()
        ui.nmapScopeInput.setPlainText("127.0.0.1")
        ui.btnNmapScopePreflight.click()
        assert controls.preflight.scope.targets == ("127.0.0.1",)
        ui.nmapScopeApproval.setChecked(True)
        ui.nmapScopeInput.setPlainText("127.0.0.2")
        assert not ui.nmapScopeApproval.isChecked()
        assert controls.preflight.scope is None
    finally:
        panel.close()
        panel.deleteLater()
        qapp.processEvents()
