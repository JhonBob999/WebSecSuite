"""Explicit, bounded numeric Nmap scope; DNS and inventory never grant access."""

from dataclasses import replace
import importlib

import pytest


def api():
    return importlib.import_module("core.recon.nmap_scope")


def test_scope_expands_complete_cidr_and_ranges_without_skipping_boundaries():
    scope = api().resolve_scope(("192.0.2.0/30", "192.0.2.4-192.0.2.6"))
    assert scope.targets == tuple(f"192.0.2.{index}" for index in range(7))
    assert scope.target_count == 7 and scope.family == 4
    assert scope.inputs == ("192.0.2.0/30", "192.0.2.4-192.0.2.6")
    assert api().scope_is_fresh(scope)


def test_scope_resolves_only_explicit_names_and_binds_every_answer():
    calls = []
    def resolver(name):
        calls.append(name)
        return ("192.0.2.2", "192.0.2.1", "192.0.2.2")
    scope = api().resolve_scope(("Example.COM",), resolver=resolver)
    assert calls == ["example.com"]
    assert scope.targets == ("192.0.2.2", "192.0.2.1")
    assert scope.dns_observations == (("example.com", scope.targets),)
    api().validate_scope(scope)


@pytest.mark.parametrize("inputs", [(), ("0.0.0.0",), ("::",), ("224.0.0.1",),
    ("ff02::1",), ("192.0.2.0/23",), ("192.0.2.1/24",), ("::/0",),
    ("192.0.2.1-192.0.3.1",), ("--script=all",), ("example.com -sV",),
    ("https://example.com",), ("192.0.2.1", "::1"), ("fe80::1%12",)])
def test_ambiguous_broad_special_or_mixed_scope_is_refused(inputs):
    with pytest.raises(ValueError):
        api().resolve_scope(inputs, resolver=lambda name: ())


def test_ipv6_range_and_cidr_are_concrete_bounded_numeric_targets():
    scope = api().resolve_scope(("2001:db8::/126", "2001:db8::4-2001:db8::5"))
    assert scope.targets == tuple("2001:db8::" + (str(index) if index else "") for index in range(6))
    assert scope.family == 6


def test_scope_forgery_mutation_expiry_and_replay_fail_closed(monkeypatch):
    scope = api().resolve_scope(("127.0.0.1",))
    with pytest.raises(ValueError):
        api().validate_scope(replace(scope))
    api().claim_scope(scope, scope_confirmed=True)
    api().validate_scope(scope)
    assert not api().scope_is_fresh(scope)
    with pytest.raises(ValueError):
        api().claim_scope(scope, scope_confirmed=True)
    another = api().resolve_scope(("127.0.0.1",))
    monkeypatch.setattr(api(), "monotonic", lambda: another.expires_at + 1)
    with pytest.raises(ValueError, match="expired"):
        api().validate_scope(another)


def test_failed_or_changed_dns_scope_is_not_authorization():
    with pytest.raises(ValueError):
        api().resolve_scope(("missing.example",), resolver=lambda name: ())
    scope = api().resolve_scope(("example.com",), resolver=lambda name: ("192.0.2.1",))
    with pytest.raises(ValueError):
        api().claim_scope(scope, scope_confirmed=False)
    object.__setattr__(scope, "dns_observations", (("example.com", ("192.0.2.2",)),))
    with pytest.raises(ValueError):
        api().validate_scope(scope)


def test_digit_hyphen_hostname_is_resolved_and_family_choice_is_explicit():
    scope = api().resolve_scope(("1-web.example",), resolver=lambda name: ("192.0.2.1", "2001:db8::1"), family=6)
    assert scope.targets == ("2001:db8::1",)
    assert scope.dns_observations == (("1-web.example", ("192.0.2.1", "2001:db8::1")),)
