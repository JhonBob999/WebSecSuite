"""Read-only Windows environment gates configuration independently of approval."""

from dataclasses import replace
import importlib

import pytest

from core.recon.nmap_profiles import BUILTIN_PROFILES


def api():
    return importlib.import_module("core.recon.nmap_capabilities")


def caps(**changes):
    values = dict(windows=True, available=True, version="7.95", npcap=True,
                  elevated=True, ipv6=True, raw_packets=True)
    values.update(changes)
    return api().NmapCapabilities(**values)


def test_connect_can_run_without_npcap_or_elevation():
    assert api().capability_reasons(BUILTIN_PROFILES[1], caps(npcap=False, elevated=False, raw_packets=False)) == ()


@pytest.mark.parametrize("technique", ["tcp-syn", "tcp-ack", "tcp-window", "tcp-fin", "tcp-null", "tcp-xmas", "tcp-maimon", "udp"])
def test_raw_scans_require_available_npcap_and_elevation(technique):
    profile = replace(BUILTIN_PROFILES[1], technique=technique, udp_ports=(53,) if technique == "udp" else ())
    assert api().capability_reasons(profile, caps(npcap=False, raw_packets=False))
    assert api().capability_reasons(profile, caps(elevated=False, raw_packets=False))
    assert api().capability_reasons(profile, caps()) == ()


def test_non_windows_or_unverified_tool_is_disabled():
    assert api().capability_reasons(BUILTIN_PROFILES[1], caps(windows=False))
    assert api().capability_reasons(BUILTIN_PROFILES[1], caps(available=False))
    actual = api().detect_capabilities()
    assert not actual.available


def test_npcap_detector_requires_driver_service_and_library(monkeypatch):
    monkeypatch.setattr(api(), "_npcap_driver", lambda: True)
    monkeypatch.setattr(api(), "_npcap_service_running", lambda: True)
    monkeypatch.setattr(api(), "_npcap_library", lambda: False)
    assert not api()._npcap_available()
    monkeypatch.setattr(api(), "_npcap_library", lambda: True)
    assert api()._npcap_available()
    monkeypatch.setattr(api(), "_npcap_service_running", lambda: False)
    assert not api()._npcap_available()


def test_capability_report_explains_conservative_non_admin_capture_policy(monkeypatch):
    monkeypatch.setattr(api(), "_npcap_driver", lambda: True)
    monkeypatch.setattr(api(), "_npcap_library", lambda: True)
    monkeypatch.setattr(api(), "_npcap_service_running", lambda: True)
    monkeypatch.setattr(api(), "_npcap_admin_only", lambda: False)
    monkeypatch.setattr(api(), "_elevated", lambda: False)
    observed = api().detect_capabilities()
    if observed.windows:
        assert observed.npcap_admin_only is False and not observed.raw_packets
        assert any("conservative" in reason for reason in observed.reasons)
