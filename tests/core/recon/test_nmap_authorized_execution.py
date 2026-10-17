"""Typed plans bind full numeric scope, configuration, installation and capability."""

from dataclasses import replace
import importlib
import os
from pathlib import Path

import pytest

from core.recon.execution_policy import ExecutionPolicy, ExecutionPolicyError
from core.recon.nmap_profiles import BUILTIN_PROFILES, duplicate_profile
from core.recon.nmap_profile_store import NmapProfileStore
from tests.core.recon.test_nmap_public_adapter import tool
from tests.core.recon.test_nmap_adapter import candidate
from tests.core.recon.test_nmap_nse import catalog


def api():
    return importlib.import_module("core.recon.nmap_authorized_execution")


@pytest.fixture
def ready(tool, monkeypatch):
    from core.recon.nmap_capabilities import NmapCapabilities
    root = Path(tool.executable_path).parent
    (root / "nmap-services").write_text("https 443/tcp 0.9\nhttp 80/tcp 0.8\ndomain 53/udp 0.9\nntp 123/udp 0.7\n", encoding="ascii")
    (root / "nmap-protocols").write_text("tcp 6\nudp 17\n", encoding="ascii")
    (root / "nmap-service-probes").write_text("Probe TCP NULL q||\n", encoding="ascii")
    (root / "nmap-os-db").write_text("# controlled OS data\n", encoding="ascii")
    (root / "nse_main.lua").write_text("-- controlled engine fixture\n", encoding="ascii")
    catalog(tool)
    caps = NmapCapabilities(True, True, "7.95", True, True, True, True)
    monkeypatch.setattr(api(), "detect_capabilities", lambda value=None: caps)
    return tool, caps


def scope(inputs=("127.0.0.1",)):
    from core.recon.nmap_scope import resolve_scope
    return resolve_scope(inputs)


def approve(ready, profile=BUILTIN_PROFILES[1], **changes):
    values = dict(scope_confirmed=True, confirmed=True)
    values.update(changes)
    return api().approve_authorized_nmap(ready[0], scope(), profile=profile, **values)


def test_exact_scope_preview_and_approval_use_identical_typed_arguments(ready):
    tool, _ = ready
    selection = scope(("192.0.2.0/30",))
    preview = api().authorized_arguments(tool, selection, BUILTIN_PROFILES[1])
    approval = api().approve_authorized_nmap(tool, selection, profile=BUILTIN_PROFILES[1],
        scope_confirmed=True, confirmed=True)
    assert preview == approval._arguments
    assert preview[-4:] == selection.targets and "--datadir" in preview
    spec = api().prepare_nmap_authorized_scan(tool, approval)
    assert spec.adapter_id == "nmap.authorized-profile" and spec._plan.targets == selection.targets
    assert spec._plan.arguments == preview
    ExecutionPolicy().validate(spec)
    ExecutionPolicy()._claim(spec)
    with pytest.raises(ValueError):
        ExecutionPolicy()._claim(spec)
    with pytest.raises(ValueError):
        api().prepare_nmap_authorized_scan(tool, approval)
    with pytest.raises(ValueError):
        api().approve_authorized_nmap(tool, selection, profile=BUILTIN_PROFILES[1], scope_confirmed=True, confirmed=True)


@pytest.mark.parametrize("technique", ["tcp-connect", "tcp-syn", "tcp-ack", "tcp-window", "tcp-fin", "tcp-null", "tcp-xmas", "tcp-maimon", "udp"])
def test_supported_techniques_build_typed_bounded_plans(ready, technique):
    profile = replace(duplicate_profile(BUILTIN_PROFILES[1]), technique=technique,
        udp_ports=(53,) if technique == "udp" else ())
    store = NmapProfileStore(Path(ready[0].executable_path).parent / "profiles.json")
    store.save(profile)
    approval = approve(ready, profile, profile_store=store)
    ExecutionPolicy().validate(api().prepare_nmap_authorized_scan(ready[0], approval))


def test_scope_requires_every_address_and_explicit_per_run_confirmation(ready):
    for changes in ({"scope_confirmed": False}, {"confirmed": False}):
        with pytest.raises(ValueError):
            approve(ready, **changes)


def test_high_impact_script_requires_extra_confirmation_and_exact_installed_file(ready):
    profile = replace(duplicate_profile(BUILTIN_PROFILES[1]), script_ids=("ssl-enum-ciphers",))
    store = NmapProfileStore(Path(ready[0].executable_path).parent / "profiles.json")
    store.save(profile)
    with pytest.raises(ValueError, match="impact"):
        approve(ready, profile, profile_store=store)
    approval = approve(ready, profile, profile_store=store, high_impact_confirmed=True)
    assert "ssl-enum-ciphers.nse" in approval._arguments
    index = approval._arguments.index("--script-timeout")
    assert approval._arguments[index + 1] == "30s"
    assert approval.scripts[0].high_impact
    ExecutionPolicy().validate(api().prepare_nmap_authorized_scan(ready[0], approval))


@pytest.mark.parametrize("mutation", ["scope", "selected-profile", "profile", "version", "capability", "expiry", "data"])
def test_changes_revoke_queued_approval(ready, monkeypatch, mutation):
    tool, caps = ready
    profile = replace(BUILTIN_PROFILES[1])
    approval = approve(ready, profile)
    spec = api().prepare_nmap_authorized_scan(tool, approval)
    if mutation == "scope":
        object.__setattr__(approval.scope, "targets", ("192.0.2.2",))
    elif mutation == "selected-profile":
        object.__setattr__(profile, "max_rate", 9)
    elif mutation == "profile":
        object.__setattr__(approval.profile, "max_rate", 9)
    elif mutation == "version":
        object.__setattr__(tool, "version", "7.96")
    elif mutation == "capability":
        monkeypatch.setattr(api(), "detect_capabilities", lambda value=None: replace(caps, npcap=False))
    elif mutation == "expiry":
        monkeypatch.setattr(api(), "monotonic", lambda: approval.expires_at + 1)
    else:
        # Native Windows read locks must also deny data edits for the run.
        path = Path(tool.executable_path).parent / "nmap-services"
        try:
            path.write_bytes(b"changed")
        except OSError:
            api().release_authorized_approval(approval)
    with pytest.raises(ValueError):
        ExecutionPolicy().validate(spec)


def test_saved_profile_change_revokes_and_version_budget_bounds_whole_process(ready):
    profile = replace(duplicate_profile(BUILTIN_PROFILES[1]), version_detection=True, version_timeout_seconds=20)
    store = NmapProfileStore(Path(ready[0].executable_path).parent / "profiles.json")
    store.save(profile)
    approval = approve(ready, profile, profile_store=store, version_nse_confirmed=True)
    spec = api().prepare_nmap_authorized_scan(ready[0], approval)
    assert spec._plan.timeout_ms == 20000
    store.save(replace(profile, max_rate=9))
    with pytest.raises(ValueError):
        ExecutionPolicy().validate(spec)


def test_top_ports_bind_installed_frequency_order_and_data(ready):
    tool, _ = ready
    profile = replace(duplicate_profile(BUILTIN_PROFILES[1]), port_mode="top", top_ports=1)
    store = NmapProfileStore(Path(tool.executable_path).parent / "profiles.json")
    store.save(profile)
    approval = approve(ready, profile, profile_store=store)
    assert approval.expected_ports == (("tcp", (443,)),)


def test_ipv6_is_numeric_and_capability_gated(ready, monkeypatch):
    tool, caps = ready
    selection = scope(("2001:db8::/126",))
    arguments = api().authorized_arguments(tool, selection, BUILTIN_PROFILES[1])
    assert "-6" in arguments and arguments[-4:] == selection.targets
    monkeypatch.setattr(api(), "detect_capabilities", lambda value=None: replace(caps, ipv6=False))
    with pytest.raises(ValueError, match="IPv6"):
        api().approve_authorized_nmap(tool, selection, profile=BUILTIN_PROFILES[1], scope_confirmed=True, confirmed=True)


def test_version_detection_requires_explicit_implicit_nse_confirmation(ready):
    profile = replace(duplicate_profile(BUILTIN_PROFILES[1]), version_detection=True)
    store = NmapProfileStore(Path(ready[0].executable_path).parent / "profiles.json")
    store.save(profile)
    with pytest.raises(ValueError, match="version.*NSE|NSE.*version"):
        approve(ready, profile, profile_store=store)
    approval = approve(ready, profile, profile_store=store, version_nse_confirmed=True)
    assert tuple(script.script_id for script in approval.scripts) == ("http-server-header",)
    assert any(Path(item.path).name == "nse_main.lua" for item in approval.data_files)
    assert approval._arguments[approval._arguments.index("--max-hostgroup") + 1] == "1"


def test_safe_environment_drops_lua_paths_proxy_and_credential_values(ready, monkeypatch):
    monkeypatch.setenv("LUA_PATH", "untrusted")
    monkeypatch.setenv("NMAPDIR", "untrusted")
    monkeypatch.setenv("HTTP_PROXY", "http://secret@proxy")
    approval = approve(ready)
    spec = api().prepare_nmap_authorized_scan(ready[0], approval)
    environment = dict(spec._plan.environment)
    assert "LUA_PATH" not in environment and "HTTP_PROXY" not in environment
    assert environment["NMAPDIR"] == str(Path(ready[0].executable_path).parent)


def test_top_ports_preserve_frequency_ties_and_use_actual_available_count(ready):
    tool, _ = ready
    (Path(tool.executable_path).parent / "nmap-services").write_text(
        "https 443/tcp 0.8\nhttp 80/tcp 0.8\nold 443/tcp 0.9\n", encoding="ascii")
    profile = replace(duplicate_profile(BUILTIN_PROFILES[1]), port_mode="top", top_ports=99)
    store = NmapProfileStore(Path(tool.executable_path).parent / "profiles.json")
    store.save(profile)
    assert approve(ready, profile, profile_store=store).expected_ports == (("tcp", (80, 443)),)


def test_version_only_plan_binds_more_than_32_implicit_scripts_without_explicit_category_execution(ready):
    from core.recon.nmap_nse import VERSION_SCRIPT_IDS
    root = Path(ready[0].executable_path).parent
    entries = []
    for script_id in sorted(VERSION_SCRIPT_IDS)[:40]:
        entries.append(f'Entry {{ filename = "{script_id}.nse", categories = {{ "version", }} }}\n')
        (root / "scripts" / f"{script_id}.nse").write_text("description=[[Controlled version fixture.]]\n", encoding="ascii")
    (root / "scripts" / "script.db").write_text("".join(entries), encoding="ascii")
    profile = replace(duplicate_profile(BUILTIN_PROFILES[1]), version_detection=True)
    store = NmapProfileStore(root / "profiles.json")
    store.save(profile)
    approval = approve(ready, profile, profile_store=store, version_nse_confirmed=True, high_impact_confirmed=True)
    assert len(approval.scripts) == 40 and "--script" not in approval._arguments
    assert approval._arguments[approval._arguments.index("--script-timeout") + 1] == "30s"
    ExecutionPolicy().validate(api().prepare_nmap_authorized_scan(ready[0], approval))


@pytest.mark.skipif(os.name != "nt", reason="Windows deny-write/delete data locks")
def test_locked_data_is_revalidated_without_rehashing_every_library_file(ready, monkeypatch):
    approval = approve(ready)
    def unnecessary_read(*args, **kwargs):
        raise AssertionError("Locked approved data must use handle-bound file identity during repeated policy checks")
    monkeypatch.setattr(api(), "bounded_file", unnecessary_read)
    ExecutionPolicy().validate(api().prepare_nmap_authorized_scan(ready[0], approval))
