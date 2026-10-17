"""R7B-2 configuration stays typed, inert and compatible with stored v1 data."""

from dataclasses import replace
import json

import pytest

from core.recon.nmap_profiles import BUILTIN_PROFILES, ProfileValidationError, duplicate_profile


def custom(**changes):
    return replace(duplicate_profile(BUILTIN_PROFILES[0]), **changes)


@pytest.mark.parametrize("technique, flag", [
    ("tcp-connect", "-sT"), ("tcp-syn", "-sS"), ("tcp-ack", "-sA"),
    ("tcp-window", "-sW"), ("tcp-fin", "-sF"), ("tcp-null", "-sN"),
    ("tcp-xmas", "-sX"), ("tcp-maimon", "-sM"), ("udp", "-sU"),
])
def test_typed_techniques_build_canonical_options(technique, flag):
    from core.recon.nmap_profiles import configuration_arguments
    profile = custom(technique=technique, udp_ports=(53, 123) if technique == "udp" else ())
    arguments = configuration_arguments(profile)
    assert arguments[0] == flag
    assert arguments[-3:] == ("--no-stylesheet", "-oX", "-")
    assert "<approved-ip>" not in arguments


def test_tcp_udp_ports_and_advanced_settings_have_structured_preview():
    from core.recon.nmap_profiles import configuration_arguments
    profile = custom(technique="tcp-syn", udp_scan=True, udp_ports=(53, 123),
                     discovery="default", discovery_probes=("syn", "icmp-echo"),
                     dns_mode="reverse", timing_template=4, min_rate=2,
                     min_parallelism=1, max_parallelism=4, version_detection=True,
                     version_intensity=3, os_detection=True, os_guess=True, traceroute=True,
                     script_ids=("http-title",), script_arguments=(("http.useragent", "WebSecSuite"),))
    arguments = configuration_arguments(profile)
    for token in ("-sS", "-sU", "T:80,443,8080,8443,U:53,123", "-PS", "-PE", "-R", "-T4", "-sV", "-O", "--osscan-guess", "--traceroute", "http-title", "http.useragent=WebSecSuite"):
        assert token in arguments
    assert arguments[arguments.index("--version-intensity") + 1] == "3"
    assert arguments[arguments.index("--script-timeout") + 1] == "30s"


@pytest.mark.parametrize("changes", [
    {"udp_ports": [53]}, {"udp_ports": (True,)}, {"udp_scan": 1},
    {"technique": "raw-options"}, {"discovery": "--script=all"},
    {"dns_mode": "system"}, {"discovery_probes": ("--script",)},
    {"discovery_probes": ("syn",)}, {"timing_template": True}, {"timing_template": 6},
    {"min_rate": 101}, {"min_parallelism": 4, "max_parallelism": 2},
    {"version_intensity": 10}, {"version_all": True}, {"os_guess": True},
    {"port_mode": "unknown"}, {"top_ports": 65536},
    {"script_ids": ("../evil",)}, {"script_ids": ("http-title.nse",)},
    {"script_ids": ["http-title"]}, {"script_ids": ("http-title", "http-title")},
    {"script_arguments": (("x", "--script=all"),)},
    {"script_ids": ("http-title",), "script_arguments": (("x", "a,b"),)},
    {"script_ids": ("http-title",), "script_arguments": (("x", "a\n"),)},
    {"script_timeout_seconds": 0}, {"version_timeout_seconds": -1},
    {"discovery": "only", "version_detection": True},
    {"discovery": "list", "os_detection": True},
])
def test_extended_fields_refuse_untyped_injection_and_conflicts(changes):
    with pytest.raises(ProfileValidationError):
        custom(**changes)


@pytest.mark.parametrize("mode, token", [("all", "1-65535"), ("top", "--top-ports")])
def test_bounded_port_modes_do_not_expand_saved_tuples(mode, token):
    from core.recon.nmap_profiles import configuration_arguments
    profile = custom(port_mode=mode, top_ports=1000)
    assert token in configuration_arguments(profile)
    assert len(profile.ports) == 4


def test_v1_migration_preserves_identifiers_notes_and_file_until_save(tmp_path):
    from core.recon.nmap_profiles import LEGACY_PROFILE_FIELDS, profile_to_dict
    from core.recon.nmap_profile_store import NmapProfileStore
    profile = custom(name="Stored profile", description="Keep my notes.")
    legacy = {key: value for key, value in profile_to_dict(profile).items() if key in LEGACY_PROFILE_FIELDS}
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({"schema": "websecsuite.nmap.profiles", "version": 1, "profiles": [legacy]}), encoding="utf-8")
    before = path.read_bytes()
    store = NmapProfileStore(path)
    assert not store.load_error
    loaded, = store.profiles
    assert loaded == profile
    assert path.read_bytes() == before
    store.save(loaded)
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["version"] == 2
    assert saved["profiles"][0]["profile_id"] == profile.profile_id
    assert saved["profiles"][0]["description"] == "Keep my notes."
    assert NmapProfileStore(path).profiles == (profile,)


def test_v2_tuple_settings_roundtrip_without_scope_fields(tmp_path):
    from core.recon.nmap_profile_store import NmapProfileStore
    profile = custom(technique="tcp-syn", udp_scan=True, udp_ports=(53,),
                     discovery="default", discovery_probes=("icmp-echo",),
                     script_ids=("http-title",), script_arguments=(("http.useragent", "WebSecSuite"),))
    path = tmp_path / "profiles.json"
    NmapProfileStore(path).save(profile)
    assert NmapProfileStore(path).profiles == (profile,)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["profiles"][0]["scope_confirmed"] = True
    path.write_text(json.dumps(document), encoding="utf-8")
    assert NmapProfileStore(path).load_error


def test_all_port_udp_impact_does_not_claim_zero_explicit_udp_ports():
    from core.recon.nmap_profiles import format_network_impact
    profile = custom(udp_scan=True, port_mode="all")
    impact = format_network_impact(profile)
    assert "all 65535" in impact
    assert "0 explicit ports" not in impact


def test_script_id_supports_installed_dot_name_without_paths_or_file_extension():
    from core.recon.nmap_profiles import configuration_arguments
    assert "http-robots.txt" in configuration_arguments(custom(script_ids=("http-robots.txt",)))
    for script_id in ("http..title", "http-title.nse", ".hidden", "dir/script"):
        with pytest.raises(ProfileValidationError):
            custom(script_ids=(script_id,))


def test_all_version_probes_cannot_silently_override_explicit_intensity():
    with pytest.raises(ProfileValidationError):
        custom(version_detection=True, version_all=True, version_intensity=3)
