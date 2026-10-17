"""Offline Nmap profile data stays bounded, immutable, and distinct from execution."""

from dataclasses import FrozenInstanceError, fields, replace
import importlib
import importlib.util
import re

import pytest


def profiles():
    assert importlib.util.find_spec("core.recon.nmap_profiles") is not None, "Offline profile model is missing"
    return importlib.import_module("core.recon.nmap_profiles")


def custom(**changes):
    values = dict(
        profile_id="custom-example", name="Example", description="Review selected TCP services.",
        is_builtin=False, ports=(80, 443), technique="tcp-connect", max_rate=10, max_retries=1,
        host_timeout_seconds=30, execution_timeout_seconds=40, version_detection=False,
        network_impact="TCP connections to the configured ports.",
    )
    values.update(changes)
    return profiles().NmapScanProfile(**values)


def test_builtin_previews_keep_exact_bounded_profiles_without_an_executable_or_target():
    module = profiles()
    assert type(module.BUILTIN_PROFILES) is tuple
    assert [(item.profile_id, item.name) for item in module.BUILTIN_PROFILES] == [
        ("quick-network-discovery", "Quick Network Discovery"), ("web-services", "Web Services"),
        ("standard-tcp", "Standard TCP"), ("deep-service-review", "Deep Service Review"),
    ]
    quick, web, standard, deep = module.BUILTIN_PROFILES
    assert module.preview_arguments(quick) == (
        "-sT", "-Pn", "-n", "-p", "80,443,8080,8443", "--max-retries", "1",
        "--max-rate", "10", "--host-timeout", "30s", "--no-stylesheet", "-oX", "-", "<approved-ip>",
    )
    assert web.ports == (80, 443, 8000, 8080, 8081, 8443, 8888, 9443)
    assert (web.host_timeout_seconds, web.execution_timeout_seconds) == (45, 60)
    assert standard.ports == tuple(range(1, 1001))
    assert (standard.host_timeout_seconds, standard.execution_timeout_seconds) == (300, 360)
    assert deep.ports == tuple(range(1, 1025))
    assert (deep.host_timeout_seconds, deep.execution_timeout_seconds) == (600, 660)
    for item in module.BUILTIN_PROFILES:
        assert item.is_builtin is True and item.max_rate == 10 and item.max_retries == 1
        assert item.technique == "tcp-connect"
        assert item.version_detection is (item is deep)
        assert item.description and item.network_impact
    assert module.preview_arguments(deep) == (
        "-sT", "-Pn", "-n", "-p", "1-1024", "--max-retries", "1", "--max-rate", "10",
        "--host-timeout", "600s", "-sV", "--no-stylesheet", "-oX", "-", "<approved-ip>",
    )


@pytest.mark.parametrize("text, expected", [
    ("80", (80,)), (" 443,80,443 ", (80, 443)), ("1-3,5,2-4", (1, 2, 3, 4, 5)),
    ("65535,1", (1, 65535)), ("0080,00443", (80, 443)), ("1-1024", tuple(range(1, 1025))),
])
def test_port_parser_normalizes_only_numeric_lists_and_ranges(text, expected):
    assert profiles().parse_ports(text) == expected


@pytest.mark.parametrize("text", [
    "", " ", ",80", "80,", "80,,443", "0", "65536", "3-1", "0-4", "1-65536",
    "1-65535", "1-1025", "-80", "+80", "80.0", "8e1", "80/tcp", "80;whoami",
    "80 --script all", "80,https", "80-", "80-81-82", "80 - 81", "８０", "٨٠",
    "80\x00", "80\n443", "80\t443", "80,443\r", "9" * 8192, "80," * 2731,
    None, 80, True, (80,), [80], b"80",
])
def test_port_parser_rejects_injection_malformed_types_and_unbounded_expansion(text):
    module = profiles()
    with pytest.raises(module.ProfileValidationError):
        module.parse_ports(text)


@pytest.mark.parametrize("ports, expected", [
    ((80,), "80"), ((1, 2, 3, 5, 7, 8, 9, 10), "1-3,5,7-10"),
    ((443, 80, 81, 80), "80-81,443"), ((1, 65535), "1,65535"),
])
def test_port_formatter_produces_deterministic_compact_numeric_ranges(ports, expected):
    assert profiles().format_ports(ports) == expected


@pytest.mark.parametrize("ports", [(), (0,), (65536,), (True,), (80.0,), ("80",),
    [80], "80", None, tuple(range(1, 1026))])
def test_profile_and_formatter_reject_non_numeric_or_unbounded_port_containers(ports):
    module = profiles()
    for operation in (lambda: custom(ports=ports), lambda: module.format_ports(ports)):
        with pytest.raises(module.ProfileValidationError):
            operation()


def test_profile_normalizes_name_and_ports_then_cannot_mutate():
    item = custom(name="  My review  ", ports=(443, 80, 443))
    assert item.name == "My review" and item.ports == (80, 443)
    assert not hasattr(item, "__dict__")
    with pytest.raises(FrozenInstanceError):
        item.max_rate = 100
    with pytest.raises(TypeError):
        item.ports[0] = 22


@pytest.mark.parametrize("changes", [
    {"profile_id": ""}, {"profile_id": "1-profile"}, {"profile_id": "Uppercase"},
    {"profile_id": "a" * 65}, {"profile_id": "custom_x"}, {"profile_id": "custom/x"},
    {"profile_id": "custom\n"}, {"profile_id": None}, {"profile_id": "quick-network-discovery"},
    {"is_builtin": 1}, {"is_builtin": "false"}, {"is_builtin": True},
    {"name": ""}, {"name": "   "}, {"name": "a" * 81}, {"name": 80},
    {"name": "line\nname"}, {"name": "name\t"}, {"name": "name\x7f"},
    {"name": "name\u202e"}, {"name": "name\ud800"},
    {"description": None}, {"description": "a" * 2001}, {"description": "bad\x00text"},
    {"description": "bad\ttext"}, {"description": "bad\rtext"},
    {"network_impact": None}, {"network_impact": "a" * 2001}, {"network_impact": "line\nbreak"},
    {"technique": "syn"}, {"technique": "-sT --script all"}, {"technique": None},
    {"max_rate": 0}, {"max_rate": 101}, {"max_rate": True}, {"max_rate": "10"}, {"max_rate": 10.0},
    {"max_retries": -1}, {"max_retries": 4}, {"max_retries": False},
    {"host_timeout_seconds": 4}, {"host_timeout_seconds": 601}, {"host_timeout_seconds": True},
    {"execution_timeout_seconds": 9}, {"execution_timeout_seconds": 901},
    {"execution_timeout_seconds": 30}, {"execution_timeout_seconds": 20},
    {"execution_timeout_seconds": 40.0}, {"version_detection": 1}, {"version_detection": "false"},
])
def test_profile_validation_rejects_invalid_text_reserved_ids_and_non_strict_types(changes):
    module = profiles()
    with pytest.raises(module.ProfileValidationError):
        custom(**changes)


def test_profile_bounds_accept_limits_and_description_only_allows_newline():
    low = custom(max_rate=1, max_retries=0, host_timeout_seconds=5, execution_timeout_seconds=10,
                 description="First line\nSecond line", network_impact="")
    high = custom(name="a" * 80, description="a" * 2000, network_impact="b" * 2000,
                  max_rate=100, max_retries=3, host_timeout_seconds=600, execution_timeout_seconds=900,
                  ports=(1, 65535), version_detection=True)
    assert low.description == "First line\nSecond line"
    assert high.execution_timeout_seconds == 900


def serialized():
    return dict(
        profile_id="custom-example", name="Example", description="Review selected TCP services.",
        is_builtin=False, ports="80,443", technique="tcp-connect", max_rate=10, max_retries=1,
        host_timeout_seconds=30, execution_timeout_seconds=40, version_detection=False,
        network_impact="TCP connections to the configured ports.",
    )


def test_strict_serialization_retains_only_recognized_typed_fields_and_compact_ports():
    module = profiles()
    data = serialized()
    assert module.profile_to_dict(custom()) == data
    assert module.profile_from_dict(data) == custom()
    data["ports"] = "443,80,81,443"
    assert module.profile_to_dict(module.profile_from_dict(data))["ports"] == "80-81,443"
    assert {field.name for field in fields(custom())} == set(serialized())
    for builtin in module.BUILTIN_PROFILES:
        assert module.profile_from_dict(module.profile_to_dict(builtin)) == builtin


@pytest.mark.parametrize("field", tuple(serialized()))
def test_deserialization_requires_every_field(field):
    module = profiles()
    data = serialized()
    data.pop(field)
    with pytest.raises(module.ProfileValidationError):
        module.profile_from_dict(data)


@pytest.mark.parametrize("field", ["arguments", "argv", "executable_path", "path", "flags", "target",
    "targets", "scope_confirmed", "approval", "timeout_ms", "run", "execute"])
def test_deserialization_rejects_any_execution_related_or_unknown_field(field):
    module = profiles()
    data = serialized()
    data[field] = "--script all"
    with pytest.raises(module.ProfileValidationError):
        module.profile_from_dict(data)


@pytest.mark.parametrize("data", [None, [], (), "{}", {"name": "partial"}])
def test_deserialization_rejects_unstructured_or_partial_data(data):
    module = profiles()
    with pytest.raises(module.ProfileValidationError):
        module.profile_from_dict(data)


@pytest.mark.parametrize("value", [(80, 443), [80, 443], 80, True, None])
def test_serialized_ports_must_be_numeric_text(value):
    module = profiles()
    data = serialized()
    data["ports"] = value
    with pytest.raises(module.ProfileValidationError):
        module.profile_from_dict(data)


def test_duplicate_gets_unique_custom_identity_and_rename_cannot_change_a_builtin():
    module = profiles()
    builtin = module.BUILTIN_PROFILES[0]
    first = module.duplicate_profile(builtin)
    second = module.duplicate_profile(builtin, name="  My copy  ")
    assert re.fullmatch(r"custom-[0-9a-f]{32}", first.profile_id)
    assert first.profile_id != second.profile_id and first.is_builtin is False
    assert first.name == "Quick Network Discovery copy" and second.name == "My copy"
    assert replace(first, profile_id=builtin.profile_id, name=builtin.name, is_builtin=True) == builtin
    renamed = module.rename_profile(second, "  Renamed  ")
    assert renamed.profile_id == second.profile_id and renamed.name == "Renamed"
    assert second.name == "My copy" and builtin.name == "Quick Network Discovery"
    assert len(module.duplicate_profile(custom(name="x" * 80)).name) <= 80
    with pytest.raises(module.ProfileValidationError):
        module.rename_profile(builtin, "Edited builtin")
    for operation in (lambda: module.rename_profile(first, ""), lambda: module.duplicate_profile(first, name="")):
        with pytest.raises(module.ProfileValidationError):
            operation()


@pytest.mark.parametrize("value", [None, {}, "quick-network-discovery"])
def test_model_helpers_reject_unvalidated_inputs(value):
    module = profiles()
    for operation in (lambda: module.profile_to_dict(value), lambda: module.preview_arguments(value),
                      lambda: module.duplicate_profile(value), lambda: module.rename_profile(value, "Name")):
        with pytest.raises(module.ProfileValidationError):
            operation()


@pytest.mark.parametrize("field, value", [
    ("max_rate", "10 --script all"), ("ports", ("80",)), ("technique", "-sS"),
    ("name", "bad\ud800"), ("description", "bad\u202e"), ("network_impact", "bad\udfff"),
    ("profile_id", "quick-network-discovery"), ("version_detection", 1),
])
def test_model_helpers_revalidate_accidentally_tampered_dataclass_fields(field, value):
    module = profiles()
    item = custom()
    object.__setattr__(item, field, value)
    for operation in (lambda: module.profile_to_dict(item), lambda: module.preview_arguments(item),
                      lambda: module.duplicate_profile(item), lambda: module.rename_profile(item, "Name")):
        with pytest.raises(module.ProfileValidationError):
            operation()


def test_preview_notice_states_offline_scope_and_version_probe_rate_limit():
    notice = profiles().PREVIEW_NOTICE.casefold()
    assert "configuration" in notice and "authorization" in notice
    assert "--max-rate" in notice and "version" in notice and "probe" in notice
