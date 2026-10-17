"""R7B execution policy is stricter than editable R7A configuration."""

from dataclasses import replace
import importlib
from pathlib import Path

import pytest

from core.recon.execution_policy import ExecutionPolicy, ExecutionPolicyError
from core.recon.nmap_profile_store import NmapProfileStore
from core.recon.nmap_profiles import BUILTIN_PROFILES, duplicate_profile
from tests.core.recon.test_nmap_public_adapter import tool, observation
from tests.core.recon.test_nmap_adapter import candidate
from tests.core.recon.test_public_target import preflight


def api():
    return importlib.import_module("core.recon.nmap_profile_execution")


def test_web_services_snapshot_and_exact_arguments():
    profile = BUILTIN_PROFILES[1]
    snapshot = api().validate_executable_profile(profile)
    assert snapshot == profile and snapshot is not profile
    assert api().execution_reasons(profile) == ()
    assert api().profile_arguments(profile, "8.8.8.8") == (
        "-sT", "-Pn", "-n", "-p", "80,443,8000,8080-8081,8443,8888,9443",
        "--max-retries", "1", "--max-rate", "10", "--host-timeout", "45s",
        "--no-stylesheet", "-oX", "-", "8.8.8.8",
    )


@pytest.mark.parametrize("index", [0, 2, 3])
def test_other_builtins_remain_editable_but_not_new_profile_executable(index):
    assert api().execution_reasons(BUILTIN_PROFILES[index])
    with pytest.raises(ValueError):
        api().validate_executable_profile(BUILTIN_PROFILES[index])


@pytest.mark.parametrize("changes", [
    {"ports": tuple(range(1, 18))}, {"version_detection": True},
    {"max_rate": 11}, {"max_retries": 2}, {"host_timeout_seconds": 61, "execution_timeout_seconds": 90},
    {"execution_timeout_seconds": 91},
])
def test_saved_configuration_outside_execution_limits_is_preserved(tmp_path, changes):
    custom = replace(duplicate_profile(BUILTIN_PROFILES[1]), **changes)
    store = NmapProfileStore(tmp_path / "profiles.json")
    store.save(custom)
    assert NmapProfileStore(store.path).profiles == (custom,)
    assert api().execution_reasons(custom)
    with pytest.raises(ValueError):
        api().validate_executable_profile(custom)


def grant(tool, observation, profile=BUILTIN_PROFILES[1], **changes):
    fields = dict(address="8.8.8.8", scope_confirmed=True, confirmed=True)
    fields.update(changes)
    return api().approve_profile_nmap(tool, observation, profile=profile, **fields)


def test_profile_plan_is_one_shot_and_cannot_reuse_dns(tool, observation):
    approval = grant(tool, observation)
    spec = api().prepare_nmap_profile_scan(tool, approval)
    assert spec.adapter_id == "nmap.public-profile"
    assert spec._plan.timeout_ms == 60000
    assert spec._plan.targets == ("8.8.8.8",)
    policy = ExecutionPolicy()
    policy.validate(spec)
    policy._claim(spec)
    with pytest.raises(ValueError):
        policy._claim(spec)
    with pytest.raises(ValueError):
        api().prepare_nmap_profile_scan(tool, approval)
    with pytest.raises(ValueError):
        grant(tool, observation)


def test_custom_must_be_saved_and_disk_edits_revoke_queued_run(tool, observation, tmp_path):
    custom = replace(duplicate_profile(BUILTIN_PROFILES[1]), ports=tuple(range(1, 17)))
    with pytest.raises(ValueError, match="saved"):
        grant(tool, observation, custom)
    store = NmapProfileStore(tmp_path / "profiles.json")
    store.save(custom)
    approval = grant(tool, observation, custom, profile_store=store)
    spec = api().prepare_nmap_profile_scan(tool, approval)
    assert spec._plan.arguments[4] == "1-16"
    ExecutionPolicy().validate(spec)
    store.save(replace(custom, max_rate=9))
    with pytest.raises(ExecutionPolicyError, match="changed"):
        ExecutionPolicy().validate(spec)


@pytest.mark.parametrize("changes", [{"confirmed": False}, {"scope_confirmed": False},
    {"address": "9.9.9.9"}, {"address": "127.0.0.1"}])
def test_missing_confirmation_scope_or_selected_ip_is_rejected(tool, observation, changes):
    with pytest.raises(ValueError):
        grant(tool, observation, **changes)


@pytest.mark.parametrize("mutation", ["profile", "snapshot", "snapshot-type", "selected-type",
                                      "address", "arguments", "timeout", "version", "executable"])
def test_bound_values_cannot_change_before_execution(tool, observation, mutation):
    # An independent selected object must also remain unchanged after approval.
    selected = replace(BUILTIN_PROFILES[1])
    approval = grant(tool, observation, selected)
    spec = api().prepare_nmap_profile_scan(tool, approval)
    if mutation == "profile":
        object.__setattr__(selected, "max_rate", 9)
    elif mutation == "snapshot":
        object.__setattr__(approval.profile, "max_rate", 9)
    elif mutation == "snapshot-type":
        object.__setattr__(approval, "profile", None)
    elif mutation == "selected-type":
        object.__setattr__(approval, "_selected_profile", None)
    elif mutation == "address":
        object.__setattr__(approval, "address", "1.1.1.1")
    elif mutation == "arguments":
        object.__setattr__(spec, "_plan", replace(spec._plan, arguments=spec._plan.arguments + ("-sV",)))
    elif mutation == "timeout":
        object.__setattr__(spec, "_plan", replace(spec._plan, timeout_ms=90000))
    elif mutation == "version":
        object.__setattr__(tool, "version", "7.96")
    else:
        Path(tool.executable_path).write_bytes(b"MZ replaced")
    with pytest.raises(ExecutionPolicyError):
        ExecutionPolicy().validate(spec)


def test_expired_preflight_and_short_lived_approval_are_rejected(tool, observation, monkeypatch):
    from core.recon import public_target
    approval = grant(tool, observation)
    spec = api().prepare_nmap_profile_scan(tool, approval)
    with monkeypatch.context() as patch:
        patch.setattr(api(), "monotonic", lambda: approval.expires_at + 1)
        with pytest.raises(ExecutionPolicyError, match="expired"):
            ExecutionPolicy().validate(spec)
    monkeypatch.setattr(public_target, "monotonic", lambda: 10**20)
    with pytest.raises(ExecutionPolicyError, match="expired"):
        ExecutionPolicy().validate(spec)


@pytest.mark.parametrize("field,value", [("ports", ()), ("technique", "syn"), ("max_rate", True),
    ("max_rate", 0), ("max_retries", -1), ("host_timeout_seconds", 4),
    ("execution_timeout_seconds", 9), ("execution_timeout_seconds", 45),
    ("is_builtin", False), ("profile_id", "standard-tcp")])
def test_bypassed_dataclass_validation_is_rechecked(field, value):
    profile = replace(BUILTIN_PROFILES[1])
    object.__setattr__(profile, field, value)
    with pytest.raises(ValueError):
        api().validate_executable_profile(profile)
