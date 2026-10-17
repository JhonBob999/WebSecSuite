"""Public Nmap capabilities bind one observed IP and the exact verified image."""

from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from core.recon import nmap_adapter as nmap, public_target as public
from core.recon.execution_policy import ExecutionPolicy, ExecutionPolicyError, ScopeApproval, preflight_scope
from tests.core.recon.test_nmap_adapter import candidate, version_result
from tests.core.recon.test_public_target import preflight


@pytest.fixture
def observation(preflight):
    service, lookups = preflight
    service.start((public.PUBLIC_HOSTNAME,))
    lookups[-1].finished.emit()
    return service.take_observation()


@pytest.fixture
def tool(candidate):
    return nmap.verify_nmap_version(candidate, version_result())


def approval(tool, observation, **changes):
    fields = dict(address="8.8.8.8", scope_confirmed=True, confirmed=True)
    fields.update(changes)
    return nmap.approve_public_nmap(tool, observation, **fields)


def test_public_operation_has_exact_immutable_arguments_and_one_shot_capability(tool, observation):
    grant = approval(tool, observation)
    spec = nmap.prepare_nmap_public_scan(tool, grant)
    assert spec.adapter_id == "nmap.public-quick-discovery"
    assert spec._plan.arguments == (
        "-sT", "-Pn", "-n", "-p", "80,443,8080,8443", "--max-retries", "1",
        "--max-rate", "10", "--host-timeout", "30s", "--no-stylesheet", "-oX", "-", "8.8.8.8",
    )
    assert spec._plan.targets == ("8.8.8.8",) and spec._plan.timeout_ms == 40000
    policy = ExecutionPolicy()
    policy.validate(spec)
    policy._claim(spec)
    with pytest.raises(ExecutionPolicyError):
        policy._claim(spec)
    with pytest.raises(ExecutionPolicyError):
        nmap.prepare_nmap_public_scan(tool, grant)
    with pytest.raises(ValueError, match="used"):
        approval(tool, observation)
    with pytest.raises(FrozenInstanceError):
        grant.address = "1.1.1.1"
    assert not preflight_scope((public.PUBLIC_HOSTNAME,), grant).allowed
    assert not preflight_scope(("8.8.8.8",), ScopeApproval(exact_domains=(public.PUBLIC_HOSTNAME,))).allowed


@pytest.mark.parametrize("changes", [{"scope_confirmed": False}, {"confirmed": False},
    {"address": "9.9.9.9"}, {"address": "127.0.0.1"}, {"address": public.PUBLIC_HOSTNAME}])
def test_missing_approval_or_changed_ip_cannot_prepare_execution(tool, observation, changes):
    with pytest.raises(ValueError):
        approval(tool, observation, **changes)


@pytest.mark.parametrize("mutation", ["ip", "arguments", "ports", "timeout", "program", "profile"])
def test_mutated_public_plans_and_approvals_fail_revalidation(tool, observation, mutation):
    grant = approval(tool, observation)
    spec = nmap.prepare_nmap_public_scan(tool, grant)
    if mutation == "profile":
        object.__setattr__(grant, "profile", "Other Profile")
    else:
        plan = spec._plan
        changes = {
            "ip": dict(targets=("1.1.1.1",)),
            "arguments": dict(arguments=plan.arguments + ("--script", "all")),
            "ports": dict(arguments=tuple("22" if item == "80,443,8080,8443" else item for item in plan.arguments)),
            "timeout": dict(timeout_ms=40001),
            "program": dict(program=str(Path(tool.executable_path).with_name("other.exe"))),
        }[mutation]
        object.__setattr__(spec, "_plan", replace(plan, **changes))
    with pytest.raises(ExecutionPolicyError):
        ExecutionPolicy().validate(spec)


def test_expiry_and_changed_executable_or_containment_block_public_launch(tool, observation, monkeypatch):
    grant = approval(tool, observation)
    spec = nmap.prepare_nmap_public_scan(tool, grant)
    monkeypatch.setattr(nmap, "monotonic", lambda: grant.expires_at + 1)
    with pytest.raises(ExecutionPolicyError, match="expired"):
        ExecutionPolicy().validate(spec)
    monkeypatch.undo()
    # Restore offline fixture's safety injection after undo.
    monkeypatch.setattr(nmap, "_process_safety", lambda: (True, "Contained"))
    Path(tool.executable_path).write_bytes(b"MZ replacement")
    with pytest.raises(ExecutionPolicyError):
        ExecutionPolicy().validate(spec)


def test_unverified_forged_or_copied_approvals_cannot_issue_public_spec(tool, observation, candidate):
    with pytest.raises(ExecutionPolicyError):
        approval(candidate, observation)
    grant = approval(tool, observation)
    with pytest.raises(TypeError):
        nmap.PublicNmapApproval()
    forged = object.__new__(nmap.PublicNmapApproval)
    for name in grant.__slots__:
        if name != "__weakref__":
            object.__setattr__(forged, name, getattr(grant, name))
    with pytest.raises(ExecutionPolicyError):
        nmap.prepare_nmap_public_scan(tool, forged)


def test_public_grant_cannot_be_used_for_local_or_version_adapters(tool, observation):
    grant = approval(tool, observation)
    nmap.prepare_nmap_public_scan(tool, grant)
    with pytest.raises(ExecutionPolicyError):
        ExecutionPolicy().prepare("nmap.local-self-test", nmap._SelfTestRequest(tool), grant)
    # Existing local path has the original target/profile and never needs DNS.
    local = nmap.prepare_nmap_self_test(tool, confirmed=True)
    assert local._plan.arguments == nmap.LOCAL_ARGUMENTS
    assert local._plan.arguments[-1] == "127.0.0.1"


def test_changed_observation_rejects_with_supervisor_policy_error(tool, observation):
    grant = approval(tool, observation)
    spec = nmap.prepare_nmap_public_scan(tool, grant)
    object.__setattr__(observation, "hostname", "changed.example")
    with pytest.raises(ExecutionPolicyError):
        ExecutionPolicy().validate(spec)
