"""Explicit authorization stays separate from imported/discovered Recon records."""

import importlib
from dataclasses import dataclass, FrozenInstanceError

import pytest


def api():
    return importlib.import_module("core.recon.execution_policy")


def test_exact_approval_normalizes_without_changing_r1_review_state():
    from core.recon.targets import TargetRecord

    target = TargetRecord("example.com", "manual", selected=True)
    approval = api().ScopeApproval(exact_domains=("EXAMPLE.COM.",))
    decision = api().preflight_scope(("Example.COM",), approval)
    assert decision.allowed
    assert decision.targets == ("example.com",)
    assert target.scope_status == "Unreviewed"
    assert not api().preflight_scope((target.hostname,), target).allowed


@pytest.mark.parametrize("target", ["other.org", "discovered.example.com", "example.com.evil.org"])
def test_exact_grant_never_expands_to_discoveries_or_subdomains(target):
    decision = api().preflight_scope((target,), api().ScopeApproval(exact_domains=("example.com",)))
    assert not decision.allowed
    assert decision.reason


def test_explicit_subdomain_range_requires_label_boundary_and_does_not_grant_apex():
    approval = api().ScopeApproval(subdomain_ranges=("example.com",))
    assert api().preflight_scope(("api.example.com", "deep.api.example.com"), approval).allowed
    assert not api().preflight_scope(("example.com",), approval).allowed
    assert not api().preflight_scope(("notexample.com",), approval).allowed


def test_exclusions_override_exact_and_range_approvals():
    approval = api().ScopeApproval(
        exact_domains=("example.com", "private.example.com"),
        subdomain_ranges=("example.com",),
        excluded_domains=("private.example.com",),
        excluded_subdomain_ranges=("private.example.com",),
    )
    assert api().preflight_scope(("example.com", "public.example.com"), approval).allowed
    assert not api().preflight_scope(("private.example.com",), approval).allowed
    assert not api().preflight_scope(("deep.private.example.com",), approval).allowed


@pytest.mark.parametrize(
    "target",
    ["--help", "-example.com", "example.com/path", "https://example.com", "example.com:443",
     "example.com\x00", "example.com\n", " example.com", "*.example.com", "127.0.0.1", None, 3],
)
def test_malformed_or_option_like_planned_targets_fail_closed(target):
    decision = api().preflight_scope((target,), api().ScopeApproval(exact_domains=("example.com",)))
    assert not decision.allowed
    assert decision.reason
    assert "\n" not in decision.reason


@pytest.mark.parametrize("targets", [(), [], "example.com", None])
def test_missing_or_unstructured_targets_are_rejected(targets):
    assert not api().preflight_scope(targets, api().ScopeApproval(exact_domains=("example.com",))).allowed


def test_approval_requires_explicit_hostname_lists_and_is_immutable():
    with pytest.raises(ValueError):
        api().ScopeApproval(exact_domains="example.com")
    with pytest.raises(ValueError):
        api().ScopeApproval(subdomain_ranges=("*.example.com",))
    approval = api().ScopeApproval(exact_domains=["example.com"])
    assert approval.exact_domains == ("example.com",)
    with pytest.raises(FrozenInstanceError):
        approval.exact_domains = ("evil.org",)


@dataclass(frozen=True)
class ControlledRequest:
    hostname: str = "example.com"
    timeout_ms: int = 1000


@pytest.fixture
def trusted_adapter(monkeypatch, tmp_path):
    policy = api()
    executable = tmp_path / "controlled-fixture.exe"
    executable.write_bytes(b"MZ controlled offline fixture; never executed")

    class ControlledAdapter:
        request_type = ControlledRequest

        def build(self, request):
            return policy._AdapterPlan(
                program=str(executable), arguments=("--target", request.hostname),
                targets=(request.hostname,), timeout_ms=request.timeout_ms,
            )

    adapter = ControlledAdapter()
    monkeypatch.setitem(policy._TRUSTED_ADAPTERS, "controlled", adapter)
    return adapter, executable


def test_r4_has_no_connected_adapters_or_generic_command_runner():
    with pytest.raises(api().ExecutionPolicyError):
        api().ExecutionPolicy().prepare("nmap", {"program": "nmap.exe", "args": ["--help"]}, None)
    with pytest.raises(TypeError):
        api().ValidatedExecutionSpec()


def test_only_registered_typed_adapter_request_can_issue_spec(trusted_adapter):
    approval = api().ScopeApproval(exact_domains=("example.com",))
    policy = api().ExecutionPolicy()
    spec = policy.prepare("controlled", ControlledRequest(), approval)
    assert spec.adapter_id == "controlled"
    policy.validate(spec)
    assert "--target" not in repr(spec)
    assert "example.com" not in repr(spec)
    with pytest.raises(api().ExecutionPolicyError):
        policy.prepare("controlled", {"hostname": "example.com"}, approval)
    with pytest.raises(api().ExecutionPolicyError):
        policy.prepare("controlled", ControlledRequest("other.org"), approval)
    with pytest.raises(api().ExecutionPolicyError):
        policy.prepare("controlled", ControlledRequest(), None)


def test_spec_is_invalid_if_adapter_was_disconnected(trusted_adapter, monkeypatch):
    policy = api().ExecutionPolicy()
    spec = policy.prepare("controlled", ControlledRequest(), api().ScopeApproval(exact_domains=("example.com",)))
    monkeypatch.delitem(api()._TRUSTED_ADAPTERS, "controlled")
    with pytest.raises(api().ExecutionPolicyError):
        policy.validate(spec)


def test_copying_capability_fields_does_not_issue_a_new_capability(trusted_adapter):
    policy = api().ExecutionPolicy()
    spec = policy.prepare("controlled", ControlledRequest(), api().ScopeApproval(exact_domains=("example.com",)))
    forged = object.__new__(api().ValidatedExecutionSpec)
    for name in ("adapter_id", "_plan", "_approval", "_adapter", "_seal"):
        object.__setattr__(forged, name, getattr(spec, name))
    with pytest.raises(api().ExecutionPolicyError):
        policy.validate(forged)


@pytest.mark.parametrize("bad_program", ["relative.exe", "missing.exe", "cmd.exe", "powershell.exe"])
def test_adapter_cannot_issue_relative_missing_or_shell_programs(trusted_adapter, tmp_path, bad_program):
    adapter, executable = trusted_adapter
    program = bad_program
    if bad_program in {"cmd.exe", "powershell.exe"}:
        program_path = tmp_path / bad_program
        program_path.write_bytes(b"MZ offline fixture")
        program = str(program_path)
    adapter.build = lambda request: api()._AdapterPlan(program, (), (request.hostname,))
    with pytest.raises(api().ExecutionPolicyError):
        api().ExecutionPolicy().prepare("controlled", ControlledRequest(), api().ScopeApproval(exact_domains=("example.com",)))


@pytest.mark.parametrize("timeout", [0, -1, True, 2**32])
def test_invalid_adapter_timeout_is_rejected(trusted_adapter, timeout):
    with pytest.raises(api().ExecutionPolicyError):
        api().ExecutionPolicy().prepare(
            "controlled", ControlledRequest(timeout_ms=timeout), api().ScopeApproval(exact_domains=("example.com",))
        )
