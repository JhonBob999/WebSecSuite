"""Offline release provenance, fixed passive arguments and one-shot scope."""

from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib
from pathlib import Path
import zipfile

import pytest

from core.recon.execution_policy import ExecutionPolicy, ExecutionPolicyError, ScopeApproval
from core.recon.process_supervisor import JobSnapshot, JobState


def api():
    return importlib.import_module("core.recon.subfinder_adapter")


@pytest.fixture
def release(monkeypatch, tmp_path):
    module = api()
    image = bytearray(128)
    image[:2] = b"MZ"
    image[60:64] = (64).to_bytes(4, "little")
    image[64:68] = b"PE\0\0"
    path = tmp_path / "subfinder.exe"
    path.write_bytes(image)
    archive = tmp_path / "subfinder_2.17.0_windows_amd64.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("subfinder.exe", image)
        output.writestr("README.md", "Synthetic release, never executed")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    monkeypatch.setattr(module, "_RELEASE_ARCHIVES", {archive.name: digest})
    monkeypatch.setattr(module, "_process_safety", lambda: (True, "Contained"))
    return path, archive


@pytest.fixture
def candidate(release):
    path, archive = release
    return api().approve_subfinder_path(str(path), archive_path=str(archive), confirmed=True)


def version_result(**changes):
    values = dict(job_id="verify-job", adapter_id="subfinder.version-check", state=JobState.SUCCEEDED,
                  stdout=b"", stderr=b"[INF] Current Version: v2.17.0\n", exit_code=0)
    values.update(changes)
    return JobSnapshot(**values)


def tool(candidate):
    return api().verify_subfinder_version(candidate, version_result())


def test_pinned_release_archive_and_selected_executable_are_bound(candidate):
    assert candidate.version == "2.17.0"
    assert candidate.sha256 == hashlib.sha256(Path(candidate.executable_path).read_bytes()).hexdigest()
    assert api().prepare_subfinder_version_check(candidate)._plan.arguments == ("-version", "-duc", "-nc")
    with pytest.raises(FrozenInstanceError):
        candidate.sha256 = "a" * 64


@pytest.mark.parametrize("change", ["no-confirm", "no-archive", "bad-digest", "different-exe"])
def test_name_or_user_confirmation_alone_cannot_establish_release_identity(release, change):
    path, archive = release
    if change == "bad-digest":
        archive.write_bytes(b"untrusted zip")
    if change == "different-exe":
        path.write_bytes(path.read_bytes() + b"changed")
    with pytest.raises(ExecutionPolicyError):
        api().approve_subfinder_path(str(path), archive_path="" if change == "no-archive" else str(archive),
                                    confirmed=change != "no-confirm")


@pytest.mark.parametrize("path", ["subfinder.exe", "", r"\\server\share\subfinder.exe", "C:\\subfinder.exe:stream"])
def test_unsafe_paths_fail_without_launching(path):
    with pytest.raises(ExecutionPolicyError):
        api().approve_subfinder_path(path, archive_path="", confirmed=True)


def test_changed_file_revokes_candidate_and_verified_tool(candidate):
    verified = tool(candidate)
    Path(candidate.executable_path).write_bytes(b"changed")
    with pytest.raises(ExecutionPolicyError):
        api().prepare_subfinder_version_check(candidate)
    with pytest.raises(ExecutionPolicyError):
        api().approve_subfinder_run(verified, ("example.com",), confirmed=True,
                                   approval=ScopeApproval(exact_domains=("example.com",)))


@pytest.mark.parametrize("changes", [dict(state=JobState.FAILED), dict(exit_code=1),
    dict(stdout_truncated=True), dict(stderr_truncated=True), dict(adapter_id="nmap.version-check"),
    dict(stderr=b"Current Version: v9.9.9\n"), dict(stderr=b"secret unsupported version\n"),
    dict(stderr=b"[INF] Current Version: v2.17.0\nsecret token\n"),
    dict(stderr=None), dict(stdout="unexpected text"), dict(exit_code=False)])
def test_version_errors_cannot_promote_an_executable(candidate, changes):
    with pytest.raises(ExecutionPolicyError):
        api().verify_subfinder_version(candidate, version_result(**changes))


@pytest.mark.parametrize("value,expected", [("EXAMPLE.com.", "example.com"),
                                          ("bücher.example", "xn--bcher-kva.example")])
def test_selected_domain_uses_existing_r1_normalization(value, expected):
    assert api().selected_subfinder_hostname((value,)) == expected


@pytest.mark.parametrize("values", [(), ("example.com", "other.com"), ("example.com", "example.com"),
                                  ("https://example.com",), ("--help",), ("127.0.0.1",), "example.com"])
def test_exactly_one_hostname_only(values):
    with pytest.raises(ValueError):
        api().selected_subfinder_hostname(values)


def grant(candidate, **kwargs):
    defaults = dict(confirmed=True, approval=ScopeApproval(exact_domains=("example.com",)))
    defaults.update(kwargs)
    return api().approve_subfinder_run(tool(candidate), ("example.com",), **defaults)


@pytest.mark.parametrize("kwargs", [dict(confirmed=False), dict(approval=None),
    dict(approval=ScopeApproval()), dict(approval=ScopeApproval(exact_domains=("other.com",))),
    dict(approval=ScopeApproval(subdomain_ranges=("example.com",))),
    dict(approval=ScopeApproval(exact_domains=("example.com",), excluded_domains=("example.com",))),
    dict(approval=ScopeApproval(exact_domains=("example.com",), excluded_subdomain_ranges=("example.com",),
                                excluded_domains=("example.com",)))])
def test_confirmation_exact_scope_and_exclusion_are_required(candidate, kwargs):
    with pytest.raises(ExecutionPolicyError):
        grant(candidate, **kwargs)


def test_fixed_passive_profile_is_immutable_and_one_shot(candidate):
    approval = grant(candidate)
    spec = api().prepare_subfinder_discovery(approval._tool, approval)
    assert spec._plan.arguments == ("-d", "example.com", "-oJ", "-cs", "-silent", "-nc", "-duc",
                                    "-rl", "2", "-timeout", "15", "-max-time", "2")
    assert spec._plan.timeout_ms == 150000
    assert spec._plan.targets == ("example.com",)
    ExecutionPolicy().validate(spec)
    with pytest.raises(ExecutionPolicyError):
        api().prepare_subfinder_discovery(approval._tool, approval)
    ExecutionPolicy()._claim(spec)
    with pytest.raises(ExecutionPolicyError):
        ExecutionPolicy()._claim(spec)
    with pytest.raises(ExecutionPolicyError):
        ExecutionPolicy().prepare(spec.adapter_id, api()._DiscoveryRequest(approval._tool, approval),
                                  ScopeApproval(exact_domains=("example.com",)))


def test_mutated_plan_and_copied_grants_fail(candidate):
    import copy
    approval = grant(candidate)
    with pytest.raises(ExecutionPolicyError):
        api().prepare_subfinder_discovery(approval._tool, copy.copy(approval))
    spec = api().prepare_subfinder_discovery(approval._tool, approval)
    object.__setattr__(spec, "_plan", replace(spec._plan, arguments=("-active",)))
    with pytest.raises(ExecutionPolicyError):
        ExecutionPolicy().validate(spec)


def test_queue_time_expiry_and_containment_fail_closed(candidate, monkeypatch):
    approval = grant(candidate)
    spec = api().prepare_subfinder_discovery(approval._tool, approval)
    monkeypatch.setattr(api(), "monotonic", lambda: approval.expires_at + 1)
    with pytest.raises(ExecutionPolicyError):
        ExecutionPolicy().validate(spec)


def test_actual_version_messages_allow_bounded_ansi_and_private_config_line(candidate):
    directory = str(Path(candidate._configuration.files[0]).parent)
    stderr = ("\x1b[34m[INF]\x1b[0m Current Version: v2.17.0\n"
              f"[INF] Subfinder Config Directory: {directory}\n").encode()
    assert api().verify_subfinder_version(candidate, version_result(stderr=stderr)).version == "2.17.0"


def test_passive_configuration_and_environment_exclude_ambient_flags_and_secrets(release, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "never-in-child")
    monkeypatch.setenv("HTTPS_PROXY", "never-in-child")
    monkeypatch.setenv("SUBFINDER_CONFIG", "never-read")
    path, archive = release
    candidate = api().approve_subfinder_path(str(path), archive_path=str(archive), confirmed=True)
    spec = api().prepare_subfinder_version_check(candidate)
    environment = dict(spec._plan.environment)
    assert "VIRUSTOTAL_API_KEY" not in environment and "HTTPS_PROXY" not in environment
    assert "PATH" not in environment
    assert environment["APPDATA"] != __import__("os").environ["APPDATA"]
    assert Path(environment["SUBFINDER_CONFIG"]).read_bytes() == b"{}\n"
    assert Path(environment["SUBFINDER_PROVIDER_CONFIG"]).read_bytes() == b"{}\n"
    assert Path(spec._plan.working_directory).is_dir()
    Path(environment["SUBFINDER_CONFIG"]).write_text("active: true\n")
    with pytest.raises(ExecutionPolicyError):
        ExecutionPolicy().validate(spec)
