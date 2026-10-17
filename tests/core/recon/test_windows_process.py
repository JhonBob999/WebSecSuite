"""Real Windows-only Job Object tests using a harmless local Python fixture.

The global network and shell/subprocess/QProcess launch bans remain installed.
Only the native backend is exercised, through an explicit test-only adapter;
no Nmap program is discovered or launched.
"""

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import importlib
import json
import os
from pathlib import Path
import sys
import time

import pytest


pytestmark = [pytest.mark.skipif(os.name != "nt", reason="Native Windows containment"),
              pytest.mark.native_local_process]
FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "recon_process.py"


def wait_until(qapp, predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        qapp.processEvents()
        if predicate():
            return
        time.sleep(0.005)
    pytest.fail("Controlled native process did not reach the expected state")


@dataclass(frozen=True)
class LocalRequest:
    mode: str = "success"
    timeout_ms: int = 5000
    extra: tuple[str, ...] = ()


@pytest.fixture
def native_runtime(monkeypatch, qapp):
    policy = importlib.import_module("core.recon.execution_policy")
    module = importlib.import_module("core.recon.process_supervisor")
    supervisors = []

    class ControlledAdapter:
        request_type = LocalRequest

        def build(self, request):
            return policy._AdapterPlan(
                str(Path(sys.executable).resolve()),
                ("-u", str(FIXTURE), request.mode, *request.extra), ("example.com",), request.timeout_ms,
            )

    monkeypatch.setitem(policy._TRUSTED_ADAPTERS, "windows-fixture", ControlledAdapter())

    class Harness:
        def start(self, mode="success", timeout_ms=5000, extra=(), **limits):
            supervisor = module.ProcessSupervisor(termination_grace_ms=50, **limits)
            supervisors.append(supervisor)
            spec = policy.ExecutionPolicy().prepare(
                "windows-fixture", LocalRequest(mode, timeout_ms, extra),
                policy.ScopeApproval(exact_domains=("example.com",)),
            )
            job = supervisor.submit(spec)
            return supervisor, job

        def finish(self, supervisor, job):
            wait_until(qapp, lambda: supervisor.snapshot(job).state.value in
                       {"SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT"})
            return supervisor.snapshot(job)

    yield Harness()
    for supervisor in supervisors:
        supervisor.shutdown(immediate=True)
    wait_until(qapp, lambda: all(supervisor._active is None for supervisor in supervisors))
    for supervisor in supervisors:
        supervisor.deleteLater()
    qapp.processEvents()


def test_process_safety_gate_exposes_native_backend_status():
    module = importlib.import_module("core.recon.process_supervisor")
    assert hasattr(module, "process_safety_status"), "R5 requires a fail-closed native safety gate"
    allowed, diagnostic = module.process_safety_status()
    assert allowed, diagnostic


def test_native_completion_captures_complete_separate_output(native_runtime):
    supervisor, job = native_runtime.start()
    result = native_runtime.finish(supervisor, job)
    assert result.state.value == "SUCCEEDED"
    assert result.stdout == b"controlled stdout\r\n"
    assert result.stderr == b"controlled stderr\r\n"
    assert result.exit_code == 0


def test_native_nonzero_exit_is_failure(native_runtime):
    supervisor, job = native_runtime.start("nonzero")
    result = native_runtime.finish(supervisor, job)
    assert result.state.value == "FAILED"
    assert result.exit_code == 7
    assert b"controlled failure" in result.stderr


@pytest.mark.parametrize("stop", ["cancel", "timeout", "shutdown", "about_to_quit", "close_fallback"])
def test_native_stop_terminates_parent_and_child(native_runtime, qapp, monkeypatch, stop):
    supervisor, job = native_runtime.start("tree", timeout_ms=1500 if stop == "timeout" else 5000)
    wait_until(qapp, lambda: b"parent " in supervisor.snapshot(job).stdout and
               b"child " in supervisor.snapshot(job).stdout)
    pids = [int(line.split()[1]) for line in supervisor.snapshot(job).stdout.splitlines()]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.IsProcessInJob.argtypes = (wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL))
    handles = [kernel.OpenProcess(0x100000 | 0x1000, False, pid) for pid in pids]
    assert all(handles), "Both harmless processes must be alive before the stop"
    try:
        for handle in handles:
            contained = wintypes.BOOL()
            assert kernel.IsProcessInJob(handle, supervisor._active.process._job, ctypes.byref(contained))
            assert contained.value, "Descendant must inherit the exact containment job"
        if stop == "close_fallback":
            backend = importlib.import_module("core.recon.windows_process")
            monkeypatch.setattr(backend._native_api(), "TerminateJobObject", lambda *args: False)
            assert supervisor.cancel(job)
        elif stop == "cancel":
            assert supervisor.cancel(job)
        elif stop == "shutdown":
            supervisor.shutdown()
        elif stop == "about_to_quit":
            qapp.aboutToQuit.emit()
            # No further Qt event processing is needed to request native cleanup.
            assert all(kernel.WaitForSingleObject(handle, 3000) == 0 for handle in handles)
        result = native_runtime.finish(supervisor, job)
        assert result.state.value == ("TIMED_OUT" if stop == "timeout" else "CANCELLED")
        assert all(kernel.WaitForSingleObject(handle, 0) == 0 for handle in handles)
    finally:
        for handle in handles:
            kernel.CloseHandle(handle)


def test_normal_parent_exit_cleans_up_remaining_child(native_runtime, qapp):
    supervisor, job = native_runtime.start("tree_exit")
    wait_until(qapp, lambda: b"child " in supervisor.snapshot(job).stdout)
    pid = next(int(line.split()[1]) for line in supervisor.snapshot(job).stdout.splitlines()
               if line.startswith(b"child "))
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel.OpenProcess(0x100000, False, pid)
    assert handle
    try:
        assert native_runtime.finish(supervisor, job).state.value == "SUCCEEDED"
        assert kernel.WaitForSingleObject(handle, 0) == 0
    finally:
        kernel.CloseHandle(handle)


def test_native_output_budget_stays_bounded_and_does_not_deadlock(native_runtime):
    supervisor, job = native_runtime.start("flood", max_output_bytes=1000)
    result = native_runtime.finish(supervisor, job)
    assert result.state.value == "SUCCEEDED"
    assert len(result.stdout) + len(result.stderr) == 1000
    assert result.stdout_truncated and result.stderr_truncated


def test_windows_argv_round_trips_without_shell_interpretation(native_runtime):
    values = ("two words", 'quote"inside', "trailing \\", "$(not-a-command)", "&", "")
    supervisor, job = native_runtime.start("arguments", extra=values)
    result = native_runtime.finish(supervisor, job)
    assert result.state.value == "SUCCEEDED"
    assert json.loads(result.stdout) == list(values)


def test_containment_failure_never_resumes_user_code(native_runtime, monkeypatch, tmp_path):
    module = importlib.import_module("core.recon.windows_process")
    api = module._native_api()
    monkeypatch.setattr(api, "AssignProcessToJobObject", lambda *args: False)
    marker = tmp_path / "must-not-exist.txt"
    supervisor, job = native_runtime.start("marker", extra=(str(marker),))
    assert native_runtime.finish(supervisor, job).state.value == "FAILED"
    assert not marker.exists()


def test_start_failure_is_terminal_without_native_resource_leaks(native_runtime, monkeypatch):
    module = importlib.import_module("core.recon.windows_process")
    api = module._native_api()
    monkeypatch.setattr(api, "CreateProcessW", lambda *args: False)
    supervisor, job = native_runtime.start()
    result = native_runtime.finish(supervisor, job)
    assert result.state.value == "FAILED"
    assert not result.stdout and not result.stderr


def test_safety_gate_fails_closed_when_job_initialization_fails(monkeypatch):
    module = importlib.import_module("core.recon.windows_process")
    api = module._native_api()
    monkeypatch.setattr(api, "SetInformationJobObject", lambda *args: False)
    allowed, diagnostic = module.process_safety_status()
    assert not allowed
    assert diagnostic


@pytest.mark.parametrize("state", ["STARTING", "RUNNING"])
def test_reentrant_cancellation_at_state_signal_remains_terminal(native_runtime, qapp, state):
    supervisor, job = native_runtime.start("sleep")
    supervisor.job_changed.connect(
        lambda snapshot: supervisor.cancel(snapshot.job_id) if snapshot.state.value == state else None)
    result = native_runtime.finish(supervisor, job)
    assert result.state.value == "CANCELLED"


def test_safety_gate_fails_closed_without_native_platform(monkeypatch):
    module = importlib.import_module("core.recon.windows_process")
    monkeypatch.setattr(module, "_native_api", lambda: (_ for _ in ()).throw(OSError("unsupported")))
    assert module.process_safety_status()[0] is False


def test_preflight_revoked_during_starting_never_creates_process(native_runtime, monkeypatch, tmp_path):
    policy = importlib.import_module("core.recon.execution_policy")
    marker = tmp_path / "must-not-execute.txt"
    supervisor, job = native_runtime.start("marker", extra=(str(marker),))

    def revoke(snapshot):
        if snapshot.state.value == "STARTING":
            monkeypatch.delitem(policy._TRUSTED_ADAPTERS, "windows-fixture")

    supervisor.job_changed.connect(revoke)
    assert native_runtime.finish(supervisor, job).state.value == "FAILED"
    assert not marker.exists()


def test_executable_lock_denies_write_and_rename_and_releases_after_failure(tmp_path):
    module = importlib.import_module("core.recon.windows_process")
    image = tmp_path / "harmless-image.exe"
    image.write_bytes(b"MZ harmless bytes; never launched")
    renamed = tmp_path / "renamed.exe"
    assert hasattr(module, "locked_executable"), "Executable validation needs an image lock"
    with pytest.raises(ValueError, match="controlled validator failure"):
        with module.locked_executable(str(image)):
            with pytest.raises(PermissionError):
                image.write_bytes(b"replacement")
            with pytest.raises(PermissionError):
                image.rename(renamed)
            raise ValueError("controlled validator failure")
    assert image.read_bytes() == b"MZ harmless bytes; never launched"
    image.write_bytes(b"released")
    image.rename(renamed)
    assert renamed.read_bytes() == b"released"


def test_native_policy_validator_runs_while_image_write_and_rename_are_denied(native_runtime, monkeypatch, tmp_path):
    policy = importlib.import_module("core.recon.execution_policy")
    image = tmp_path / "never-launched.exe"
    image.write_bytes(b"MZ harmless non-executable fixture")
    # This file is deliberately unsuitable for execution. Its validator rejects
    # it, so the integration opt-in never reaches CreateProcessW for this path.
    monkeypatch.setattr(sys, "executable", str(image))
    original_validate = policy.ExecutionPolicy.validate
    starting = False
    denied = set()

    def validate(instance, spec):
        original_validate(instance, spec)
        if starting:
            try:
                image.write_bytes(b"unverified replacement")
            except PermissionError:
                denied.add("write")
            try:
                image.rename(tmp_path / "renamed.exe")
            except PermissionError:
                denied.add("rename")
            raise policy.ExecutionPolicyError("Controlled validation rejection")

    monkeypatch.setattr(policy.ExecutionPolicy, "validate", validate)
    supervisor, job = native_runtime.start()

    def mark_starting(snapshot):
        nonlocal starting
        if snapshot.state.value == "STARTING":
            starting = True

    supervisor.job_changed.connect(mark_starting)
    assert native_runtime.finish(supervisor, job).state.value == "FAILED"
    assert denied == {"write", "rename"}
    assert image.read_bytes() == b"MZ harmless non-executable fixture"
    image.write_bytes(b"lock released after rejection")
