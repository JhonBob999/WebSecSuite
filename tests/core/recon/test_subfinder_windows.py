"""Real shared Windows backend with a harmless credential-free child fixture."""

from dataclasses import replace
import json
import os

import pytest

from core.recon import execution_policy
from tests.core.recon.test_windows_process import native_runtime


pytestmark = [pytest.mark.skipif(os.name != "nt", reason="Native Windows containment"),
              pytest.mark.native_local_process]


def test_native_child_receives_only_explicit_unicode_environment_and_directory(native_runtime, monkeypatch, tmp_path):
    monkeypatch.setenv("RECON_FIXTURE_SECRET", "must-not-leak")
    adapter = execution_policy._TRUSTED_ADAPTERS["windows-fixture"]
    original_build = adapter.build
    environment = tuple(sorted({
        "SystemRoot": os.environ["SystemRoot"], "WINDIR": os.environ["WINDIR"],
        "RECON_FIXTURE_ENV": "isolated ☃",
    }.items()))
    monkeypatch.setattr(adapter, "build", lambda request: replace(
        original_build(request), environment=environment, working_directory=str(tmp_path)))
    supervisor, job = native_runtime.start("environment")
    result = native_runtime.finish(supervisor, job)
    assert result.state.value == "SUCCEEDED"
    document = json.loads(result.stdout)
    assert document["environment"]["RECON_FIXTURE_ENV"] == "isolated ☃"
    assert "RECON_FIXTURE_SECRET" not in document["environment"]
    assert "HTTPS_PROXY" not in document["environment"]
    assert os.path.normcase(document["directory"]) == os.path.normcase(str(tmp_path))


@pytest.mark.parametrize("stop", ["cancel", "timeout", "shutdown"])
def test_isolated_environment_preserves_native_parent_and_child_containment(
    native_runtime, monkeypatch, tmp_path, qapp, stop,
):
    import ctypes
    from ctypes import wintypes
    from tests.core.recon.test_windows_process import wait_until

    adapter = execution_policy._TRUSTED_ADAPTERS["windows-fixture"]
    original_build = adapter.build
    environment = tuple(sorted({"SystemRoot": os.environ["SystemRoot"], "WINDIR": os.environ["WINDIR"]}.items()))
    monkeypatch.setattr(adapter, "build", lambda request: replace(
        original_build(request), environment=environment, working_directory=str(tmp_path)))
    supervisor, job = native_runtime.start("tree", timeout_ms=2000 if stop == "timeout" else 5000)
    wait_until(qapp, lambda: b"parent " in supervisor.snapshot(job).stdout
               and b"child " in supervisor.snapshot(job).stdout)
    pids = [int(line.split()[1]) for line in supervisor.snapshot(job).stdout.splitlines()]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.IsProcessInJob.argtypes = (wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL))
    handles = [kernel.OpenProcess(0x100000 | 0x1000, False, pid) for pid in pids]
    assert all(handles)
    try:
        for handle in handles:
            contained = wintypes.BOOL()
            assert kernel.IsProcessInJob(handle, supervisor._active.process._job, ctypes.byref(contained))
            assert contained.value
        if stop == "cancel":
            supervisor.cancel(job)
        elif stop == "shutdown":
            supervisor.shutdown(immediate=True)
        result = native_runtime.finish(supervisor, job)
        assert result.state.value == ("TIMED_OUT" if stop == "timeout" else "CANCELLED")
        assert all(kernel.WaitForSingleObject(handle, 0) == 0 for handle in handles)
    finally:
        for handle in handles:
            kernel.CloseHandle(handle)
