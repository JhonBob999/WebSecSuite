"""Read-only discovery never executes or authorizes external tools."""

import importlib
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest


def api():
    return importlib.import_module("core.recon.tool_discovery")


def native_executable(path, payload=b""):
    path.parent.mkdir(parents=True, exist_ok=True)
    header = bytearray(512)
    header[:2] = b"MZ"
    header[60:64] = (128).to_bytes(4, "little")
    header[128:132] = b"PE\0\0"
    path.write_bytes(header + payload)
    return path


def discover(known_paths=None, path_entries=(), platform="win32"):
    return api().ToolDiscoveryService(
        known_paths=known_paths or {}, path_entries=path_entries, platform=platform
    ).discover()


def record_for(records, tool_id):
    return next(record for record in records if record.tool_id == tool_id)


def test_missing_tools_are_distinct_immutable_records_with_disabled_defaults():
    records = discover()
    assert isinstance(records, tuple)
    assert [record.tool_id for record in records] == ["subfinder", "httpx", "nmap", "ffuf"]
    assert [record.display_name for record in records] == [
        "Subfinder", "ProjectDiscovery httpx", "Nmap", "FFUF"
    ]
    for record in records:
        assert record.status is api().ToolDiscoveryStatus.NOT_FOUND
        assert record.executable_path is None
        assert record.diagnostic
        assert record.compatibility_verified is False
        assert record.adapter_connected is False
        assert record.execution_permitted is False
    with pytest.raises(FrozenInstanceError):
        records[0].execution_permitted = True


def test_candidate_from_path_is_absolute_unverified_and_never_executed(tmp_path):
    candidate = native_executable(tmp_path / "nmap.exe")
    record = record_for(discover(path_entries=(str(tmp_path),)), "nmap")
    assert record.status is api().ToolDiscoveryStatus.CANDIDATE_UNVERIFIED
    assert record.executable_path == str(candidate.absolute())
    assert "not verified" in record.diagnostic.lower()
    assert record.compatibility_verified is False
    assert record.execution_permitted is False


def test_relative_known_candidate_normalizes_to_an_absolute_path(tmp_path, monkeypatch):
    native_executable(tmp_path / "tools" / "ffuf.exe")
    monkeypatch.chdir(tmp_path)
    record = record_for(discover({"ffuf": ["tools/../tools/ffuf.exe"]}), "ffuf")
    assert record.executable_path == str(tmp_path / "tools" / "ffuf.exe")
    assert Path(record.executable_path).is_absolute()
    assert record.status is api().ToolDiscoveryStatus.CANDIDATE_UNVERIFIED


@pytest.mark.parametrize("kind", ["directory", "text", "dos_only", "script_in_exe", "cmd", "ps1", "py"])
def test_invalid_candidates_are_reported_without_a_runnable_path(tmp_path, kind):
    candidate = tmp_path / "nmap.exe"
    if kind == "directory":
        candidate.mkdir()
    elif kind == "text":
        candidate.write_text("not an executable", encoding="utf-8")
    elif kind == "dos_only":
        candidate.write_bytes(b"MZ" + b"\0" * 100)
    elif kind == "script_in_exe":
        candidate.write_bytes(b"#!/bin/sh\necho hello\n")
    else:
        candidate = tmp_path / f"nmap.{kind}"
        candidate.write_text("echo hello", encoding="utf-8")
    record = record_for(discover({"nmap": [candidate]}), "nmap")
    assert record.status is api().ToolDiscoveryStatus.INVALID_CANDIDATE
    assert record.executable_path is None
    assert record.diagnostic
    assert record.execution_permitted is False


def test_path_shell_wrapper_is_detected_but_not_accepted(tmp_path):
    (tmp_path / "subfinder.cmd").write_text("echo hello", encoding="utf-8")
    record = record_for(discover(path_entries=(tmp_path,)), "subfinder")
    assert record.status is api().ToolDiscoveryStatus.INVALID_CANDIDATE
    assert record.executable_path is None


@pytest.mark.parametrize("candidate", [None, 17, "", "bad\x00path", Path(Path.cwd().anchor)])
def test_malformed_or_root_known_paths_do_not_abort_discovery(candidate):
    records = discover({"nmap": [candidate]})
    record = record_for(records, "nmap")
    assert record.status is api().ToolDiscoveryStatus.INVALID_CANDIDATE
    assert record.executable_path is None
    assert len(records) == 4


def test_refresh_rechecks_files_without_cached_detection(tmp_path):
    service = api().ToolDiscoveryService(known_paths={}, path_entries=(tmp_path,), platform="win32")
    assert record_for(service.discover(), "nmap").status is api().ToolDiscoveryStatus.NOT_FOUND
    native_executable(tmp_path / "nmap.exe")
    record = record_for(service.discover(), "nmap")
    assert record.status is api().ToolDiscoveryStatus.CANDIDATE_UNVERIFIED
    assert record.compatibility_verified is False


def test_unreadable_candidate_returns_safe_diagnostic(tmp_path, monkeypatch):
    candidate = native_executable(tmp_path / "nmap.exe")

    def unreadable(*args, **kwargs):
        raise PermissionError("secret credential should not appear in diagnostic")

    monkeypatch.setattr(Path, "open", unreadable)
    record = record_for(discover({"nmap": [candidate]}), "nmap")
    assert record.status is api().ToolDiscoveryStatus.INVALID_CANDIDATE
    assert "secret credential" not in record.diagnostic


@pytest.mark.parametrize("marker", [b"from httpx import main", b"httpx.__main__", b"httpx._main:main"])
def test_python_httpx_launcher_is_a_name_collision(tmp_path, marker):
    candidate = native_executable(tmp_path / "httpx.exe", marker)
    record = record_for(discover({"httpx": [candidate]}), "httpx")
    assert record.status is api().ToolDiscoveryStatus.NAME_COLLISION
    assert record.executable_path is None
    assert "python" in record.diagnostic.lower()
    assert record.compatibility_verified is False


def test_httpx_in_python_scripts_directory_is_conservatively_a_collision(tmp_path):
    candidate = native_executable(tmp_path / ".venv" / "Scripts" / "httpx.exe")
    record = record_for(discover({"httpx": [candidate]}), "httpx")
    assert record.status is api().ToolDiscoveryStatus.NAME_COLLISION
    assert record.executable_path is None
    assert "python" in record.diagnostic.lower()


def test_native_httpx_name_alone_does_not_verify_projectdiscovery_compatibility(tmp_path):
    candidate = native_executable(tmp_path / "go" / "bin" / "httpx.exe")
    record = record_for(discover({"httpx": [candidate]}), "httpx")
    assert record.status is api().ToolDiscoveryStatus.CANDIDATE_UNVERIFIED
    assert record.executable_path == str(candidate)
    assert record.compatibility_verified is False


def test_later_native_candidate_can_be_found_after_a_python_collision(tmp_path):
    python_httpx = native_executable(tmp_path / "venv" / "Scripts" / "httpx.exe")
    native_httpx = native_executable(tmp_path / "go" / "bin" / "httpx.exe")
    record = record_for(discover({"httpx": [python_httpx, native_httpx]}), "httpx")
    assert record.status is api().ToolDiscoveryStatus.CANDIDATE_UNVERIFIED
    assert record.executable_path == str(native_httpx)


def test_default_known_locations_include_user_go_bin(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("GOPATH", raising=False)
    candidate = native_executable(tmp_path / "go" / "bin" / "subfinder.exe")
    records = api().ToolDiscoveryService(path_entries=(), platform="win32").discover()
    assert record_for(records, "subfinder").executable_path == str(candidate)


@pytest.mark.parametrize("path", [r"\\server\tools\nmap.exe", r"\\?\C:\tools\nmap.exe", r"\\.\pipe\nmap.exe", "//server/tools/nmap.exe"])
def test_unc_and_device_candidates_are_rejected_before_filesystem_reads(monkeypatch, path):
    module = api()

    def forbidden(*args, **kwargs):
        raise AssertionError("Unsafe path must not be inspected")

    monkeypatch.setattr(module.os, "lstat", forbidden)
    record = record_for(discover({"nmap": [path]}), "nmap")
    assert record.status is module.ToolDiscoveryStatus.INVALID_CANDIDATE
    assert record.executable_path is None


def test_mapped_network_drive_is_rejected_before_filesystem_reads(tmp_path, monkeypatch):
    module = api()
    monkeypatch.setattr(module, "_is_remote_windows_drive", lambda path: True)

    def forbidden(*args, **kwargs):
        raise AssertionError("Mapped network drive must not be inspected")

    monkeypatch.setattr(module.os, "lstat", forbidden)
    record = record_for(discover({"nmap": [tmp_path / "nmap.exe"]}), "nmap")
    assert record.status is module.ToolDiscoveryStatus.INVALID_CANDIDATE
    assert record.executable_path is None


def test_unsafe_path_directories_are_skipped_without_claiming_a_candidate():
    records = discover(path_entries=(r"\\server\tools", r"\\?\C:\tools"))
    assert all(record.status is api().ToolDiscoveryStatus.NOT_FOUND for record in records)
    assert all("skipped" in record.diagnostic.lower() for record in records)


def test_discovery_reuses_local_component_and_drive_metadata(tmp_path, monkeypatch):
    module = api()
    native_executable(tmp_path / "tools" / "nmap.exe")
    original_lstat = module.os.lstat
    original_remote_check = module._is_remote_windows_drive
    inspected_paths = []
    inspected_drives = []

    def inspect_path(path, *args, **kwargs):
        inspected_paths.append(str(path))
        return original_lstat(path, *args, **kwargs)

    def inspect_drive(path):
        inspected_drives.append(path.anchor)
        return original_remote_check(path)

    monkeypatch.setattr(module.os, "lstat", inspect_path)
    monkeypatch.setattr(module, "_is_remote_windows_drive", inspect_drive)
    records = discover(path_entries=(tmp_path / "tools", tmp_path / "tools"))
    assert record_for(records, "nmap").status is module.ToolDiscoveryStatus.CANDIDATE_UNVERIFIED
    assert len(inspected_paths) == len(set(inspected_paths))
    assert len(inspected_drives) == len(set(inspected_drives))


def test_reparse_component_is_rejected_before_opening_its_target(tmp_path, monkeypatch):
    module = api()
    candidate = native_executable(tmp_path / "tools" / "nmap.exe")
    original_lstat = module.os.lstat

    class ReparseInfo:
        st_mode = 0o040755
        st_file_attributes = 0x400

    def reparse_lstat(path, *args, **kwargs):
        if Path(path) == candidate.parent:
            return ReparseInfo()
        return original_lstat(path, *args, **kwargs)

    def forbidden(*args, **kwargs):
        raise AssertionError("Reparse target must not be opened")

    monkeypatch.setattr(module.os, "lstat", reparse_lstat)
    monkeypatch.setattr(Path, "open", forbidden)
    record = record_for(discover({"nmap": [candidate]}), "nmap")
    assert record.status is module.ToolDiscoveryStatus.INVALID_CANDIDATE
    assert record.executable_path is None


def test_large_httpx_launcher_is_read_in_bounded_chunks_including_tail(tmp_path, monkeypatch):
    candidate = native_executable(tmp_path / "httpx.exe")
    with candidate.open("ab") as stream:
        stream.seek(0)
        stream.write(b"\0" * 200_000)
        stream.write(b"from httpx import main")
    original_open = Path.open
    reads = []

    class BoundedReader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, size=-1):
            assert 0 <= size <= 65_536
            reads.append(size)
            return self.stream.read(size)

        def seek(self, *args):
            return self.stream.seek(*args)

        def tell(self):
            return self.stream.tell()

    monkeypatch.setattr(Path, "open", lambda path, *args, **kwargs: BoundedReader(original_open(path, *args, **kwargs)))
    record = record_for(discover({"httpx": [candidate]}), "httpx")
    assert record.status is api().ToolDiscoveryStatus.NAME_COLLISION
    assert len(reads) <= 2
    assert sum(reads) <= 131_072


def test_posix_candidate_requires_native_binary_and_execute_permission(tmp_path, monkeypatch):
    candidate = tmp_path / "ffuf"
    candidate.write_bytes(b"\x7fELF" + b"\0" * 200)
    monkeypatch.setattr(api().os, "access", lambda *args: False)
    record = record_for(discover({"ffuf": [candidate]}, platform="linux"), "ffuf")
    assert record.status is api().ToolDiscoveryStatus.INVALID_CANDIDATE
    monkeypatch.setattr(api().os, "access", lambda *args: True)
    record = record_for(discover({"ffuf": [candidate]}, platform="linux"), "ffuf")
    assert record.status is api().ToolDiscoveryStatus.CANDIDATE_UNVERIFIED
