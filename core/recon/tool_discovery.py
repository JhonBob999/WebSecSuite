"""Read-only local CLI discovery; filenames never establish compatibility."""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class ToolDiscoveryStatus(Enum):
    NOT_FOUND = "Not found"
    CANDIDATE_UNVERIFIED = "Candidate found, not verified"
    INVALID_CANDIDATE = "Invalid candidate"
    NAME_COLLISION = "Name collision"


@dataclass(frozen=True)
class ToolDiscoveryRecord:
    tool_id: str
    display_name: str
    status: ToolDiscoveryStatus
    executable_path: str | None
    diagnostic: str
    compatibility_verified: bool = False
    adapter_connected: bool = False
    execution_permitted: bool = False


_TOOLS = (
    ("subfinder", "Subfinder"),
    ("httpx", "ProjectDiscovery httpx"),
    ("nmap", "Nmap"),
    ("ffuf", "FFUF"),
)
_READ_LIMIT = 65_536
_SCRIPT_SUFFIXES = {".bat", ".cmd", ".com", ".ps1", ".py", ".pyw", ".sh"}
_PYTHON_HTTPX_MARKERS = (b"from httpx import", b"httpx.__main__", b"httpx._main")
_NATIVE_POSIX_MAGICS = (
    b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
)


def _is_remote_windows_drive(path: Path) -> bool:
    """Query drive metadata locally, without touching a mapped drive's files."""
    if os.name != "nt":
        return False
    import ctypes

    get_drive_type = ctypes.WinDLL("kernel32", use_last_error=True).GetDriveTypeW
    get_drive_type.argtypes = [ctypes.c_wchar_p]
    get_drive_type.restype = ctypes.c_uint
    return get_drive_type(path.anchor) == 4  # DRIVE_REMOTE


class _UnsafeLocation(ValueError):
    pass


class _LocalInspection:
    """Reuse local metadata within one refresh, never between refreshes."""

    def __init__(self, windows: bool):
        self._windows = windows
        self._drives: dict[str, bool] = {}
        self._metadata: dict[Path, tuple[int, int] | str] = {}

    def _component(self, path: Path) -> tuple[int, int]:
        if path not in self._metadata:
            try:
                info = os.lstat(path)
            except FileNotFoundError:
                self._metadata[path] = "missing"
            except OSError:
                self._metadata[path] = "unreadable"
            else:
                self._metadata[path] = (info.st_mode, getattr(info, "st_file_attributes", 0))
        info = self._metadata[path]
        if info == "missing":
            raise FileNotFoundError
        if info == "unreadable":
            raise OSError("Local candidate cannot be inspected.")
        return info

    def path(self, value: str | os.PathLike[str], *, directory: bool = False) -> Path:
        raw = os.fspath(value)
        if not isinstance(raw, str) or not raw or any(ord(char) < 32 for char in raw):
            raise _UnsafeLocation("Candidate path is malformed.")
        if raw.replace("\\", "/").startswith("//"):
            raise _UnsafeLocation("Network and device paths are not inspected.")
        expanded = os.path.expanduser(raw)
        if expanded.replace("\\", "/").startswith("//"):
            raise _UnsafeLocation("Network and device paths are not inspected.")
        path = Path(os.path.abspath(expanded))
        if self._windows:
            if path.anchor not in self._drives:
                self._drives[path.anchor] = _is_remote_windows_drive(path)
            if self._drives[path.anchor]:
                raise _UnsafeLocation("Mapped network drives are not inspected.")

        # A junction may lead to UNC: inspect components without following links.
        current = Path(path.anchor)
        mode, attributes = self._component(current)
        for part in path.parts[1:]:
            if stat.S_ISLNK(mode) or attributes & 0x400:
                raise _UnsafeLocation("Symbolic links, junctions and reparse paths are not inspected.")
            current /= part
            mode, attributes = self._component(current)
        if stat.S_ISLNK(mode) or attributes & 0x400:
            raise _UnsafeLocation("Symbolic links, junctions and reparse paths are not inspected.")
        if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
            raise ValueError("Candidate is not a regular local file or directory.")
        return path


def _read_candidate(path: Path) -> tuple[bytes, bytes]:
    """Read bounded head/tail samples, including appended Python launchers."""
    with path.open("rb") as stream:
        head = stream.read(_READ_LIMIT)
        end = stream.seek(0, os.SEEK_END)
        tail = b""
        if end > len(head):
            stream.seek(max(len(head), end - _READ_LIMIT))
            tail = stream.read(_READ_LIMIT)
    return head, tail


def _python_httpx_candidate(path: Path, head: bytes, tail: bytes) -> bool:
    # Python console launchers commonly live in Scripts (Windows) or a venv's
    # bin. Treat those locations conservatively even if the sample is opaque.
    parts = tuple(part.lower() for part in path.parts[:-1])
    python_location = "scripts" in parts or (
        "bin" in parts and any(part in {"venv", ".venv", "virtualenv"} for part in parts)
    )
    return python_location or any(
        marker in sample.lower() for sample in (head, tail) for marker in _PYTHON_HTTPX_MARKERS
    )


def _native_candidate(path: Path, head: bytes, windows: bool) -> bool:
    if path.suffix.lower() in _SCRIPT_SUFFIXES or head.startswith(b"#!"):
        return False
    if windows:
        if path.suffix.lower() != ".exe" or len(head) < 64 or head[:2] != b"MZ":
            return False
        pe_offset = int.from_bytes(head[60:64], "little")
        return 64 <= pe_offset <= len(head) - 4 and head[pe_offset:pe_offset + 4] == b"PE\0\0"
    return head.startswith(_NATIVE_POSIX_MAGICS) and os.access(path, os.X_OK)


class ToolDiscoveryService:
    """Discover local candidates without spawning, importing or authorizing them.

    Explicit known_paths and path_entries replace the corresponding defaults,
    so tests and callers can inspect a deterministic set of local locations.
    Compatibility/version verification belongs to a future trusted adapter.
    """

    def __init__(
        self,
        *,
        known_paths: Mapping[str, Iterable[str | os.PathLike[str]]] | None = None,
        path_entries: Iterable[str | os.PathLike[str]] | None = None,
        platform: str | None = None,
    ) -> None:
        self._known_paths = None if known_paths is None else {
            tool_id: (paths,) if isinstance(paths, (str, os.PathLike)) else tuple(paths)
            for tool_id, paths in known_paths.items()
        }
        self._path_entries = None if path_entries is None else tuple(path_entries)
        self._windows = (platform or sys.platform).startswith("win")

    def _known_locations(self) -> dict[str, tuple[Path, ...]]:
        home = Path(os.environ.get("USERPROFILE") or os.environ.get("HOME") or os.path.expanduser("~"))
        directories = [home / "go" / "bin", home / ".local" / "bin"]
        if os.environ.get("GOBIN"):
            directories.append(Path(os.environ["GOBIN"]))
        directories.extend(
            Path(entry) / "bin" for entry in os.environ.get("GOPATH", "").split(os.pathsep) if entry
        )
        if not self._windows:
            directories.extend(Path(entry) for entry in ("/usr/local/bin", "/usr/bin", "/opt/homebrew/bin"))
        suffix = ".exe" if self._windows else ""
        locations = {
            tool_id: tuple(directory / (tool_id + suffix) for directory in directories)
            for tool_id, _ in _TOOLS
        }
        if self._windows:
            locations["nmap"] += tuple(
                Path(os.environ[key]) / "Nmap" / "nmap.exe"
                for key in ("ProgramFiles", "ProgramFiles(x86)") if os.environ.get(key)
            )
        return locations

    def _search_directories(self, inspection: _LocalInspection) -> tuple[tuple[Path, ...], bool]:
        entries = self._path_entries
        if entries is None:
            entries = os.environ.get("PATH", "").split(os.pathsep)
        directories = []
        skipped = False
        for entry in entries:
            try:
                raw = os.fspath(entry).strip().strip('"')
                # Empty/relative PATH entries implicitly search the working directory.
                if not raw or not Path(raw).is_absolute():
                    continue
                directory = inspection.path(raw, directory=True)
                if directory not in directories:
                    directories.append(directory)
            except FileNotFoundError:
                continue
            except (OSError, ValueError, TypeError):
                skipped = True
        return tuple(directories), skipped

    def _candidates(self, tool_id: str, known_paths: Mapping[str, Iterable], directories: tuple[Path, ...]) -> Iterable:
        yield from known_paths.get(tool_id, ())
        suffixes = (".exe", "", ".cmd", ".bat", ".ps1", ".py", ".sh") if self._windows else ("", ".sh", ".py")
        for directory in directories:
            for suffix in suffixes:
                yield directory / (tool_id + suffix)

    def discover(self) -> tuple[ToolDiscoveryRecord, ...]:
        known_paths = self._known_locations() if self._known_paths is None else self._known_paths
        inspection = _LocalInspection(self._windows)
        directories, skipped = self._search_directories(inspection)
        return tuple(
            self._discover_tool(tool_id, name, known_paths, inspection, directories, skipped)
            for tool_id, name in _TOOLS
        )

    def _discover_tool(
        self, tool_id: str, name: str, known_paths: Mapping, inspection: _LocalInspection,
        directories: tuple[Path, ...], skipped: bool,
    ) -> ToolDiscoveryRecord:
        rejected = None
        seen = set()
        for candidate in self._candidates(tool_id, known_paths, directories):
            try:
                key = os.path.normcase(os.fspath(candidate))
                if key in seen:
                    continue
                seen.add(key)
                path = inspection.path(candidate)
                head, tail = _read_candidate(path)
                if tool_id == "httpx" and _python_httpx_candidate(path, head, tail):
                    rejected = ToolDiscoveryRecord(
                        tool_id, name, ToolDiscoveryStatus.NAME_COLLISION, None,
                        "Possible Python HTTPX launcher; ProjectDiscovery compatibility is not verified.",
                    )
                    continue
                if not _native_candidate(path, head, self._windows):
                    raise ValueError("Candidate is not a supported native executable; scripts and wrappers are rejected.")
                return ToolDiscoveryRecord(
                    tool_id, name, ToolDiscoveryStatus.CANDIDATE_UNVERIFIED, str(path),
                    "Native executable candidate found; compatibility and version are not verified. Execution disabled.",
                )
            except FileNotFoundError:
                continue
            except (OSError, ValueError, TypeError) as error:
                if isinstance(error, _UnsafeLocation) and self._known_paths is None:
                    skipped = True
                    continue
                if rejected is None:
                    rejected = ToolDiscoveryRecord(
                        tool_id, name, ToolDiscoveryStatus.INVALID_CANDIDATE, None,
                        "Candidate is unreadable, unsafe, or not a supported local native executable. Execution disabled.",
                    )
        return rejected or ToolDiscoveryRecord(
            tool_id, name, ToolDiscoveryStatus.NOT_FOUND, None,
            "No local executable candidate found in known locations or PATH. "
            + ("Unsafe or unreadable search locations were skipped. " if skipped else "")
            + "Execution disabled.",
        )
