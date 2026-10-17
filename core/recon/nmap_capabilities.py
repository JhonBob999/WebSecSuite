"""Conservative read-only Windows/Npcap execution capability observations."""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
import os
from pathlib import Path
import socket


@dataclass(frozen=True, slots=True)
class NmapCapabilities:
    windows: bool
    available: bool
    version: str
    npcap: bool
    elevated: bool
    ipv6: bool
    raw_packets: bool
    reasons: tuple[str, ...] = ()
    npcap_admin_only: bool | None = None


def _elevated():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _npcap_driver():
    """Read the installed driver's registry configuration; never start services."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap") as key:
            image, _ = winreg.QueryValueEx(key, "ImagePath")
            kind, _ = winreg.QueryValueEx(key, "Type")
        expanded = os.path.expandvars(image)
        if expanded.startswith("\\SystemRoot\\"):
            expanded = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / expanded[12:])
        return kind == 1 and Path(expanded.strip('"')).is_file()
    except (ImportError, OSError, TypeError, ValueError):
        return False


def _npcap_library():
    try:
        from core.recon.tool_discovery import _LocalInspection
        directory = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Npcap"
        for name in ("wpcap.dll", "Packet.dll"):
            _LocalInspection(True).path(directory / name)
        return True
    except (OSError, ValueError):
        return False


def _npcap_available():
    return _npcap_driver() and _npcap_library() and _npcap_service_running()


def _npcap_admin_only():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap\Parameters") as key:
            value, kind = winreg.QueryValueEx(key, "AdminOnly")
        return bool(value) if kind == winreg.REG_DWORD and value in (0, 1) else None
    except (ImportError, OSError, ValueError, TypeError):
        return None


def _npcap_service_running():
    """Query service state with SERVICE_QUERY_STATUS; never start the driver."""
    manager = service = None
    try:
        from ctypes import wintypes as wt
        library = ctypes.WinDLL("advapi32", use_last_error=True)
        library.OpenSCManagerW.argtypes = (wt.LPCWSTR, wt.LPCWSTR, wt.DWORD)
        library.OpenSCManagerW.restype = wt.HANDLE
        library.OpenServiceW.argtypes = (wt.HANDLE, wt.LPCWSTR, wt.DWORD)
        library.OpenServiceW.restype = wt.HANDLE
        library.QueryServiceStatusEx.argtypes = (wt.HANDLE, wt.DWORD, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD))
        library.QueryServiceStatusEx.restype = wt.BOOL
        library.CloseServiceHandle.argtypes = (wt.HANDLE,)
        library.CloseServiceHandle.restype = wt.BOOL
        class Status(ctypes.Structure):
            _fields_ = [(name, wt.DWORD) for name in ("type", "state", "controls", "exit_code", "specific_exit", "checkpoint", "wait_hint", "pid", "flags")]
        manager = library.OpenSCManagerW(None, None, 1)
        if not manager:
            return False
        service = library.OpenServiceW(manager, "npcap", 4)
        if not service:
            return False
        status, needed = Status(), wt.DWORD()
        return bool(library.QueryServiceStatusEx(service, 0, ctypes.byref(status), ctypes.sizeof(status), ctypes.byref(needed))) and status.state == 4
    except (AttributeError, OSError, ValueError):
        return False
    finally:
        if service:
            library.CloseServiceHandle(service)
        if manager:
            library.CloseServiceHandle(manager)


def detect_capabilities(tool=None) -> NmapCapabilities:
    """No probes, elevation, network queries, DLL loads or service modifications."""
    windows = os.name == "nt"
    available, version = False, ""
    if tool is not None:
        from core.recon.nmap_adapter import _validate_tool
        try:
            _validate_tool(tool)
            available, version = True, tool.version
        except ValueError:
            pass
    npcap = windows and _npcap_available()
    elevated = windows and _elevated()
    ipv6 = bool(socket.has_ipv6)
    reasons = [] if windows else ["Live Nmap execution requires the Windows containment backend."]
    admin_only = _npcap_admin_only() if windows and npcap else None
    if windows and not npcap:
        reasons.append("Npcap driver, capture libraries and a running driver service are all required for raw-packet scans.")
    if windows and npcap and not elevated:
        if admin_only is False:
            reasons.append("Npcap permits non-admin capture; this integration uses a conservative elevation gate because adapter access has not been actively probed.")
        elif admin_only is True:
            reasons.append("Npcap is installed in AdminOnly mode; raw scans require an already elevated application.")
        else:
            reasons.append("Npcap access policy is unknown; raw scans conservatively require an already elevated application.")
    return NmapCapabilities(windows, available, version, npcap, elevated, ipv6,
        windows and available and npcap and elevated, tuple(reasons), admin_only)


def capability_reasons(profile, caps: NmapCapabilities) -> tuple[str, ...]:
    reasons = []
    if type(caps) is not NmapCapabilities:
        return ("Refresh Windows capabilities before execution.",)
    if not caps.windows:
        reasons.append("Live scans require Windows process containment.")
    if not caps.available:
        reasons.append("Choose and verify an official Nmap executable first.")
    raw = (profile.technique != "tcp-connect" or profile.udp_scan or profile.os_detection or profile.traceroute
           or bool(profile.discovery_probes) or profile.discovery in {"default", "only"})
    if raw and not caps.npcap:
        reasons.append("This configuration requires an installed Npcap driver and capture libraries.")
    if raw and not caps.elevated:
        reasons.append("This raw-packet configuration requires an already elevated application; automatic elevation is disabled.")
    if raw and not caps.raw_packets and caps.npcap and caps.elevated:
        reasons.append("Raw-packet capability is unavailable; the scan will not fall back to TCP Connect.")
    return tuple(reasons)
