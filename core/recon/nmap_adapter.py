"""Reviewed Windows Nmap verification and narrowly approved scan profiles.

No discovery or import calls execute a program. Before a bounded --version
probe, require explicit path approval, local native-file discovery, official
Nmap version resources and an offline Windows Authenticode trust check with
an Nmap publisher allowlist. Every queued execution rechecks the file digest.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import json
import os
from pathlib import Path
import re
from time import monotonic
from weakref import WeakKeyDictionary, WeakSet
from xml.parsers import expat

from core.recon import execution_policy as policy
from core.recon.nmap_import import MAX_XML_DEPTH, MAX_XML_ELEMENTS, MAX_XML_STRING, _xml_root, parse_nmap_xml
from core.recon.observations import MAX_IMPORT_BYTES, ObservationBatch, ObservationImportError, EvidenceRef
from core.recon.tool_discovery import ToolDiscoveryService, ToolDiscoveryStatus
from core.recon.public_target import (
    PUBLIC_HOSTNAME, PUBLIC_PROFILE, PublicTargetObservation,
    claim_public_observation, validate_public_address, validate_public_observation,
)


LOCAL_TARGET = "127.0.0.1"
LOCAL_PORTS = (80, 443, 8080, 8443)
LOCAL_ARGUMENTS = (
    "-sT", "-Pn", "-n", "-p", "80,443,8080,8443", "--max-retries", "1",
    "--max-rate", "10", "--host-timeout", "30s", "--no-stylesheet", "-oX", "-", LOCAL_TARGET,
)
_MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
_VERSION = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}[A-Za-z0-9.]{0,24}")
_CANDIDATES = WeakSet()
_TOOLS = WeakSet()
_APPROVALS = WeakSet()
_BOUND_APPROVALS = WeakSet()
_PROBE_APPROVALS = WeakSet()
_PUBLIC_APPROVALS = WeakKeyDictionary()
PUBLIC_ARGUMENT_PREFIX = (
    "-sT", "-Pn", "-n", "-p", "80,443,8080,8443", "--max-retries", "1",
    "--max-rate", "10", "--host-timeout", "30s", "--no-stylesheet", "-oX", "-",
)
PUBLIC_TIMEOUT_MS = 40_000
PUBLIC_APPROVAL_TTL_SECONDS = 60


@dataclass(frozen=True, init=False, slots=True, weakref_slot=True, eq=False)
class ApprovedNmapCandidate:
    executable_path: str
    sha256: str
    resource_version: str

    def __init__(self):
        raise TypeError("Nmap candidates require explicit file approval and static identity checks.")


@dataclass(frozen=True, init=False, slots=True, weakref_slot=True, eq=False)
class ValidatedNmapTool:
    executable_path: str
    sha256: str
    version: str
    _candidate: ApprovedNmapCandidate = field(repr=False)

    def __init__(self):
        raise TypeError("Nmap tools require a completed, successful version verification.")


@dataclass(frozen=True, eq=False)
class _ProbeApproval:
    candidate: ApprovedNmapCandidate


@dataclass(frozen=True)
class _VersionRequest:
    candidate: ApprovedNmapCandidate


@dataclass(frozen=True)
class _SelfTestRequest:
    tool: ValidatedNmapTool


@dataclass(frozen=True, init=False, slots=True, weakref_slot=True, eq=False)
class PublicNmapApproval:
    """Ephemeral per-run IP grant; never serialized or added to target scope."""

    _tool: ValidatedNmapTool = field(repr=False)
    observation: PublicTargetObservation = field(repr=False)
    hostname: str
    address: str
    profile: str
    expires_at: float
    _program: str = field(repr=False)
    _sha256: str = field(repr=False)
    _arguments: tuple[str, ...] = field(repr=False)

    def __init__(self):
        raise TypeError("Public Nmap approval requires fresh DNS and explicit IP-scope confirmation.")


@dataclass(frozen=True)
class _PublicScanRequest:
    tool: ValidatedNmapTool
    approval: PublicNmapApproval


def _public_approval_identity(approval: PublicNmapApproval) -> tuple:
    return (approval._tool, approval.observation, approval.hostname, approval.address, approval.profile,
            approval.expires_at, approval._program, approval._sha256, approval._arguments)


def _validate_public_approval(approval: PublicNmapApproval) -> None:
    if (type(approval) is not PublicNmapApproval or approval not in _PUBLIC_APPROVALS
            or _public_approval_identity(approval) != _PUBLIC_APPROVALS[approval]):
        raise policy.ExecutionPolicyError("An unchanged explicit public Nmap approval is required.")
    if monotonic() >= approval.expires_at:
        raise policy.ExecutionPolicyError("Public Nmap approval expired; preflight and confirm again.")
    try:
        validate_public_observation(approval.observation)
    except ValueError as error:
        # The supervisor handles policy errors before starting any process.
        raise policy.ExecutionPolicyError(str(error)) from None
    _validate_tool(approval._tool)
    if (approval.hostname != PUBLIC_HOSTNAME or approval.observation.hostname != approval.hostname
            or validate_public_address(approval.address) not in approval.observation.ipv4_addresses
            or approval.profile != PUBLIC_PROFILE
            or approval._arguments != PUBLIC_ARGUMENT_PREFIX + (approval.address,)
            or approval._program != approval._tool.executable_path
            or approval._program != approval._tool._candidate.executable_path
            or approval._sha256 != approval._tool.sha256
            or approval._sha256 != approval._tool._candidate.sha256):
        raise policy.ExecutionPolicyError("The approved public target, profile or executable changed.")


def approve_public_nmap(tool: ValidatedNmapTool, observation: PublicTargetObservation, *,
                        address: str, scope_confirmed: bool, confirmed: bool) -> PublicNmapApproval:
    _validate_tool(tool)
    _require_safety()
    if confirmed is not True:
        raise policy.ExecutionPolicyError("Confirm the exact hostname, IP and public profile for this run.")
    expiry = claim_public_observation(observation, address, scope_confirmed=scope_confirmed)
    approval = object.__new__(PublicNmapApproval)
    for name, value in (
        ("_tool", tool), ("observation", observation), ("hostname", PUBLIC_HOSTNAME), ("address", address),
        ("profile", PUBLIC_PROFILE), ("expires_at", min(expiry, monotonic() + PUBLIC_APPROVAL_TTL_SECONDS)),
        ("_program", tool.executable_path), ("_sha256", tool.sha256),
        ("_arguments", PUBLIC_ARGUMENT_PREFIX + (address,)),
    ):
        object.__setattr__(approval, name, value)
    _PUBLIC_APPROVALS[approval] = _public_approval_identity(approval)
    return approval


def _process_safety() -> tuple[bool, str]:
    from core.recon.process_supervisor import process_safety_status
    return process_safety_status()


def _require_safety() -> None:
    safe, _reason = _process_safety()
    if not safe:
        raise policy.ExecutionPolicyError("Nmap is on HOLD: reliable Windows process containment is unavailable.")


def _file_digest(path: str) -> str:
    try:
        with Path(path).open("rb") as stream:
            digest = hashlib.sha256()
            total = 0
            while block := stream.read(65536):
                total += len(block)
                if total > _MAX_EXECUTABLE_BYTES:
                    raise OSError
                digest.update(block)
            if not total:
                raise OSError
            return digest.hexdigest()
    except (OSError, ValueError):
        raise policy.ExecutionPolicyError("The approved Nmap file is missing, unreadable or too large.") from None


def _discover_approved_path(path: str) -> str:
    if (not isinstance(path, str) or not Path(path).is_absolute()
            or path.replace("\\", "/").startswith("//") or ":" in path[2:]
            or Path(path).name.casefold() != "nmap.exe"):
        raise policy.ExecutionPolicyError("Choose an absolute local nmap.exe file.")
    record = next(record for record in ToolDiscoveryService(
        known_paths={"nmap": (path,)}, path_entries=(), platform="win32",
    ).discover() if record.tool_id == "nmap")
    if record.status is not ToolDiscoveryStatus.CANDIDATE_UNVERIFIED or not record.executable_path:
        raise policy.ExecutionPolicyError("The selected Nmap file is not a suitable local Windows executable.")
    return record.executable_path


def _read_version_resources(path: str) -> dict[str, str]:
    """Read PE version data with Windows data APIs; never load executable code."""
    import ctypes
    from ctypes import wintypes as wt

    dll = ctypes.WinDLL("version", use_last_error=True)
    dll.GetFileVersionInfoSizeW.argtypes = [wt.LPCWSTR, ctypes.POINTER(wt.DWORD)]
    dll.GetFileVersionInfoSizeW.restype = wt.DWORD
    dll.GetFileVersionInfoW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID]
    dll.GetFileVersionInfoW.restype = wt.BOOL
    dll.VerQueryValueW.argtypes = [wt.LPCVOID, wt.LPCWSTR, ctypes.POINTER(wt.LPVOID), ctypes.POINTER(wt.UINT)]
    dll.VerQueryValueW.restype = wt.BOOL
    ignored = wt.DWORD()
    size = dll.GetFileVersionInfoSizeW(path, ctypes.byref(ignored))
    if not 1 <= size <= 1024 * 1024:
        raise ValueError
    data = ctypes.create_string_buffer(size)
    if not dll.GetFileVersionInfoW(path, 0, size, data):
        raise ValueError
    values = {}
    # Official nmap.rc defines US English / Unicode (040904b0).
    for name in ("ProductName", "InternalName", "FileDescription", "OriginalFilename", "CompanyName", "FileVersion"):
        pointer, length = wt.LPVOID(), wt.UINT()
        if not dll.VerQueryValueW(data, "\\StringFileInfo\\040904b0\\" + name,
                                 ctypes.byref(pointer), ctypes.byref(length)) or not 1 <= length.value <= 256:
            raise ValueError
        values[name] = ctypes.wstring_at(pointer, length.value).rstrip("\x00")
    return values


def _trusted_publisher(path: str) -> str:
    """Verify embedded Authenticode locally and read the verified leaf subject.

    Windows cached trust only: no certificate/CRL URL retrieval is permitted.
    An unavailable chain or unrecognized signer fails closed.
    """
    import ctypes
    from ctypes import wintypes as wt

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD), ("Data4", ctypes.c_ubyte * 8)]

    class FileInfo(ctypes.Structure):
        _fields_ = [("cbStruct", wt.DWORD), ("pcwszFilePath", wt.LPCWSTR), ("hFile", wt.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

    class TrustData(ctypes.Structure):
        _fields_ = [("cbStruct", wt.DWORD), ("pPolicyCallbackData", ctypes.c_void_p), ("pSIPClientData", ctypes.c_void_p),
                    ("dwUIChoice", wt.DWORD), ("fdwRevocationChecks", wt.DWORD), ("dwUnionChoice", wt.DWORD),
                    ("pFile", ctypes.POINTER(FileInfo)), ("dwStateAction", wt.DWORD), ("hWVTStateData", wt.HANDLE),
                    ("pwszURLReference", wt.LPCWSTR), ("dwProvFlags", wt.DWORD), ("dwUIContext", wt.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    class ProviderCert(ctypes.Structure):
        _fields_ = [("cbStruct", wt.DWORD), ("pCert", ctypes.c_void_p)]

    class ProviderSigner(ctypes.Structure):
        _fields_ = [("cbStruct", wt.DWORD), ("sftVerifyAsOf", wt.FILETIME), ("csCertChain", wt.DWORD),
                    ("pasCertChain", ctypes.POINTER(ProviderCert))]

    trust = ctypes.WinDLL("wintrust", use_last_error=True)
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    trust.WinVerifyTrust.argtypes = [wt.HWND, ctypes.POINTER(GUID), ctypes.POINTER(TrustData)]
    trust.WinVerifyTrust.restype = wt.LONG
    trust.WTHelperProvDataFromStateData.argtypes = [wt.HANDLE]
    trust.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
    trust.WTHelperGetProvSignerFromChain.argtypes = [ctypes.c_void_p, wt.DWORD, wt.BOOL, wt.DWORD]
    trust.WTHelperGetProvSignerFromChain.restype = ctypes.POINTER(ProviderSigner)
    crypt.CertGetNameStringW.argtypes = [ctypes.c_void_p, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.LPWSTR, wt.DWORD]
    crypt.CertGetNameStringW.restype = wt.DWORD
    action = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    file = FileInfo(ctypes.sizeof(FileInfo), path, None, None)
    data = TrustData()
    data.cbStruct, data.dwUIChoice, data.dwUnionChoice = ctypes.sizeof(TrustData), 2, 1
    data.pFile, data.dwStateAction, data.dwProvFlags = ctypes.pointer(file), 1, 0x1010
    try:
        if trust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data)) != 0:
            raise ValueError
        provider = trust.WTHelperProvDataFromStateData(data.hWVTStateData)
        signer = trust.WTHelperGetProvSignerFromChain(provider, 0, False, 0) if provider else None
        if not signer or signer.contents.csCertChain < 1:
            raise ValueError
        certificate = signer.contents.pasCertChain[0].pCert
        oid = ctypes.c_char_p(b"2.5.4.10")  # Organization of the verified signer.
        name = ctypes.create_unicode_buffer(256)
        length = crypt.CertGetNameStringW(certificate, 3, 0, oid, name, len(name))
        if not 1 < length <= len(name):
            raise ValueError
        return name.value
    finally:
        data.dwStateAction = 2
        trust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))


def _inspect_native_identity(path: str) -> str:
    if os.name != "nt":
        raise policy.ExecutionPolicyError("Nmap R5 live integration requires Windows.")
    try:
        values = _read_version_resources(path)
        if (any(values[name] != "Nmap" for name in ("ProductName", "InternalName", "FileDescription"))
                or values["OriginalFilename"].casefold() != "nmap.exe"
                or values["CompanyName"] != "Insecure.Org" or not _VERSION.fullmatch(values["FileVersion"])
                or _trusted_publisher(path) not in {"Insecure.Com LLC", "Nmap Software LLC"}):
            raise ValueError
        return values["FileVersion"]
    except (OSError, ValueError, AttributeError):
        raise policy.ExecutionPolicyError(
            "Nmap identity is unverified: install an official signed Windows Nmap build with valid cached certificate trust."
        ) from None


def approve_nmap_path(path: str, *, confirmed: bool) -> ApprovedNmapCandidate:
    """Inspect only an explicitly approved file; do not execute a version probe."""
    if confirmed is not True:
        raise policy.ExecutionPolicyError("Explicit approval of the Nmap executable path is required.")
    canonical = _discover_approved_path(path)
    from core.recon.windows_process import locked_executable
    try:
        # A single deny-write/delete image handle binds the resources,
        # Authenticode result and both digests to the same immutable file.
        # Separate unlocked reads would permit an A/B/A replacement race.
        with locked_executable(canonical):
            if _discover_approved_path(canonical) != canonical:
                raise policy.ExecutionPolicyError("The selected Nmap path changed during approval.")
            before = _file_digest(canonical)
            version = _inspect_native_identity(canonical)
            if _file_digest(canonical) != before:
                raise policy.ExecutionPolicyError("The Nmap file changed during identity verification.")
    except OSError:
        raise policy.ExecutionPolicyError("The Nmap file could not be locked for safe identity verification.") from None
    candidate = object.__new__(ApprovedNmapCandidate)
    for name, value in (("executable_path", canonical), ("sha256", before), ("resource_version", version)):
        object.__setattr__(candidate, name, value)
    _CANDIDATES.add(candidate)
    return candidate


def _validate_candidate(candidate: ApprovedNmapCandidate) -> None:
    if type(candidate) is not ApprovedNmapCandidate or candidate not in _CANDIDATES:
        raise policy.ExecutionPolicyError("An explicitly approved and statically verified Nmap file is required.")
    if (_discover_approved_path(candidate.executable_path) != candidate.executable_path
            or _file_digest(candidate.executable_path) != candidate.sha256):
        raise policy.ExecutionPolicyError("The approved Nmap executable changed; approve and verify it again.")


def _validate_tool(tool: ValidatedNmapTool) -> None:
    if type(tool) is not ValidatedNmapTool or tool not in _TOOLS:
        raise policy.ExecutionPolicyError("A verified Nmap version is required before a local self-test.")
    _validate_candidate(tool._candidate)


class _VersionAdapter:
    request_type = _VersionRequest

    def build(self, request):
        _validate_candidate(request.candidate)
        return policy._AdapterPlan(request.candidate.executable_path, ("--version",), (), 5000)


class _SelfTestAdapter:
    request_type = _SelfTestRequest

    def build(self, request):
        _validate_tool(request.tool)
        return policy._AdapterPlan(request.tool.executable_path, LOCAL_ARGUMENTS, (LOCAL_TARGET,), 40000)


class _PublicScanAdapter:
    request_type = _PublicScanRequest

    def build(self, request):
        _validate_public_approval(request.approval)
        if request.tool is not request.approval._tool:
            raise policy.ExecutionPolicyError("Public approval belongs to another verified executable.")
        approval = request.approval
        return policy._AdapterPlan(approval._program, approval._arguments, (approval.address,), PUBLIC_TIMEOUT_MS)


_VERSION_ADAPTER = _VersionAdapter()
_SELF_TEST_ADAPTER = _SelfTestAdapter()
_PUBLIC_SCAN_ADAPTER = _PublicScanAdapter()


def _connect_adapters() -> None:
    policy._TRUSTED_ADAPTERS["nmap.version-check"] = _VERSION_ADAPTER
    policy._TRUSTED_ADAPTERS["nmap.local-self-test"] = _SELF_TEST_ADAPTER
    policy._TRUSTED_ADAPTERS["nmap.public-quick-discovery"] = _PUBLIC_SCAN_ADAPTER


def _validate_nmap_plan(adapter_id, adapter, plan, approval) -> None:
    _require_safety()
    if adapter_id == "nmap.public-profile":
        from core.recon.nmap_profile_execution import _validate_profile_plan
        _validate_profile_plan(adapter, plan, approval)
        return
    if (adapter_id == "nmap.version-check" and adapter is _VERSION_ADAPTER
            and type(approval) is _ProbeApproval and approval in _PROBE_APPROVALS):
        expected = _VERSION_ADAPTER.build(_VersionRequest(approval.candidate))
    elif (adapter_id == "nmap.local-self-test" and adapter is _SELF_TEST_ADAPTER
            and type(approval) is policy.LocalSelfTestApproval and approval in _APPROVALS):
        expected = _SELF_TEST_ADAPTER.build(_SelfTestRequest(approval._tool))
    elif (adapter_id == "nmap.public-quick-discovery" and adapter is _PUBLIC_SCAN_ADAPTER
            and type(approval) is PublicNmapApproval and approval in _PUBLIC_APPROVALS):
        expected = _PUBLIC_SCAN_ADAPTER.build(_PublicScanRequest(approval._tool, approval))
    else:
        raise policy.ExecutionPolicyError("A confirmation belonging to this exact Nmap operation is required.")
    if plan != expected:
        raise policy.ExecutionPolicyError("Only the immutable approved Nmap operation is allowed.")


def _bind_nmap_approval(approval) -> None:
    if approval in _BOUND_APPROVALS:
        raise policy.ExecutionPolicyError("Each Nmap confirmation can prepare only one execution.")
    _BOUND_APPROVALS.add(approval)


def prepare_nmap_version_check(candidate: ApprovedNmapCandidate) -> policy.ValidatedExecutionSpec:
    _validate_candidate(candidate)
    _require_safety()
    _connect_adapters()
    approval = _ProbeApproval(candidate)
    _PROBE_APPROVALS.add(approval)
    return policy.ExecutionPolicy().prepare("nmap.version-check", _VersionRequest(candidate), approval)


def verify_nmap_version(candidate: ApprovedNmapCandidate, result) -> ValidatedNmapTool:
    """Accept only a complete successful supervisor result, never arbitrary text."""
    from core.recon.process_supervisor import JobSnapshot, JobState
    _validate_candidate(candidate)
    if (type(result) is not JobSnapshot or result.adapter_id != "nmap.version-check"
            or result.state is not JobState.SUCCEEDED or result.exit_code != 0 or result.output_truncated
            or len(result.stdout) > 65536):
        raise policy.ExecutionPolicyError("Nmap version verification did not complete successfully.")
    match = re.match(rb"Nmap version ([0-9]{1,3}\.[0-9]{1,3}[A-Za-z0-9.]{0,24}) \( https://nmap\.org \)\r?\n", result.stdout)
    if match is None or match[1].decode("ascii") != candidate.resource_version:
        raise policy.ExecutionPolicyError("The Nmap version response did not match the approved executable.")
    tool = object.__new__(ValidatedNmapTool)
    for name, value in (("executable_path", candidate.executable_path), ("sha256", candidate.sha256),
                        ("version", candidate.resource_version), ("_candidate", candidate)):
        object.__setattr__(tool, name, value)
    _TOOLS.add(tool)
    return tool


def prepare_nmap_self_test(tool: ValidatedNmapTool, *, confirmed: bool, target=LOCAL_TARGET) -> policy.ValidatedExecutionSpec:
    _validate_tool(tool)
    _require_safety()
    if confirmed is not True or type(target) is not str or target != LOCAL_TARGET:
        raise policy.ExecutionPolicyError("Confirm this run on exactly 127.0.0.1 before starting the Nmap local self-test.")
    _connect_adapters()
    approval = object.__new__(policy.LocalSelfTestApproval)
    object.__setattr__(approval, "_tool", tool)
    _APPROVALS.add(approval)
    return policy.ExecutionPolicy().prepare("nmap.local-self-test", _SelfTestRequest(tool), approval)


def prepare_nmap_public_scan(tool: ValidatedNmapTool, approval: PublicNmapApproval) -> policy.ValidatedExecutionSpec:
    """Prepare exactly one approved numeric target, without accepting CLI input."""
    _require_safety()
    _validate_public_approval(approval)
    _connect_adapters()
    return policy.ExecutionPolicy().prepare(
        "nmap.public-quick-discovery", _PublicScanRequest(tool, approval), approval,
    )


def _normalize_local_xml(content: bytes) -> tuple[bytes, bool]:
    """Check original well-formedness before removing its sole benign DTD."""
    declaration = b"<!DOCTYPE nmaprun>"
    declarations = list(re.finditer(br"<!DOCTYPE\b", content, re.IGNORECASE))
    if declarations and (len(declarations) != 1 or
            content[declarations[0].start():declarations[0].start() + len(declaration)] != declaration):
        raise ObservationImportError("Unexpected Nmap XML DOCTYPE; only the exact harmless local form is supported.")
    parser = expat.ParserCreate(namespace_separator="}")
    declaration_count = depth = elements = 0

    def reject(*_args):
        raise ObservationImportError("Unexpected Nmap XML DTD or entity declaration.")

    def doctype(name, system, public, internal):
        nonlocal declaration_count
        if name != "nmaprun" or system is not None or public is not None or internal:
            reject()
        declaration_count += 1

    def start(name, attributes):
        nonlocal depth, elements
        depth += 1
        elements += 1
        if (depth > MAX_XML_DEPTH or elements > MAX_XML_ELEMENTS or len(attributes) > 32
                or len(name) > MAX_XML_STRING or any(len(key) > MAX_XML_STRING or len(value) > MAX_XML_STRING
                                                    for key, value in attributes.items())):
            raise ObservationImportError("Nmap XML exceeds its structural limits.")

    def end(_name):
        nonlocal depth
        depth -= 1

    parser.StartDoctypeDeclHandler = doctype
    parser.EntityDeclHandler = reject
    parser.ExternalEntityRefHandler = reject
    parser.SkippedEntityHandler = reject
    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(content, True)
    except (expat.ExpatError, LookupError, ValueError) as error:
        if isinstance(error, ObservationImportError):
            raise
        raise ObservationImportError("Malformed or truncated Nmap XML process output.") from None
    if declaration_count != len(declarations):
        # A DOCTYPE-looking token in comments/CDATA is not a declaration and
        # must never be removed from those locations to repair malformed XML.
        raise ObservationImportError("Nmap XML contains unexpected declaration text.")
    if declarations:
        offset = declarations[0].start()
        return content[:offset] + content[offset + len(declaration):], True
    return content, False


def parse_trusted_nmap_output(content: bytes) -> ObservationBatch:
    """Normalize exactly Nmap's inert DOCTYPE only for trusted process output.

    The offline importer remains strict. Original bytes define the digest/run
    identity even when the declaration is removed for the existing R3 parser.
    """
    if type(content) is not bytes or not content or len(content) > MAX_IMPORT_BYTES:
        raise ObservationImportError("Complete bounded Nmap XML process output is required.")
    if b"\x00" in content:
        raise ObservationImportError("Trusted Nmap output must use its UTF-8 XML format.")
    normalized, declaration_removed = _normalize_local_xml(content)
    root = _xml_root(normalized)
    if root.get("scanner") != "nmap":
        raise ObservationImportError("The local report must identify the Nmap scanner.")
    finished = root.findall("runstats/finished")
    if len(finished) != 1 or finished[0].get("exit") != "success":
        raise ObservationImportError("Nmap did not report a complete successful scan.")
    hosts = root.findall("host")
    if len(hosts) != 1:
        raise ObservationImportError("The local self-test report must contain exactly one loopback host.")
    statuses = hosts[0].findall("status")
    summaries = root.findall("runstats/hosts")
    if (hosts[0].get("timedout") not in {None, "false"} or len(statuses) != 1
            or statuses[0].get("state") != "up" or len(summaries) != 1
            or any(summaries[0].get(name) != value for name, value in (("up", "1"), ("down", "0"), ("total", "1")))):
        raise ObservationImportError("The local self-test host did not complete successfully.")
    addresses = hosts[0].findall("address")
    if (len(addresses) != 1 or addresses[0].get("addrtype") != "ipv4"
            or addresses[0].get("addr") != LOCAL_TARGET or hosts[0].findall("hostnames/hostname")):
        raise ObservationImportError("The local self-test report contains an unexpected target identity.")
    port_containers = hosts[0].findall("ports")
    if len(port_containers) != 1:
        raise ObservationImportError("The local self-test report is missing complete port results.")
    seen_ports = set()
    for port in port_containers[0].findall("port"):
        if port.get("protocol") != "tcp" or port.get("portid") not in {"80", "443", "8080", "8443"}:
            raise ObservationImportError("The local self-test report contains an unexpected port or transport.")
        states = port.findall("state")
        if (port.get("portid") in seen_ports or len(states) != 1
                or states[0].get("state") not in {"open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"}):
            raise ObservationImportError("The local self-test report has duplicate or incomplete port outcomes.")
        seen_ports.add(port.get("portid"))
    reported = len(seen_ports)
    for extra in port_containers[0].findall("extraports"):
        count = extra.get("count", "")
        if (not re.fullmatch(r"[0-4]", count) or extra.get("state") not in
                {"closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"}):
            raise ObservationImportError("The local self-test report has invalid aggregate port outcomes.")
        reported += int(count)
    if reported != 4:
        raise ObservationImportError("The local self-test did not report all four selected ports.")
    scans = root.findall("scaninfo")
    if (len(scans) != 1 or scans[0].get("type") != "connect" or scans[0].get("protocol") != "tcp"
            or scans[0].get("numservices") != "4" or scans[0].get("services") != "80,443,8080,8443"):
        raise ObservationImportError("The local self-test report has an unexpected scan profile.")
    batch = parse_nmap_xml(normalized)
    digest = hashlib.sha256(content).hexdigest()
    run_id = "nmap:sha256:" + digest
    observations = []
    for observation in batch.observations:
        evidence = []
        for item in observation.evidence:
            metadata = item.metadata
            if item.kind == "nmap-run":
                metadata = {**metadata, "file_sha256": digest, "file_size": len(content),
                            "doctype_normalized": declaration_removed, "execution_mode": "local-self-test",
                            "profile": "Local Self-Test", "target": LOCAL_TARGET, "ports": list(LOCAL_PORTS),
                            "technique": "tcp-connect"}
            evidence.append(EvidenceRef(item.ref.replace(batch.run_id, run_id, 1), item.kind,
                                        None if metadata is None else json.dumps(metadata, sort_keys=True, separators=(",", ":"))))
        observations.append(replace(observation, run_id=run_id, evidence=tuple(evidence)))
    return replace(batch, run_id=run_id, observations=tuple(observations))


__all__ = ["ApprovedNmapCandidate", "ValidatedNmapTool", "approve_nmap_path", "prepare_nmap_version_check",
           "verify_nmap_version", "prepare_nmap_self_test", "parse_trusted_nmap_output", "LOCAL_TARGET", "LOCAL_PORTS",
           "PublicNmapApproval", "approve_public_nmap", "prepare_nmap_public_scan"]
