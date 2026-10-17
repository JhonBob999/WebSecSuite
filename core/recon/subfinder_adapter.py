"""Release-backed Windows Subfinder trust and one-shot passive capabilities.

Release ZIP checksums authenticate the selected executable before any probe.
No download, installation, DNS lookup or executable discovery runs code here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import io
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory
from time import monotonic
from weakref import WeakKeyDictionary, WeakSet
import zipfile

from core.recon import execution_policy as policy
from core.recon.targets import normalize_hostname
from core.recon.tool_discovery import ToolDiscoveryService, ToolDiscoveryStatus, _LocalInspection


PROFILE = "Passive Standard"
RELEASE_VERSION = "2.17.0"
# Official v2.17.0 checksum asset and GitHub release API asset digests agree.
# https://github.com/projectdiscovery/subfinder/releases/tag/v2.17.0
_RELEASE_ARCHIVES = {
    "subfinder_2.17.0_windows_amd64.zip": "a3fd612928d591fb31c1e59a2e06055e364421ba32251e553073f5673a2d3103",
    "subfinder_2.17.0_windows_arm64.zip": "579f8dc7b5bb3da01672fb8b48ba1c232002fe20d1f22d3ddf4b952790f65fe9",
}
PASSIVE_ARGUMENTS = ("-oJ", "-cs", "-silent", "-nc", "-duc", "-rl", "2", "-timeout", "15", "-max-time", "2")
VERSION_ARGUMENTS = ("-version", "-duc", "-nc")
PASSIVE_TIMEOUT_MS = 150_000
_MAX_FILE_BYTES = 128 * 1024 * 1024
_CANDIDATES = WeakKeyDictionary()
_TOOLS = WeakKeyDictionary()
_APPROVALS = WeakKeyDictionary()
_PROBES = WeakKeyDictionary()
_BOUND = WeakSet()


class _IsolatedConfiguration:
    """Private empty config and credential-free environment, never user config."""

    def __init__(self):
        self._temporary = TemporaryDirectory(prefix="websecsuite-subfinder-")
        self.directory = str(Path(self._temporary.name).resolve())
        root = Path(self.directory)
        appdata = root / "appdata"
        config = appdata / "subfinder" / "config.yaml"
        config.parent.mkdir(parents=True)
        providers = config.parent / "provider-config.yaml"
        for path in (config, providers):
            path.write_bytes(b"{}\n")
        self.files = (str(config), str(providers))
        environment = {key: value for key in ("SystemRoot", "WINDIR", "SystemDrive")
                       if (value := os.environ.get(key))}
        environment.update(APPDATA=str(appdata), LOCALAPPDATA=str(appdata),
                           USERPROFILE=self.directory, HOME=self.directory,
                           TEMP=self.directory, TMP=self.directory,
                           SUBFINDER_CONFIG=str(config), SUBFINDER_PROVIDER_CONFIG=str(providers))
        self.environment = tuple(sorted(environment.items()))

    def validate(self):
        try:
            for path in self.files:
                local = _LocalInspection(True).path(path)
                with local.open("rb") as stream:
                    if stream.read(4) != b"{}\n":
                        raise ValueError
        except (OSError, ValueError):
            raise policy.ExecutionPolicyError("Subfinder's isolated empty configuration changed; verify again.") from None


@dataclass(frozen=True, init=False, slots=True, weakref_slot=True, eq=False)
class ApprovedSubfinderCandidate:
    executable_path: str
    sha256: str
    version: str
    archive_name: str
    _configuration: _IsolatedConfiguration = field(repr=False)

    def __init__(self):
        raise TypeError("Subfinder requires explicit release-backed executable approval.")


@dataclass(frozen=True, init=False, slots=True, weakref_slot=True, eq=False)
class ValidatedSubfinderTool:
    executable_path: str
    sha256: str
    version: str
    _candidate: ApprovedSubfinderCandidate = field(repr=False)

    def __init__(self):
        raise TypeError("Subfinder requires a successful bounded version check.")


@dataclass(frozen=True, init=False, slots=True, weakref_slot=True, eq=False)
class SubfinderApproval:
    _tool: ValidatedSubfinderTool = field(repr=False)
    hostname: str
    profile: str
    expires_at: float
    _scope: policy.ScopeApproval = field(repr=False)

    def __init__(self):
        raise TypeError("Subfinder approval requires explicit per-run passive scope confirmation.")


@dataclass(frozen=True, eq=False)
class _ProbeApproval:
    candidate: ApprovedSubfinderCandidate


@dataclass(frozen=True)
class _VersionRequest:
    candidate: ApprovedSubfinderCandidate


@dataclass(frozen=True)
class _DiscoveryRequest:
    tool: ValidatedSubfinderTool
    approval: SubfinderApproval


def _identity(value):
    return tuple(getattr(value, name) for name in value.__dataclass_fields__)


def _require_registered(value, kind, registry, message):
    if type(value) is not kind or value not in registry or _identity(value) != registry[value]:
        raise policy.ExecutionPolicyError(message)


def selected_subfinder_hostname(selected_targets) -> str:
    if type(selected_targets) not in (tuple, list) or len(selected_targets) != 1:
        raise policy.ExecutionPolicyError("Select exactly one valid Target Manager hostname.")
    try:
        return normalize_hostname(selected_targets[0])
    except (ValueError, TypeError):
        raise policy.ExecutionPolicyError("Select exactly one valid Target Manager hostname.") from None


def _process_safety():
    from core.recon.process_supervisor import process_safety_status
    return process_safety_status()


def _require_safety():
    if not _process_safety()[0]:
        raise policy.ExecutionPolicyError("Subfinder is on HOLD: Windows process-tree containment is unavailable.")


def _local_path(path: str) -> Path:
    if (type(path) is not str or not Path(path).is_absolute()
            or path.replace("\\", "/").startswith("//") or ":" in path[2:]):
        raise policy.ExecutionPolicyError("Choose an absolute regular local file; network/device paths are rejected.")
    try:
        return _LocalInspection(True).path(path)
    except (OSError, ValueError, TypeError):
        raise policy.ExecutionPolicyError("The selected local file is missing, unsafe or unreadable.") from None


def _executable_path(path):
    local = _local_path(path)
    if local.name.casefold() != "subfinder.exe":
        raise policy.ExecutionPolicyError("Choose an absolute local subfinder.exe file.")
    record = next(item for item in ToolDiscoveryService(
        known_paths={"subfinder": (str(local),)}, path_entries=(), platform="win32",
    ).discover() if item.tool_id == "subfinder")
    if record.status is not ToolDiscoveryStatus.CANDIDATE_UNVERIFIED or not record.executable_path:
        raise policy.ExecutionPolicyError("The selected Subfinder file is not a native Windows executable.")
    return record.executable_path


def _bounded_bytes(path):
    try:
        with Path(path).open("rb") as stream:
            content = stream.read(_MAX_FILE_BYTES + 1)
        if not 0 < len(content) <= _MAX_FILE_BYTES:
            raise ValueError
        return content
    except (OSError, ValueError):
        raise policy.ExecutionPolicyError("The Subfinder file is missing, unreadable or exceeds 128 MiB.") from None


def approve_subfinder_path(path: str, *, archive_path: str, confirmed: bool) -> ApprovedSubfinderCandidate:
    if confirmed is not True:
        raise policy.ExecutionPolicyError("Explicit approval of this local Subfinder executable is required.")
    _require_safety()
    canonical = _executable_path(path)
    archive = _local_path(archive_path)
    expected = _RELEASE_ARCHIVES.get(archive.name)
    if expected is None:
        raise policy.ExecutionPolicyError("HOLD: select the supported official v2.17.0 Windows amd64 or arm64 ZIP.")
    from core.recon.windows_process import locked_executable
    try:
        with locked_executable(canonical), locked_executable(str(archive)):
            if _executable_path(canonical) != canonical or _local_path(str(archive)) != archive:
                raise ValueError
            archive_bytes = _bounded_bytes(archive)
            if hashlib.sha256(archive_bytes).hexdigest() != expected:
                raise policy.ExecutionPolicyError("HOLD: the local ZIP does not match the pinned official release checksum.")
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as release:
                members = release.infolist()
                matches = [item for item in members if item.filename == "subfinder.exe"]
                if (len(members) > 32 or len(matches) != 1 or matches[0].flag_bits & 1
                        or not 0 < matches[0].file_size <= _MAX_FILE_BYTES):
                    raise ValueError
                with release.open(matches[0]) as stream:
                    image = stream.read(_MAX_FILE_BYTES + 1)
                if len(image) != matches[0].file_size:
                    raise ValueError
            digest = hashlib.sha256(image).hexdigest()
            if hashlib.sha256(_bounded_bytes(canonical)).hexdigest() != digest:
                raise policy.ExecutionPolicyError("HOLD: selected subfinder.exe does not match the official ZIP executable.")
    except policy.ExecutionPolicyError:
        raise
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
        raise policy.ExecutionPolicyError("HOLD: Subfinder release identity could not be safely verified.") from None
    candidate = object.__new__(ApprovedSubfinderCandidate)
    for name, value in (("executable_path", canonical), ("sha256", digest), ("version", RELEASE_VERSION),
                        ("archive_name", archive.name), ("_configuration", _IsolatedConfiguration())):
        object.__setattr__(candidate, name, value)
    _CANDIDATES[candidate] = _identity(candidate)
    return candidate


def _validate_candidate(candidate):
    _require_registered(candidate, ApprovedSubfinderCandidate, _CANDIDATES,
                        "An unchanged release-verified Subfinder executable is required.")
    if (_executable_path(candidate.executable_path) != candidate.executable_path
            or hashlib.sha256(_bounded_bytes(candidate.executable_path)).hexdigest() != candidate.sha256):
        raise policy.ExecutionPolicyError("The approved Subfinder executable changed; approve and verify it again.")
    candidate._configuration.validate()


def _validate_tool(tool):
    _require_registered(tool, ValidatedSubfinderTool, _TOOLS, "A verified Subfinder version is required.")
    _validate_candidate(tool._candidate)


def _scope_identity(scope):
    return tuple(getattr(scope, name) for name in scope.__dataclass_fields__)


def _approval_identity(approval):
    return _identity(approval) + (_scope_identity(approval._scope),)


def _validate_approval(approval):
    if (type(approval) is not SubfinderApproval or approval not in _APPROVALS
            or _approval_identity(approval) != _APPROVALS[approval]):
        raise policy.ExecutionPolicyError("An unchanged explicit passive Subfinder confirmation is required.")
    if monotonic() >= approval.expires_at:
        raise policy.ExecutionPolicyError("Subfinder confirmation expired; confirm this run again.")
    _validate_tool(approval._tool)
    if approval.profile != PROFILE or approval.hostname not in approval._scope.exact_domains:
        raise policy.ExecutionPolicyError("An exact root-domain passive grant is required.")
    decision = policy.preflight_scope((approval.hostname,), approval._scope)
    if not decision.allowed:
        raise policy.ExecutionPolicyError(decision.reason)


def approve_subfinder_run(tool, selected_targets, *, confirmed: bool, approval: policy.ScopeApproval):
    _require_safety()
    _validate_tool(tool)
    hostname = selected_subfinder_hostname(selected_targets)
    if confirmed is not True or type(approval) is not policy.ScopeApproval:
        raise policy.ExecutionPolicyError("Explicit authorization for this passive enumeration run is required.")
    if hostname not in approval.exact_domains:
        raise policy.ExecutionPolicyError("An exact root-domain passive grant is required.")
    decision = policy.preflight_scope((hostname,), approval)
    if not decision.allowed:
        raise policy.ExecutionPolicyError(decision.reason)
    grant = object.__new__(SubfinderApproval)
    for name, value in (("_tool", tool), ("hostname", hostname), ("profile", PROFILE),
                        ("expires_at", monotonic() + 60), ("_scope", approval)):
        object.__setattr__(grant, name, value)
    _APPROVALS[grant] = _approval_identity(grant)
    return grant


def _plan(candidate, arguments, targets, timeout):
    context = candidate._configuration
    return policy._AdapterPlan(candidate.executable_path, arguments, targets, timeout,
                               environment=context.environment, working_directory=context.directory)


class _VersionAdapter:
    request_type = _VersionRequest

    def build(self, request):
        _validate_candidate(request.candidate)
        return _plan(request.candidate, VERSION_ARGUMENTS, (), 5000)


class _DiscoveryAdapter:
    request_type = _DiscoveryRequest

    def build(self, request):
        _validate_approval(request.approval)
        if request.tool is not request.approval._tool:
            raise policy.ExecutionPolicyError("Subfinder approval belongs to another executable.")
        return _plan(request.tool._candidate, ("-d", request.approval.hostname) + PASSIVE_ARGUMENTS,
                     (request.approval.hostname,), PASSIVE_TIMEOUT_MS)


_VERSION_ADAPTER = _VersionAdapter()
_DISCOVERY_ADAPTER = _DiscoveryAdapter()


def _connect():
    policy._TRUSTED_ADAPTERS["subfinder.version-check"] = _VERSION_ADAPTER
    policy._TRUSTED_ADAPTERS["subfinder.passive-standard"] = _DISCOVERY_ADAPTER


def _validate_subfinder_plan(adapter_id, adapter, plan, approval):
    _require_safety()
    if (adapter_id == "subfinder.version-check" and adapter is _VERSION_ADAPTER
            and type(approval) is _ProbeApproval and approval in _PROBES
            and _identity(approval) == _PROBES[approval]):
        expected = _VERSION_ADAPTER.build(_VersionRequest(approval.candidate))
    elif adapter_id == "subfinder.passive-standard" and adapter is _DISCOVERY_ADAPTER:
        _validate_approval(approval)
        expected = _DISCOVERY_ADAPTER.build(_DiscoveryRequest(approval._tool, approval))
    else:
        raise policy.ExecutionPolicyError("A confirmation for this exact Subfinder operation is required.")
    if plan != expected:
        raise policy.ExecutionPolicyError("Only the immutable approved passive Subfinder operation is allowed.")


def _bind_subfinder_approval(approval):
    if approval in _BOUND:
        raise policy.ExecutionPolicyError("Each Subfinder confirmation can prepare only one operation.")
    _BOUND.add(approval)


def prepare_subfinder_version_check(candidate):
    _validate_candidate(candidate)
    _require_safety()
    _connect()
    approval = _ProbeApproval(candidate)
    _PROBES[approval] = _identity(approval)
    return policy.ExecutionPolicy().prepare("subfinder.version-check", _VersionRequest(candidate), approval)


def verify_subfinder_version(candidate, result):
    from core.recon.process_supervisor import JobSnapshot, JobState
    _validate_candidate(candidate)
    if (type(result) is not JobSnapshot or result.adapter_id != "subfinder.version-check"
            or result.state is not JobState.SUCCEEDED or type(result.exit_code) is not int or result.exit_code != 0
            or type(result.stdout) is not bytes or type(result.stderr) is not bytes
            or type(result.stdout_truncated) is not bool or type(result.stderr_truncated) is not bool
            or result.output_truncated
            or len(result.stdout) + len(result.stderr) > 4096):
        raise policy.ExecutionPolicyError("Subfinder version verification did not complete successfully.")
    # The pinned runner logs exactly this version message to stderr using gologger.
    text = re.sub(rb"\x1b\[[0-9;]{0,32}m", b"", result.stderr)
    try:
        lines = [line.removeprefix("[INF] ") for line in text.decode("utf-8").strip().splitlines()]
    except UnicodeError:
        lines = []
    config_directory = str(Path(candidate._configuration.files[0]).parent)
    expected = ["Current Version: v" + candidate.version]
    full_expected = expected + ["Subfinder Config Directory: " + config_directory]
    if result.stdout or lines not in (expected, full_expected):
        raise policy.ExecutionPolicyError("Subfinder's version response did not match the pinned release.")
    tool = object.__new__(ValidatedSubfinderTool)
    for name, value in (("executable_path", candidate.executable_path), ("sha256", candidate.sha256),
                        ("version", candidate.version), ("_candidate", candidate)):
        object.__setattr__(tool, name, value)
    _TOOLS[tool] = _identity(tool)
    return tool


def prepare_subfinder_discovery(tool, approval):
    _require_safety()
    _validate_approval(approval)
    _connect()
    return policy.ExecutionPolicy().prepare("subfinder.passive-standard", _DiscoveryRequest(tool, approval), approval)
