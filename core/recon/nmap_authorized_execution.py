"""Typed authorized R7B-2 plans using the existing trusted execution policy.

Profiles, DNS and catalog entries remain inert. A short-lived one-shot grant
binds numeric scope, saved configuration, verified executable, capabilities,
installed data and exact argv. No shell, preview text or expert CLI is executed.
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass, field, fields, replace
import hashlib
import os
from pathlib import Path
import re
from time import monotonic
from weakref import WeakKeyDictionary, finalize

from core.recon import execution_policy as policy
from core.recon.nmap_capabilities import NmapCapabilities, capability_reasons, detect_capabilities
from core.recon.nmap_nse import (ScriptInfo, bounded_file, discover_scripts, distribution_directory,
    validate_script_arguments, validate_scripts)
from core.recon.nmap_profiles import BUILTIN_PROFILES, NmapScanProfile, configuration_arguments
from core.recon.nmap_profile_store import NmapProfileStore
from core.recon.nmap_profile_execution import _saved_digest
from core.recon.nmap_scope import ScopeSnapshot, claim_scope, validate_scope
from core.recon.tool_discovery import _LocalInspection


APPROVAL_TTL_SECONDS = 60
MAX_DATA_FILES = 2048
MAX_DATA_BYTES = 64 * 1024 * 1024
MAX_SINGLE_DATA_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class DistributionFile:
    path: str
    sha256: str
    size: int
    stat_key: tuple[int, int, int, int] = field(repr=False)


def _profile(profile):
    if type(profile) is not NmapScanProfile:
        raise ValueError("Select a validated Nmap scan profile.")
    snapshot = replace(profile)
    if snapshot.is_builtin and snapshot not in BUILTIN_PROFILES:
        raise ValueError("Built-in profiles cannot be changed; duplicate and save a custom profile first.")
    return snapshot


def _profile_identity(profile):
    return tuple(getattr(profile, item.name) for item in fields(NmapScanProfile))


def _caps_identity(caps):
    return tuple(getattr(caps, item.name) for item in fields(NmapCapabilities))


def _scripts_identity(scripts):
    return tuple(tuple(getattr(script, item.name) for item in fields(ScriptInfo)) for script in scripts)


def _selected_scripts(tool, profile):
    validate_script_arguments(profile.script_arguments)
    if not profile.script_ids and not profile.version_detection:
        return ()
    if profile.dns_mode != "never":
        raise ValueError("NSE requires DNS resolution disabled (-n), preserving exact numeric target scope.")
    catalog = {item.script_id: item for item in discover_scripts(tool)}
    if any(script_id not in catalog for script_id in profile.script_ids):
        raise ValueError("An explicitly selected NSE script is not in this verified Nmap installation.")
    implicit = tuple(item.script_id for item in catalog.values() if "version" in item.categories) if profile.version_detection else ()
    if profile.version_detection and not implicit:
        raise ValueError("Service version NSE data is missing; reinstall a complete official Nmap distribution.")
    script_ids = tuple(dict.fromkeys((*profile.script_ids, *implicit)))
    scripts = tuple(catalog[script_id] for script_id in script_ids)
    return validate_scripts(tool, scripts)


def implicit_version_scripts(tool) -> tuple[ScriptInfo, ...]:
    """Inert display of the installed NSE version engine's implicit selection."""
    return tuple(script for script in discover_scripts(tool) if "version" in script.categories)


def _require_capabilities(profile, scope, caps):
    if reasons := capability_reasons(profile, caps):
        raise ValueError(" ".join(reasons))
    if scope.family == 6 and not caps.ipv6:
        raise ValueError("IPv6 is unavailable on this Windows system.")
    if scope.family == 6 and "icmp-mask" in profile.discovery_probes:
        raise ValueError("ICMP address-mask discovery is unavailable for IPv6.")
    if scope.family == 6 and "icmp-timestamp" in profile.discovery_probes:
        raise ValueError("ICMP timestamp discovery is unavailable for IPv6.")


def authorized_arguments(tool, scope: ScopeSnapshot, profile: NmapScanProfile) -> tuple[str, ...]:
    """Inert canonical preview; approval reconstructs this from typed values."""
    validate_scope(scope)
    snapshot = _profile(profile)
    root = distribution_directory(tool)
    scripts = _selected_scripts(tool, snapshot)
    return _canonical_arguments(scope, snapshot, root, scripts)


def _canonical_arguments(scope, snapshot, root, scripts):
    arguments = list(configuration_arguments(snapshot))
    if scripts:
        index = arguments.index("--no-stylesheet")
        arguments[index:index] = ["--max-hostgroup", "1"]
        # .nse forces exact files rather than category/pattern expressions.
        if snapshot.script_ids:
            index = arguments.index("--script")
            arguments[index + 1] = ",".join(script_id + ".nse" for script_id in snapshot.script_ids)
        if "--script-timeout" not in arguments:
            index = arguments.index("--no-stylesheet")
            arguments[index:index] = ["--script-timeout", f"{snapshot.script_timeout_seconds}s"]
        # Bound library responses and outstanding HTTP requests. Profile values
        # stay within reviewed limits and cannot add targets/files/commands.
        defaults = {"http.max-body-size": "65536", "http.max-pipeline": "1", "http.pipeline": "1"}
        defaults.update(dict(validate_script_arguments(snapshot.script_arguments)))
        if "--script-args" in arguments:
            index = arguments.index("--script-args")
            arguments[index + 1] = ",".join(f"{key}={value}" for key, value in sorted(defaults.items()))
        else:
            index = arguments.index("--no-stylesheet")
            arguments[index:index] = ["--script-args", ",".join(f"{key}={value}" for key, value in sorted(defaults.items()))]
    prefix = ("-6",) if scope.family == 6 else ()
    return (*prefix, "--datadir", str(root), *arguments, *scope.targets)


def _data_files(tool, profile, scripts, *, locked_manifest=None) -> tuple[DistributionFile, ...]:
    root = distribution_directory(tool)
    paths = set()
    for name in ("nmap-services", "nmap-protocols", "nmap-mac-prefixes", "nmap-rpc", "nmap-payloads"):
        path = root / name
        if path.exists() or name in {"nmap-services", "nmap-protocols"}:
            paths.add(path)
    if profile.version_detection:
        paths.add(root / "nmap-service-probes")
    if profile.os_detection:
        paths.add(root / "nmap-os-db")
    if scripts:
        paths.add(root / "scripts" / "script.db")
        paths.update(Path(script.path) for script in scripts)
        paths.add(root / "nse_main.lua")
        library = root / "nselib"
        if library.exists():
            inspection = _LocalInspection(os.name == "nt")
            inspection.path(library, directory=True)
            # Inspect every directory before recursion, refusing reparse points.
            pending = [library]
            visited = 0
            while pending:
                directory = pending.pop()
                for path in directory.iterdir():
                    visited += 1
                    if visited > MAX_DATA_FILES:
                        raise ValueError("Installed NSE library exceeds the bounded data catalog.")
                    if path.is_dir():
                        pending.append(inspection.path(path, directory=True))
                    else:
                        paths.add(inspection.path(path))
    if len(paths) > MAX_DATA_FILES:
        raise ValueError("Installed Nmap data exceeds the file-count limit.")
    result, total = [], 0
    held = {item.path: item for item in locked_manifest} if locked_manifest is not None else {}
    inspection = _LocalInspection(os.name == "nt")
    for path in sorted(paths):
        path = inspection.path(path)
        stat = path.stat()
        stat_key = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
        previous = held.get(str(path))
        if previous is not None:
            if previous.stat_key != stat_key:
                raise ValueError("A locked installed Nmap data identity changed.")
            result.append(previous)
            total += previous.size
            continue
        content = bounded_file(path, limit=MAX_SINGLE_DATA_BYTES)
        total += len(content)
        if total > MAX_DATA_BYTES:
            raise ValueError("Installed Nmap data exceeds the 64 MiB inspection limit.")
        result.append(DistributionFile(str(path), hashlib.sha256(content).hexdigest(), len(content), stat_key))
    return tuple(result)


def _expected_ports(profile, data_files):
    if profile.discovery in {"only", "list"}:
        return ()
    protocols = (() if profile.technique == "udp" else ("tcp",)) + (("udp",) if profile.udp_scan or profile.technique == "udp" else ())
    if profile.port_mode == "all":
        return tuple((protocol, tuple(range(1, 65536))) for protocol in protocols)
    if profile.port_mode == "explicit":
        return tuple((protocol, profile.ports if protocol == "tcp" else profile.udp_ports) for protocol in protocols)
    services = next(item for item in data_files if Path(item.path).name == "nmap-services")
    text = bounded_file(services.path, limit=MAX_SINGLE_DATA_BYTES).decode("ascii", "strict")
    entries, seen = [], set()
    for line in text.splitlines():
        body = line.partition("#")[0].strip()
        if not body:
            continue
        parts = body.split()
        if len(parts) < 3:
            raise ValueError("Top-port selection requires an installed frequency-format nmap-services database.")
        match = re.fullmatch(r"([0-9]{1,5})/(tcp|udp|sctp)", parts[1])
        if match is None:
            continue
        port, protocol = int(match[1]), match[2]
        if not 1 <= port <= 65535 or (protocol, port) in seen:
            continue
        try:
            ratio_text = parts[2]
            if "/" in ratio_text:
                numerator, denominator = ratio_text.split("/")
                ratio = int(numerator) / int(denominator)
            else:
                ratio = float(ratio_text)
            if not 0 <= ratio <= 1:
                raise ValueError
        except (ValueError, ZeroDivisionError):
            raise ValueError("Installed nmap-services contains an invalid port frequency.") from None
        entries.append((protocol, port, ratio))
        seen.add((protocol, port))
    # Nmap services.cc uses stable std::list.sort on frequency only, preserving
    # source order for ties; duplicates keep first. Sort selected ports numeric.
    ranked = sorted(entries, key=lambda entry: -entry[2])
    result = tuple((protocol, tuple(sorted([item[1] for item in ranked if item[0] == protocol][:profile.top_ports]))) for protocol in protocols)
    if any(not ports for _, ports in result):
        raise ValueError("Installed nmap-services has no ports for the selected protocol.")
    return result


def _environment(root):
    # Drop NMAPDIR, LUA_PATH/LUA_CPATH, proxy variables and caller CWD search.
    # Only ordinary Windows system paths are inherited. No credentials appear
    # in plans or diagnostics.
    values = {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "TEMP", "TMP", "SystemDrive") if key in os.environ}
    system_root = values.get("SystemRoot", values.get("WINDIR", r"C:\Windows"))
    values["PATH"] = os.pathsep.join((str(root), str(Path(system_root) / "System32"), str(Path(system_root) / "System32" / "Npcap")))
    values["NMAPDIR"] = str(root)
    return tuple(sorted(values.items()))


@dataclass(frozen=True, init=False, slots=True, weakref_slot=True, eq=False)
class AuthorizedNmapApproval:
    _tool: object = field(repr=False)
    scope: ScopeSnapshot
    profile: NmapScanProfile
    capabilities: NmapCapabilities
    scripts: tuple[ScriptInfo, ...]
    data_files: tuple[DistributionFile, ...] = field(repr=False)
    expected_ports: tuple[tuple[str, tuple[int, ...]], ...] = field(repr=False)
    expires_at: float
    _selected_profile: NmapScanProfile = field(repr=False)
    _source_path: str | None = field(repr=False)
    _source_digest: str | None = field(repr=False)
    _program: str = field(repr=False)
    _sha256: str = field(repr=False)
    _version: str = field(repr=False)
    _arguments: tuple[str, ...] = field(repr=False)
    _environment: tuple[tuple[str, str], ...] = field(repr=False)
    _working_directory: str = field(repr=False)
    _high_impact_confirmed: bool = field(repr=False)
    _version_nse_confirmed: bool = field(repr=False)

    def __init__(self):
        raise TypeError("Authorized Nmap approval requires explicit bounded target and per-run confirmation.")


_APPROVALS = WeakKeyDictionary()
_FINALIZERS = WeakKeyDictionary()


def _identity(approval):
    return (approval._tool, approval.scope, _profile_identity(approval.profile),
        _profile_identity(approval._selected_profile), _caps_identity(approval.capabilities),
        _scripts_identity(approval.scripts), tuple((item.path, item.sha256, item.size, item.stat_key) for item in approval.data_files),
        approval.expected_ports, approval.expires_at, approval._source_path, approval._source_digest,
        approval._program, approval._sha256, approval._version, approval._arguments,
        approval._environment, approval._working_directory, approval._high_impact_confirmed, approval._version_nse_confirmed)


def release_authorized_approval(approval):
    """Release transient installation locks after completion/cancellation."""
    _APPROVALS.pop(approval, None)
    finalizer = _FINALIZERS.pop(approval, None)
    if finalizer is not None:
        finalizer()


def approve_authorized_nmap(tool, scope: ScopeSnapshot, *, profile: NmapScanProfile,
        profile_store=None, scope_confirmed: bool, confirmed: bool, high_impact_confirmed: bool = False,
        version_nse_confirmed: bool = False) -> AuthorizedNmapApproval:
    from core.recon import nmap_adapter as nmap
    nmap._require_safety()
    nmap._validate_tool(tool)
    validate_scope(scope)
    snapshot = _profile(profile)
    if confirmed is not True or scope_confirmed is not True:
        raise policy.ExecutionPolicyError("Confirm this run and authorization for every concrete target address.")
    if snapshot.version_detection and version_nse_confirmed is not True:
        raise policy.ExecutionPolicyError("Explicit confirmation of the implicit NSE version scripts used by service version detection (-sV) is required.")
    caps = detect_capabilities(tool)
    _require_capabilities(snapshot, scope, caps)
    scripts = _selected_scripts(tool, snapshot)
    if any(script.high_impact for script in scripts) and high_impact_confirmed is not True:
        raise policy.ExecutionPolicyError("Additional explicit confirmation is required for high-impact NSE scripts.")
    source_path = source_digest = None
    if not snapshot.is_builtin:
        if type(profile_store) is not NmapProfileStore:
            raise policy.ExecutionPolicyError("Custom profiles must be saved before execution.")
        source_path = str(profile_store.path.resolve())
        source_digest = _saved_digest(snapshot, source_path)
    root = distribution_directory(tool)
    arguments = _canonical_arguments(scope, snapshot, root, scripts)
    data_files = _data_files(tool, snapshot, scripts)
    stack = ExitStack()
    try:
        from core.recon.windows_process import locked_executable
        # These ordinary deny-write/delete handles stay alive for the complete
        # run, binding Lua/dependencies/services to the approved hashes.
        for item in data_files:
            stack.enter_context(locked_executable(item.path))
        if _data_files(tool, snapshot, scripts) != data_files:
            raise ValueError("Installed Nmap data changed during approval.")
        if scripts:
            validate_scripts(tool, scripts)
        expected_ports = _expected_ports(snapshot, data_files)
        expiry = claim_scope(scope, scope_confirmed=scope_confirmed)
        approval = object.__new__(AuthorizedNmapApproval)
        for name, value in (
            ("_tool", tool), ("scope", scope), ("profile", snapshot), ("capabilities", caps), ("scripts", scripts),
            ("data_files", data_files), ("expected_ports", expected_ports),
            ("expires_at", min(expiry, monotonic() + APPROVAL_TTL_SECONDS)), ("_selected_profile", profile),
            ("_source_path", source_path), ("_source_digest", source_digest),
            ("_program", tool.executable_path), ("_sha256", tool.sha256), ("_version", tool.version),
            ("_arguments", arguments), ("_environment", _environment(root)), ("_working_directory", str(root)),
            ("_high_impact_confirmed", high_impact_confirmed is True),
            ("_version_nse_confirmed", version_nse_confirmed is True),
        ):
            object.__setattr__(approval, name, value)
        _APPROVALS[approval] = _identity(approval)
        _FINALIZERS[approval] = finalize(approval, stack.close)
        return approval
    except Exception:
        stack.close()
        raise


def _validate_approval(approval):
    from core.recon import nmap_adapter as nmap
    try:
        if type(approval) is not AuthorizedNmapApproval or approval not in _APPROVALS or _identity(approval) != _APPROVALS[approval]:
            raise ValueError("An unchanged explicit authorized scan approval is required.")
        if monotonic() >= approval.expires_at:
            raise ValueError("Nmap approval expired; preflight and confirm again.")
        validate_scope(approval.scope)
        snapshot = _profile(approval.profile)
        if approval._selected_profile != snapshot:
            raise ValueError("The selected profile changed after confirmation.")
        if not snapshot.is_builtin and _saved_digest(snapshot, approval._source_path) != approval._source_digest:
            raise ValueError("The saved profile document changed after confirmation.")
        nmap._validate_tool(approval._tool)
        if (approval._program != approval._tool.executable_path or approval._sha256 != approval._tool.sha256
                or approval._sha256 != approval._tool._candidate.sha256 or approval._version != approval._tool.version):
            raise ValueError("The verified Nmap executable identity changed.")
        caps = detect_capabilities(approval._tool)
        _require_capabilities(snapshot, approval.scope, caps)
        if caps != approval.capabilities:
            raise ValueError("Windows execution capabilities changed; preflight again.")
        finalizer = _FINALIZERS.get(approval)
        if finalizer is None or not finalizer.alive:
            raise ValueError("The approved installed-data locks were released.")
        # Native deny-write/delete handles retain the exact data contents for
        # the run. Recheck safe paths, file identities and catalog membership
        # without synchronously rehashing every Lua library at each Qt signal.
        manifest = approval.data_files if os.name == "nt" else None
        if _data_files(approval._tool, snapshot, approval.scripts, locked_manifest=manifest) != approval.data_files:
            raise ValueError("Installed Nmap data changed; preflight again.")
        if _canonical_arguments(approval.scope, snapshot, Path(approval._working_directory), approval.scripts) != approval._arguments:
            raise ValueError("The approved canonical arguments changed.")
    except (ValueError, TypeError, AttributeError, OSError) as error:
        raise policy.ExecutionPolicyError(str(error)) from None


@dataclass(frozen=True)
class _AuthorizedRequest:
    tool: object
    approval: AuthorizedNmapApproval


class _AuthorizedAdapter:
    request_type = _AuthorizedRequest

    def build(self, request):
        _validate_approval(request.approval)
        approval = request.approval
        if request.tool is not approval._tool:
            raise policy.ExecutionPolicyError("Approval belongs to a different verified Nmap executable.")
        timeout = approval.profile.execution_timeout_seconds
        if approval.profile.version_detection and approval.profile.version_timeout_seconds:
            timeout = min(timeout, approval.profile.version_timeout_seconds)
        return policy._AdapterPlan(approval._program, approval._arguments, approval.scope.targets,
            timeout * 1000, approval._environment, approval._working_directory)


_ADAPTER = _AuthorizedAdapter()


def _validate_authorized_plan(adapter, plan, approval):
    if adapter is not _ADAPTER or type(approval) is not AuthorizedNmapApproval:
        raise policy.ExecutionPolicyError("A confirmation belonging to this exact authorized Nmap operation is required.")
    if plan != _ADAPTER.build(_AuthorizedRequest(approval._tool, approval)):
        raise policy.ExecutionPolicyError("Only the exact immutable authorized Nmap operation is allowed.")


def prepare_nmap_authorized_scan(tool, approval: AuthorizedNmapApproval) -> policy.ValidatedExecutionSpec:
    from core.recon import nmap_adapter as nmap
    nmap._require_safety()
    _validate_approval(approval)
    policy._TRUSTED_ADAPTERS["nmap.authorized-profile"] = _ADAPTER
    return policy.ExecutionPolicy().prepare("nmap.authorized-profile", _AuthorizedRequest(tool, approval), approval)
