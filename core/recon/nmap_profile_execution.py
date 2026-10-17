"""R7B-1 execution eligibility and one-shot plans, separate from R7A storage.

Only Web Services and saved bounded Custom profiles can use this adapter.
Configuration, DNS and inventory records never grant execution permission.
"""

from __future__ import annotations

from dataclasses import MISSING, dataclass, field, fields, replace
import hashlib
from pathlib import Path
from time import monotonic
from weakref import WeakKeyDictionary

from core.recon import execution_policy as policy
from core.recon.nmap_profiles import BUILTIN_PROFILES, NmapScanProfile, format_ports
from core.recon.nmap_profile_store import NmapProfileStore, MAX_PROFILE_DOCUMENT_BYTES, _parse_document
from core.recon.public_target import (
    PUBLIC_HOSTNAME, PublicTargetObservation, claim_public_observation,
    validate_public_address, validate_public_observation,
)


class ProfileExecutionError(ValueError):
    """A valid editable configuration is not eligible for R7B-1 execution."""


def execution_reasons(profile: NmapScanProfile) -> tuple[str, ...]:
    try:
        if type(profile) is not NmapScanProfile:
            raise ValueError("Select a validated Nmap scan profile.")
        profile = replace(profile)  # Revalidate every field, even on a frozen instance.
    except (TypeError, ValueError) as error:
        return (str(error),)
    reasons = []
    if profile.technique != "tcp-connect":
        reasons.append("The legacy profile action supports TCP Connect only; use Authorized Profile Scan for other techniques.")
    if any(item.default is not MISSING and getattr(profile, item.name) != item.default
           for item in fields(NmapScanProfile)):
        reasons.append("Extended options require the Authorized Profile Scan workflow; the legacy action cannot apply them.")
    if profile.is_builtin and profile != BUILTIN_PROFILES[1]:
        reasons.append("Not executable in R7B-1. Only the unchanged built-in Web Services profile is enabled here.")
    if profile.profile_id == "quick-network-discovery":
        reasons.append("Use the existing Public Scan / Quick Network Discovery action.")
    if not 1 <= len(profile.ports) <= 16:
        reasons.append("R7B-1 requires 1–16 distinct TCP ports.")
    if profile.version_detection:
        reasons.append("Version detection (-sV) must be disabled in R7B-1.")
    for name, value, low, high in (
        ("Maximum rate", profile.max_rate, 1, 10),
        ("Maximum retries", profile.max_retries, 0, 1),
        ("Host timeout", profile.host_timeout_seconds, 5, 60),
        ("Overall timeout", profile.execution_timeout_seconds, 10, 90),
    ):
        if not low <= value <= high:
            reasons.append(f"{name} must be {low}–{high} in R7B-1.")
    return tuple(reasons)


def validate_executable_profile(profile: NmapScanProfile) -> NmapScanProfile:
    """Return a newly validated immutable snapshot; never modify saved data."""
    if reasons := execution_reasons(profile):
        raise ProfileExecutionError(" ".join(reasons))
    return replace(profile)


def profile_arguments(profile: NmapScanProfile, address: str) -> tuple[str, ...]:
    """Construct typed argv directly from validated fields, never preview text."""
    profile = validate_executable_profile(profile)
    address = validate_public_address(address)
    return (
        "-sT", "-Pn", "-n", "-p", format_ports(profile.ports),
        "--max-retries", str(profile.max_retries), "--max-rate", str(profile.max_rate),
        "--host-timeout", f"{profile.host_timeout_seconds}s", "--no-stylesheet", "-oX", "-", address,
    )


def _profile_identity(profile):
    return tuple(getattr(profile, item.name) for item in fields(NmapScanProfile))


def _saved_digest(profile, path: str) -> str:
    """Read and validate the same bounded bytes used to bind the saved profile."""
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_PROFILE_DOCUMENT_BYTES + 1)
        profiles = _parse_document(raw)
        if next((item for item in profiles if item.profile_id == profile.profile_id), None) != profile:
            raise ValueError
        return hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError):
        raise policy.ExecutionPolicyError("The saved Custom profile changed, is missing or is invalid; reopen and confirm again.") from None


@dataclass(frozen=True, init=False, slots=True, weakref_slot=True, eq=False)
class ProfileNmapApproval:
    _tool: object = field(repr=False)
    observation: PublicTargetObservation = field(repr=False)
    hostname: str
    address: str
    profile: NmapScanProfile
    expires_at: float
    _selected_profile: NmapScanProfile = field(repr=False)
    _source_path: str | None = field(repr=False)
    _source_digest: str | None = field(repr=False)
    _program: str = field(repr=False)
    _sha256: str = field(repr=False)
    _version: str = field(repr=False)
    _arguments: tuple[str, ...] = field(repr=False)

    def __init__(self):
        raise TypeError("Profile scans require fresh DNS and explicit per-run scope confirmation.")


_APPROVALS = WeakKeyDictionary()


def _identity(approval):
    return (approval._tool, approval.observation, approval.hostname, approval.address,
            _profile_identity(approval.profile), _profile_identity(approval._selected_profile),
            approval.expires_at, approval._source_path, approval._source_digest,
            approval._program, approval._sha256, approval._version, approval._arguments)


def _validate_approval(approval):
    from core.recon import nmap_adapter as nmap
    if (type(approval) is not ProfileNmapApproval or approval not in _APPROVALS
            or type(approval.profile) is not NmapScanProfile
            or type(approval._selected_profile) is not NmapScanProfile
            or _identity(approval) != _APPROVALS[approval]):
        raise policy.ExecutionPolicyError("An unchanged explicit profile scan approval is required.")
    if monotonic() >= approval.expires_at:
        raise policy.ExecutionPolicyError("Profile scan approval expired; preflight and confirm again.")
    try:
        validate_public_observation(approval.observation)
        snapshot = validate_executable_profile(approval.profile)
        if (approval.hostname != PUBLIC_HOSTNAME or approval.observation.hostname != PUBLIC_HOSTNAME
                or approval.address not in approval.observation.ipv4_addresses
                or profile_arguments(snapshot, approval.address) != approval._arguments
                or approval._selected_profile != snapshot):
            raise ValueError("The approved profile, hostname or selected IP changed.")
        if not snapshot.is_builtin:
            if not approval._source_path or _saved_digest(snapshot, approval._source_path) != approval._source_digest:
                raise ValueError("The saved profile document changed; preflight and confirm again.")
        nmap._validate_tool(approval._tool)
        if (approval._program != approval._tool.executable_path
                or approval._program != approval._tool._candidate.executable_path
                or approval._sha256 != approval._tool.sha256
                or approval._sha256 != approval._tool._candidate.sha256
                or approval._version != approval._tool.version):
            raise ValueError("The verified Nmap executable identity changed.")
    except ValueError as error:
        raise policy.ExecutionPolicyError(str(error)) from None


def approve_profile_nmap(tool, observation: PublicTargetObservation, *, profile: NmapScanProfile,
                         address: str, scope_confirmed: bool, confirmed: bool,
                         profile_store: NmapProfileStore | None = None) -> ProfileNmapApproval:
    from core.recon import nmap_adapter as nmap
    nmap._validate_tool(tool)
    nmap._require_safety()
    snapshot = validate_executable_profile(profile)
    if confirmed is not True:
        raise policy.ExecutionPolicyError("Confirm the exact hostname, IP and selected profile for this run.")
    source_path = source_digest = None
    if not snapshot.is_builtin:
        if type(profile_store) is not NmapProfileStore:
            raise policy.ExecutionPolicyError("Custom profiles must be saved before execution.")
        source_path = str(profile_store.path.resolve())
        source_digest = _saved_digest(snapshot, source_path)
    arguments = profile_arguments(snapshot, address)
    expiry = claim_public_observation(observation, address, scope_confirmed=scope_confirmed)
    approval = object.__new__(ProfileNmapApproval)
    for name, value in (
        ("_tool", tool), ("observation", observation), ("hostname", PUBLIC_HOSTNAME), ("address", address),
        ("profile", snapshot), ("_selected_profile", profile),
        ("expires_at", min(expiry, monotonic() + nmap.PUBLIC_APPROVAL_TTL_SECONDS)),
        ("_source_path", source_path), ("_source_digest", source_digest),
        ("_program", tool.executable_path), ("_sha256", tool.sha256), ("_version", tool.version),
        ("_arguments", arguments),
    ):
        object.__setattr__(approval, name, value)
    _APPROVALS[approval] = _identity(approval)
    return approval


@dataclass(frozen=True)
class _ProfileScanRequest:
    tool: object
    approval: ProfileNmapApproval


class _ProfileScanAdapter:
    request_type = _ProfileScanRequest

    def build(self, request):
        _validate_approval(request.approval)
        approval = request.approval
        if request.tool is not approval._tool:
            raise policy.ExecutionPolicyError("Profile approval belongs to another verified executable.")
        return policy._AdapterPlan(approval._program, approval._arguments, (approval.address,),
                                   approval.profile.execution_timeout_seconds * 1000)


_ADAPTER = _ProfileScanAdapter()


def _validate_profile_plan(adapter, plan, approval):
    if adapter is not _ADAPTER or type(approval) is not ProfileNmapApproval:
        raise policy.ExecutionPolicyError("A confirmation belonging to this exact profile operation is required.")
    if plan != _ADAPTER.build(_ProfileScanRequest(approval._tool, approval)):
        raise policy.ExecutionPolicyError("Only the immutable approved Nmap profile operation is allowed.")


def prepare_nmap_profile_scan(tool, approval: ProfileNmapApproval) -> policy.ValidatedExecutionSpec:
    from core.recon import nmap_adapter as nmap
    nmap._require_safety()
    _validate_approval(approval)
    policy._TRUSTED_ADAPTERS["nmap.public-profile"] = _ADAPTER
    return policy.ExecutionPolicy().prepare("nmap.public-profile", _ProfileScanRequest(tool, approval), approval)
