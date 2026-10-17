"""Scope decisions and one-shot capabilities for reviewed Recon adapters.

Domain scope remains separate from narrowly bound Nmap per-operation grants.
Discovery records, selected R1 targets and imported dictionaries grant nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Protocol
from weakref import WeakKeyDictionary

from core.recon.targets import normalize_hostname


class ExecutionPolicyError(ValueError):
    """A plan has no trusted adapter or fails execution/scope preflight."""


def _hostname(value: str) -> str:
    if not isinstance(value, str) or value != value.strip() or value.startswith("-"):
        raise ValueError("Target must be a hostname without whitespace or options.")
    return normalize_hostname(value)


def _hostname_list(values) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)):
        raise ValueError("Scope identities must be an explicit list of hostnames.")
    return tuple(dict.fromkeys(_hostname(value) for value in values))


@dataclass(frozen=True)
class ScopeApproval:
    """Explicit application approval, separate from all discovery/review records.

    Ranges authorize descendants only. An apex requires an exact-domain grant.
    Exclusions use the same rules and always take precedence over approvals.
    There is deliberately no import-from-inventory or disable-checks helper.
    """

    exact_domains: tuple[str, ...] = ()
    subdomain_ranges: tuple[str, ...] = ()
    excluded_domains: tuple[str, ...] = ()
    excluded_subdomain_ranges: tuple[str, ...] = ()

    def __post_init__(self):
        for name in ("exact_domains", "subdomain_ranges", "excluded_domains", "excluded_subdomain_ranges"):
            object.__setattr__(self, name, _hostname_list(getattr(self, name)))


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    targets: tuple[str, ...] = ()
    reason: str = ""


@dataclass(frozen=True, init=False, slots=True, weakref_slot=True, eq=False)
class LocalSelfTestApproval:
    """Opaque per-run confirmation, usable only by the fixed Nmap adapter.

    This is deliberately not a ScopeApproval and never authorizes R1 targets.
    Only nmap_adapter's confirmation factory can issue an accepted instance.
    """

    _tool: object = field(repr=False)

    def __init__(self):
        raise TypeError("Local self-test confirmation is issued by the Nmap adapter.")


def _within(hostname: str, exact: tuple[str, ...], ranges: tuple[str, ...]) -> bool:
    return hostname in exact or any(hostname.endswith("." + root) for root in ranges)


def preflight_scope(targets, approval: ScopeApproval | None) -> ScopeDecision:
    """Check only explicit hostname identities; never resolve DNS or infer grants."""
    if type(approval) is not ScopeApproval:
        return ScopeDecision(False, reason="Explicit scope approval is required.")
    try:
        canonical = _hostname_list(targets)
    except (ValueError, TypeError):
        return ScopeDecision(False, reason="Planned targets contain a malformed hostname or option.")
    if not canonical:
        return ScopeDecision(False, reason="At least one approved target identity is required.")
    for hostname in canonical:
        if _within(hostname, approval.excluded_domains, approval.excluded_subdomain_ranges):
            return ScopeDecision(False, reason="A planned target is explicitly excluded.")
        if not _within(hostname, approval.exact_domains, approval.subdomain_ranges):
            return ScopeDecision(False, reason="A planned target is outside the approved scope.")
    return ScopeDecision(True, canonical, "Explicit scope approval accepted.")


@dataclass(frozen=True)
class _AdapterPlan:
    """Private adapter output. Never constructed from user/imported CLI options."""

    program: str
    arguments: tuple[str, ...]
    targets: tuple[str, ...]
    timeout_ms: int = 30_000
    environment: tuple[tuple[str, str], ...] | None = None
    working_directory: str | None = None


class _TrustedAdapter(Protocol):
    request_type: type

    def build(self, request: object) -> _AdapterPlan: ...


# No public registration API. The fixed Nmap adapter registers privately only
# when its application helper is used; discovery never registers or runs it.
_TRUSTED_ADAPTERS: dict[str, _TrustedAdapter] = {}
_SPEC_SEAL = object()
_SHELL_NAMES = {"cmd", "powershell", "pwsh", "sh", "bash", "zsh", "dash", "csh"}


@dataclass(frozen=True, init=False, slots=True, weakref_slot=True, eq=False)
class ValidatedExecutionSpec:
    """Opaque immutable capability issued exclusively by ExecutionPolicy.

    Python privacy is an application boundary, not a sandbox against malicious
    in-process Python. Untrusted serialized data must never instantiate this.
    """

    adapter_id: str
    _plan: _AdapterPlan = field(repr=False)
    _approval: object = field(repr=False)
    _adapter: object = field(repr=False)
    _seal: object = field(repr=False)

    def __init__(self):
        raise TypeError("Execution specifications are issued by ExecutionPolicy.")


# Identity-based, weak bookkeeping prevents copied/serialized capabilities and
# resubmission without retaining completed plans for the life of the process.
_ISSUED_SPECS: WeakKeyDictionary[ValidatedExecutionSpec, bool] = WeakKeyDictionary()


def _validate_plan(plan: _AdapterPlan, approval: object, *, adapter_id=None, adapter=None) -> _AdapterPlan:
    if type(plan) is not _AdapterPlan:
        raise ExecutionPolicyError("Trusted adapter did not return a typed plan.")
    if adapter_id in {"subfinder.version-check", "subfinder.passive-standard"}:
        from core.recon.subfinder_adapter import _validate_subfinder_plan
        _validate_subfinder_plan(adapter_id, adapter, plan, approval)
    elif type(approval) is ScopeApproval:
        decision = preflight_scope(plan.targets, approval)
        if not decision.allowed:
            raise ExecutionPolicyError(decision.reason)
        if type(plan.targets) is not tuple or plan.targets != decision.targets:
            raise ExecutionPolicyError("Adapter targets must be canonical hostname identities.")
    else:
        # The Nmap module checks exact adapter, approval type/identity, fixed
        # profile, executable hash and containment. No generic scope bypass.
        from core.recon.nmap_adapter import _validate_nmap_plan
        _validate_nmap_plan(adapter_id, adapter, plan, approval)
    if type(plan.arguments) is not tuple or any(
        not isinstance(argument, str) or "\x00" in argument for argument in plan.arguments
    ):
        raise ExecutionPolicyError("Adapter arguments must be a typed sequence of text values.")
    if type(plan.timeout_ms) is not int or not 1 <= plan.timeout_ms <= 2_147_483_647:
        raise ExecutionPolicyError("Adapter timeout must be a positive bounded duration.")
    if not isinstance(plan.program, str) or not plan.program or "\x00" in plan.program:
        raise ExecutionPolicyError("Adapter executable must be an absolute local file.")
    program = Path(plan.program)
    if not program.is_absolute() or plan.program.replace("\\", "/").startswith("//"):
        raise ExecutionPolicyError("Adapter executable must be an absolute local file.")
    try:
        resolved = program.resolve(strict=True)
        if not resolved.is_file() or resolved.stat().st_size == 0:
            raise OSError
        if resolved.stem.casefold() in _SHELL_NAMES:
            raise OSError
        if os.name == "nt" and resolved.suffix.casefold() != ".exe":
            raise OSError
        if os.name != "nt" and not os.access(resolved, os.X_OK):
            raise OSError
    except (OSError, ValueError):
        raise ExecutionPolicyError("Adapter executable is missing, unsuitable, or a shell.") from None
    if plan.environment is not None:
        if (type(plan.environment) is not tuple or not plan.environment
                or any(type(pair) is not tuple or len(pair) != 2
                       or any(type(item) is not str or "\x00" in item for item in pair)
                       or not pair[0] or "=" in pair[0] for pair in plan.environment)
                or len({key.casefold() for key, _ in plan.environment}) != len(plan.environment)):
            raise ExecutionPolicyError("Adapter environment must be explicit immutable text pairs.")
    if plan.working_directory is not None:
        from core.recon.tool_discovery import _LocalInspection
        try:
            if (not Path(plan.working_directory).is_absolute()
                    or str(_LocalInspection(os.name == "nt").path(plan.working_directory, directory=True))
                    != plan.working_directory):
                raise ValueError
        except (OSError, ValueError, TypeError):
            raise ExecutionPolicyError("Adapter working directory must be a safe absolute local directory.") from None
    return _AdapterPlan(str(resolved), plan.arguments, plan.targets, plan.timeout_ms,
                        plan.environment, plan.working_directory)


class ExecutionPolicy:
    """Issue capabilities only from reviewed application adapters and scope grants."""

    def prepare(self, adapter_id: str, request: object, approval: object) -> ValidatedExecutionSpec:
        adapter = _TRUSTED_ADAPTERS.get(adapter_id) if type(adapter_id) is str else None
        if adapter is None:
            raise ExecutionPolicyError("No trusted adapter is connected; R4 live execution is disabled.")
        if type(request) is not adapter.request_type:
            raise ExecutionPolicyError("A typed request belonging to the trusted adapter is required.")
        try:
            plan = _validate_plan(adapter.build(request), approval, adapter_id=adapter_id, adapter=adapter)
        except ExecutionPolicyError:
            raise
        except Exception:
            # Adapter exceptions can contain credentials/arguments; never echo them.
            raise ExecutionPolicyError("Trusted adapter could not prepare an execution plan.") from None
        if adapter_id in {"subfinder.version-check", "subfinder.passive-standard"}:
            from core.recon.subfinder_adapter import _bind_subfinder_approval
            _bind_subfinder_approval(approval)
        elif type(approval) is not ScopeApproval:
            from core.recon.nmap_adapter import _bind_nmap_approval
            _bind_nmap_approval(approval)
        spec = object.__new__(ValidatedExecutionSpec)
        for name, value in (
            ("adapter_id", adapter_id), ("_plan", plan), ("_approval", approval),
            ("_adapter", adapter), ("_seal", _SPEC_SEAL),
        ):
            object.__setattr__(spec, name, value)
        _ISSUED_SPECS[spec] = False
        return spec

    def validate(self, spec: ValidatedExecutionSpec) -> None:
        """Recheck approval and adapter connection immediately before execution."""
        if (type(spec) is not ValidatedExecutionSpec
                or getattr(spec, "_seal", None) is not _SPEC_SEAL or spec not in _ISSUED_SPECS):
            raise ExecutionPolicyError("A validated application execution specification is required.")
        if _TRUSTED_ADAPTERS.get(spec.adapter_id) is not spec._adapter:
            raise ExecutionPolicyError("The trusted adapter is no longer connected.")
        if _validate_plan(spec._plan, spec._approval, adapter_id=spec.adapter_id, adapter=spec._adapter) != spec._plan:
            raise ExecutionPolicyError("The validated executable identity changed.")

    def _claim(self, spec: ValidatedExecutionSpec) -> None:
        self.validate(spec)
        if _ISSUED_SPECS[spec]:
            raise ExecutionPolicyError("Execution specifications can only be submitted once.")
        _ISSUED_SPECS[spec] = True
