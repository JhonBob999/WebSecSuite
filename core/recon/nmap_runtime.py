"""Explicit Nmap setup and bounded approved runs through the shared runtime."""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from core.recon.inventory import AssetInventory
from core.recon.nmap_adapter import (
    approve_nmap_path, parse_trusted_nmap_output, prepare_nmap_self_test,
    prepare_nmap_version_check, verify_nmap_version, approve_public_nmap, prepare_nmap_public_scan,
)
from core.recon.nmap_public_output import parse_public_nmap_output
from core.recon.nmap_profile_execution import (
    approve_profile_nmap, prepare_nmap_profile_scan, validate_executable_profile,
)
from core.recon.nmap_authorized_execution import (
    approve_authorized_nmap, prepare_nmap_authorized_scan, release_authorized_approval,
)
from core.recon.nmap_authorized_output import parse_authorized_nmap_output
from core.recon.process_supervisor import JobSnapshot, JobState, ProcessSupervisor, process_safety_status
from core.recon.public_target import PublicTargetPreflight, selected_public_hostname, validate_public_address


class NmapRuntime(QObject):
    """Keep process results separate from successful, validated inventory imports.

    Construction never launches anything. Approval starts a bounded version
    check; each scan requires its own confirmation. The supervisor is parented
    to the application so it outlives a disappearing UI while stopping a job.
    Raw process output stays only in the supervisor's bounded memory history.
    """

    changed = Signal()
    inventory_changed = Signal()

    def __init__(self, inventory: AssetInventory, parent: QObject | None = None):
        super().__init__(parent)
        self._inventory = inventory
        self._supervisor = ProcessSupervisor()
        self._supervisor.job_changed.connect(self._job_changed)
        self._supervisor.job_finished.connect(self._job_finished)
        supervisor = self._supervisor
        self.destroyed.connect(lambda: supervisor.shutdown(immediate=True))
        self._job_id: str | None = None
        self._submitting = False
        self._phase = ""
        self._candidate = None
        self._tool = None
        self._closing = False
        self._stop_requested = False
        self._status = "Setup required: choose and approve a local Nmap executable."
        self.public_preflight = PublicTargetPreflight(self)
        self.public_preflight.changed.connect(self.changed)
        self._public_context = None
        self._profile_context = None
        self._authorized_context = None
        self.last_authorized_result = None

    @property
    def busy(self) -> bool:
        return self._job_id is not None or self._submitting

    @property
    def safety_reason(self) -> str:
        available, reason = process_safety_status()
        return "" if available else reason

    @property
    def can_run(self) -> bool:
        return (not self._closing and not self.busy and not self.public_preflight.busy
                and self._tool is not None and not self.safety_reason)

    @property
    def executable_path(self) -> str:
        return self._tool.executable_path if self._tool is not None else ""

    @property
    def version(self) -> str:
        return self._tool.version if self._tool is not None else ""

    def capabilities(self):
        """Explicit read-only inspection; construction does not inspect or launch tools."""
        from core.recon.nmap_capabilities import detect_capabilities
        return detect_capabilities(self._tool)

    def discover_nse_scripts(self):
        from core.recon.nmap_nse import discover_scripts
        if self._tool is None:
            raise ValueError("Choose and verify Nmap before loading its script catalog.")
        return discover_scripts(self._tool)

    def authorized_arguments(self, scope, profile):
        from core.recon.nmap_authorized_execution import authorized_arguments
        if self._tool is None:
            raise ValueError("Choose and verify Nmap before reviewing the executable plan.")
        return authorized_arguments(self._tool, scope, profile)

    def implicit_version_scripts(self):
        from core.recon.nmap_authorized_execution import implicit_version_scripts
        if self._tool is None:
            raise ValueError("Choose and verify Nmap before reviewing version engine scripts.")
        return implicit_version_scripts(self._tool)

    @property
    def status(self) -> str:
        return self._status

    def _require_idle_safe(self) -> None:
        if self._closing:
            raise ValueError("The Nmap runtime is shutting down.")
        if self.busy:
            raise ValueError("A Nmap operation is already running.")
        if self.public_preflight.busy:
            raise ValueError("A public DNS preflight is already running.")
        if reason := self.safety_reason:
            self._status = "HOLD: " + reason
            self.changed.emit()
            raise ValueError(reason)

    def approve_executable(self, path: str) -> str:
        """Called only after explicit executable selection/approval by the user."""
        self._require_idle_safe()
        self._tool = self._candidate = None
        self.public_preflight.clear()
        try:
            candidate = approve_nmap_path(path, confirmed=True)
            spec = prepare_nmap_version_check(candidate)
            self._candidate = candidate
            job_id = self._supervisor.submit(spec)
        except (ValueError, RuntimeError) as error:
            self._candidate = None
            self._status = f"Nmap verification failed: {error}"
            self.changed.emit()
            raise
        self._job_id, self._phase = job_id, "verify"
        self._stop_requested = False
        self._status = "Verifying approved Nmap executable…"
        self.changed.emit()
        return job_id

    def _public_run_observation(self, selected_targets, *, address, scope_confirmed, confirmed):
        """Shared public target checks; DNS remains observation, never scope."""
        self._require_idle_safe()
        hostname = selected_public_hostname(selected_targets)
        if confirmed is not True or scope_confirmed is not True:
            raise ValueError("Confirm this run and that the selected public IP is within your authorized scope.")
        if self._tool is None:
            raise ValueError("Choose and verify an approved Nmap executable first.")
        observation = self.public_preflight.observation
        if (not self.public_preflight.is_fresh or observation.hostname != hostname
                or validate_public_address(address) not in observation.ipv4_addresses):
            raise ValueError("Select one public IPv4 from a fresh DNS preflight for the selected hostname.")
        return observation

    def start_public_scan(self, selected_targets, *, address: str, scope_confirmed: bool, confirmed: bool) -> str:
        """Consume one preflight only after explicit hostname/IP/run confirmation."""
        observation = self._public_run_observation(selected_targets, address=address,
            scope_confirmed=scope_confirmed, confirmed=confirmed)
        hostname = observation.hostname
        observation = self.public_preflight.take_observation()
        try:
            approval = approve_public_nmap(self._tool, observation, address=address,
                                           scope_confirmed=scope_confirmed, confirmed=confirmed)
            spec = prepare_nmap_public_scan(self._tool, approval)
            job_id = self._supervisor.submit(spec)
        except (ValueError, RuntimeError) as error:
            self._status = f"Quick Network Discovery preflight failed: {error}"
            self.changed.emit()
            raise
        # Capture immutable provenance separately from the consumed grant. UI
        # target changes during execution cannot change this numeric target.
        self._public_context = (observation, address)
        self._job_id, self._phase = job_id, "public-scan"
        self._stop_requested = False
        self._status = f"Quick Network Discovery queued: {hostname} → {address}, TCP 80, 443, 8080, 8443."
        self.changed.emit()
        return job_id

    def start_profile_scan(self, selected_targets, *, profile, profile_store=None, address: str,
                           scope_confirmed: bool, confirmed: bool) -> str:
        """Run a saved eligible snapshot through the existing contained supervisor."""
        self._public_run_observation(selected_targets, address=address,
            scope_confirmed=scope_confirmed, confirmed=confirmed)
        snapshot = validate_executable_profile(profile)
        self._submitting = True
        self._phase = "profile-scan"
        self._stop_requested = False
        try:
            observation = self.public_preflight.take_observation()
            if self._closing or self._stop_requested:
                raise ValueError("Profile scan cancelled before launch.")
            approval = approve_profile_nmap(self._tool, observation, profile=profile,
                profile_store=profile_store, address=address,
                scope_confirmed=scope_confirmed, confirmed=confirmed)
            spec = prepare_nmap_profile_scan(self._tool, approval)
            # Capture inert provenance separately from the one-shot grant.
            snapshot = validate_executable_profile(approval.profile)
            self._public_context = (observation, address)
            self._profile_context = (snapshot, self._tool.version)
            if self._closing or self._stop_requested:
                raise ValueError("Profile scan cancelled before launch.")
            job_id = self._supervisor.submit(spec)
            # A queued signal can synchronously Stop/shut down and finish the
            # job before submit returns. Never resurrect that completed job.
            if self._phase == "profile-scan":
                self._job_id = job_id
                if self._closing or self._stop_requested:
                    self._supervisor.cancel(job_id)
                elif self._job_id is not None:
                    self._status = f"{snapshot.name} queued: {observation.hostname} → {address}, {len(snapshot.ports)} TCP ports."
        except (ValueError, RuntimeError) as error:
            if self._job_id is None:
                self._phase = ""
                self._public_context = self._profile_context = None
            self._status = f"Profile scan preflight failed: {error}"
            raise
        finally:
            self._submitting = False
            self.changed.emit()
        return job_id

    def start_self_test(self, *, confirmed: bool, target: str = "127.0.0.1") -> str:
        self._require_idle_safe()
        if confirmed is not True or type(target) is not str or target != "127.0.0.1":
            raise ValueError("Confirm this run on exactly 127.0.0.1; no other target is permitted.")
        if self._tool is None:
            raise ValueError("Choose and verify an approved Nmap executable first.")
        try:
            spec = prepare_nmap_self_test(self._tool, confirmed=True, target=target)
            job_id = self._supervisor.submit(spec)
        except (ValueError, RuntimeError) as error:
            self._tool = None
            self._status = f"Local Self-Test preflight failed: {error}"
            self.changed.emit()
            raise
        self._job_id, self._phase = job_id, "scan"
        self._stop_requested = False
        self._status = "Local Self-Test queued: 127.0.0.1, TCP ports 80, 443, 8080, 8443."
        self.changed.emit()
        return job_id

    def start_authorized_scan(self, scope, *, profile, profile_store=None,
                              scope_confirmed: bool, confirmed: bool,
                              high_impact_confirmed: bool = False,
                              version_nse_confirmed: bool = False) -> str:
        """Submit one explicitly authorized profile through the existing supervisor."""
        self._require_idle_safe()
        if self._tool is None:
            raise ValueError("Choose and verify an approved Nmap executable first.")
        self._submitting = True
        self._phase = "authorized-scan"
        self._stop_requested = False
        self.last_authorized_result = None
        approval = None
        try:
            approval = approve_authorized_nmap(self._tool, scope, profile=profile,
                profile_store=profile_store, scope_confirmed=scope_confirmed,
                confirmed=confirmed, high_impact_confirmed=high_impact_confirmed,
                version_nse_confirmed=version_nse_confirmed)
            spec = prepare_nmap_authorized_scan(self._tool, approval)
            self._authorized_context = approval
            if self._closing or self._stop_requested:
                raise ValueError("Authorized scan cancelled before launch.")
            job_id = self._supervisor.submit(spec)
            if self._phase == "authorized-scan":
                self._job_id = job_id
                if self._closing or self._stop_requested:
                    self._supervisor.cancel(job_id)
                else:
                    self._status = f"{approval.profile.name}: authorized scan queued."
        except (ValueError, RuntimeError) as error:
            if self._job_id is None:
                self._phase = ""
                self._authorized_context = None
                if approval is not None:
                    release_authorized_approval(approval)
            self._status = f"Authorized scan preflight failed: {error}"
            raise
        finally:
            self._submitting = False
            self.changed.emit()
        return job_id

    def stop(self) -> None:
        if self.public_preflight.busy:
            self.public_preflight.clear()
        if self.busy and not self._stop_requested:
            self._stop_requested = True
            if self._job_id is not None:
                self._supervisor.cancel(self._job_id)
            # cancel() may finish a queued job synchronously.
            if self.busy and self._phase:
                self._status = "Stopping Nmap…"
                self.changed.emit()

    def shutdown(self, *, immediate: bool = False) -> None:
        self._closing = True
        self._stop_requested = True
        self.public_preflight.clear()
        self._supervisor.shutdown(immediate=immediate)
        self.changed.emit()


    def _job_changed(self, snapshot: JobSnapshot) -> None:
        pending_adapter = {"profile-scan": "nmap.public-profile", "authorized-scan": "nmap.authorized-profile"}.get(self._phase)
        if (self._submitting and pending_adapter and self._job_id is None
                and snapshot.adapter_id == pending_adapter and snapshot.state == JobState.QUEUED):
            self._job_id = snapshot.job_id
            if self._stop_requested or self._closing:
                self._supervisor.cancel(snapshot.job_id)
        if snapshot.job_id != self._job_id:
            return
        if snapshot.state in (JobState.STARTING, JobState.RUNNING):
            action = self._action(self._phase)
            self._status = f"{action}: {snapshot.state.value.lower()}."
            self.changed.emit()

    def _job_finished(self, snapshot: JobSnapshot) -> None:
        if snapshot.job_id != self._job_id:
            return
        phase, candidate, public_context = self._phase, self._candidate, self._public_context
        profile_context = self._profile_context
        authorized_context = self._authorized_context
        self._authorized_context = None
        self._public_context = None
        self._profile_context = None
        self._job_id, self._phase, self._candidate = None, "", None
        action = self._action(phase)
        if self._closing or self._stop_requested or snapshot.state == JobState.CANCELLED:
            self._status = f"{action}: cancelled. No results imported."
        elif snapshot.state == JobState.TIMED_OUT:
            self._status = f"{action}: timed out. No results imported."
        elif snapshot.state != JobState.SUCCEEDED or snapshot.exit_code != 0:
            self._status = f"{action}: failed. {snapshot.diagnostic} No results imported."
        elif snapshot.output_truncated:
            self._status = f"{action}: failed; output limit exceeded. No results imported."
        elif phase == "public-scan" and snapshot.adapter_id != "nmap.public-quick-discovery":
            self._status = f"{action}: failed; unexpected execution identity. No results imported."
        elif phase == "profile-scan" and snapshot.adapter_id != "nmap.public-profile":
            self._status = f"{action}: failed; unexpected execution identity. No results imported."
        elif phase == "authorized-scan" and snapshot.adapter_id != "nmap.authorized-profile":
            self._status = f"{action}: failed; unexpected execution identity. No results imported."
        else:
            try:
                if phase == "verify":
                    self._tool = verify_nmap_version(candidate, snapshot)
                    self._status = f"Nmap {self._tool.version} verified. Local Self-Test ready for confirmation."
                else:
                    if phase == "authorized-scan":
                        approval = authorized_context
                        batch = parse_authorized_nmap_output(snapshot.stdout, scope=approval.scope,
                            profile=approval.profile, executable_version=approval._version,
                            executable_sha256=approval._sha256, arguments=approval._arguments,
                            scripts=approval.scripts, expected_ports=getattr(approval, "expected_ports", ()),
                            run_id="nmap:authorized:" + snapshot.job_id)
                        label = f"Nmap {approval.profile.name} · authorized scope"
                    elif phase == "profile-scan":
                        observation, address = public_context
                        profile, version = profile_context
                        batch = parse_public_nmap_output(snapshot.stdout, observation=observation,
                            address=address, run_id="nmap:public:" + snapshot.job_id,
                            profile=profile, executable_version=version)
                        label = f"Nmap {profile.name} · {observation.hostname} · {address}"
                    elif phase == "public-scan":
                        observation, address = public_context
                        batch = parse_public_nmap_output(snapshot.stdout, observation=observation,
                                                        address=address, run_id="nmap:public:" + snapshot.job_id)
                        label = f"Nmap Quick Network Discovery · {observation.hostname} · {address}"
                    else:
                        batch = parse_trusted_nmap_output(snapshot.stdout)
                        label = "Nmap Local Self-Test"
                    result = self._inventory.import_batch(
                        batch, label=label, format_name="Nmap live XML",
                    )
                    if phase == "authorized-scan":
                        self.last_authorized_result = {
                            "run_id": batch.run_id, "profile": approval.profile.name,
                            "observations": [item.to_dict() for item in batch.observations],
                        }
                    open_count = sum(item.entity_type == "service" for item in batch.observations)
                    self._status = (
                        f"{action} succeeded: {open_count} open {'TCP/UDP' if phase == 'authorized-scan' else 'TCP'} ports · "
                        f"Added: {result.added_observations} observations · Duplicates: {result.duplicates}."
                    )
                    self.inventory_changed.emit()
            except (ValueError, RuntimeError) as error:
                if phase == "verify":
                    self._tool = None
                self._status = f"{action} failed: {error} No results imported."
        if authorized_context is not None:
            release_authorized_approval(authorized_context)
        self.changed.emit()

    @staticmethod
    def _action(phase: str) -> str:
        if phase == "verify":
            return "Nmap verification"
        if phase == "profile-scan":
            return "Nmap profile scan"
        if phase == "authorized-scan":
            return "Authorized Nmap scan"
        return "Quick Network Discovery" if phase == "public-scan" else "Local Self-Test"


__all__ = ["NmapRuntime"]
