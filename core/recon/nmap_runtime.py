"""Explicit Nmap setup and localhost runs through the shared Recon runtime."""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from core.recon.inventory import AssetInventory
from core.recon.nmap_adapter import (
    approve_nmap_path, parse_trusted_nmap_output, prepare_nmap_self_test,
    prepare_nmap_version_check, verify_nmap_version,
)
from core.recon.process_supervisor import JobSnapshot, JobState, ProcessSupervisor, process_safety_status


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
        self._phase = ""
        self._candidate = None
        self._tool = None
        self._closing = False
        self._stop_requested = False
        self._status = "Setup required: choose and approve a local Nmap executable."

    @property
    def busy(self) -> bool:
        return self._job_id is not None

    @property
    def safety_reason(self) -> str:
        available, reason = process_safety_status()
        return "" if available else reason

    @property
    def can_run(self) -> bool:
        return not self._closing and not self.busy and self._tool is not None and not self.safety_reason

    @property
    def executable_path(self) -> str:
        return self._tool.executable_path if self._tool is not None else ""

    @property
    def version(self) -> str:
        return self._tool.version if self._tool is not None else ""

    @property
    def status(self) -> str:
        return self._status

    def _require_idle_safe(self) -> None:
        if self._closing:
            raise ValueError("The Nmap runtime is shutting down.")
        if self.busy:
            raise ValueError("A Nmap operation is already running.")
        if reason := self.safety_reason:
            self._status = "HOLD: " + reason
            self.changed.emit()
            raise ValueError(reason)

    def approve_executable(self, path: str) -> str:
        """Called only after explicit executable selection/approval by the user."""
        self._require_idle_safe()
        self._tool = self._candidate = None
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

    def stop(self) -> None:
        if self._job_id is not None and not self._stop_requested:
            self._stop_requested = True
            self._supervisor.cancel(self._job_id)
            # cancel() may finish a queued job synchronously.
            if self.busy:
                self._status = "Stopping Nmap…"
                self.changed.emit()

    def shutdown(self, *, immediate: bool = False) -> None:
        self._closing = True
        self._stop_requested = True
        self._supervisor.shutdown(immediate=immediate)
        self.changed.emit()

    def _job_changed(self, snapshot: JobSnapshot) -> None:
        if snapshot.job_id != self._job_id:
            return
        if snapshot.state in (JobState.STARTING, JobState.RUNNING):
            action = "Nmap verification" if self._phase == "verify" else "Local Self-Test"
            self._status = f"{action}: {snapshot.state.value.lower()}."
            self.changed.emit()

    def _job_finished(self, snapshot: JobSnapshot) -> None:
        if snapshot.job_id != self._job_id:
            return
        phase, candidate = self._phase, self._candidate
        self._job_id, self._phase, self._candidate = None, "", None
        action = "Nmap verification" if phase == "verify" else "Local Self-Test"
        if self._closing or self._stop_requested or snapshot.state == JobState.CANCELLED:
            self._status = f"{action}: cancelled. No results imported."
        elif snapshot.state == JobState.TIMED_OUT:
            self._status = f"{action}: timed out. No results imported."
        elif snapshot.state != JobState.SUCCEEDED or snapshot.exit_code != 0:
            self._status = f"{action}: failed. {snapshot.diagnostic} No results imported."
        elif snapshot.output_truncated:
            self._status = f"{action}: failed; output limit exceeded. No results imported."
        else:
            try:
                if phase == "verify":
                    self._tool = verify_nmap_version(candidate, snapshot)
                    self._status = f"Nmap {self._tool.version} verified. Local Self-Test ready for confirmation."
                else:
                    batch = parse_trusted_nmap_output(snapshot.stdout)
                    result = self._inventory.import_batch(
                        batch, label="Nmap Local Self-Test", format_name="Nmap live XML",
                    )
                    open_count = sum(item.entity_type == "service" for item in batch.observations)
                    self._status = (
                        f"Local Self-Test succeeded: {open_count} open TCP ports · "
                        f"Added: {result.added_observations} observations · Duplicates: {result.duplicates}."
                    )
                    self.inventory_changed.emit()
            except (ValueError, RuntimeError) as error:
                if phase == "verify":
                    self._tool = None
                self._status = f"{action} failed: {error} No results imported."
        self.changed.emit()


__all__ = ["NmapRuntime"]
