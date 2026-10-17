"""Explicit Subfinder setup and passive discovery through the bounded supervisor."""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from core.recon.execution_policy import ExecutionPolicyError, ScopeApproval
from core.recon.inventory import AssetInventory
from core.recon.process_supervisor import JobSnapshot, JobState, ProcessSupervisor, process_safety_status
from core.recon.subfinder_adapter import (
    approve_subfinder_path, approve_subfinder_run, prepare_subfinder_discovery,
    prepare_subfinder_version_check, verify_subfinder_version,
)
from core.recon.subfinder_output import parse_subfinder_output


class SubfinderRuntime(QObject):
    """Keep executable trust, explicit run approval, and imports separate.

    Construction performs no discovery or execution. Candidate/tool references
    retain the adapter's private configuration throughout queued/running jobs.
    The application-owned supervisor outlives this controller while stopping.
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
        self._submitting = False
        self._candidate = None
        self._tool = None
        self._root_domain: str | None = None
        self._closing = False
        self._stop_requested = False
        self._status = "Setup required: approve a local Subfinder executable and official release ZIP."

    @property
    def busy(self) -> bool:
        return bool(self._phase) or self._submitting

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
            raise ValueError("The Subfinder runtime is shutting down.")
        if self.busy:
            raise ValueError("A Subfinder operation is already running.")
        if reason := self.safety_reason:
            self._status = "HOLD: " + reason
            self.changed.emit()
            raise ValueError(reason)

    def approve_executable(self, path: str, *, archive_path: str) -> str:
        """Approve release identity before a single bounded version probe."""
        self._require_idle_safe()
        self._tool = self._candidate = None
        self._phase = "verify"
        self._stop_requested = False
        try:
            self._candidate = approve_subfinder_path(path, archive_path=archive_path, confirmed=True)
            spec = prepare_subfinder_version_check(self._candidate)
            self._status = "Verifying approved Subfinder executable…"
            return self._queue(spec)
        except ExecutionPolicyError as error:
            self._clear_failed_start()
            self._status = "HOLD: " + str(error)
            self.changed.emit()
            raise ValueError(self._status) from None
        except (OSError, ValueError, RuntimeError):
            self._clear_failed_start()
            self._status = "Subfinder verification failed. Approve the matching official release files again."
            self.changed.emit()
            raise ValueError(self._status) from None

    def start_discovery(self, selected_targets, *, confirmed: bool, approval: ScopeApproval) -> str:
        """Capture one canonical root using the adapter's one-shot scope grant."""
        self._require_idle_safe()
        if self._tool is None:
            raise ValueError("Choose and verify an approved Subfinder executable first.")
        self._phase = "discovery"
        self._stop_requested = False
        try:
            grant = approve_subfinder_run(self._tool, selected_targets, confirmed=confirmed, approval=approval)
            self._root_domain = grant.hostname
            spec = prepare_subfinder_discovery(self._tool, grant)
            self._status = f"Passive Standard queued: {self._root_domain}."
            return self._queue(spec)
        except ExecutionPolicyError as error:
            self._clear_failed_start()
            self._status = "Passive Standard preflight failed: " + str(error)
            self.changed.emit()
            raise ValueError(self._status) from None
        except (OSError, ValueError, RuntimeError):
            self._clear_failed_start()
            self._status = "Passive Standard preflight failed. Confirm one approved root and unchanged verified tool."
            self.changed.emit()
            raise ValueError(self._status) from None

    def _queue(self, spec) -> str:
        # submit() emits QUEUED synchronously. Bind that job before any callback
        # can stop it; a synchronous finish must never be reinstated as active.
        self._submitting = True
        try:
            job_id = self._supervisor.submit(spec)
            if self._phase and self._job_id is None:
                self._job_id = job_id
                if self._stop_requested or self._closing:
                    self._supervisor.cancel(job_id)
        finally:
            self._submitting = False
            self._release_closed_context()
        self.changed.emit()
        return job_id

    def _clear_failed_start(self) -> None:
        if self._job_id is not None:
            self._stop_requested = True
            self._supervisor.cancel(self._job_id)
            # Retain operation context until a submitted process really stops.
            if self._job_id is not None:
                return
        self._phase = ""
        self._candidate = None
        self._root_domain = None
        self._release_closed_context()

    def _release_closed_context(self) -> None:
        if self._closing and not self.busy:
            self._tool = self._candidate = None
            self._root_domain = None

    def stop(self) -> None:
        if self.busy and not self._stop_requested:
            self._stop_requested = True
            if self._job_id is not None:
                self._supervisor.cancel(self._job_id)
            if self.busy:
                self._status = "Stopping Subfinder…"
                self.changed.emit()

    def shutdown(self, *, immediate: bool = False) -> None:
        self._closing = True
        self._stop_requested = True
        self._supervisor.shutdown(immediate=immediate)
        self._release_closed_context()
        self.changed.emit()

    def _job_changed(self, snapshot: JobSnapshot) -> None:
        if type(snapshot) is not JobSnapshot or type(snapshot.state) is not JobState:
            return
        expected = "subfinder.version-check" if self._phase == "verify" else "subfinder.passive-standard"
        if (self._submitting and self._phase and self._job_id is None
                and snapshot.adapter_id == expected and snapshot.state is JobState.QUEUED):
            self._job_id = snapshot.job_id
            if self._stop_requested or self._closing:
                self._supervisor.cancel(snapshot.job_id)
        if (snapshot.job_id != self._job_id or snapshot.adapter_id != expected
                or self._stop_requested or self._closing):
            return
        if snapshot.state in (JobState.STARTING, JobState.RUNNING):
            self._status = f"{self._action(self._phase)}: {snapshot.state.value.lower()}."
            self.changed.emit()

    def _job_finished(self, snapshot: JobSnapshot) -> None:
        if type(snapshot) is not JobSnapshot or snapshot.job_id != self._job_id:
            return
        phase, candidate, root_domain = self._phase, self._candidate, self._root_domain
        self._job_id, self._phase, self._candidate, self._root_domain = None, "", None, None
        action = self._action(phase)
        expected = "subfinder.version-check" if phase == "verify" else "subfinder.passive-standard"
        if self._closing or self._stop_requested or snapshot.state is JobState.CANCELLED:
            self._status = f"{action}: cancelled. No results imported."
        elif snapshot.state is JobState.TIMED_OUT:
            self._status = f"{action}: timed out. No results imported."
        elif (phase not in {"verify", "discovery"} or snapshot.adapter_id != expected
                or type(snapshot.state) is not JobState or snapshot.state is not JobState.SUCCEEDED
                or type(snapshot.exit_code) is not int or snapshot.exit_code != 0
                or type(snapshot.stdout) is not bytes or type(snapshot.stderr) is not bytes
                or type(snapshot.stdout_truncated) is not bool or snapshot.stdout_truncated
                or type(snapshot.stderr_truncated) is not bool or snapshot.stderr_truncated):
            self._status = f"{action}: failed or incomplete output. No results imported."
        else:
            try:
                if phase == "verify":
                    self._tool = verify_subfinder_version(candidate, snapshot)
                    self._status = f"Subfinder {self._tool.version} verified. Passive Standard ready for confirmation."
                else:
                    batch = parse_subfinder_output(snapshot, root_domain=root_domain,
                                                   run_id="subfinder:passive:" + snapshot.job_id)
                    result = self._inventory.import_batch(
                        batch, label=f"Subfinder Passive Standard · {root_domain}",
                        format_name="Subfinder live JSONL",
                    )
                    self._status = (
                        f"Passive Standard succeeded: {len(batch.observations)} discovered hostnames · "
                        f"Added: {result.added_observations} observations · Duplicates: {result.duplicates} · "
                        "Saved in import history."
                    )
                    self.inventory_changed.emit()
            except ExecutionPolicyError as error:
                if phase == "verify":
                    self._tool = None
                self._status = "HOLD: " + str(error) + " No results imported."
            except (OSError, ValueError, RuntimeError):
                if phase == "verify":
                    self._tool = None
                self._status = f"{action} failed validation or import. No results imported."
        self._release_closed_context()
        self.changed.emit()

    @staticmethod
    def _action(phase: str) -> str:
        return "Subfinder verification" if phase == "verify" else "Passive Standard"


__all__ = ["SubfinderRuntime"]
