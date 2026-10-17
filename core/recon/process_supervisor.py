"""Asynchronous, single-process Recon lifecycle with bounded in-memory output.

Only capabilities from execution_policy are accepted. It is independent
of ScraperTaskManager and never changes the global thread pool.

Windows uses a suspended native launch assigned to a private kill-on-close Job
Object before user code can run. Other platforms retain the QProcess backend.
Retain this QObject until shutdown_finished; shutdown never blocks the GUI.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
import os
from uuid import uuid4

from PySide6.QtCore import QCoreApplication, QObject, QProcess, QProcessEnvironment, QTimer, Signal

from core.recon.execution_policy import ExecutionPolicy, ExecutionPolicyError, ValidatedExecutionSpec
from core.recon.windows_process import WindowsJobProcess, process_safety_status


_QT_PROCESS = QProcess


class JobState(str, Enum):
    QUEUED = "QUEUED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


_TERMINAL = frozenset((JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED, JobState.TIMED_OUT))


@dataclass(frozen=True)
class JobSnapshot:
    job_id: str
    adapter_id: str
    state: JobState
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    exit_code: int | None = None
    diagnostic: str = ""

    @property
    def output_truncated(self) -> bool:
        return self.stdout_truncated or self.stderr_truncated


@dataclass
class _Job:
    job_id: str
    adapter_id: str
    spec: ValidatedExecutionSpec | None = field(repr=False)
    state: JobState = JobState.QUEUED
    stdout: bytearray = field(default_factory=bytearray, repr=False)
    stderr: bytearray = field(default_factory=bytearray, repr=False)
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    exit_code: int | None = None
    diagnostic: str = "Queued for execution."
    process: QProcess | WindowsJobProcess | None = field(default=None, repr=False)
    timeout: QTimer | None = field(default=None, repr=False)
    grace: QTimer | None = field(default=None, repr=False)
    pending_terminal: JobState | None = None
    drain_scheduled: bool = False
    next_channel: int = 0
    kill_sent: bool = False


class ProcessSupervisor(QObject):
    """Own one contained process at a time; methods run on the owning Qt thread.

    The output budget is combined stdout + stderr per job. Both the queued-job
    count and completed history are bounded. Snapshots contain raw bounded
    bytes for future parsers, but diagnostics never include argv, environment,
    Qt errorString(), or adapter exception text. Nothing is persisted/logged.
    """

    job_changed = Signal(object)
    job_finished = Signal(object)
    shutdown_finished = Signal()

    def __init__(
        self, parent: QObject | None = None, *, max_output_bytes: int = 1_048_576,
        read_chunk_bytes: int = 16_384, drain_budget_bytes: int = 262_144,
        termination_grace_ms: int = 1000, max_queued_jobs: int = 32, max_completed_jobs: int = 32,
    ):
        app = QCoreApplication.instance()
        super().__init__(parent if parent is not None else app)
        limits = (read_chunk_bytes, drain_budget_bytes, termination_grace_ms, max_queued_jobs, max_completed_jobs)
        if type(max_output_bytes) is not int or max_output_bytes < 0 or any(type(value) is not int or value < 1 for value in limits):
            raise ValueError("Supervisor limits must be bounded nonnegative/positive integers.")
        if drain_budget_bytes < read_chunk_bytes or termination_grace_ms > 2_147_483_647:
            raise ValueError("Drain budget must cover a chunk and grace duration must fit a Qt timer.")
        self._policy = ExecutionPolicy()
        self._max_output = max_output_bytes
        self._chunk = read_chunk_bytes
        self._drain_budget = drain_budget_bytes
        self._grace_ms = termination_grace_ms
        self._max_queued = max_queued_jobs
        self._max_completed = max_completed_jobs
        self._jobs: dict[str, _Job] = {}
        self._queue: deque[str] = deque()
        self._completed: deque[str] = deque()
        self._active: _Job | None = None
        self._start_scheduled = False
        self._closing = False
        self._shutdown_emitted = False
        if app is not None:
            app.aboutToQuit.connect(self._about_to_quit)

    def submit(self, spec: ValidatedExecutionSpec) -> str:
        if self._closing:
            raise RuntimeError("The process supervisor is shutting down.")
        if len(self._queue) >= self._max_queued:
            raise RuntimeError("The process queue is full.")
        self._policy._claim(spec)
        job = _Job(uuid4().hex, spec.adapter_id, spec)
        self._jobs[job.job_id] = job
        self._queue.append(job.job_id)
        self.job_changed.emit(self.snapshot(job.job_id))
        self._schedule_start()
        return job.job_id

    def snapshot(self, job_id: str) -> JobSnapshot:
        job = self._jobs[job_id]
        return JobSnapshot(
            job.job_id, job.adapter_id, job.state, bytes(job.stdout), bytes(job.stderr),
            job.stdout_truncated, job.stderr_truncated, job.exit_code, job.diagnostic,
        )

    def cancel(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if job is None or job.state in _TERMINAL or job.pending_terminal is not None:
            return False
        self._request_stop(job, JobState.CANCELLED, "Process cancelled.")
        return True

    def shutdown(self, *, immediate: bool = False) -> None:
        """Cancel queued jobs and stop the process tree without a blocking wait.

        Call before quitting to allow terminate() + the grace timer to run.
        aboutToQuit uses immediate kill because Qt may not deliver more timers.
        Windows also closes the kill-on-close job before the event loop ends.
        On other platforms termination still controls the direct process only.
        """
        self._closing = True
        for job_id in tuple(self._queue):
            self.cancel(job_id)
        job = self._active
        if job is not None:
            self.cancel(job.job_id)
            if immediate and self._active is job:
                self._kill(job)
                if isinstance(job.process, WindowsJobProcess):
                    job.process.close_job()
        self._check_shutdown()

    def _about_to_quit(self) -> None:
        self.shutdown(immediate=True)

    def _schedule_start(self) -> None:
        if not self._closing and not self._start_scheduled and self._active is None and self._queue:
            self._start_scheduled = True
            QTimer.singleShot(0, self._start_next)

    def _start_next(self) -> None:
        self._start_scheduled = False
        if self._closing or self._active is not None or not self._queue:
            return
        job = self._jobs[self._queue.popleft()]
        self._active = job
        try:
            self._policy.validate(job.spec)
        except ExecutionPolicyError:
            self._complete(job, JobState.FAILED, "Execution preflight is no longer valid.")
            return
        try:
            # Preserve injected QProcess doubles and the cross-platform backend.
            # A real Windows launch never falls back to uncontained QProcess.
            factory = WindowsJobProcess if os.name == "nt" and QProcess is _QT_PROCESS else QProcess
            process = job.process = factory(self)
            process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
            process.setProgram(job.spec._plan.program)
            process.setArguments(list(job.spec._plan.arguments))
            if job.spec._plan.environment is not None:
                environment = QProcessEnvironment()
                for key, value in job.spec._plan.environment:
                    environment.insert(key, value)
                process.setProcessEnvironment(environment)
            if job.spec._plan.working_directory is not None:
                process.setWorkingDirectory(job.spec._plan.working_directory)
            if isinstance(process, WindowsJobProcess):
                process.setPreflightValidator(lambda: self._policy.validate(job.spec))
            process.started.connect(lambda: self._started(job))
            process.finished.connect(lambda code, status: self._finished(job, code, status))
            process.errorOccurred.connect(lambda error: self._error(job, error))
            process.stateChanged.connect(lambda state: self._state_changed(job, state))
            process.readyReadStandardOutput.connect(lambda: self._drain(job))
            process.readyReadStandardError.connect(lambda: self._drain(job))
            job.timeout = self._timer("recon_timeout", lambda: self._request_stop(job, JobState.TIMED_OUT, "Process timed out."))
            job.grace = self._timer("recon_termination_grace", lambda: self._kill(job))
            job.state = JobState.STARTING
            job.diagnostic = "Starting trusted tool."
            self.job_changed.emit(self.snapshot(job.job_id))
            # Signal consumers may cancel or shut down reentrantly.
            if not self._current(job) or job.pending_terminal is not None:
                return
            job.timeout.start(job.spec._plan.timeout_ms)
            process.start()
        except Exception:
            # No Qt/OS exception text is exposed; it may contain sensitive argv.
            if self._current(job):
                self._request_stop(job, JobState.FAILED, "The process could not be started.")

    def _timer(self, name: str, callback) -> QTimer:
        timer = QTimer(self)
        timer.setObjectName(name)
        timer.setSingleShot(True)
        timer.timeout.connect(callback)
        return timer

    def _current(self, job: _Job) -> bool:
        return self._active is job and job.state not in _TERMINAL

    def _started(self, job: _Job) -> None:
        if not self._current(job):
            return
        if job.pending_terminal is not None:
            # terminate() during Starting can precede creation of the OS process.
            if job.kill_sent:
                job.process.kill()
            else:
                job.process.terminate()
            return
        if job.state != JobState.RUNNING:
            job.state = JobState.RUNNING
            job.diagnostic = "Trusted tool is running."
            self.job_changed.emit(self.snapshot(job.job_id))

    def _finished(self, job: _Job, code: int, status) -> None:
        if not self._current(job):
            return
        job.exit_code = code
        if job.pending_terminal is None:
            normal = status == QProcess.ExitStatus.NormalExit and code == 0
            job.pending_terminal = JobState.SUCCEEDED if normal else JobState.FAILED
            job.diagnostic = "Process completed." if normal else "Process exited unsuccessfully."
        self._finish_if_stopped(job)

    def _error(self, job: _Job, error) -> None:
        if not self._current(job):
            return
        diagnostic = "The process could not be started." if error == QProcess.ProcessError.FailedToStart else "The process reported a runtime error."
        self._request_stop(job, JobState.FAILED, diagnostic)

    def _state_changed(self, job: _Job, state) -> None:
        if self._current(job) and job.pending_terminal is not None and state == QProcess.ProcessState.NotRunning:
            job.exit_code = job.process.exitCode()
            self._finish_if_stopped(job)

    def _request_stop(self, job: _Job, state: JobState, diagnostic: str) -> None:
        if job.state in _TERMINAL or job.pending_terminal is not None:
            return
        job.pending_terminal = state
        job.diagnostic = diagnostic
        if job.process is None:
            self._complete(job, state, diagnostic)
            return
        if job.timeout is not None:
            job.timeout.stop()
        if job.process.state() == QProcess.ProcessState.NotRunning:
            self._finish_if_stopped(job)
            return
        job.grace.start(self._grace_ms)
        job.process.terminate()

    def _kill(self, job: _Job) -> None:
        if not self._current(job) or job.process is None:
            return
        if job.process.state() == QProcess.ProcessState.NotRunning:
            self._finish_if_stopped(job)
        elif not job.kill_sent:
            job.kill_sent = True
            job.process.kill()

    def _finish_if_stopped(self, job: _Job) -> None:
        if not self._current(job) or job.process.state() != QProcess.ProcessState.NotRunning:
            return
        for timer in (job.timeout, job.grace):
            if timer is not None:
                timer.stop()
        self._drain(job)

    def _available(self, job: _Job) -> bool:
        for channel in (QProcess.ProcessChannel.StandardOutput, QProcess.ProcessChannel.StandardError):
            job.process.setReadChannel(channel)
            if job.process.bytesAvailable():
                return True
        return False

    def _drain(self, job: _Job) -> None:
        if not self._current(job) or job.process is None:
            return
        budget = self._drain_budget
        channels = (
            (QProcess.ProcessChannel.StandardOutput, "stdout"),
            (QProcess.ProcessChannel.StandardError, "stderr"),
        )
        while budget:
            made_progress = False
            # Preserve the turn between callbacks, including a one-chunk budget.
            for index in (job.next_channel, 1 - job.next_channel):
                channel, name = channels[index]
                job.process.setReadChannel(channel)
                if not budget or not job.process.bytesAvailable():
                    continue
                data = bytes(job.process.read(min(self._chunk, budget)))
                if not data:
                    continue
                made_progress = True
                job.next_channel = 1 - index
                budget -= len(data)
                room = self._max_output - len(job.stdout) - len(job.stderr)
                getattr(job, name).extend(data[:room])
                if len(data) > room:
                    setattr(job, name + "_truncated", True)
            if not made_progress:
                break
        if self._available(job):
            if not job.drain_scheduled:
                job.drain_scheduled = True
                QTimer.singleShot(0, lambda: self._continue_drain(job))
        elif job.pending_terminal is not None and job.process.state() == QProcess.ProcessState.NotRunning:
            self._complete(job, job.pending_terminal, job.diagnostic)

    def _continue_drain(self, job: _Job) -> None:
        job.drain_scheduled = False
        self._drain(job)

    def _complete(self, job: _Job, state: JobState, diagnostic: str) -> None:
        if job.state in _TERMINAL:
            return
        if job.process is not None and job.process.state() != QProcess.ProcessState.NotRunning:
            return  # Keep every process/timer alive until the direct process stops.
        for timer in (job.timeout, job.grace):
            if timer is not None:
                timer.stop()
                timer.deleteLater()
        if job.process is not None:
            job.process.deleteLater()
        job.process = job.timeout = job.grace = None
        job.spec = None
        job.state, job.diagnostic = state, diagnostic
        if job.job_id in self._queue:
            self._queue.remove(job.job_id)
        if self._active is job:
            self._active = None
        self._completed.append(job.job_id)
        while len(self._completed) > self._max_completed:
            self._jobs.pop(self._completed.popleft(), None)
        result = self.snapshot(job.job_id)
        self.job_changed.emit(result)
        self.job_finished.emit(result)
        self._schedule_start()
        self._check_shutdown()

    def _check_shutdown(self) -> None:
        if self._closing and self._active is None and not self._queue and not self._shutdown_emitted:
            self._shutdown_emitted = True
            self.shutdown_finished.emit()
