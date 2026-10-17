"""Offline lifecycle tests; no QProcess.start or external program is invoked."""

from collections import deque
from dataclasses import dataclass
import importlib

import pytest
from PySide6.QtCore import QObject, QProcess as QtProcess, Signal


class ManualTimer(QObject):
    timeout = Signal()
    callbacks = deque()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.active = False
        self.interval = None

    def setSingleShot(self, value):
        assert value

    def start(self, interval):
        self.interval = interval
        self.active = True

    def stop(self):
        self.active = False

    @staticmethod
    def singleShot(interval, callback):
        assert interval == 0
        ManualTimer.callbacks.append(callback)

    def fire(self):
        if self.active:
            self.active = False
            self.timeout.emit()


class FakeProcess(QObject):
    started = Signal()
    finished = Signal(int, QtProcess.ExitStatus)
    errorOccurred = Signal(QtProcess.ProcessError)
    stateChanged = Signal(QtProcess.ProcessState)
    readyReadStandardOutput = Signal()
    readyReadStandardError = Signal()
    ProcessState = QtProcess.ProcessState
    ProcessError = QtProcess.ProcessError
    ExitStatus = QtProcess.ExitStatus
    ProcessChannel = QtProcess.ProcessChannel
    ProcessChannelMode = QtProcess.ProcessChannelMode
    instances = []

    def __init__(self, parent=None):
        super().__init__(parent)
        self.instances.append(self)
        self.program = None
        self.arguments = None
        self.channel = QtProcess.ProcessChannel.StandardOutput
        self.buffers = {QtProcess.ProcessChannel.StandardOutput: bytearray(), QtProcess.ProcessChannel.StandardError: bytearray()}
        self.process_state = QtProcess.ProcessState.NotRunning
        self.exit_code = 0
        self.exit_status = QtProcess.ExitStatus.NormalExit
        self.starts = self.terminations = self.kills = 0
        self.deleted = False
        self.read_sizes = []

    def setProgram(self, value):
        self.program = value

    def setArguments(self, values):
        assert type(values) is list
        self.arguments = values

    def setProcessChannelMode(self, mode):
        assert mode == QtProcess.ProcessChannelMode.SeparateChannels

    def setReadChannel(self, channel):
        self.channel = channel

    def bytesAvailable(self):
        return len(self.buffers[self.channel])

    def read(self, size):
        self.read_sizes.append(size)
        chunk = bytes(self.buffers[self.channel][:size])
        del self.buffers[self.channel][:size]
        return chunk

    def state(self):
        return self.process_state

    def exitCode(self):
        return self.exit_code

    def exitStatus(self):
        return self.exit_status

    def start(self):
        self.starts += 1
        self.process_state = QtProcess.ProcessState.Starting

    def complete_start(self):
        self.process_state = QtProcess.ProcessState.Running
        self.stateChanged.emit(self.process_state)
        self.started.emit()

    def terminate(self):
        self.terminations += 1

    def kill(self):
        self.kills += 1

    def deleteLater(self):
        assert self.state() == QtProcess.ProcessState.NotRunning
        self.deleted = True

    def finish(self, code=0, status=QtProcess.ExitStatus.NormalExit):
        self.exit_code, self.exit_status = code, status
        self.process_state = QtProcess.ProcessState.NotRunning
        self.stateChanged.emit(self.process_state)
        self.finished.emit(code, status)

    def fail_start(self):
        self.process_state = QtProcess.ProcessState.NotRunning
        self.errorOccurred.emit(QtProcess.ProcessError.FailedToStart)

    def feed(self, data, stderr=False):
        channel = QtProcess.ProcessChannel.StandardError if stderr else QtProcess.ProcessChannel.StandardOutput
        self.buffers[channel].extend(data)
        (self.readyReadStandardError if stderr else self.readyReadStandardOutput).emit()


@dataclass(frozen=True)
class ControlledRequest:
    hostname: str = "example.com"
    timeout_ms: int = 1000


@pytest.fixture
def runtime(monkeypatch, tmp_path, qapp):
    policy = importlib.import_module("core.recon.execution_policy")
    module = importlib.import_module("core.recon.process_supervisor")
    executable = tmp_path / "controlled-fixture.exe"
    executable.write_bytes(b"MZ controlled fixture; never executed")

    class ControlledAdapter:
        request_type = ControlledRequest

        def build(self, request):
            return policy._AdapterPlan(str(executable), ("--target", request.hostname), (request.hostname,), request.timeout_ms)

    monkeypatch.setitem(policy._TRUSTED_ADAPTERS, "controlled", ControlledAdapter())
    monkeypatch.setattr(module, "QProcess", FakeProcess)
    monkeypatch.setattr(module, "QTimer", ManualTimer)
    FakeProcess.instances.clear()
    ManualTimer.callbacks.clear()
    supervisors = []

    class Harness:
        def spec(self):
            return policy.ExecutionPolicy().prepare(
                "controlled", ControlledRequest(), policy.ScopeApproval(exact_domains=("example.com",))
            )

        def supervisor(self, **kwargs):
            supervisor = module.ProcessSupervisor(**kwargs)
            supervisors.append(supervisor)
            return supervisor

        def pump(self):
            for _ in range(1000):
                if not ManualTimer.callbacks:
                    return
                ManualTimer.callbacks.popleft()()
            pytest.fail("Supervisor did not yield finite queued work")

        def timer(self, supervisor, name):
            return supervisor.findChild(ManualTimer, name)

    harness = Harness()
    yield harness
    for supervisor in supervisors:
        supervisor.shutdown(immediate=True)
    for process in FakeProcess.instances:
        if process.state() != QtProcess.ProcessState.NotRunning:
            process.finish()
    harness.pump()
    for supervisor in supervisors:
        supervisor.deleteLater()
    qapp.processEvents()
    ManualTimer.callbacks.clear()


def test_successful_job_uses_absolute_program_and_separate_arguments(runtime):
    supervisor = runtime.supervisor()
    states, results = [], []
    supervisor.job_changed.connect(lambda snapshot: states.append(snapshot.state.value))
    supervisor.job_finished.connect(results.append)
    job = supervisor.submit(runtime.spec())
    assert supervisor.snapshot(job).state.value == "QUEUED"
    runtime.pump()
    process = FakeProcess.instances[0]
    assert process.program.endswith("controlled-fixture.exe")
    assert ":" in process.program  # The Windows fixture is an absolute local path.
    assert process.arguments == ["--target", "example.com"]
    process.complete_start()
    process.feed(b"useful evidence")
    process.feed(b"diagnostic", stderr=True)
    process.finish()
    runtime.pump()
    assert states == ["QUEUED", "STARTING", "RUNNING", "SUCCEEDED"]
    assert len(results) == 1
    assert results[0].stdout == b"useful evidence"
    assert results[0].stderr == b"diagnostic"
    assert results[0].exit_code == 0
    assert process.deleted


@pytest.mark.parametrize("failure", ["start", "nonzero", "crash", "runtime"])
def test_start_exit_and_runtime_failures_are_distinct_from_success(runtime, failure):
    supervisor = runtime.supervisor()
    job = supervisor.submit(runtime.spec())
    runtime.pump()
    process = FakeProcess.instances[0]
    if failure == "start":
        process.fail_start()
    else:
        process.complete_start()
        if failure == "runtime":
            process.errorOccurred.emit(QtProcess.ProcessError.ReadError)
            assert not process.deleted
        process.finish(7 if failure == "nonzero" else 0,
                       QtProcess.ExitStatus.CrashExit if failure == "crash" else QtProcess.ExitStatus.NormalExit)
    runtime.pump()
    result = supervisor.snapshot(job)
    assert result.state.value == "FAILED"
    assert result.diagnostic
    assert "--target" not in result.diagnostic
    assert "example.com" not in result.diagnostic


@pytest.mark.parametrize("reason", ["cancel", "timeout"])
def test_stop_escalates_once_and_keeps_resources_until_process_stops(runtime, reason):
    supervisor = runtime.supervisor(termination_grace_ms=20)
    results = []
    supervisor.job_finished.connect(results.append)
    job = supervisor.submit(runtime.spec())
    runtime.pump()
    process = FakeProcess.instances[0]
    process.complete_start()
    if reason == "cancel":
        assert supervisor.cancel(job)
        assert not supervisor.cancel(job)
    else:
        runtime.timer(supervisor, "recon_timeout").fire()
    assert process.terminations == 1
    assert not process.deleted
    assert not results
    runtime.timer(supervisor, "recon_termination_grace").fire()
    assert process.kills == 1
    assert not process.deleted
    process.finish(-1, QtProcess.ExitStatus.CrashExit)
    process.finished.emit(0, QtProcess.ExitStatus.NormalExit)
    process.started.emit()
    runtime.pump()
    assert len(results) == 1
    assert results[0].state.value == ("CANCELLED" if reason == "cancel" else "TIMED_OUT")
    assert results[0].exit_code == -1
    assert process.deleted


def test_cancelling_during_start_does_not_return_to_running(runtime):
    supervisor = runtime.supervisor()
    job = supervisor.submit(runtime.spec())
    runtime.pump()
    process = FakeProcess.instances[0]
    assert supervisor.cancel(job)
    process.complete_start()
    assert process.terminations >= 1
    process.finish()
    runtime.pump()
    assert supervisor.snapshot(job).state.value == "CANCELLED"


def test_cancelled_queued_job_never_starts_and_only_one_process_runs(runtime):
    supervisor = runtime.supervisor()
    first, second, third = [supervisor.submit(runtime.spec()) for _ in range(3)]
    runtime.pump()
    assert len(FakeProcess.instances) == 1
    assert supervisor.cancel(second)
    assert not supervisor.cancel(second)
    FakeProcess.instances[0].finish()
    runtime.pump()
    assert len(FakeProcess.instances) == 2
    assert supervisor.snapshot(first).state.value == "SUCCEEDED"
    assert supervisor.snapshot(second).state.value == "CANCELLED"
    assert supervisor.snapshot(third).state.value == "STARTING"
    FakeProcess.instances[1].finish()
    runtime.pump()


def test_output_is_chunked_bounded_combined_and_still_drained_after_truncation(runtime):
    supervisor = runtime.supervisor(max_output_bytes=10, read_chunk_bytes=4, drain_budget_bytes=8)
    job = supervisor.submit(runtime.spec())
    runtime.pump()
    process = FakeProcess.instances[0]
    process.complete_start()
    process.feed(b"12345678901234567890")
    # A flood leaves work queued so unrelated GUI events can be processed.
    assert ManualTimer.callbacks
    process.feed(b"abcdefghij", stderr=True)
    process.finish()
    runtime.pump()
    result = supervisor.snapshot(job)
    assert len(result.stdout) + len(result.stderr) == 10
    assert result.stdout_truncated
    assert result.stderr_truncated
    assert result.output_truncated
    assert not any(process.buffers.values())
    assert max(process.read_sizes) <= 4


@pytest.mark.parametrize("budget", [4, 8])
def test_stderr_drains_while_a_stdout_flood_remains_buffered(runtime, budget):
    supervisor = runtime.supervisor(max_output_bytes=50, read_chunk_bytes=4, drain_budget_bytes=budget)
    job = supervisor.submit(runtime.spec())
    runtime.pump()
    process = FakeProcess.instances[0]
    process.feed(b"x" * 100)
    process.feed(b"ERR!", stderr=True)
    assert process.buffers[QtProcess.ProcessChannel.StandardOutput]
    assert not process.buffers[QtProcess.ProcessChannel.StandardError]
    assert supervisor.snapshot(job).stderr == b"ERR!"
    process.finish()
    runtime.pump()


def test_repeated_or_late_process_signals_cannot_complete_another_job(runtime):
    supervisor = runtime.supervisor()
    results = []
    supervisor.job_finished.connect(results.append)
    first = supervisor.submit(runtime.spec())
    second = supervisor.submit(runtime.spec())
    runtime.pump()
    old = FakeProcess.instances[0]
    old.finish()
    runtime.pump()
    old.finished.emit(3, QtProcess.ExitStatus.CrashExit)
    old.errorOccurred.emit(QtProcess.ProcessError.Crashed)
    old.readyReadStandardOutput.emit()
    assert len(results) == 1
    assert results[0].job_id == first
    assert supervisor.snapshot(second).state.value == "STARTING"
    FakeProcess.instances[1].finish()
    runtime.pump()
    assert len(results) == 2


def test_shutdown_cancels_queue_and_waits_asynchronously_for_direct_process_cleanup(runtime):
    supervisor = runtime.supervisor()
    completed = []
    supervisor.shutdown_finished.connect(lambda: completed.append(True))
    first, second = [supervisor.submit(runtime.spec()) for _ in range(2)]
    runtime.pump()
    process = FakeProcess.instances[0]
    process.complete_start()
    supervisor.shutdown()
    supervisor.shutdown()
    assert supervisor.snapshot(second).state.value == "CANCELLED"
    assert not completed
    assert process.terminations == 1
    assert not process.deleted
    process.finish()
    runtime.pump()
    assert supervisor.snapshot(first).state.value == "CANCELLED"
    assert completed == [True]
    with pytest.raises(RuntimeError):
        supervisor.submit(runtime.spec())


def test_about_to_quit_kills_direct_process_immediately_without_waiting_for_timer(runtime, qapp):
    supervisor = runtime.supervisor()
    job = supervisor.submit(runtime.spec())
    runtime.pump()
    process = FakeProcess.instances[0]
    process.complete_start()
    qapp.aboutToQuit.emit()
    assert process.kills == 1
    assert not process.deleted
    process.finish()
    runtime.pump()
    assert supervisor.snapshot(job).state.value == "CANCELLED"


def test_shutdown_from_terminal_signal_cannot_start_the_next_job(runtime):
    supervisor = runtime.supervisor()
    supervisor.job_finished.connect(lambda result: supervisor.shutdown())
    supervisor.submit(runtime.spec())
    second = supervisor.submit(runtime.spec())
    runtime.pump()
    FakeProcess.instances[0].finish()
    runtime.pump()
    assert len(FakeProcess.instances) == 1
    assert supervisor.snapshot(second).state.value == "CANCELLED"


def test_preflight_is_rechecked_when_a_queued_job_reaches_the_front(runtime, monkeypatch):
    policy = importlib.import_module("core.recon.execution_policy")
    supervisor = runtime.supervisor()
    supervisor.submit(runtime.spec())
    queued = supervisor.submit(runtime.spec())
    runtime.pump()
    monkeypatch.delitem(policy._TRUSTED_ADAPTERS, "controlled")
    FakeProcess.instances[0].finish()
    runtime.pump()
    assert len(FakeProcess.instances) == 1
    assert supervisor.snapshot(queued).state.value == "FAILED"


def test_generic_forged_and_replayed_specs_are_rejected(runtime):
    policy = importlib.import_module("core.recon.execution_policy")
    supervisor = runtime.supervisor()
    for value in ({"program": "arbitrary.exe", "arguments": []}, object(), object.__new__(policy.ValidatedExecutionSpec)):
        with pytest.raises(policy.ExecutionPolicyError):
            supervisor.submit(value)
    spec = runtime.spec()
    supervisor.submit(spec)
    with pytest.raises(policy.ExecutionPolicyError):
        supervisor.submit(spec)
    other = runtime.supervisor()
    with pytest.raises(policy.ExecutionPolicyError):
        other.submit(spec)


def test_queue_and_completed_output_history_have_explicit_bounds(runtime):
    supervisor = runtime.supervisor(max_queued_jobs=2, max_completed_jobs=1)
    first = supervisor.submit(runtime.spec())
    second = supervisor.submit(runtime.spec())
    with pytest.raises(RuntimeError):
        supervisor.submit(runtime.spec())
    runtime.pump()
    FakeProcess.instances[0].finish()
    runtime.pump()
    FakeProcess.instances[1].finish()
    runtime.pump()
    with pytest.raises(KeyError):
        supervisor.snapshot(first)
    assert supervisor.snapshot(second).state.value == "SUCCEEDED"
