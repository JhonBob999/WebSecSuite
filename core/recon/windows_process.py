"""Minimal Win32 Job Object backend for the shared Recon supervisor.

CreateProcessW starts the tool suspended. The primary thread is resumed only
after assignment to a private job with KILL_ON_JOB_CLOSE and no breakaway flags.
Only stdin/stdout/stderr handles are inherited; the job handle is never inherited.
The job is terminated even after a normal parent exit, then observed empty before
completion. Closing/destroying the owner also kills the complete contained tree.

This is process lifetime containment, not a sandbox for hostile executables.
Only reviewed adapter capabilities may reach it through ProcessSupervisor.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from contextlib import contextmanager
from functools import lru_cache
import os
from subprocess import list2cmdline
import sys

from PySide6.QtCore import QObject, QProcess, QTimer, Signal


_KILL_ON_CLOSE = 0x2000
_EXTENDED_LIMITS = 9
_BASIC_ACCOUNTING = 1
_BROKEN_PIPE = {109, 232, 233}


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", wintypes.DWORD), ("descriptor", wintypes.LPVOID), ("inherit", wintypes.BOOL)]


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64), ("flags", wintypes.DWORD),
        ("min_working", ctypes.c_size_t), ("max_working", ctypes.c_size_t),
        ("active_limit", wintypes.DWORD), ("affinity", ctypes.c_size_t),
        ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in
                ("reads", "writes", "others", "read_bytes", "write_bytes", "other_bytes")]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [("basic", _BasicLimits), ("io", _IoCounters),
                ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]


class _Accounting(ctypes.Structure):
    _fields_ = [(name, ctypes.c_int64) for name in ("user_time", "kernel_time", "period_user", "period_kernel")] + [
        (name, wintypes.DWORD) for name in ("page_faults", "total", "active", "terminated")]


class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("reserved", wintypes.LPWSTR), ("desktop", wintypes.LPWSTR),
        ("title", wintypes.LPWSTR), ("x", wintypes.DWORD), ("y", wintypes.DWORD),
        ("xsize", wintypes.DWORD), ("ysize", wintypes.DWORD), ("xchars", wintypes.DWORD),
        ("ychars", wintypes.DWORD), ("fill", wintypes.DWORD), ("flags", wintypes.DWORD),
        ("show", wintypes.WORD), ("reserved_size", wintypes.WORD), ("reserved_bytes", wintypes.LPVOID),
        ("stdin", wintypes.HANDLE), ("stdout", wintypes.HANDLE), ("stderr", wintypes.HANDLE),
    ]


class _StartupInfoEx(ctypes.Structure):
    _fields_ = [("startup", _StartupInfo), ("attributes", wintypes.LPVOID)]


class _ProcessInfo(ctypes.Structure):
    _fields_ = [("process", wintypes.HANDLE), ("thread", wintypes.HANDLE),
                ("pid", wintypes.DWORD), ("tid", wintypes.DWORD)]


def _require(value):
    if not value:
        raise OSError("Native process containment operation failed.")
    return value


class _Win32:
    def __init__(self):
        if os.name != "nt" or sys.getwindowsversion().major < 10:
            raise OSError("This backend requires Windows 10 or later.")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        handle, dword, void, size, boolean = wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, ctypes.c_size_t, wintypes.BOOL
        signatures = {
            "CreateJobObjectW": (handle, (void, wintypes.LPCWSTR)),
            "SetInformationJobObject": (boolean, (handle, ctypes.c_int, void, dword)),
            "QueryInformationJobObject": (boolean, (handle, ctypes.c_int, void, dword, void)),
            "AssignProcessToJobObject": (boolean, (handle, handle)),
            "TerminateJobObject": (boolean, (handle, wintypes.UINT)),
            "CloseHandle": (boolean, (handle,)),
            "CreatePipe": (boolean, (void, void, void, dword)),
            "SetHandleInformation": (boolean, (handle, dword, dword)),
            "CreateFileW": (handle, (wintypes.LPCWSTR, dword, dword, void, dword, dword, handle)),
            "InitializeProcThreadAttributeList": (boolean, (void, dword, dword, void)),
            "UpdateProcThreadAttribute": (boolean, (void, dword, size, void, size, void, void)),
            "DeleteProcThreadAttributeList": (None, (void,)),
            "CreateProcessW": (boolean, (wintypes.LPCWSTR, wintypes.LPWSTR, void, void, boolean, dword,
                                          void, wintypes.LPCWSTR, void, void)),
            "ResumeThread": (dword, (handle,)),
            "TerminateProcess": (boolean, (handle, wintypes.UINT)),
            "WaitForSingleObject": (dword, (handle, dword)),
            "GetExitCodeProcess": (boolean, (handle, void)),
            "OpenProcess": (handle, (dword, boolean, dword)),
            "IsProcessInJob": (boolean, (handle, handle, void)),
            "PeekNamedPipe": (boolean, (handle, void, dword, void, void, void)),
            "ReadFile": (boolean, (handle, void, dword, void, void)),
        }
        for name, (result, arguments) in signatures.items():
            function = getattr(kernel, name)
            function.restype, function.argtypes = result, arguments
            setattr(self, name, function)

    def create_job(self):
        job = _require(self.CreateJobObjectW(None, None))
        try:
            limits = _ExtendedLimits()
            limits.basic.flags = _KILL_ON_CLOSE
            _require(self.SetInformationJobObject(job, _EXTENDED_LIMITS, ctypes.byref(limits), ctypes.sizeof(limits)))
            actual = _ExtendedLimits()
            _require(self.QueryInformationJobObject(job, _EXTENDED_LIMITS, ctypes.byref(actual), ctypes.sizeof(actual), None))
            # No breakaway or silent-breakaway flag is accepted.
            _require(actual.basic.flags == _KILL_ON_CLOSE)
            return job
        except Exception:
            self.CloseHandle(job)
            raise


@lru_cache(maxsize=1)
def _native_api():
    return _Win32()


@contextmanager
def locked_executable(path):
    """Hold a local image open while checking identity and creating its process.

    FILE_SHARE_READ permits hashing/resource/signature readers while denying
    concurrent writes, deletion, and replacement until the handle is released.
    This helper never launches or approves the file by itself.
    """
    program = os.fspath(path)
    if (not isinstance(program, str) or "\x00" in program or not os.path.isabs(program)
            or program.replace("\\", "/").startswith("//")):
        raise ValueError("An absolute local executable path is required.")
    api = _native_api()
    handle = api.CreateFileW(program, 0x80000000, 1, None, 3, 0x80, None)
    _require(handle and handle != ctypes.c_void_p(-1).value)
    try:
        yield handle
    finally:
        _require(api.CloseHandle(handle))


def process_safety_status() -> tuple[bool, str]:
    """Probe native job initialization without launching any executable.

    Every actual launch separately verifies assignment before ResumeThread.
    Unsupported platforms and failed initialization always disable live tools.
    """
    try:
        api = _native_api()
        job = api.create_job()
        _require(api.CloseHandle(job))
    except Exception:
        return False, "Windows process-tree containment is unavailable; live execution is disabled."
    return True, "Windows Job Object process-tree containment is available."


class _Resources:
    """Keep native ownership independent of the QObject's C++ lifetime."""

    def __init__(self, api):
        self.api = api
        self.handles = set()
        self.job = None

    def add(self, handle):
        _require(handle and handle != ctypes.c_void_p(-1).value)
        self.handles.add(handle)
        return handle

    def close_handle(self, handle):
        if handle in self.handles:
            self.api.CloseHandle(handle)
            self.handles.discard(handle)
        if handle == self.job:
            self.job = None

    def close(self):
        # Kill-on-close takes effect before any process/pipe handle is released.
        if self.job:
            self.close_handle(self.job)
        for handle in tuple(self.handles):
            self.close_handle(handle)


class WindowsJobProcess(QObject):
    """QProcess-compatible lifecycle subset; pipe bytes stay in bounded OS pipes.

    Only this Qt thread reads these handles. PeekNamedPipe checks available
    bytes before ReadFile, so no empty-pipe read can block the GUI. The shared
    supervisor controls each drain budget and retains only its output limit.
    """

    started = Signal()
    finished = Signal(int, QProcess.ExitStatus)
    errorOccurred = Signal(QProcess.ProcessError)
    stateChanged = Signal(QProcess.ProcessState)
    readyReadStandardOutput = Signal()
    readyReadStandardError = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._api = _native_api()
        self._resources = _Resources(self._api)
        resources = self._resources
        self.destroyed.connect(lambda: resources.close())
        self._program = ""
        self._arguments = []
        self._environment = None
        self._working_directory = None
        self._preflight_validator = None
        self._state = QProcess.ProcessState.NotRunning
        self._exit_code = 0
        self._exit_status = QProcess.ExitStatus.NormalExit
        self._process = None
        self._stdout = self._stderr = None
        self._channel = QProcess.ProcessChannel.StandardOutput
        self._terminating = False
        self._tree_handles = []
        self._io_failed = False
        self._timer = QTimer(self)
        self._timer.setInterval(10)
        self._timer.timeout.connect(self._poll)

    @property
    def _job(self):
        return self._resources.job

    def setProcessChannelMode(self, mode):
        if mode != QProcess.ProcessChannelMode.SeparateChannels:
            raise ValueError("Only separate process output channels are supported.")

    def setProgram(self, program):
        self._program = program

    def setArguments(self, arguments):
        self._arguments = list(arguments)

    def setProcessEnvironment(self, environment):
        self._environment = tuple(sorted(
            ((key, environment.value(key)) for key in environment.keys()), key=lambda pair: pair[0].casefold()))

    def setWorkingDirectory(self, directory):
        self._working_directory = directory

    def setPreflightValidator(self, validator):
        """Supply the supervisor's capability check for use under the image lock."""
        if not callable(validator):
            raise TypeError("A callable execution preflight validator is required.")
        self._preflight_validator = validator

    def setReadChannel(self, channel):
        self._channel = channel

    def state(self):
        return self._state

    def exitCode(self):
        return self._exit_code

    def exitStatus(self):
        return self._exit_status

    def _set_state(self, state):
        self._state = state
        self.stateChanged.emit(state)

    def _pipe(self, security):
        read, write = wintypes.HANDLE(), wintypes.HANDLE()
        _require(self._api.CreatePipe(ctypes.byref(read), ctypes.byref(write), ctypes.byref(security), 65_536))
        read_handle, write_handle = self._resources.add(read.value), self._resources.add(write.value)
        _require(self._api.SetHandleInformation(read_handle, 1, 0))
        return read_handle, write_handle

    def start(self):
        if self._state != QProcess.ProcessState.NotRunning:
            raise RuntimeError("Native process is already active.")
        self._set_state(QProcess.ProcessState.Starting)
        api, resources = self._api, self._resources
        attributes = None
        primary_thread = stdin = out_write = err_write = None
        info = _ProcessInfo()
        try:
            resources.job = resources.add(api.create_job())
            security = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, True)
            self._stdout, out_write = self._pipe(security)
            self._stderr, err_write = self._pipe(security)
            stdin = resources.add(api.CreateFileW("NUL", 0x80000000, 3, ctypes.byref(security), 3, 0, None))
            size = ctypes.c_size_t()
            api.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
            _require(0 < size.value <= 65_536)
            buffer = ctypes.create_string_buffer(size.value)
            _require(api.InitializeProcThreadAttributeList(buffer, 1, 0, ctypes.byref(size)))
            attributes = buffer
            inherited = (wintypes.HANDLE * 3)(stdin, out_write, err_write)
            _require(api.UpdateProcThreadAttribute(attributes, 0, 0x20002, inherited, ctypes.sizeof(inherited), None, None))
            startup = _StartupInfoEx()
            startup.startup.cb = ctypes.sizeof(startup)
            startup.startup.flags = 0x100  # STARTF_USESTDHANDLES
            startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = stdin, out_write, err_write
            startup.attributes = ctypes.cast(attributes, wintypes.LPVOID)
            command = ctypes.create_unicode_buffer(list2cmdline([self._program, *self._arguments]))
            environment = None
            creation_flags = 0x08080004
            if self._environment is not None:
                environment = ctypes.create_unicode_buffer(
                    "\x00".join(key + "=" + value for key, value in self._environment) + "\x00\x00")
                creation_flags |= 0x400  # CREATE_UNICODE_ENVIRONMENT
            # STARTING observers have already run. Lock the selected image,
            # then revalidate its capability/digest before Windows resolves it.
            with locked_executable(self._program):
                _require(self._preflight_validator is not None)
                self._preflight_validator()
                # CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW.
                _require(api.CreateProcessW(self._program, command, None, None, True, creation_flags,
                                            environment, self._working_directory,
                                            ctypes.byref(startup), ctypes.byref(info)))
                self._process = resources.add(info.process)
                primary_thread = resources.add(info.thread)
            _require(api.AssignProcessToJobObject(self._job, self._process))
            _require(api.ResumeThread(primary_thread) != 0xFFFFFFFF)
        except Exception:
            # Failed assignment leaves a suspended, uncontained primary process.
            # It has never executed user code and must be terminated explicitly.
            if self._process:
                api.TerminateProcess(self._process, 1)
            resources.close()
            self._process = self._stdout = self._stderr = None
            self._set_state(QProcess.ProcessState.NotRunning)
            self.errorOccurred.emit(QProcess.ProcessError.FailedToStart)
            return
        finally:
            if attributes is not None:
                api.DeleteProcThreadAttributeList(attributes)
            for handle in (primary_thread, stdin, out_write, err_write):
                resources.close_handle(handle)
        self._timer.start()
        self._set_state(QProcess.ProcessState.Running)
        self.started.emit()

    def _pipe_available(self, handle):
        if not handle:
            return 0
        available = wintypes.DWORD()
        if not self._api.PeekNamedPipe(handle, None, 0, None, ctypes.byref(available), None):
            if ctypes.get_last_error() not in _BROKEN_PIPE and not self._io_failed:
                self._io_failed = True
                self.errorOccurred.emit(QProcess.ProcessError.ReadError)
            return 0
        return available.value

    def bytesAvailable(self):
        return self._pipe_available(self._stdout if self._channel == QProcess.ProcessChannel.StandardOutput else self._stderr)

    def read(self, size):
        handle = self._stdout if self._channel == QProcess.ProcessChannel.StandardOutput else self._stderr
        amount = min(max(0, size), self._pipe_available(handle), 65_536)
        if not amount:
            return b""
        buffer, read = ctypes.create_string_buffer(amount), wintypes.DWORD()
        if not self._api.ReadFile(handle, buffer, amount, ctypes.byref(read), None):
            if not self._io_failed:
                self._io_failed = True
                self.errorOccurred.emit(QProcess.ProcessError.ReadError)
            return b""
        return buffer.raw[:read.value]

    def terminate(self):
        self.kill()

    def kill(self):
        if self._job and not self._terminating:
            self._terminating = True
            # ActiveProcesses can become zero just before process objects are
            # signaled. Retain handles so terminal signals follow observed exit.
            try:
                self._retain_tree_handles()
            except OSError:
                self.close_job()
                self.errorOccurred.emit(QProcess.ProcessError.Crashed)
                return
            if not self._api.TerminateJobObject(self._job, 1):
                # The non-inheritable job has one owner; close is the OS fallback.
                self.close_job()

    def _retain_tree_handles(self):
        capacity = 128
        for _ in range(4):
            buffer = ctypes.create_string_buffer(8 + capacity * ctypes.sizeof(ctypes.c_size_t))
            succeeded = self._api.QueryInformationJobObject(self._job, 3, buffer, ctypes.sizeof(buffer), None)
            assigned, present = (wintypes.DWORD * 2).from_buffer(buffer)
            if succeeded and assigned <= present <= capacity:
                break
            _require(0 < assigned <= 4096)
            capacity = min(4096, max(capacity * 2, assigned))
        else:
            raise OSError("Native process membership could not be observed.")
        identifiers = (ctypes.c_size_t * present).from_buffer(buffer, 8)
        for pid in identifiers:
            handle = self._api.OpenProcess(0x100000 | 0x1000, False, pid)
            if not handle and ctypes.get_last_error() == 87:  # Already exited.
                continue
            _require(handle)
            self._resources.add(handle)
            contained = wintypes.BOOL()
            _require(self._api.IsProcessInJob(handle, self._job, ctypes.byref(contained)))
            if contained.value:
                self._tree_handles.append(handle)
            else:  # A process ID may have been reused after the snapshot.
                self._resources.close_handle(handle)

    def close_job(self):
        """Immediate kill-on-close for application shutdown without Qt timers."""
        if self._job:
            self._resources.close_handle(self._job)

    def _poll(self):
        if self._state != QProcess.ProcessState.Running or not self._process:
            return
        if self._pipe_available(self._stdout):
            self.readyReadStandardOutput.emit()
        if self._pipe_available(self._stderr):
            self.readyReadStandardError.emit()
        if self._api.WaitForSingleObject(self._process, 0) != 0:
            return
        code = wintypes.DWORD()
        if not self._api.GetExitCodeProcess(self._process, ctypes.byref(code)):
            self.errorOccurred.emit(QProcess.ProcessError.Crashed)
            return
        self._exit_code = ctypes.c_int32(code.value).value
        self._exit_status = QProcess.ExitStatus.CrashExit if code.value >= 0x80000000 else QProcess.ExitStatus.NormalExit
        # A completed parent may have left children; never mark success yet.
        self.kill()
        if self._job:
            accounting = _Accounting()
            if not self._api.QueryInformationJobObject(self._job, _BASIC_ACCOUNTING, ctypes.byref(accounting),
                                                       ctypes.sizeof(accounting), None):
                self.close_job()
                self.errorOccurred.emit(QProcess.ProcessError.Crashed)
            elif accounting.active:
                return
        if any(self._api.WaitForSingleObject(handle, 0) != 0 for handle in self._tree_handles):
            return
        self.close_job()
        self._resources.close_handle(self._process)
        self._process = None
        self._timer.stop()
        self._set_state(QProcess.ProcessState.NotRunning)
        self.finished.emit(self._exit_code, self._exit_status)

    def deleteLater(self):
        self._timer.stop()
        self._resources.close()
        super().deleteLater()
