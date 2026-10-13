"""Per-process activity sampling: disk bytes written + CPU time in a sliding window.

Ransomware is, above all, a process that writes a lot of bytes into many user files in
a short time.  psutil exposes io_counters() on Windows/Linux only; on macOS the same
number is read through libproc's proc_pid_rusage (what Activity Monitor shows as
"Bytes Written").  The ProcessWatcher feeds this sampler every poll tick, so when the
behaviour detector fires we already know who was writing during the window.
"""
from __future__ import annotations

import ctypes
import logging
import threading
import time
from collections import deque

import psutil

from ..utils import IS_MACOS

_LOG = logging.getLogger("sentry.activity")

Key = tuple[int, float]            # (pid, create_time) - survives pid reuse
Sample = tuple[float, int, float]  # (ts, write_bytes or -1 if unknown, cpu_seconds)


class _RusageInfoV2(ctypes.Structure):
    _fields_ = [("ri_uuid", ctypes.c_uint8 * 16)] + [
        (n, ctypes.c_uint64) for n in (
            "ri_user_time", "ri_system_time", "ri_pkg_idle_wkups", "ri_interrupt_wkups", "ri_pageins",
            "ri_wired_size", "ri_resident_size", "ri_phys_footprint", "ri_proc_start_abstime",
            "ri_proc_exit_abstime", "ri_child_user_time", "ri_child_system_time", "ri_child_pkg_idle_wkups",
            "ri_child_interrupt_wkups", "ri_child_pageins", "ri_child_elapsed_abstime",
            "ri_diskio_bytesread", "ri_diskio_byteswritten")]


_libproc = None
if IS_MACOS:
    try:
        _libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
        _libproc.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        _libproc.proc_pid_rusage.restype = ctypes.c_int
    except OSError as e:  # pragma: no cover
        _LOG.warning("libproc unavailable, no per-process write accounting: %s", e)


def write_bytes(proc: psutil.Process) -> int | None:
    """Lifetime bytes written by the process, or None if not readable."""
    if _libproc is not None:
        info = _RusageInfoV2()
        if _libproc.proc_pid_rusage(proc.pid, 2, ctypes.byref(info)) != 0:
            return None
        return int(info.ri_diskio_byteswritten)
    try:
        return int(proc.io_counters().write_bytes)
    except (psutil.Error, AttributeError, OSError):
        return None


def proc_key(proc: psutil.Process) -> Key | None:
    try:
        return (proc.pid, float(proc.create_time()))
    except psutil.Error:
        return None


class ActivitySampler:
    def __init__(self, window: float = 60.0):
        self.window = float(window)
        self._hist: dict[Key, deque[Sample]] = {}
        self._lock = threading.Lock()

    def sample(self, proc: psutil.Process, now: float | None = None) -> Sample | None:
        key = proc_key(proc)
        if key is None:
            return None
        try:
            ct = proc.cpu_times()
            cpu = float(ct.user + ct.system)
        except psutil.Error:
            return None
        wb = write_bytes(proc)
        s: Sample = (now or time.time(), -1 if wb is None else wb, cpu)
        with self._lock:
            dq = self._hist.setdefault(key, deque())
            dq.append(s)
            cutoff = s[0] - self.window
            while len(dq) > 2 and dq[1][0] < cutoff:   # keep one sample older than the window as baseline
                dq.popleft()
        return s

    def forget_dead(self, live: set[Key]) -> None:
        with self._lock:
            for k in [k for k in self._hist if k not in live]:
                self._hist.pop(k, None)

    def delta(self, proc: psutil.Process, seconds: float) -> tuple[int | None, float]:
        """(bytes written, cpu seconds) during the last `seconds`.

        A process younger than `seconds` has its lifetime counters used directly, so a
        freshly started encryptor is measured even before two samples exist.
        bytes is None when the counter is not readable (other user's process, no root).
        """
        key = proc_key(proc)
        now = time.time()
        if key is None:
            return None, 0.0
        age = now - key[1]
        latest = self.sample(proc, now)
        if latest is None:
            return None, 0.0
        if age <= seconds:
            return (None if latest[1] < 0 else latest[1]), latest[2]
        with self._lock:
            dq = self._hist.get(key)
            if not dq or len(dq) < 2:
                return None, 0.0
            cutoff = now - seconds
            base = dq[0]
            for s in dq:
                if s[0] <= cutoff:
                    base = s
                else:
                    break
        b = None if (latest[1] < 0 or base[1] < 0) else max(0, latest[1] - base[1])
        return b, max(0.0, latest[2] - base[2])
