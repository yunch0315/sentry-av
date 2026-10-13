"""Attribution policy tests with fake processes (nothing is really suspended or killed)."""
import os
import time

import psutil
import pytest

from sentry.realtime import responder as R
from sentry.realtime.activity import ActivitySampler
from sentry.realtime.detector import Assessment
from sentry.whitelist import Whitelist


class FakeProc:
    def __init__(self, pid, name, exe, cmdline, age_s, cwd="/", write_bytes=0, cpu=0.0):
        self.pid = pid
        self._name, self._exe, self._cmd, self._cwd = name, exe, cmdline, cwd
        self._ct = time.time() - age_s
        self.info = {"pid": pid, "name": name, "create_time": self._ct, "exe": exe, "cmdline": cmdline}
        self.wb, self.cpu = write_bytes, cpu
        self.suspended = self.killed = False

    def name(self): return self._name
    def exe(self): return self._exe
    def cmdline(self): return self._cmd
    def cwd(self): return self._cwd
    def create_time(self): return self._ct
    def username(self): return "me"
    def ppid(self): return 1
    def is_running(self): return not self.killed
    def status(self): return psutil.STATUS_RUNNING
    def suspend(self): self.suspended = True
    def resume(self): self.suspended = False
    def kill(self): self.killed = True
    def children(self, recursive=False): return []
    def open_files(self): return []


class FakeActivity(ActivitySampler):
    def delta(self, proc, seconds):
        return proc.wb, proc.cpu


@pytest.fixture
def world(cfg, monkeypatch, tmp_path):
    procs: list[FakeProc] = []
    monkeypatch.setattr(R.psutil, "process_iter", lambda attrs=None: list(procs))
    monkeypatch.setattr(R, "kill_tree", lambda p, timeout=3.0: (p.kill(), [p.pid])[1])
    monkeypatch.setattr(R, "notify", lambda *a, **k: None)
    monkeypatch.setattr(R.psutil, "wait_procs", lambda procs, timeout=0: (procs, []))
    wl = Whitelist(cfg)
    monkeypatch.setattr(wl, "signature_valid", lambda exe: "Signed" in exe)
    monkeypatch.setattr(wl, "is_trusted_process", lambda p: p.pid in wl.protected_pids)
    cfg.set("suspend_hold_seconds", 60)
    resp = R.Responder(cfg, wl, dry_run=False, activity=FakeActivity())
    victim = str(tmp_path / "Documents")
    os.makedirs(victim)
    paths = [os.path.join(victim, f"doc_{i}.pdf.locked") for i in range(30)]
    return procs, resp, victim, paths


def test_fresh_process_naming_victim_dir_is_killed(world):
    procs, resp, victim, paths = world
    attacker = FakeProc(5001, "python3", "/usr/local/bin/python3", ["python3", "/tmp/enc.py", victim], 3, write_bytes=200_000)
    procs.append(attacker)
    inc = resp.respond(Assessment("ransomware", ["canary"], paths, True))
    assert attacker.killed
    assert [k["pid"] for k in inc["killed"]] == [5001]


def test_heavy_writer_without_targeting_is_not_killed(world):
    """A long-running browser writing its cache from a temp-ish clone path (Chrome on macOS)."""
    procs, resp, victim, paths = world
    chrome = FakeProc(1023, "Google Chrome", "/private/var/folders/xx/code_sign_clone/Google Chrome",
                      ["Google Chrome"], age_s=3600 * 5, write_bytes=25_000_000, cpu=4.0)
    procs.append(chrome)
    inc = resp.respond(Assessment("ransomware", ["canary"], paths, True))
    assert not chrome.killed and not chrome.suspended
    assert inc["killed"] == [] and "could not attribute" in inc.get("note", "")


def test_direct_link_suspect_preferred_over_recent_heavy_writer(world):
    procs, resp, victim, paths = world
    exporter = FakeProc(7001, "VideoExport", "/Applications/Export.app/Contents/MacOS/VideoExport",
                        ["VideoExport"], age_s=20, write_bytes=900_000_000, cpu=9.0)      # new + heavy
    attacker = FakeProc(7002, "enc", "/Users/me/Downloads/enc", ["enc"], age_s=15, cwd=victim, write_bytes=400_000)
    procs += [exporter, attacker]
    inc = resp.respond(Assessment("ransomware", ["renames"], paths, False))
    assert attacker.killed and not exporter.killed
    assert [k["pid"] for k in inc["killed"]] == [7002]


def test_signed_app_gets_discount(world):
    procs, resp, victim, paths = world
    signed = FakeProc(8001, "Editor", "/Applications/Signed.app/Contents/MacOS/Editor",
                      ["Editor", victim], age_s=30, write_bytes=100_000)   # 6 + 3 + 4 + 2 - 4 = 11 -> still high
    procs.append(signed)
    suspects = resp.attribute(paths)
    assert any("valid code signature (-4)" in r for r in suspects[0].reasons)


def test_own_ancestry_never_touched(world):
    procs, resp, victim, paths = world
    me = FakeProc(os.getpid(), "pytest", "/usr/bin/python3", ["pytest", victim], 1, cwd=victim, write_bytes=10**7)
    procs.append(me)
    inc = resp.respond(Assessment("ransomware", ["canary"], paths, True))
    assert not me.killed and not me.suspended and inc["killed"] == []


def test_suspicious_level_only_freezes_clear_culprits(world):
    procs, resp, victim, paths = world
    recent = FakeProc(9001, "foo", "/Users/me/foo", ["foo"], age_s=5, write_bytes=50_000)   # 3 + 4 (+2 top) = 9
    culprit = FakeProc(9002, "bar", "/Users/me/bar", ["bar", victim], age_s=5, write_bytes=50_000)  # 6 + 3 + 4 = 13
    procs += [recent, culprit]
    inc = resp.respond(Assessment("suspicious", ["churn"], paths, False))
    assert culprit.suspended and not culprit.killed
    assert not recent.suspended
    assert [s["pid"] for s in inc["suspended"]] == [9002]


def test_hold_release(world, monkeypatch):
    procs, resp, victim, paths = world
    p = FakeProc(9100, "bar", "/Users/me/bar", ["bar", victim], age_s=5, write_bytes=50_000)
    procs.append(p)
    resp.respond(Assessment("suspicious", ["churn"], paths, False))
    assert p.suspended
    resp.release_suspended()            # hold (60s) not expired
    assert p.suspended
    resp._suspended[p.pid] -= 120
    monkeypatch.setattr(R.psutil, "Process", lambda pid=None: p)   # restored by pytest afterwards
    resp.release_suspended()
    assert not p.suspended


def test_dry_run_never_kills(world):
    procs, resp, victim, paths = world
    resp.dry_run = True
    attacker = FakeProc(5002, "enc", "/tmp/enc", ["enc", victim], 2, write_bytes=500_000)
    procs.append(attacker)
    inc = resp.respond(Assessment("ransomware", ["canary"], paths, True))
    assert not attacker.killed and inc["killed"][0]["action"] == "dry-run"
