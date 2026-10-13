import os
import subprocess
import sys
import time

import psutil

from sentry.realtime.activity import ActivitySampler, write_bytes
from sentry.realtime.process_watch import match_cmdline


def test_dangerous_commands_match():
    assert match_cmdline("vssadmin.exe delete shadows /all /quiet") == ("kill", "shadow copy deletion")
    assert match_cmdline("bcdedit /set {default} recoveryenabled No")[0] == "kill"
    assert match_cmdline("tmutil deletelocalsnapshots /")[0] == "kill"
    assert match_cmdline('powershell -nop -w hidden -enc ' + "A" * 120)[0] == "flag"
    assert match_cmdline("rm -rf /Users/")[0] == "kill"


def test_benign_commands_do_not_match():
    for cmd in ("ls -la /Users/me", "python3 -m pytest", "git commit -m 'delete shadows'",
                "rm -rf ./build", "vssadmin list shadows", "tmutil listlocalsnapshots /"):
        assert match_cmdline(cmd) is None, cmd


def test_write_bytes_counter_tracks_own_writes(tmp_path):
    me = psutil.Process()
    before = write_bytes(me)
    if before is None:
        import pytest
        pytest.skip("no per-process write accounting on this platform")
    (tmp_path / "blob").write_bytes(os.urandom(1 << 20))
    assert write_bytes(me) - before >= 1 << 20


def test_sampler_delta_for_young_process(tmp_path):
    """A process younger than the window is measured from its lifetime counters."""
    code = f"import os,time; open({str(tmp_path / 'x')!r},'wb').write(os.urandom(300000)); time.sleep(3)"
    child = subprocess.Popen([sys.executable, "-c", code])
    try:
        time.sleep(0.6)
        s = ActivitySampler()
        p = psutil.Process(child.pid)
        s.sample(p)
        wb, _cpu = s.delta(p, 10)
        if wb is None:
            import pytest
            pytest.skip("counter not readable")
        assert wb >= 300000
    finally:
        child.kill()


def test_sampler_window_delta(monkeypatch):
    s = ActivitySampler(window=60)
    me = psutil.Process()
    fake = iter([(100, 1.0), (100_100, 1.5), (300_100, 2.0)])
    import sentry.realtime.activity as A
    monkeypatch.setattr(A, "write_bytes", lambda proc: next(fake)[0])
    born = time.time() - 3600
    monkeypatch.setattr(A, "proc_key", lambda proc: (me.pid, born))  # one "old" process
    t = time.time()
    s.sample(me, t - 20)
    s.sample(me, t - 5)
    wb, _ = s.delta(me, 10)          # baseline = sample at t-20 (latest at/before cutoff t-10)
    assert wb == 300_000
