"""Self-update: version comparison, asset selection, checksum verification, atomic replace."""
import hashlib
import os
import stat
from pathlib import Path

import pytest

from sentry import selfupdate as su


def test_version_compare():
    assert su.is_newer("v0.2.0", "0.1.0")
    assert su.is_newer("0.1.1", "0.1.0")
    assert su.is_newer("1.0", "0.9.9")
    assert not su.is_newer("0.1.0", "0.1.0")
    assert not su.is_newer("v0.1", "0.1.0")
    assert not su.is_newer("0.0.9", "0.1.0")
    assert not su.is_newer("nightly", "0.1.0")
    assert su.parse_version("v1.2.3-rc1") == (1, 2, 3)


def test_asset_names():
    assert su.asset_name_for_platform("Windows", "AMD64") == "sentry-windows-x64.exe"
    assert su.asset_name_for_platform("Darwin", "arm64") == "sentry-macos-arm64"
    assert su.asset_name_for_platform("Darwin", "x86_64") == "sentry-macos-x64"
    assert su.asset_name_for_platform("Linux", "aarch64") == "sentry-linux-arm64"


def test_parse_checksums():
    h = "a" * 64
    txt = f"{h}  sentry-macos-arm64\n{'b' * 64} *sentry-windows-x64.exe\nnot a line\n"
    assert su.parse_checksums(txt) == {"sentry-macos-arm64": h, "sentry-windows-x64.exe": "b" * 64}


class FakeGitHub:
    """Stands in for selfupdate.GitHub: serves one release with the given assets."""
    def __init__(self, tag, files: dict[str, bytes], sums: str | None = None):
        self.tag = tag
        self.files = dict(files)
        if sums is None:
            sums = "".join(f"{hashlib.sha256(b).hexdigest()}  {n}\n" for n, b in files.items())
        self.files[su.CHECKSUMS_NAME] = sums.encode()
        self.calls = []

    def latest_release(self):
        self.calls.append("latest")
        return su.Release(tag=self.tag, version=self.tag.lstrip("v"), html_url="https://x/rel",
                          assets={n: {"url": f"asset://{n}", "size": len(b)} for n, b in self.files.items()})

    def asset_text(self, asset):
        return self.files[asset["url"].split("://")[1]].decode()

    def download_asset(self, asset, dest, progress=None):
        dest.write_bytes(self.files[asset["url"].split("://")[1]])
        if progress:
            progress(asset["size"], asset["size"])
        return dest


@pytest.fixture
def updater(cfg, monkeypatch):
    up = su.Updater(cfg)
    monkeypatch.setattr(su, "is_frozen", lambda: True)
    monkeypatch.setattr(su, "verify_binary", lambda path, timeout=90.0: None)   # fake binaries cannot run
    return up


def _name():
    return su.asset_name_for_platform()


def test_check_records_state_and_detects_newer(updater):
    updater.gh = FakeGitHub("v9.9.9", {_name(): b"new-binary"})
    rel = updater.check()
    assert rel.newer and su.load_state()["latest"] == "9.9.9"
    updater.gh = FakeGitHub("v0.0.1", {_name(): b"old"})
    assert updater.available() is None


def test_check_failure_is_soft(updater):
    class Broken:
        def latest_release(self):
            raise OSError("offline")
    updater.gh = Broken()
    assert updater.check() is None
    assert "offline" in su.load_state()["last_error"]


def test_download_verifies_checksum(updater, tmp_path):
    rel = FakeGitHub("v9.9.9", {_name(): b"payload"}).latest_release()
    updater.gh = FakeGitHub("v9.9.9", {_name(): b"payload"})
    got = updater.download(rel)
    assert got.read_bytes() == b"payload"

    # tampered asset -> rejected and removed
    bad = FakeGitHub("v9.9.9", {_name(): b"payload"})
    bad.files[_name()] = b"evil"
    updater.gh = bad
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        updater.download(bad.latest_release())
    leftovers = [f.read_bytes() for f in su.app_dir().glob("sentry-update-*/" + _name())]
    assert leftovers == [b"payload"]          # the good download stays staged; the bad one is gone


def test_download_requires_checksums_and_platform_asset(updater):
    gh = FakeGitHub("v9.9.9", {_name(): b"x"}, sums="")
    updater.gh = gh
    with pytest.raises(RuntimeError, match="does not list"):
        updater.download(gh.latest_release())
    gh = FakeGitHub("v9.9.9", {"sentry-other-cpu": b"x"})
    updater.gh = gh
    with pytest.raises(RuntimeError, match="no build for this platform"):
        updater.download(gh.latest_release())


def test_install_replaces_atomically_and_keeps_backup(updater, tmp_path):
    target = tmp_path / "bin" / "sentry"
    target.parent.mkdir()
    target.write_bytes(b"old")
    os.chmod(target, 0o700)
    new = tmp_path / "stage" / _name()
    new.parent.mkdir()
    new.write_bytes(b"new")

    out = updater.install(new, target)
    assert out == target.resolve() and target.read_bytes() == b"new"
    assert target.with_name("sentry.old").read_bytes() == b"old"
    if os.name != "nt":
        assert stat.S_IMODE(target.stat().st_mode) & stat.S_IXUSR
    assert not new.exists() and not new.parent.exists()      # download cleaned up after the copy
    assert su.load_state()["installed_from"] == _name()

    updater.cleanup_backup(target)
    assert not target.with_name("sentry.old").exists()


def test_install_refuses_from_source(cfg, monkeypatch):
    monkeypatch.setattr(su, "is_frozen", lambda: False)
    up = su.Updater(cfg)
    with pytest.raises(RuntimeError, match="git pull"):
        up.install(Path("whatever"))


def test_upgrade_end_to_end(updater, tmp_path, monkeypatch):
    target = tmp_path / "sentry"
    target.write_bytes(b"old")
    updater.exe = target
    updater.gh = FakeGitHub("v9.9.9", {_name(): b"brand-new"})
    rel = updater.upgrade()
    assert rel.version == "9.9.9" and target.read_bytes() == b"brand-new"
    # second run: already current (fake says 9.9.9 but we are still __version__) -> would re-install;
    # so simulate an older release instead
    updater.gh = FakeGitHub("v0.0.1", {_name(): b"ancient"})
    assert updater.upgrade() is None and target.read_bytes() == b"brand-new"


def test_autoupdate_thread_installs_and_calls_back(cfg, updater, monkeypatch):
    done = {}
    t = su.AutoUpdateThread(cfg, lambda rel: done.setdefault("rel", rel), interval_hours=0, first_delay=0)
    t.updater = updater
    target = updater.exe = su.app_dir() / "sentry"
    target.write_bytes(b"old")
    updater.gh = FakeGitHub("v9.9.9", {_name(): b"auto"})
    t.start(); t.join(5)
    assert not t.is_alive() and done["rel"].version == "9.9.9" and target.read_bytes() == b"auto"


def test_check_due_uses_state():
    assert su.check_due(24)
    su.save_state(last_check=__import__("time").time())
    assert not su.check_due(24)
    assert su.check_due(0)


def test_install_retargets_pyinstaller_archive(updater, tmp_path, monkeypatch):
    """After renaming the running exe, the PyInstaller loader must read modules from the
    renamed file, not from the new binary that now sits at the old path."""
    import sys, types
    target = tmp_path / "sentry"
    target.write_bytes(b"old")
    new = tmp_path / _name()
    new.write_bytes(b"new")
    fake = types.SimpleNamespace(pyz_archive=types.SimpleNamespace(_filename=str(target)))
    monkeypatch.setitem(sys.modules, "pyimod02_importers", fake)
    updater.install(new, target)
    assert fake.pyz_archive._filename == str(target.with_name("sentry.old"))


def test_relaunch_env_drops_pyinstaller_vars(monkeypatch):
    monkeypatch.setenv("_PYI_ARCHIVE_FILE", "/x/sentry")
    monkeypatch.setenv("_PYI_APPLICATION_HOME_DIR", "/tmp/_MEI1")
    monkeypatch.setenv("_MEIPASS2", "/tmp/_MEI1")
    monkeypatch.setenv("SENTRY_HOME", "/keep")
    env = su._fresh_env()
    assert not [k for k in env if k.startswith("_PYI_") or k == "_MEIPASS2"]
    assert env["SENTRY_HOME"] == "/keep"


def test_remove_backup(tmp_path):
    target = tmp_path / "sentry"
    old = tmp_path / "sentry.old"
    old.write_bytes(b"x")
    assert su.remove_backup(target) and not old.exists()
    assert su.remove_backup(target)          # nothing left: still True


def test_relaunch_posix_deletes_old_before_exec(tmp_path, monkeypatch):
    if su.IS_WINDOWS:
        pytest.skip("posix path")
    exe = tmp_path / "sentry"
    exe.write_bytes(b"new")
    (tmp_path / "sentry.old").write_bytes(b"old")
    monkeypatch.setattr(su.sys, "executable", str(exe))
    called = {}
    monkeypatch.setattr(su.os, "execve", lambda path, args, env: called.update(path=path, args=args, env=env))
    su.relaunch(["--no-elevate"])
    assert not (tmp_path / "sentry.old").exists()
    assert called["path"] == str(exe) and called["args"] == [str(exe), "--no-elevate"]
    assert not [k for k in called["env"] if k.startswith("_PYI_")]


def test_install_rolls_back_when_new_binary_does_not_run(updater, tmp_path, monkeypatch):
    target = tmp_path / "sentry"
    target.write_bytes(b"old")
    new = tmp_path / "dl" / _name()
    new.parent.mkdir()
    new.write_bytes(b"blocked")
    monkeypatch.setattr(su, "verify_binary", lambda path, timeout=90.0: "exit code 1: access denied")
    with pytest.raises(RuntimeError, match="되돌렸습니다"):
        updater.install(new, target)
    assert target.read_bytes() == b"old"
    assert not target.with_name("sentry.old").exists() and not target.with_name("sentry.new").exists()
    assert new.exists()                                    # the download is kept for inspection


def test_verify_binary_reports_failures(tmp_path):
    script = tmp_path / "fake"
    script.write_text("#!/bin/sh\necho sentry-av 9.9.9\n")
    script.chmod(0o755)
    if su.IS_WINDOWS:
        pytest.skip("posix shell script")
    assert su.verify_binary(script) is None
    bad = tmp_path / "bad"
    bad.write_text("#!/bin/sh\necho nope >&2; exit 3\n")
    bad.chmod(0o755)
    assert "exit code 3" in su.verify_binary(bad)
    assert su.verify_binary(tmp_path / "missing") is not None


def test_relaunch_reports_launch_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(su.sys, "executable", str(tmp_path / "gone"))
    if su.IS_WINDOWS:
        monkeypatch.setattr(su.subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(OSError(5, "denied")))
    else:
        monkeypatch.setattr(su.os, "execve", lambda *a: (_ for _ in ()).throw(OSError(13, "denied")))
    assert su.relaunch([]) is False
