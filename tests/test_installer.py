"""Self-installer: copy into a dedicated folder, exec bit, broad-folder detection, uninstall."""
import sys
from pathlib import Path

import pytest

from sentry import installer


def _fake_exe(tmp_path, monkeypatch, where):
    where.mkdir(parents=True, exist_ok=True)
    exe = where / ("sentry.exe" if sys.platform.startswith("win") else "sentry")
    exe.write_bytes(b"MZ fake binary" if sys.platform.startswith("win") else b"#!/bin/sh\necho hi\n")
    monkeypatch.setattr(installer, "is_frozen", lambda: True)
    monkeypatch.setattr(installer.sys, "executable", str(exe))
    return exe


def test_running_from_broad_dir(tmp_path, monkeypatch):
    home = installer.user_home()
    _fake_exe(tmp_path, monkeypatch, home / "Downloads")
    assert installer.running_from_broad_dir() and not installer.is_installed_here()
    _fake_exe(tmp_path, monkeypatch, tmp_path / "Programs" / "Sentry-AV")
    assert not installer.running_from_broad_dir() and installer.is_installed_here()


def test_install_copies_into_dest_and_sets_exec_bit(tmp_path, monkeypatch):
    _fake_exe(tmp_path, monkeypatch, installer.user_home() / "Downloads")
    dest = tmp_path / "install"
    res = installer.install(dest, desktop=False, start_menu=False, exclude_defender=False)
    assert res.exe == dest / installer.installed_name()
    assert res.exe.exists() and res.exe.read_bytes().startswith((b"MZ", b"#!"))
    if not sys.platform.startswith("win"):
        import os, stat
        assert os.stat(res.exe).st_mode & stat.S_IXUSR


def test_install_refuses_source_checkout(monkeypatch):
    monkeypatch.setattr(installer, "is_frozen", lambda: False)
    with pytest.raises(RuntimeError, match="소스"):
        installer.install(exclude_defender=False)


def test_install_refuses_to_install_over_itself(tmp_path, monkeypatch):
    exe = _fake_exe(tmp_path, monkeypatch, tmp_path / "Programs" / "Sentry-AV")
    with pytest.raises(RuntimeError, match="이미"):
        installer.install(exe.parent, desktop=False, start_menu=False, exclude_defender=False)


def test_uninstall_removes_the_installed_exe(tmp_path, monkeypatch):
    _fake_exe(tmp_path, monkeypatch, installer.user_home() / "Downloads")
    dest = tmp_path / "install"
    installer.install(dest, desktop=False, start_menu=False, exclude_defender=False)
    # pretend we are NOT running the installed copy, so it can be deleted
    monkeypatch.setattr(installer.sys, "executable", str(tmp_path / "elsewhere" / "sentry"))
    removed = installer.uninstall(dest)
    assert any(str(dest) in r for r in removed)
    assert not (dest / installer.installed_name()).exists()
