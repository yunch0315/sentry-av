"""Startup update check shown before the interactive menu."""
import sys
import types

import pytest

from sentry import cli, selfupdate as su


class FakeUpdater:
    def __init__(self, rel, *a, **k):
        self._rel = rel
        self.gh = types.SimpleNamespace(timeout=15)
        self.exe = "/bin/sentry"
        self.calls = []

    def check(self):
        return self._rel

    def cleanup_backup(self, target=None):
        self.calls.append("cleanup")

    def download(self, rel, progress=None):
        self.calls.append("download"); return "staged"

    def install(self, path):
        self.calls.append("install"); return "/bin/sentry"


def _rel(ver):
    return su.Release(tag=f"v{ver}", version=ver, html_url="https://x", assets={})


@pytest.fixture
def wire(cfg, monkeypatch):
    def _wire(rel, frozen=True, answers=()):
        fu = FakeUpdater(rel)
        monkeypatch.setattr(su, "Updater", lambda *a, **k: fu)
        monkeypatch.setattr("sentry.utils.is_frozen", lambda: frozen)
        it = iter(answers)
        monkeypatch.setattr("builtins.input", lambda *_: next(it))
        relaunched = []
        monkeypatch.setattr(su, "relaunch", lambda argv=None: relaunched.append(argv) or True)
        return fu, relaunched
    return _wire


def test_menu_no_longer_lists_upgrade():
    assert all("upgrade" not in argv for _, argv in cli._MENU)


def test_startup_check_current_version_continues(cfg, wire, capsys):
    fu, relaunched = wire(_rel("0.0.1"))
    cli._startup_update_check(cfg)
    assert fu.calls == ["cleanup"] and relaunched == []
    assert "최신 버전" in capsys.readouterr().out


def test_startup_check_offline_continues(cfg, wire, capsys):
    fu, relaunched = wire(None)
    cli._startup_update_check(cfg)
    assert "확인 실패" in capsys.readouterr().out and relaunched == []


def test_startup_check_installs_on_enter(cfg, wire, capsys):
    fu, relaunched = wire(_rel("9.9.9"), answers=[""])
    cli._startup_update_check(cfg)
    assert fu.calls == ["cleanup", "download", "install"] and len(relaunched) == 1
    assert "업데이트 완료" in capsys.readouterr().out


def test_startup_check_skips_on_n(cfg, wire, capsys):
    fu, relaunched = wire(_rel("9.9.9"), answers=["n"])
    cli._startup_update_check(cfg)
    assert fu.calls == ["cleanup"] and relaunched == []
    assert "건너뜁니다" in capsys.readouterr().out


def test_startup_check_disabled_by_config(cfg, wire):
    cfg.set("auto_update", False)
    fu, relaunched = wire(_rel("9.9.9"), answers=[""])
    cli._startup_update_check(cfg)
    assert fu.calls == ["cleanup"]


def test_startup_check_source_checkout_only_advises(cfg, wire, capsys):
    fu, relaunched = wire(_rel("9.9.9"), frozen=False, answers=[""])
    cli._startup_update_check(cfg)
    assert fu.calls == ["cleanup"] and "git pull" in capsys.readouterr().out
