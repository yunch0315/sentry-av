"""Defender helper: file-level (not folder) exclusions, broad-folder guard, non-Windows no-op."""
import sys

from sentry import defender


def test_exclusions_are_file_level_not_the_parent_folder(isolated_home, monkeypatch):
    monkeypatch.setattr(defender, "exe_path", lambda: __import__("pathlib").Path("/opt/sentry/sentry"))
    paths = defender.exclusion_paths()
    assert "/opt/sentry/sentry" in paths                 # the exe file itself
    assert "/opt/sentry" not in paths                    # never the parent folder
    assert str(isolated_home / "home" / ".sentry-av") in paths
    assert defender.exclusion_process() == "sentry"


def test_broad_install_dir_is_detected(monkeypatch):
    from pathlib import Path
    home = defender.user_home()
    monkeypatch.setattr(defender, "exe_path", lambda: home / "Downloads" / "sentry.exe")
    assert defender.install_dir_is_broad()
    monkeypatch.setattr(defender, "exe_path", lambda: Path("/opt/sentry-av/sentry"))
    assert not defender.install_dir_is_broad()


def test_add_refuses_when_exe_sits_in_a_broad_folder(monkeypatch):
    if not sys.platform.startswith("win"):
        return
    monkeypatch.setattr(defender, "install_dir_is_broad", lambda: True)
    try:
        defender.add_exclusions()
    except RuntimeError as e:
        assert "전용 폴더" in str(e)
    else:
        assert False, "expected refusal"


def test_status_matches_paths_and_process_case_insensitively(monkeypatch):
    from pathlib import Path
    monkeypatch.setattr(defender, "exclusion_paths", lambda: [r"C:\Sentry\sentry.exe", r"C:\Users\me\.sentry-av"])
    monkeypatch.setattr(defender, "exclusion_process", lambda: "sentry.exe")
    monkeypatch.setattr(defender, "current_exclusions",
                        lambda: {"paths": [r"c:\sentry\sentry.exe"], "processes": ["SENTRY.EXE"]})
    st = defender.status()
    assert st[r"C:\Sentry\sentry.exe"] is True
    assert st[r"C:\Users\me\.sentry-av"] is False
    assert st["process:sentry.exe"] is True


def test_non_windows_is_a_noop():
    if sys.platform.startswith("win"):
        return
    assert defender.current_exclusions() == {"paths": [], "processes": []}
    assert "Windows" in defender.add_exclusions()
    assert "Windows" in defender.remove_exclusions()
