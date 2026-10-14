"""Defender helper: paths, status parsing, non-Windows no-ops."""
import sys

from sentry import defender


def test_exclusion_paths_cover_install_and_data(isolated_home):
    paths = defender.exclusion_paths()
    assert str(defender.install_dir()) in paths and str(isolated_home / "home" / ".sentry-av") in paths


def test_status_matches_case_insensitively(monkeypatch):
    monkeypatch.setattr(defender, "exclusion_paths", lambda: [r"C:\Apps\Sentry", r"C:\Users\me\.sentry-av"])
    monkeypatch.setattr(defender, "current_exclusions", lambda: [r"c:\apps\sentry\\"])
    st = defender.status()
    assert st[r"C:\Apps\Sentry"] is True and st[r"C:\Users\me\.sentry-av"] is False


def test_non_windows_is_a_noop():
    if sys.platform.startswith("win"):
        return
    assert defender.current_exclusions() == []
    assert "Windows" in defender.add_exclusions()
    assert "Windows" in defender.remove_exclusions()
