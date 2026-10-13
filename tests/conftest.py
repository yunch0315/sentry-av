import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Keep ~/.sentry-av (config, incidents, quarantine) inside the test tmp dir."""
    monkeypatch.setenv("SENTRY_HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    yield tmp_path


@pytest.fixture
def cfg(isolated_home):
    from sentry.config import load_config
    return load_config(isolated_home / "home" / "config.json")
