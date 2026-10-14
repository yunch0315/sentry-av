"""Configuration: defaults merged with ~/.sentry-av/config.json."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .utils import IS_MACOS, IS_WINDOWS, app_dir, user_home

_LOG = logging.getLogger("sentry.config")


def _user_dirs() -> list[str]:
    h = user_home()
    names = ["Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music", "Videos"]
    out = [str(h / n) for n in names if (h / n).is_dir()]
    if IS_WINDOWS:
        for extra in ("OneDrive",):
            if (h / extra).is_dir():
                out.append(str(h / extra))
    return out or [str(h)]


def _quick_scan_paths() -> list[str]:
    paths = _user_dirs()
    h = user_home()
    if IS_WINDOWS:
        paths += [str(h / "AppData" / "Local" / "Temp"),
                  str(h / "AppData" / "Roaming"),
                  r"C:\Users\Public", r"C:\ProgramData", r"C:\Windows\Temp"]
    elif IS_MACOS:
        paths += [str(h / "Library" / "LaunchAgents"), "/Library/LaunchAgents",
                  "/Library/LaunchDaemons", "/tmp"]
    else:
        paths += ["/tmp", "/var/tmp"]
    return [p for p in paths if Path(p).exists()]


def _default_excludes() -> list[str]:
    ex = [str(app_dir())]
    if IS_WINDOWS:
        ex += [r"C:\Windows\WinSxS", r"C:\Windows\servicing", r"C:\$Recycle.Bin",
               r"C:\System Volume Information", r"C:\Windows\SoftwareDistribution"]
    else:
        ex += ["/proc", "/sys", "/dev", "/System/Volumes", "/private/var/db",
               "/Volumes/.timemachine", "/.Spotlight-V100", "/.fseventsd"]
        h = user_home()
        ex += [str(h / "Library" / "Caches"), str(h / "Library" / "Containers"),
               str(h / ".Trash")]
    return ex


DEFAULTS: dict[str, Any] = {
    "max_file_size_mb": 200,
    "scan_threads": 4,
    "quick_scan_paths": _quick_scan_paths(),
    "monitor_paths": _user_dirs(),
    "excluded_paths": _default_excludes(),
    "trust_signed_files": True,   # drop heuristic hits on validly signed apps/binaries (hash matches still count)
    # ---- real-time detection ----
    "canary_enabled": True,
    "canary_per_dir": 3,
    "window_seconds": 10,
    "min_events_per_window": 30,
    "min_suspicious_renames": 5,
    "min_high_entropy_writes": 5,
    "entropy_threshold": 7.6,
    "aggressive": False,          # kill medium-confidence suspects instead of suspending
    "recent_process_minutes": 30, # process age considered "new" for attribution
    "kill_score": 10,             # evidence score needed to kill a suspect (see realtime/responder.py)
    "suspend_score": 5,           # evidence score needed to suspend a suspect
    "min_write_bytes": 32768,     # bytes written in the window that count as "writing a lot"
    "suspend_hold_seconds": 30,   # how long un-attributed suspects stay frozen
    "poll_interval": 0.5,         # decision loop period (it also wakes instantly on canary hits)
    "procwatch_interval": 1.0,    # process-table polling period (command-line rules, write accounting)
    # ---- whitelist (user-extendable) ----
    "whitelist_process_names": [],
    "whitelist_path_prefixes": [],
    "trusted_signers": [],
    "trusted_team_ids": [],
    # ---- signature updates ----
    "signature_urls": [
        "https://bazaar.abuse.ch/export/txt/sha256/recent/",
    ],
    # ---- program self-update (GitHub Releases, see selfupdate.py) ----
    "update_repo": "yunch0315/sentry-av",
    "auto_update": True,                # monitor: install new releases by itself and restart
    "update_check_interval_hours": 24,  # how often to ask GitHub (menu/commands and monitor)
    "update_token": "",                 # GitHub token; only needed while the repo is private
}


class Config:
    def __init__(self, data: dict[str, Any], path: Path):
        self._d = data
        self.path = path

    def __getattr__(self, item: str) -> Any:
        try:
            return self._d[item]
        except KeyError as e:
            raise AttributeError(item) from e

    def get(self, key: str, default: Any = None) -> Any:
        return self._d.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._d[key] = value

    def as_dict(self) -> dict[str, Any]:
        return dict(self._d)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._d, indent=2, ensure_ascii=False), encoding="utf-8")


def load_config(path: Path | None = None) -> Config:
    path = path or (app_dir() / "config.json")
    data = dict(DEFAULTS)
    if path.exists():
        try:
            user = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(user, dict):
                data.update(user)
        except (OSError, json.JSONDecodeError) as e:
            _LOG.warning("config %s unreadable (%s); using defaults", path, e)
    cfg = Config(data, path)
    if not path.exists():
        try:
            cfg.save()
        except OSError:
            pass
    return cfg
