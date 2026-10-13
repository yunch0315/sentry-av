"""Shared helpers: platform detection, hashing, entropy, logging, notifications."""
from __future__ import annotations

import hashlib
import logging
import math
import os
import platform
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

IS_WINDOWS = sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

APP_NAME = "sentry-av"
_LOG = logging.getLogger("sentry")


def user_home() -> Path:
    """Home of the *real* user, even when elevated via sudo / UAC."""
    env_home = os.environ.get("SENTRY_HOME")
    if env_home:
        return Path(env_home)
    if not IS_WINDOWS:
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user and sudo_user != "root":
            if IS_MACOS:
                p = Path("/Users") / sudo_user
            else:
                p = Path("/home") / sudo_user
            if p.is_dir():
                return p
    return Path.home()


def app_dir() -> Path:
    d = user_home() / f".{APP_NAME}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def resource_dir() -> Path:
    return Path(__file__).resolve().parent / "signatures"


def is_frozen() -> bool:
    """True when running as a PyInstaller single-file executable."""
    return bool(getattr(sys, "frozen", False))


def self_command(windowless: bool = False) -> list[str]:
    """Command prefix that re-launches this program (frozen exe or `python -m sentry`)."""
    if is_frozen():
        return [sys.executable]
    exe = sys.executable
    if IS_WINDOWS and windowless:
        pyw = Path(exe).with_name("pythonw.exe")
        if pyw.exists():
            exe = str(pyw)
    return [exe, "-m", "sentry"]


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def setup_logging(verbose: bool = False, logfile: Path | None = None) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if logfile:
        try:
            logfile.parent.mkdir(parents=True, exist_ok=True)
            handlers.append(logging.FileHandler(logfile, encoding="utf-8"))
        except OSError:
            pass
    logging.basicConfig(level=level, format=fmt, handlers=handlers, force=True)
    for noisy in ("watchdog", "fsevents"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def sha256_file(path: str | os.PathLike, chunk: int = 1 << 20) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                b = f.read(chunk)
                if not b:
                    break
                h.update(b)
    except OSError:
        return None
    return h.hexdigest()


def read_head(path: str | os.PathLike, n: int) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0..8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f}{unit}" if unit != "B" else f"{int(n)}B"
        n /= 1024
    return f"{n:.1f}TB"


def run_cmd(args: list[str], timeout: float = 15.0) -> tuple[int, str, str]:
    try:
        kw = {}
        if IS_WINDOWS:
            kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           errors="replace", **kw)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return -1, "", str(e)


def notify(title: str, message: str) -> None:
    """Best-effort desktop notification; never raises."""
    _LOG.warning("%s - %s", title, message)
    try:
        if IS_MACOS:
            safe_t = title.replace('"', "'")
            safe_m = message.replace('"', "'")
            script = f'display notification "{safe_m}" with title "{safe_t}" sound name "Basso"'
            subprocess.Popen(["osascript", "-e", script],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif IS_WINDOWS:
            safe_t = title.replace("'", "''")
            safe_m = message.replace("'", "''")
            ps = (
                "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
                "ContentType = WindowsRuntime] | Out-Null;"
                "$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
                "[Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
                "$n=$t.GetElementsByTagName('text');"
                f"$n.Item(0).AppendChild($t.CreateTextNode('{safe_t}'))|Out-Null;"
                f"$n.Item(1).AppendChild($t.CreateTextNode('{safe_m}'))|Out-Null;"
                "$toast=[Windows.UI.Notifications.ToastNotification]::new($t);"
                "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
                "'Sentry-AV').Show($toast)"
            )
            subprocess.Popen(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             creationflags=0x08000000)
        elif IS_LINUX:
            subprocess.Popen(["notify-send", title, message],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:  # noqa: BLE001
        pass


def platform_label() -> str:
    return f"{platform.system()} {platform.release()} ({platform.machine()})"


def monotonic() -> float:
    return time.monotonic()
