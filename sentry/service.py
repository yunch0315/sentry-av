"""Install the real-time monitor as a background service started at boot / logon."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from .utils import IS_MACOS, IS_WINDOWS, run_cmd, self_command, user_home

TASK_NAME = "SentryAV-Monitor"
PLIST_LABEL = "com.sentry-av.monitor"
PLIST_PATH = Path("/Library/LaunchDaemons") / f"{PLIST_LABEL}.plist"
AGENT_PATH = user_home() / "Library" / "LaunchAgents" / f"{PLIST_LABEL}.plist"


def _plist(home: str, log_dir: str) -> str:
    args = "".join(f"\n        <string>{a}</string>" for a in _monitor_cmd())
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>{PLIST_LABEL}</string>
    <key>ProgramArguments</key><array>{args}
    </array>
    <key>EnvironmentVariables</key><dict>
        <key>SENTRY_HOME</key><string>{home}</string>
        <key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin</string>
    </dict>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>{log_dir}/service.out.log</string>
    <key>StandardErrorPath</key><string>{log_dir}/service.err.log</string>
</dict></plist>
"""


def _monitor_cmd(windowless: bool = False) -> list[str]:
    return [*self_command(windowless), "monitor", "--no-elevate"]


def _win_quote(a: str) -> str:
    return f'"{a}"' if (" " in a or not a) else a


def install() -> str:
    if IS_WINDOWS:
        # Highest privileges at logon of the installing (admin) user
        tr = " ".join(_win_quote(a) for a in _monitor_cmd(windowless=True))
        rc, out, err = run_cmd(["schtasks", "/Create", "/F", "/TN", TASK_NAME, "/SC", "ONLOGON",
                                "/RL", "HIGHEST", "/TR", tr], timeout=30)
        if rc != 0:
            raise RuntimeError(err or out)
        run_cmd(["schtasks", "/Run", "/TN", TASK_NAME], timeout=30)
        return f"scheduled task '{TASK_NAME}' installed (runs at logon with highest privileges) and started"
    if IS_MACOS:
        home = str(user_home())
        log_dir = f"{home}/.sentry-av"
        if os.geteuid() == 0:
            PLIST_PATH.write_text(_plist(home, log_dir))
            os.chmod(PLIST_PATH, 0o644)
            run_cmd(["launchctl", "bootout", "system", str(PLIST_PATH)], timeout=15)
            rc, out, err = run_cmd(["launchctl", "bootstrap", "system", str(PLIST_PATH)], timeout=30)
            if rc != 0:
                raise RuntimeError(err or out)
            return f"LaunchDaemon {PLIST_LABEL} installed and started (root, at boot)"
        # no root: per-user LaunchAgent, starts at login with the user's own privileges
        AGENT_PATH.parent.mkdir(parents=True, exist_ok=True)
        AGENT_PATH.write_text(_plist(home, log_dir))
        domain = f"gui/{os.getuid()}"
        run_cmd(["launchctl", "bootout", domain, str(AGENT_PATH)], timeout=15)
        rc, out, err = run_cmd(["launchctl", "bootstrap", domain, str(AGENT_PATH)], timeout=30)
        if rc != 0:
            raise RuntimeError(err or out)
        return (f"LaunchAgent {PLIST_LABEL} installed and started (runs at login as {os.environ.get('USER', 'user')}; "
                f"run with root for a system-wide LaunchDaemon)")
    # linux: systemd
    unit = Path("/etc/systemd/system/sentry-av.service")
    unit.write_text(f"""[Unit]
Description=Sentry-AV real-time ransomware protection
After=network.target
[Service]
Environment=SENTRY_HOME={user_home()}
ExecStart={' '.join(_monitor_cmd())}
Restart=always
[Install]
WantedBy=multi-user.target
""")
    subprocess.call(["systemctl", "daemon-reload"])
    subprocess.call(["systemctl", "enable", "--now", "sentry-av"])
    return "systemd unit sentry-av installed and started"


def uninstall() -> str:
    if IS_WINDOWS:
        run_cmd(["schtasks", "/End", "/TN", TASK_NAME], timeout=15)
        rc, out, err = run_cmd(["schtasks", "/Delete", "/F", "/TN", TASK_NAME], timeout=15)
        return "task removed" if rc == 0 else f"remove failed: {err or out}"
    if IS_MACOS:
        removed = []
        if AGENT_PATH.exists():
            run_cmd(["launchctl", "bootout", f"gui/{os.getuid()}", str(AGENT_PATH)], timeout=15)
            AGENT_PATH.unlink(missing_ok=True)
            removed.append("LaunchAgent")
        if PLIST_PATH.exists():
            if os.geteuid() != 0:
                raise RuntimeError("system LaunchDaemon is installed; removing it needs root")
            run_cmd(["launchctl", "bootout", "system", str(PLIST_PATH)], timeout=15)
            PLIST_PATH.unlink(missing_ok=True)
            removed.append("LaunchDaemon")
        return ", ".join(removed) + " removed" if removed else "not installed"
    subprocess.call(["systemctl", "disable", "--now", "sentry-av"])
    Path("/etc/systemd/system/sentry-av.service").unlink(missing_ok=True)
    return "systemd unit removed"


def status() -> str:
    if IS_WINDOWS:
        rc, out, err = run_cmd(["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST"], timeout=15)
        return out if rc == 0 else "not installed"
    if IS_MACOS:
        for kind, target in (("LaunchDaemon", f"system/{PLIST_LABEL}"), ("LaunchAgent", f"gui/{os.getuid()}/{PLIST_LABEL}")):
            rc, out, _ = run_cmd(["launchctl", "print", target], timeout=15)
            if rc == 0:
                state = [l.strip() for l in out.splitlines() if "state =" in l or "pid =" in l]
                return f"{kind} installed: " + "; ".join(state)
        return "not installed"
    rc, out, _ = run_cmd(["systemctl", "is-active", "sentry-av"], timeout=15)
    return out.strip() or "not installed"
