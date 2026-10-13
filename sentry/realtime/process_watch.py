"""Process command-line watcher.

Polls the process table and kills processes whose command line matches
ransomware "preparation" behaviour (destroying backups, disabling recovery,
tampering with security software).  These rules apply to *every* process,
including ones from trusted paths - the commands themselves are the signal.
If the matching process was spawned by a non-trusted parent, the parent is
killed too (ransomware commonly shells out to vssadmin / wmic / bcdedit).
"""
from __future__ import annotations

import logging
import re
import threading
import time
from typing import Callable

import psutil

from ..whitelist import Whitelist, proc_info
from .activity import ActivitySampler

_LOG = logging.getLogger("sentry.procwatch")

# (regex, severity, label).  severity: "kill" => terminate immediately; "flag" => log + notify only
RULES: list[tuple[str, str, str]] = [
    (r"vssadmin(\.exe)?\s+delete\s+shadows", "kill", "shadow copy deletion"),
    (r"vssadmin(\.exe)?\s+resize\s+shadowstorage.*maxsize=\s*(401mb|unbounded|\d+(mb|%))", "kill", "shadow storage shrink"),
    (r"wmic(\.exe)?\s+shadowcopy\s+delete", "kill", "shadow copy deletion (wmic)"),
    (r"Get-WmiObject\s+Win32_ShadowCopy.*\.Delete\(|Win32_ShadowCopy.*Remove-WmiObject", "kill", "shadow copy deletion (PowerShell)"),
    (r"wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup)", "kill", "backup catalog deletion"),
    (r"bcdedit(\.exe)?\s+.*recoveryenabled\s+no", "kill", "disables Windows recovery"),
    (r"bcdedit(\.exe)?\s+.*bootstatuspolicy\s+ignoreallfailures", "kill", "boot status policy tamper"),
    (r"cipher(\.exe)?\s+/w:", "flag", "free-space wipe"),
    (r"Set-MpPreference\s+-Disable(RealtimeMonitoring|IOAVProtection|BehaviorMonitoring|IntrusionPreventionSystem)",
     "kill", "disables Windows Defender"),
    (r"Add-MpPreference\s+-ExclusionPath", "flag", "adds Defender exclusion"),
    (r"netsh\s+advfirewall\s+set\s+\w+\s+state\s+off", "flag", "disables firewall"),
    (r"reg(\.exe)?\s+add\s+.*Windows Defender.*DisableAntiSpyware", "kill", "Defender registry tamper"),
    (r"(sc(\.exe)?\s+(stop|delete|config)|net(\.exe)?\s+stop)\s+(WinDefend|wscsvc|SecurityHealthService|MsMpSvc|vss|SDRSVC|wbengine|VeeamBackupSvc|BackupExecVSSProvider)",
     "kill", "stops security/backup service"),
    (r"taskkill(\.exe)?\s+.*(/im\s+)?(MsMpEng|NisSrv|vgc\.exe|vgtray|EasyAntiCheat|BEService|sqlservr|veeam|AhnLab|V3)", "kill", "kills security/backup process"),
    (r"icacls(\.exe)?\s+.*\s+/grant\s+Everyone:F\s+/T", "flag", "mass ACL grant"),
    (r"takeown(\.exe)?\s+/F\s+\S+\s+/R", "flag", "recursive takeown"),
    (r"powershell.*\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{100,}", "flag", "long encoded PowerShell"),
    (r"mshta(\.exe)?\s+(https?:|javascript:|vbscript:)", "kill", "mshta remote/script execution"),
    (r"rundll32(\.exe)?\s+javascript:", "kill", "rundll32 javascript execution"),
    (r"regsvr32(\.exe)?\s+/s\s+/n\s+/u\s+/i:https?:", "kill", "regsvr32 remote scriptlet"),
    (r"certutil(\.exe)?\s+.*-urlcache.*-split.*https?:", "flag", "certutil download"),
    (r"fsutil(\.exe)?\s+usn\s+deletejournal", "kill", "USN journal deletion"),
    (r"wevtutil(\.exe)?\s+cl\s+", "flag", "event log clearing"),
    # macOS / Linux
    (r"tmutil\s+deletelocalsnapshots", "kill", "Time Machine snapshot deletion"),
    (r"tmutil\s+disable\b", "kill", "disables Time Machine"),
    (r"(find|for)\s.{0,300}openssl\s+enc\s+-(aes|chacha)|openssl\s+enc\s+-(aes|chacha).{0,300}\s(find|for)\s",
     "kill", "bulk openssl encryption"),
    (r"gpg\s+(--batch\s+)?(-c|--symmetric)\s.{0,200}\*", "flag", "bulk gpg encryption"),
    (r"launchctl\s+(unload|bootout|disable)\s+.*(com\.apple\.(XProtect|MRT|syspolicy|backupd)|sentry)", "kill", "disables macOS protection"),
    (r"csrutil\s+disable", "flag", "SIP disable attempt"),
    (r"spctl\s+--master-disable|spctl\s+--global-disable", "flag", "Gatekeeper disable"),
    (r"xattr\s+-[rd]+\s+com\.apple\.quarantine\s+/", "flag", "quarantine flag removal"),
    (r"(rm|shred)\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+(/\s|/\*|~|\$HOME|/Users/|/home/)", "kill", "recursive deletion of user data"),
    (r"chflags\s+-R\s+(schg|uchg)\s+(/Users|~|/home)", "flag", "mass immutable flag"),
    (r"dd\s+if=/dev/(zero|urandom)\s+of=/dev/(disk|sd|nvme|rdisk)", "kill", "raw disk overwrite"),
    (r"history\s+-c|unset\s+HISTFILE", "flag", "shell history wipe"),
]
_COMPILED = [(re.compile(p, re.IGNORECASE | re.DOTALL), sev, label) for p, sev, label in RULES]


def match_cmdline(cmdline: str) -> tuple[str, str] | None:
    for rx, sev, label in _COMPILED:
        if rx.search(cmdline):
            return sev, label
    return None


class ProcessWatcher(threading.Thread):
    def __init__(self, whitelist: Whitelist, on_incident: Callable[[dict], None],
                 interval: float = 0.5, dry_run: bool = False, activity: ActivitySampler | None = None):
        super().__init__(name="ProcessWatcher", daemon=True)
        self.wl = whitelist
        self.on_incident = on_incident
        self.interval = interval
        self.dry_run = dry_run
        self.activity = activity or ActivitySampler()
        self._stop = threading.Event()
        self._seen: set[tuple[int, float]] = set()
        self._trusted: dict[tuple[int, float], bool] = {}

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        _LOG.info("process watcher started (%d rules)", len(_COMPILED))
        first = True
        while not self._stop.is_set():
            try:
                self._tick(first)
            except Exception as e:  # noqa: BLE001
                _LOG.debug("procwatch tick error: %s", e)
            first = False
            self._stop.wait(self.interval)

    def _tick(self, initial: bool) -> None:
        current: set[tuple[int, float]] = set()
        now = time.time()
        for p in psutil.process_iter(["pid", "create_time", "cmdline"]):
            try:
                key = (p.pid, float(p.info["create_time"] or 0.0))
                current.add(key)
                trusted = self._trusted.get(key)
                if trusted is None:
                    trusted = self._trusted[key] = self.wl.is_trusted_process(p)
                if not trusted:
                    # write/CPU accounting for everything that could later become a suspect
                    self.activity.sample(p, now)
                if key in self._seen:
                    continue
                cmd = " ".join(p.info["cmdline"] or [])
                if not cmd:
                    continue
                hit = match_cmdline(cmd)
                if hit:
                    self.handle(p, cmd, *hit)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        self._seen = current
        for k in [k for k in self._trusted if k not in current]:
            self._trusted.pop(k, None)
        self.activity.forget_dead(current)

    def handle(self, proc: psutil.Process, cmd: str, severity: str, label: str) -> None:
        if proc.pid == self.wl.own_pid:
            return
        info = proc_info(proc)
        info["cmdline"] = cmd
        killed: list[dict] = []
        action = "flagged"
        if severity == "kill" and not self.dry_run:
            action = "killed"
            # freeze first so it cannot progress while we inspect the parent
            try:
                proc.suspend()
            except psutil.Error:
                pass
            try:
                parent = proc.parent()
            except psutil.Error:
                parent = None
            if parent and parent.pid != self.wl.own_pid and not self.wl.is_trusted_process(parent):
                killed.append(proc_info(parent))
                _kill_tree(parent)
            killed.append(info)
            _kill_tree(proc)
        _LOG.warning("%s process %s (pid %s): %s | %s", action, info.get("name"), proc.pid, label, cmd[:300])
        self.on_incident({
            "type": "process-rule", "severity": "high" if severity == "kill" else "medium",
            "label": label, "action": action, "process": info, "killed": killed,
        })


def _kill_tree(proc: psutil.Process, timeout: float = 3.0) -> list[int]:
    """Suspend, then kill a process and all of its descendants. Returns killed pids."""
    pids: list[int] = []
    try:
        procs = [proc] + proc.children(recursive=True)
    except psutil.Error:
        procs = [proc]
    for p in procs:
        try:
            p.suspend()
        except psutil.Error:
            pass
    for p in procs:
        try:
            p.kill()
            pids.append(p.pid)
        except psutil.Error:
            pass
    gone, alive = psutil.wait_procs(procs, timeout=timeout)
    for p in alive:
        try:
            p.kill()
        except psutil.Error:
            pass
    return pids


kill_tree = _kill_tree
