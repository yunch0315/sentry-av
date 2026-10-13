"""Attribute ransomware behaviour to a process and stop it.

Attribution is evidence-based.  Every untrusted process gets a score from:
  * an open handle on an affected file / directory         (+10, targeting)
  * command line or cwd pointing at an affected directory   (+6 / +4, targeting)
  * started recently                                        (+3 / +1, targeting)
  * executable or script in a dropper location (tmp, Downloads, ...) (+2)
  * bytes written during the detection window               (+4, +2 if >= 10x, +2 top writer)
  * CPU burnt during the window                             (+1)
Only processes with score >= kill_score AND at least one *targeting* signal are killed
at ransomware level; if any of them has a *direct* link (handle / cmdline / cwd) only
those are killed.  A valid code signature (Developer ID / Authenticode) is worth -4.  Suspects with score >= suspend_score and a targeting signal are
frozen for suspend_hold_seconds and reported.  A long-running process that merely
writes a lot (an IDE, a browser, a sync client you forgot to whitelist) is only
reported (frozen too in --aggressive mode), never killed.  Our own ancestry (terminal,
IDE that launched us) is never touched.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import psutil

from ..quarantine import Quarantine
from ..utils import IS_WINDOWS, app_dir, notify, now_iso, user_home
from ..whitelist import Whitelist, proc_info
from .activity import ActivitySampler
from .process_watch import kill_tree

_LOG = logging.getLogger("sentry.responder")

# interpreters are never quarantined themselves - the script they were given is
_INTERPRETERS = {"python", "python3", "pythonw", "python.exe", "pythonw.exe", "bash", "sh", "zsh", "dash", "fish",
                 "powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                 "mshta.exe", "node", "node.exe", "perl", "ruby", "osascript", "java", "java.exe", "php"}
_SCRIPT_EXTS = (".py", ".sh", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".command", ".jar", ".scpt")


def _is_interpreter(exe: str | None) -> bool:
    if not exe:
        return False
    name = os.path.basename(exe).lower()
    return name in _INTERPRETERS or name.startswith(("python3.", "python2."))


def _dropper_prefixes() -> list[str]:
    """Places malware is typically dropped and run from."""
    h = user_home()
    if IS_WINDOWS:
        return [str(h / "Downloads"), str(h / "AppData" / "Local" / "Temp"), str(h / "AppData" / "Roaming"),
                str(h / "Desktop"), r"C:\Users\Public", r"C:\ProgramData", r"C:\Windows\Temp", r"C:\Windows\Tasks",
                r"C:\PerfLogs", r"C:\Recovery"]
    return [str(h / "Downloads"), str(h / "Desktop"), str(h / "Documents"), "/tmp", "/private/tmp", "/var/tmp",
            "/private/var/folders", "/var/folders", "/Users/Shared", "/Volumes", "/dev/shm"]


def _under(path: str, prefixes: list[str]) -> bool:
    if not path:
        return False
    p = os.path.normcase(os.path.normpath(path))
    for pre in prefixes:
        pre = os.path.normcase(os.path.normpath(pre))
        if p == pre or p.startswith(pre + os.sep):
            return True
    return False


@dataclass
class Suspect:
    proc: psutil.Process
    score: int = 0
    targeting: bool = False   # any evidence tying the process to the victim or to "just appeared"
    direct: bool = False      # evidence tying it to the victim files themselves (handle / cmdline / cwd)
    reasons: list[str] = field(default_factory=list)
    write_bytes: int | None = None

    def add(self, pts: int, why: str, targeting: bool = False, direct: bool = False) -> None:
        self.score += pts
        self.reasons.append(f"{why} ({pts:+d})")
        self.targeting = self.targeting or targeting or direct
        self.direct = self.direct or direct


class Responder:
    def __init__(self, cfg, whitelist: Whitelist, quarantine: Quarantine | None = None,
                 dry_run: bool = False, activity: ActivitySampler | None = None):
        self.cfg = cfg
        self.wl = whitelist
        self.q = quarantine or Quarantine()
        self.dry_run = dry_run
        self.aggressive = bool(cfg.get("aggressive", False))
        self.recent_minutes = float(cfg.get("recent_process_minutes", 30))
        self.window = float(cfg.get("window_seconds", 10))
        self.kill_score = int(cfg.get("kill_score", 10))
        self.suspend_score = int(cfg.get("suspend_score", 5))
        self.min_write_bytes = int(cfg.get("min_write_bytes", 32 * 1024))
        self.hold = float(cfg.get("suspend_hold_seconds", 30))
        self.activity = activity or ActivitySampler(window=max(60.0, self.window * 6))
        self.incident_log = app_dir() / "incidents.jsonl"
        self._lock = threading.Lock()
        self._suspended: dict[int, float] = {}
        self.droppers = _dropper_prefixes()

    # ---- attribution ----------------------------------------------------------
    def _handle_holders(self, paths: list[str], dirs: set[str]) -> set[int]:
        pids: set[int] = set()
        path_set = set(paths)
        for p in psutil.process_iter(["pid"]):
            try:
                if self.wl.is_trusted_process(p):
                    continue
                for f in p.open_files():
                    if f.path in path_set or os.path.dirname(f.path) in dirs:
                        pids.add(p.pid)
                        break
            except (psutil.Error, OSError):
                continue
        return pids

    def attribute(self, paths: list[str]) -> list[Suspect]:
        """Score every untrusted process; returns suspects sorted by score (desc)."""
        dirs = {os.path.dirname(p) for p in paths}
        now = time.time()
        holders = self._handle_holders(paths, dirs)
        suspects: list[Suspect] = []
        for p in psutil.process_iter(["pid", "name", "create_time", "exe", "cmdline"]):
            try:
                if self.wl.is_trusted_process(p):
                    continue
                s = Suspect(p)
                if p.pid in holders:
                    s.add(10, "open handle on affected files", direct=True)
                exe = p.info.get("exe") or ""
                cmd = p.info.get("cmdline") or []
                cmd_text = " ".join(cmd)
                if any(d and d in cmd_text for d in dirs):
                    s.add(6, "command line names an affected directory", direct=True)
                try:
                    cwd = p.cwd() or ""
                except psutil.Error:
                    cwd = ""
                if cwd and (cwd in dirs or any(cwd.startswith(d.rstrip(os.sep) + os.sep) for d in dirs if d)):
                    s.add(4, "working directory is inside an affected directory", direct=True)
                age_min = (now - (p.info.get("create_time") or now)) / 60
                if age_min <= max(2.0, self.window / 30):
                    s.add(3, "started moments ago", True)
                elif age_min <= self.recent_minutes:
                    s.add(1, f"started {age_min:.0f} min ago", True)
                script = next((a for a in cmd[1:] if a.lower().endswith(_SCRIPT_EXTS) and os.path.isfile(a)), "")
                if _under(exe, self.droppers) or (script and _under(script, self.droppers)):
                    s.add(2, "runs from a temp/download location")
                wb, cpu = self.activity.delta(p, self.window)
                s.write_bytes = wb
                if wb is not None and wb >= self.min_write_bytes:
                    s.add(4, f"wrote {wb // 1024} KB during the window")
                    if wb >= 10 * self.min_write_bytes:
                        s.add(2, "heavy writer")
                if cpu >= min(1.0, self.window / 10):
                    s.add(1, f"{cpu:.1f}s CPU during the window")
                if s.score > 0:
                    suspects.append(s)
            except (psutil.Error, OSError):
                continue
        writers = [s for s in suspects if s.write_bytes]
        if writers:
            top = max(writers, key=lambda s: s.write_bytes or 0)
            if (top.write_bytes or 0) >= self.min_write_bytes:
                top.add(2, "top writer among untrusted processes")
        for s in suspects:
            if s.score >= self.suspend_score and s.targeting:   # codesign/Authenticode cost only where it matters
                try:
                    exe = s.proc.exe() or ""
                except psutil.Error:
                    exe = ""
                if exe and self.wl.signature_valid(exe):
                    s.add(-4, "valid code signature")
        suspects.sort(key=lambda s: -s.score)
        return suspects

    # ---- response ------------------------------------------------------------
    def respond(self, assessment, level_override: str | None = None) -> dict:
        level = level_override or assessment.level
        t0 = time.time()
        suspects = self.attribute(assessment.paths)
        kill_ok = [s for s in suspects if s.score >= self.kill_score and s.targeting]
        if any(s.direct for s in kill_ok):
            kill_ok = [s for s in kill_ok if s.direct]
        # default: only freeze processes that also point at the victim; aggressive: any heavy writer
        hold_only = [s for s in suspects if s.score >= self.suspend_score and s not in kill_ok
                     and (s.targeting or self.aggressive)]
        incident = {
            "type": "behaviour", "time": now_iso(), "level": level,
            "reasons": assessment.reasons, "canary": assessment.canary_hit,
            "sample_paths": assessment.paths[:20], "killed": [], "suspended": [], "quarantined": [],
            "suspects": [self._describe(s) for s in suspects[:8]],
        }
        if level == "ransomware":
            targets = kill_ok
            if not targets and self.aggressive and hold_only:
                # --aggressive: no clear culprit, so take every suspect that at least points at
                # the victim directory or just appeared.  Default mode only freezes them: the
                # encryptor keeps writing while frozen suspects do not, so the next detection
                # (within a second or two) attributes it with a much higher score.
                targets = [s for s in hold_only if s.targeting]
            # freeze everything plausible first - speed matters more than precision here
            for s in targets + hold_only:
                self._suspend(s.proc)
            for s in targets:
                incident["killed"].append(self._kill_and_quarantine(s, incident))
            for s in hold_only:
                if s not in targets:
                    incident["suspended"].append(self._describe(s))
            if not targets:
                incident["note"] = (f"could not attribute to a process; {len(hold_only)} suspect(s) suspended "
                                    f"for {self.hold:.0f}s")
        else:  # suspicious: only freeze processes that already look like a culprit
            for s in kill_ok:
                self._suspend(s.proc)
                incident["suspended"].append(self._describe(s))
        incident["response_ms"] = int((time.time() - t0) * 1000)
        self._log(incident)
        if level == "ransomware":
            names = ", ".join(f"{k.get('name')}({k.get('pid')})" for k in incident["killed"]) or "no process attributed"
            notify("Sentry-AV: 랜섬웨어 차단", f"{'; '.join(assessment.reasons)[:120]} / 종료: {names}")
        elif incident["suspended"]:
            notify("Sentry-AV: 의심 행위 감지", f"{'; '.join(assessment.reasons)[:160]}")
        return incident

    def release_suspended(self, older_than: float | None = None) -> None:
        """Resume processes we froze once the hold time passed without a kill decision."""
        hold = self.hold if older_than is None else older_than
        now = time.time()
        for pid, ts in list(self._suspended.items()):
            if now - ts >= hold:
                try:
                    p = psutil.Process(pid)
                    p.resume()
                    _LOG.info("resumed pid %d (%s) - hold expired without further evidence", pid, p.name())
                except psutil.Error:
                    pass
                self._suspended.pop(pid, None)

    def _describe(self, s: Suspect) -> dict:
        d = proc_info(s.proc)
        d.update({"score": s.score, "targeting": s.targeting, "evidence": s.reasons, "write_bytes": s.write_bytes})
        return d

    def _suspend(self, p: psutil.Process) -> None:
        if self.dry_run or self.wl.is_trusted_process(p):
            return
        try:
            if p.pid not in self._suspended and p.status() != psutil.STATUS_STOPPED:
                p.suspend()
                _LOG.warning("suspended pid %d (%s)", p.pid, p.name())
            self._suspended[p.pid] = time.time()
        except psutil.Error:
            pass

    def _kill_and_quarantine(self, s: Suspect, incident: dict) -> dict:
        p = s.proc
        info = self._describe(s)
        if self.dry_run:
            info["action"] = "dry-run"
            return info
        exe = info.get("exe")
        pids = kill_tree(p)
        self._suspended.pop(p.pid, None)
        info["action"] = "killed"
        info["killed_pids"] = pids
        _LOG.warning("KILLED ransomware suspect %s pid=%s score=%d exe=%s evidence=%s",
                     info.get("name"), p.pid, s.score, exe, s.reasons)
        if exe and os.path.isfile(exe) and not _is_interpreter(exe) and not self.wl.is_trusted_process_path(exe):
            qid = self.q.add(exe, f"ransomware behaviour: {'; '.join(incident['reasons'])[:200]}")
            if qid:
                incident["quarantined"].append({"id": qid, "path": exe})
        # also quarantine the script passed to an interpreter (python foo.py / bash foo.sh)
        for arg in (info.get("cmdline") or [])[1:]:
            if os.path.isfile(arg) and Path(arg).suffix.lower() in _SCRIPT_EXTS:
                qid = self.q.add(arg, "script run by killed ransomware suspect")
                if qid:
                    incident["quarantined"].append({"id": qid, "path": arg})
        return info

    def _log(self, incident: dict) -> None:
        with self._lock:
            try:
                with open(self.incident_log, "a", encoding="utf-8") as f:
                    f.write(json.dumps(incident, ensure_ascii=False, default=str) + "\n")
            except OSError as e:
                _LOG.error("cannot write incident log: %s", e)
