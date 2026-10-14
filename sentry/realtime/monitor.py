"""Real-time monitor: file-system events + canary files + process watcher -> responder."""
from __future__ import annotations

import hashlib
import logging
import os
import random
import signal
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from ..quarantine import Quarantine
from ..scanner.signatures import SignatureDB
from ..utils import app_dir, notify, now_iso
from ..whitelist import Whitelist
from .activity import ActivitySampler
from .detector import BehaviorDetector
from .process_watch import ProcessWatcher
from .responder import Responder

_LOG = logging.getLogger("sentry.monitor")

# decoys sort first and last in a directory listing, so sequential encryptors hit them early
_CANARY_NAMES = ["!!_important_backup.docx", "~zz_archive_2024.xlsx", "aaa_passwords.pdf",
                 "zzz_family_photos.jpg", "00_contract_final.docx"]
_CANARY_HEADERS = {".docx": b"PK\x03\x04", ".xlsx": b"PK\x03\x04", ".pdf": b"%PDF-1.7\n",
                   ".jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"}


class _Handler(FileSystemEventHandler):
    def __init__(self, detector: BehaviorDetector, wl: Whitelist):
        self.det = detector
        self.wl = wl

    def _ok(self, path: str) -> bool:
        return not self.wl.is_excluded_path(path)

    def on_created(self, e):
        if not e.is_directory and self._ok(e.src_path):
            self.det.feed("created", e.src_path)

    def on_modified(self, e):
        if not e.is_directory and self._ok(e.src_path):
            self.det.feed("modified", e.src_path)

    def on_moved(self, e):
        if not e.is_directory and self._ok(e.src_path):
            self.det.feed("moved", e.src_path, e.dest_path)

    def on_deleted(self, e):
        if not e.is_directory and self._ok(e.src_path):
            self.det.feed("deleted", e.src_path)


class RealtimeMonitor:
    def __init__(self, cfg, paths: list[str] | None = None, canary: bool = True,
                 dry_run: bool = False, aggressive: bool | None = None):
        self.cfg = cfg
        if aggressive is not None:
            cfg.set("aggressive", aggressive)
        self.paths = [os.path.abspath(p) for p in (paths or cfg.get("monitor_paths", [])) if os.path.isdir(p)]
        self.wl = Whitelist(cfg)
        self.sigdb = SignatureDB()
        self.q = Quarantine()
        self.canary_enabled = canary and bool(cfg.get("canary_enabled", True))
        self.canaries: set[str] = set()
        self._canary_hash: dict[str, str] = {}
        self._wake = threading.Event()
        self.detector = BehaviorDetector(cfg, self.sigdb, self.canaries, self._canary_intact,
                                         on_alert=self._wake.set)
        self.activity = ActivitySampler(window=max(60.0, float(cfg.get("window_seconds", 10)) * 6))
        self.responder = Responder(cfg, self.wl, self.q, dry_run=dry_run, activity=self.activity)
        self.dry_run = dry_run
        self.observer = Observer()
        self.procwatch = ProcessWatcher(self.wl, self._on_proc_incident,
                                        interval=float(cfg.get("procwatch_interval", 1.0)), dry_run=dry_run,
                                        activity=self.activity)
        self._stop = threading.Event()
        self._last_response = 0.0
        self.incidents: list[dict] = []

    # ---- canaries --------------------------------------------------------------
    def deploy_canaries(self) -> None:
        if not self.canary_enabled:
            return
        per_dir = int(self.cfg.get("canary_per_dir", 3))
        rnd = random.Random(42)
        for root in self.paths:
            for name in _CANARY_NAMES[:per_dir]:
                p = Path(root) / name
                try:
                    if not p.exists():
                        ext = p.suffix.lower()
                        body = _CANARY_HEADERS.get(ext, b"") + bytes(rnd.getrandbits(8) for _ in range(2048))
                        # low-entropy filler so an encryptor visibly changes it
                        body += b"Sentry-AV canary file. Do not delete. " * 200
                        p.write_bytes(body)
                        try:
                            os.chflags(p, 0x8000) if hasattr(os, "chflags") else None  # UF_HIDDEN on macOS
                        except OSError:
                            pass
                    self._canary_hash[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
                    self.canaries.add(str(p))
                except OSError as e:
                    _LOG.debug("canary deploy failed in %s: %s", root, e)
        _LOG.info("deployed %d canary files", len(self.canaries))

    def _canary_intact(self, path: str) -> bool:
        want = self._canary_hash.get(path)
        if not want:
            return False
        try:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest() == want
        except OSError:
            return False

    def remove_canaries(self) -> None:
        for c in list(self.canaries):
            try:
                Path(c).unlink(missing_ok=True)
            except OSError:
                pass

    # ---- lifecycle -------------------------------------------------------------
    def start(self) -> None:
        if not self.paths:
            raise SystemExit("no valid directories to monitor")
        self.deploy_canaries()
        handler = _Handler(self.detector, self.wl)
        for p in self.paths:
            try:
                self.observer.schedule(handler, p, recursive=True)
            except OSError as e:
                _LOG.warning("cannot watch %s: %s", p, e)
        self.observer.start()
        self.procwatch.start()
        _LOG.info("real-time protection ON  paths=%s  canaries=%s  aggressive=%s  dry_run=%s",
                  self.paths, self.canary_enabled, self.cfg.get("aggressive"), self.dry_run)

    def stop(self) -> None:
        self._stop.set()
        self.procwatch.stop()
        try:
            self.observer.stop()
            self.observer.join(timeout=5)
        except Exception:  # noqa: BLE001
            pass
        self.remove_canaries()
        _LOG.info("real-time protection OFF")

    def request_stop(self) -> None:
        """Thread-safe: make run_forever() return (used by the self-updater)."""
        self._stop.set()
        self._wake.set()

    def run_forever(self) -> None:
        self.start()

        def _sig(*_):
            self._stop.set()
            self._wake.set()

        for s in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(s, _sig)
            except (ValueError, OSError):
                pass
        try:
            interval = float(self.cfg.get("poll_interval", 0.5))
            while not self._stop.is_set():
                self.tick()
                self._wake.wait(interval)      # returns early when the detector raises an alert
                self._wake.clear()
        finally:
            self.stop()

    # ---- decision loop -----------------------------------------------------------
    def tick(self) -> dict | None:
        a = self.detector.assess()
        if a.level == "none":
            self.responder.release_suspended()
            return None
        now = time.time()
        if a.level == "suspicious" and now - self._last_response < 5:
            return None
        _LOG.warning("assessment=%s reasons=%s", a.level, a.reasons)
        inc = self.responder.respond(a)
        self._last_response = now
        self.incidents.append(inc)
        if a.level == "ransomware":
            self.detector.reset()
            self._heal_canaries()
        return inc

    def _heal_canaries(self) -> None:
        for c in list(self.canaries):
            if not os.path.exists(c):
                self.detector.ignore_path(c, 5)
        self.deploy_canaries()

    def _on_proc_incident(self, inc: dict) -> None:
        inc["time"] = now_iso()
        self.incidents.append(inc)
        self.responder._log(inc)
        if inc["action"] == "killed":
            notify("Sentry-AV: 위험 명령 차단", f"{inc['label']}: {inc['process'].get('name')} (pid {inc['process'].get('pid')})")
        else:
            notify("Sentry-AV: 의심 명령 감지", f"{inc['label']}: {inc['process'].get('name')}")
