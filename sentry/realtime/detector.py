"""Behavioural ransomware detector fed by file-system events.

Signals (within a sliding window):
  * canary (decoy) file modified / renamed / deleted  -> immediate alert
  * burst of modifications + renames to ransomware-style / unknown extensions
  * burst of overwrites where document files suddenly have random (high-entropy) content
  * ransom-note-like files being created
"""
from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Callable

from ..scanner import heuristics as H
from ..utils import entropy, read_head

_LOG = logging.getLogger("sentry.detector")


@dataclass
class FsEvent:
    kind: str          # created | modified | moved | deleted
    path: str
    dest: str | None
    ts: float
    is_canary: bool = False


@dataclass
class Assessment:
    level: str                       # none | suspicious | ransomware
    reasons: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    canary_hit: bool = False


class BehaviorDetector:
    def __init__(self, cfg, sigdb, canary_paths: set[str] | None = None,
                 canary_intact: Callable[[str], bool] | None = None,
                 on_alert: Callable[[], None] | None = None):
        self.window = float(cfg.get("window_seconds", 10))
        self.min_events = int(cfg.get("min_events_per_window", 30))
        self.min_renames = int(cfg.get("min_suspicious_renames", 5))
        self.min_entropy_writes = int(cfg.get("min_high_entropy_writes", 5))
        self.entropy_threshold = float(cfg.get("entropy_threshold", 7.6))
        self.sigdb = sigdb
        # shared by reference: RealtimeMonitor fills it when it deploys the decoys
        self.canaries = canary_paths if canary_paths is not None else set()
        # returns True when the decoy still has the content we wrote (filters spurious/late
        # FSEvents "modified" notifications, e.g. from the deployment itself)
        self.canary_intact = canary_intact or (lambda _p: False)
        self.on_alert = on_alert            # called (outside the lock) when strong evidence appears
        self._events: deque[FsEvent] = deque()
        self._lock = threading.Lock()
        self._entropy_hits: deque[tuple[float, str]] = deque()
        self._renames: deque[tuple[float, str]] = deque()
        self._notes: deque[tuple[float, str]] = deque()
        self._canary_hits: deque[tuple[float, str]] = deque()
        self._ignore_until: dict[str, float] = {}

    # ---- input --------------------------------------------------------------
    def ignore_path(self, path: str, seconds: float = 3.0) -> None:
        self._ignore_until[path] = time.time() + seconds

    def feed(self, kind: str, path: str, dest: str | None = None) -> None:
        now = time.time()
        exp = self._ignore_until.get(path)
        if exp and exp > now:
            return
        is_canary = path in self.canaries or (dest in self.canaries if dest else False)
        ev = FsEvent(kind, path, dest, now, is_canary)
        alert = False
        with self._lock:
            self._events.append(ev)
            if is_canary and kind in ("modified", "moved", "deleted"):
                if kind == "modified" and self.canary_intact(path):
                    _LOG.debug("canary %s reported modified but content is intact - ignored", path)
                else:
                    self._canary_hits.append((now, path))
                    _LOG.warning("CANARY touched: %s (%s)", path, kind)
                    alert = True
            self._classify(ev, now)
            self._prune(now)
            if len(self._renames) >= self.min_renames or self._notes:
                alert = True
        if alert and self.on_alert:
            self.on_alert()

    def _classify(self, ev: FsEvent, now: float) -> None:
        target = ev.dest or ev.path
        name = PurePath(target).name
        ext = PurePath(target).suffix.lower()
        if ev.kind == "moved" and ev.dest:
            old_ext = PurePath(ev.path).suffix.lower()
            if ext != old_ext and (self.sigdb.is_ransom_ext(ext) or
                                   (old_ext in H.DOC_EXTS and ext not in H.DOC_EXTS and ext not in ("", ".tmp", ".bak", ".part", ".crdownload"))):
                self._renames.append((now, target))
        elif ev.kind == "created" and self.sigdb.is_ransom_ext(ext):
            self._renames.append((now, target))
        if ev.kind in ("created", "modified") and self.sigdb.is_ransom_note_name(name):
            self._notes.append((now, target))
        # entropy sampling on document-type files (cheap: 4 KiB head)
        if ev.kind in ("modified", "created") and ext in H.DOC_EXTS and ext in H.MAGIC:
            head = read_head(target, 4096)
            if len(head) >= 1024 and not any(head.startswith(m) for m in H.MAGIC[ext]):
                if entropy(head) >= self.entropy_threshold:
                    self._entropy_hits.append((now, target))

    def _prune(self, now: float) -> None:
        cutoff = now - self.window
        for dq in (self._events,):
            while dq and dq[0].ts < cutoff:
                dq.popleft()
        for dq in (self._entropy_hits, self._renames, self._notes, self._canary_hits):
            while dq and dq[0][0] < cutoff:
                dq.popleft()

    # ---- output -------------------------------------------------------------
    def assess(self) -> Assessment:
        now = time.time()
        with self._lock:
            self._prune(now)
            n_events = len(self._events)
            n_ent = len({p for _, p in self._entropy_hits})
            n_ren = len({p for _, p in self._renames})
            n_notes = len({p for _, p in self._notes})
            canary = [p for _, p in self._canary_hits]
            paths = list({(e.dest or e.path) for e in self._events})
        reasons: list[str] = []
        if canary:
            reasons.append(f"{len(canary)} canary file(s) tampered: {', '.join(os.path.basename(c) for c in canary[:3])}")
            return Assessment("ransomware", reasons, paths, True)
        if n_notes:
            reasons.append(f"{n_notes} ransom-note-like file(s) created")
        if n_ren >= self.min_renames:
            reasons.append(f"{n_ren} files renamed to encrypted/unknown extensions")
        if n_ent >= self.min_entropy_writes:
            reasons.append(f"{n_ent} document files overwritten with high-entropy data")
        strong = (n_ren >= self.min_renames) + (n_ent >= self.min_entropy_writes) + (n_notes > 0)
        if strong >= 2 or (strong >= 1 and n_events >= self.min_events):
            reasons.insert(0, f"{n_events} file events in {self.window:.0f}s")
            return Assessment("ransomware", reasons, paths)
        if strong >= 1 or n_events >= self.min_events * 3:
            if n_events >= self.min_events * 3 and strong == 0:
                reasons.append(f"very high file churn: {n_events} events in {self.window:.0f}s")
            return Assessment("suspicious", reasons, paths)
        return Assessment("none")

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
            self._entropy_hits.clear()
            self._renames.clear()
            self._notes.clear()
            self._canary_hits.clear()
