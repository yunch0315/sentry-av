"""File-system scanner: walks paths, hashes files, applies signatures + heuristics."""
from __future__ import annotations

import logging
import os
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from ..utils import is_frozen, read_head, sha256_file
from . import heuristics as H
from .signatures import SignatureDB
from .trust import TrustChecker
from .yara_engine import YaraEngine

_LOG = logging.getLogger("sentry.scanner")

SEV_ORDER = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    path: str
    severity: str
    category: str
    reasons: list[str] = field(default_factory=list)
    sha256: str | None = None
    size: int = 0
    kind: str = "other"
    score: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanStats:
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    errors: int = 0
    started: float = field(default_factory=time.time)
    finished: float | None = None

    @property
    def duration(self) -> float:
        return (self.finished or time.time()) - self.started


class Scanner:
    HEAD_BYTES = 4096
    DEEP_BYTES = 8 << 20  # read at most 8 MiB of executables/scripts for string analysis

    def __init__(self, cfg, whitelist, sigdb: SignatureDB | None = None, yara_engine: YaraEngine | None = None):
        self.cfg = cfg
        self.wl = whitelist
        self.sigdb = sigdb or SignatureDB()
        self.yara = yara_engine or YaraEngine()
        self.max_bytes = int(cfg.get("max_file_size_mb", 200)) * 1024 * 1024
        self.threads = max(1, int(cfg.get("scan_threads", 4)))
        self.trust = TrustChecker(enabled=bool(cfg.get("trust_signed_files", True)))
        self.suppressed_signed = 0
        self._stop = threading.Event()
        self._self_paths = self._own_paths()

    @staticmethod
    def _own_paths() -> list[str]:
        """Our own code / build must never show up as a finding (it contains the very
        strings the heuristics look for)."""
        import sys
        own: list[str] = []
        if is_frozen():
            own.append(os.path.abspath(sys.executable))
            mp = getattr(sys, "_MEIPASS", None)
            if mp:
                own.append(os.path.abspath(mp))
        pkg = Path(__file__).resolve().parents[1]           # .../sentry
        own.append(str(pkg))
        if (pkg.parent / "pyproject.toml").is_file():       # development checkout
            own.append(str(pkg.parent))
        return own

    def _is_own(self, path: str) -> bool:
        for o in self._self_paths:
            if path == o or path.startswith(o.rstrip(os.sep) + os.sep):
                return True
        return False

    def stop(self) -> None:
        self._stop.set()

    # ---- walking -----------------------------------------------------------
    def iter_files(self, roots: Iterable[str]) -> Iterable[str]:
        seen_dirs: set[tuple[int, int]] = set()
        for root in roots:
            root = os.path.abspath(root)
            if os.path.isfile(root):
                yield root
                continue
            if not os.path.isdir(root):
                _LOG.warning("skip missing path %s", root)
                continue
            stack = [root]
            while stack and not self._stop.is_set():
                d = stack.pop()
                if self.wl.is_excluded_path(d) or self._is_own(d):
                    continue
                try:
                    st = os.stat(d)
                    key = (st.st_dev, st.st_ino)
                    if key in seen_dirs:
                        continue
                    seen_dirs.add(key)
                    with os.scandir(d) as it:
                        for e in it:
                            try:
                                if e.is_symlink():
                                    continue
                                if e.is_dir(follow_symlinks=False):
                                    stack.append(e.path)
                                elif e.is_file(follow_symlinks=False):
                                    yield e.path
                            except OSError:
                                continue
                except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
                    continue

    # ---- single file -------------------------------------------------------
    def scan_file(self, path: str) -> Finding | None:
        try:
            st = os.stat(path, follow_symlinks=False)
        except OSError:
            return None
        if not stat.S_ISREG(st.st_mode):
            return None
        size = st.st_size
        if size == 0:
            return None
        if self.wl.is_excluded_path(path) or self._is_own(path):
            return None
        ext = Path(path).suffix.lower()
        head = read_head(path, self.HEAD_BYTES)
        kind = H.detect_type(head, ext)

        reasons: list[str] = []
        severity = "clean"
        category = ""
        score = 0
        sha = None

        if size <= self.max_bytes:
            sha = sha256_file(path)
            label = self.sigdb.lookup_hash(sha)
            if label:
                return Finding(path, "critical", "known-malware", [f"hash match: {label}"], sha, size, kind, 100)

        def merge(a: H.Analysis) -> None:
            nonlocal severity, category, score
            if a.severity == "clean":
                return
            for ev in a.evidence:
                reasons.append(f"{ev.label} (+{ev.score})")
            score += a.score
            if SEV_ORDER[a.severity] > SEV_ORDER[severity]:
                severity, category = a.severity, a.category
            elif not category:
                category = a.category

        # content heuristics for executables & scripts
        if kind in ("pe", "macho", "elf", "exec-ext") and size <= self.max_bytes:
            data = read_head(path, min(size, self.DEEP_BYTES))
            merge(H.analyze_executable(data, kind))
        elif kind == "script" and size <= self.max_bytes:
            data = read_head(path, min(size, self.DEEP_BYTES))
            merge(H.analyze_script(data))
        elif kind == "office":
            merge(H.analyze_office(path))

        # ransomware output / notes (applies to every file type)
        merge(H.analyze_encrypted(path, head, self.sigdb))

        # heuristic hits inside a validly signed app / signed binary are not malware
        if severity != "clean" and self.trust.is_trusted(path, kind, sha):
            _LOG.debug("signed & intact, suppressed: %s (%s)", path, "; ".join(reasons))
            self.suppressed_signed += 1
            return None

        # YARA (optional)
        if self.yara.available and size <= self.max_bytes:
            for rule, sev in self.yara.match(path):
                reasons.append(f"yara:{rule}")
                sev = sev if sev in SEV_ORDER else "medium"
                score += 8 if sev == "high" else 4
                if SEV_ORDER[sev] > SEV_ORDER[severity]:
                    severity, category = sev, "yara-match"

        if severity == "clean":
            return None
        return Finding(path, severity, category, reasons, sha, size, kind, score)

    # ---- batch -------------------------------------------------------------
    def scan_paths(self, roots: Iterable[str], on_progress: Callable[[str, ScanStats], None] | None = None,
                   min_severity: str = "low") -> tuple[list[Finding], ScanStats]:
        stats = ScanStats()
        findings: list[Finding] = []
        min_rank = SEV_ORDER.get(min_severity, 1)
        lock = threading.Lock()

        def work(p: str) -> Finding | None:
            try:
                st_size = os.path.getsize(p)
            except OSError:
                with lock:
                    stats.errors += 1
                return None
            try:
                f = self.scan_file(p)
            except Exception as e:  # noqa: BLE001
                _LOG.debug("scan error %s: %s", p, e)
                with lock:
                    stats.errors += 1
                return None
            with lock:
                stats.files_scanned += 1
                stats.bytes_scanned += min(st_size, self.max_bytes)
            if on_progress:
                on_progress(p, stats)
            return f

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            pending = set()
            for p in self.iter_files(roots):
                if self._stop.is_set():
                    break
                pending.add(ex.submit(work, p))
                if len(pending) >= self.threads * 8:
                    done = next(as_completed(pending))
                    pending.discard(done)
                    r = done.result()
                    if r and SEV_ORDER[r.severity] >= min_rank:
                        findings.append(r)
            for fut in as_completed(pending):
                r = fut.result()
                if r and SEV_ORDER[r.severity] >= min_rank:
                    findings.append(r)
        stats.finished = time.time()
        findings.sort(key=lambda f: (-SEV_ORDER[f.severity], -f.score, f.path))
        return findings, stats
