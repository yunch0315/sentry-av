"""Quarantine store: files are moved to ~/.sentry-av/quarantine, XOR-obfuscated so they
cannot run or be re-detected by other AV engines, and indexed for restore."""
from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import threading
import uuid
from datetime import datetime
from pathlib import Path

from .utils import app_dir, now_iso, sha256_file

_LOG = logging.getLogger("sentry.quarantine")
_XOR_KEY = 0x5A


def _xor_copy(src: Path, dst: Path) -> None:
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while True:
            chunk = fi.read(1 << 20)
            if not chunk:
                break
            fo.write(bytes(b ^ _XOR_KEY for b in chunk))


class Quarantine:
    def __init__(self, base: Path | None = None):
        self.dir = (base or app_dir()) / "quarantine"
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass
        self.index_path = self.dir / "index.json"
        self._lock = threading.Lock()
        self._index: dict[str, dict] = self._load()

    def _load(self) -> dict[str, dict]:
        if self.index_path.exists():
            try:
                return json.loads(self.index_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                _LOG.warning("quarantine index corrupt; starting fresh")
        return {}

    def _save(self) -> None:
        tmp = self.index_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._index, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.index_path)

    def add(self, path: str | os.PathLike, reason: str, sha256: str | None = None) -> str | None:
        """Quarantine a file. Returns quarantine id or None on failure."""
        src = Path(path)
        if not src.is_file():
            return None
        qid = datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
        dst = self.dir / f"{qid}.quar"
        try:
            try:
                src.chmod(src.stat().st_mode | stat.S_IWUSR | stat.S_IRUSR)
            except OSError:
                pass
            sha = sha256 or sha256_file(src)
            mode = stat.S_IMODE(src.stat().st_mode)
            _xor_copy(src, dst)
            try:
                src.unlink()
            except PermissionError:
                # locked executable (Windows): neutralise by truncating + renaming
                try:
                    os.replace(src, src.with_suffix(src.suffix + ".sentry-quarantined"))
                except OSError as e:
                    _LOG.warning("could not remove %s after quarantining: %s", src, e)
            with self._lock:
                self._index[qid] = {
                    "id": qid, "original_path": str(src), "sha256": sha, "reason": reason,
                    "size": dst.stat().st_size, "time": now_iso(), "mode": mode,
                }
                self._save()
            _LOG.info("quarantined %s -> %s (%s)", src, qid, reason)
            return qid
        except OSError as e:
            _LOG.error("quarantine failed for %s: %s", src, e)
            if dst.exists():
                dst.unlink(missing_ok=True)
            return None

    def list(self) -> list[dict]:
        return sorted(self._index.values(), key=lambda r: r["time"], reverse=True)

    def restore(self, qid: str, dest: str | None = None) -> Path:
        rec = self._index.get(qid)
        if not rec:
            raise KeyError(qid)
        src = self.dir / f"{qid}.quar"
        target = Path(dest) if dest else Path(rec["original_path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        _xor_copy(src, target)
        try:
            os.chmod(target, rec.get("mode") or 0o644)
        except OSError:
            pass
        src.unlink(missing_ok=True)
        with self._lock:
            del self._index[qid]
            self._save()
        _LOG.info("restored %s -> %s", qid, target)
        return target

    def delete(self, qid: str) -> None:
        rec = self._index.get(qid)
        if not rec:
            raise KeyError(qid)
        (self.dir / f"{qid}.quar").unlink(missing_ok=True)
        with self._lock:
            del self._index[qid]
            self._save()

    def purge(self) -> int:
        n = len(self._index)
        for qid in list(self._index):
            self.delete(qid)
        return n

    def total_size(self) -> int:
        return sum(r.get("size", 0) for r in self._index.values())

    def remove_tree(self) -> None:  # tests only
        shutil.rmtree(self.dir, ignore_errors=True)
