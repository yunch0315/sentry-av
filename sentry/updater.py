"""Download public malware-hash feeds into the app dir.

* recent feeds (abuse.ch MalwareBazaar / ThreatFox, a few hundred KB) -> ``hashes_extra.txt``
  text with labels, appended; refreshed daily by the CLI / menu start-up.
* full dump (MalwareBazaar, ~45 MB zip, >1.1 M hashes) -> ``hashes_full.bin``
  compact sorted index (scanner/hashindex.py); refreshed every ``signature_full_days``.

Feeds are plain text (one hash per line), CSV (ThreatFox: hash in column 3, family in
column 8) or a zip of those.  Anything that is not a 64-hex SHA-256 is ignored.
"""
from __future__ import annotations

import csv
import io
import logging
import os
import re
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable, Iterator

from . import __version__
from .scanner.hashindex import HashIndex
from .selfupdate import load_state, save_state
from .utils import app_dir, now_iso, ssl_context

_LOG = logging.getLogger("sentry.updater")
_HEX64 = re.compile(r"\b([0-9a-fA-F]{64})\b")
USER_AGENT = f"sentry-av/{__version__} (+hash-feed)"
EXTRA_FILE = "hashes_extra.txt"
FULL_FILE = "hashes_full.bin"

Progress = Callable[[int, int], None]


def _fetch(url: str, timeout: float, dest: Path | None = None, progress: Progress | None = None) -> bytes | Path:
    """GET ``url``; return the body, or stream it into ``dest`` and return that path."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout, context=ssl_context()) as r:
        total = int(r.headers.get("Content-Length") or 0)
        if dest is None:
            return r.read()
        done = 0
        with open(dest, "wb") as f:
            while True:
                chunk = r.read(1 << 16)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
        return dest


def iter_hashes(data: bytes, name: str = "") -> Iterator[tuple[str, str]]:
    """Yield ``(sha256, label)`` from txt / CSV / zip feed content."""
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for member in zf.namelist():
                    if member.endswith("/"):
                        continue
                    yield from iter_hashes(zf.read(member), member)
        except zipfile.BadZipFile as e:
            _LOG.warning("bad zip feed %s: %s", name, e)
        return
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _HEX64.search(s)
        if not m:
            continue
        label = ""
        if s.startswith('"'):               # ThreatFox CSV: malware_printable is column 8
            try:
                row = next(csv.reader([s], skipinitialspace=True))
                if len(row) > 7 and row[7] and row[7].lower() != "none":
                    label = row[7]
            except (csv.Error, StopIteration):
                pass
        yield m.group(1).lower(), label


def iter_hashes_file(path: Path) -> Iterator[tuple[str, str]]:
    """Like iter_hashes but streams a (possibly zipped) file without loading it whole."""
    with open(path, "rb") as f:
        head = f.read(2)
    if head == b"PK":
        with zipfile.ZipFile(path) as zf:
            for member in zf.namelist():
                if member.endswith("/"):
                    continue
                with zf.open(member) as m:
                    for raw in io.TextIOWrapper(m, encoding="utf-8", errors="replace"):
                        s = raw.strip()
                        if s and not s.startswith("#"):
                            mm = _HEX64.search(s)
                            if mm:
                                yield mm.group(1).lower(), ""
        return
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            s = raw.strip()
            if s and not s.startswith("#"):
                mm = _HEX64.search(s)
                if mm:
                    yield mm.group(1).lower(), ""


def _existing_extra(out: Path) -> set[str]:
    existing: set[str] = set()
    if out.exists():
        for line in out.read_text(encoding="utf-8", errors="replace").splitlines():
            m = _HEX64.search(line)
            if m:
                existing.add(m.group(1).lower())
    return existing


def update_signatures(urls: list[str], timeout: float = 30.0) -> dict:
    """Append new hashes from the recent feeds to hashes_extra.txt."""
    out = app_dir() / EXTRA_FILE
    existing = _existing_extra(out)
    added = 0
    results: dict[str, str] = {}
    new_lines: list[str] = []
    for url in urls:
        try:
            body = _fetch(url, timeout)
        except Exception as e:  # noqa: BLE001
            results[url] = f"failed: {e}"
            _LOG.warning("feed %s failed: %s", url, e)
            continue
        n = 0
        host = url.split("/")[2]
        for h, label in iter_hashes(body, url):
            if h in existing:
                continue
            existing.add(h)
            new_lines.append(f"{h} {label + ' ' if label else ''}feed:{host}")
            n += 1
        results[url] = f"ok (+{n} hashes)"
        added += n
    if new_lines:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"# updated {now_iso()}\n")
            f.write("\n".join(new_lines) + "\n")
    if any(v.startswith("ok") for v in results.values()):
        save_state(last_sig_update=time.time(), sig_updated_at=now_iso())
    return {"added": added, "total": len(existing), "file": str(out), "feeds": results}


def signatures_due(interval_hours: float = 24.0) -> bool:
    last = float(load_state().get("last_sig_update", 0) or 0)
    return time.time() - last >= interval_hours * 3600


def full_index_path() -> Path:
    return app_dir() / FULL_FILE


def full_index_age_days() -> float | None:
    p = full_index_path()
    if not p.exists():
        return None
    return (time.time() - p.stat().st_mtime) / 86400


def full_due(max_age_days: float) -> bool:
    age = full_index_age_days()
    return age is None or age >= max_age_days


def update_full(url: str, timeout: float = 600.0, progress: Progress | None = None) -> dict:
    """Download the full dump and rebuild hashes_full.bin (atomic; the old index stays
    in use until the new one is complete)."""
    target = full_index_path()
    tmpdir = Path(tempfile.mkdtemp(prefix="sentry-feed-", dir=str(app_dir())))
    try:
        dump = _fetch(url, timeout, tmpdir / "full.bin", progress)
        count = HashIndex.build(target, (h for h, _ in iter_hashes_file(dump)))
    finally:
        try:
            for p in tmpdir.iterdir():
                p.unlink()
            tmpdir.rmdir()
        except OSError:
            pass
    save_state(last_full_update=time.time(), full_updated_at=now_iso(), full_count=count)
    return {"count": count, "file": str(target), "bytes": target.stat().st_size}
