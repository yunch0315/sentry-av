"""Compact on-disk index of SHA-256 digests (sorted, 32 bytes each, binary-searched via mmap).

The full MalwareBazaar dump is >1.1 million hashes; as Python strings in a dict that is
hundreds of MB, as this file it is ~37 MB on disk and ~0 in RAM.
"""
from __future__ import annotations

import mmap
import os
import struct
from pathlib import Path
from typing import Iterable

MAGIC = b"SAVH1\0"
HEADER = struct.Struct("<6sxxQ")      # magic, pad, count
ENTRY = 32


class HashIndex:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.count = 0
        self._f = None
        self._mm: mmap.mmap | None = None
        self._open()

    def _open(self) -> None:
        try:
            self._f = open(self.path, "rb")
            head = self._f.read(HEADER.size)
            magic, count = HEADER.unpack(head)
            if magic != MAGIC:
                raise ValueError("bad magic")
            size = os.fstat(self._f.fileno()).st_size
            if size != HEADER.size + count * ENTRY:
                raise ValueError("truncated index")
            self.count = count
            self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ) if count else None
        except (OSError, ValueError, struct.error):
            self.close()
            self.count = 0

    def close(self) -> None:
        if self._mm is not None:
            self._mm.close()
            self._mm = None
        if self._f is not None:
            self._f.close()
            self._f = None

    def contains(self, sha256_hex: str | None) -> bool:
        if not sha256_hex or self._mm is None or len(sha256_hex) != 64:
            return False
        try:
            key = bytes.fromhex(sha256_hex)
        except ValueError:
            return False
        mm, lo, hi = self._mm, 0, self.count
        while lo < hi:
            mid = (lo + hi) // 2
            off = HEADER.size + mid * ENTRY
            cur = mm[off:off + ENTRY]
            if cur < key:
                lo = mid + 1
            elif cur > key:
                hi = mid
            else:
                return True
        return False

    @property
    def mtime(self) -> float:
        try:
            return self.path.stat().st_mtime
        except OSError:
            return 0.0

    @classmethod
    def build(cls, path: Path, hashes: Iterable[str]) -> int:
        """Write a new index atomically from hex strings; returns the number of unique digests."""
        digests = set()
        for h in hashes:
            if len(h) == 64:
                try:
                    digests.add(bytes.fromhex(h))
                except ValueError:
                    continue
        ordered = sorted(digests)
        path = Path(path)
        tmp = path.with_name(path.name + ".tmp")
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "wb") as f:
            f.write(HEADER.pack(MAGIC, len(ordered)))
            for i in range(0, len(ordered), 65536):
                f.write(b"".join(ordered[i:i + 65536]))
        os.replace(tmp, path)
        return len(ordered)
