"""Load hash / extension / note-name signature data."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..utils import app_dir, resource_dir

_LOG = logging.getLogger("sentry.signatures")


class SignatureDB:
    def __init__(self) -> None:
        self.hashes: dict[str, str] = {}
        self.ransom_exts: set[str] = set()
        self.note_patterns: list[re.Pattern] = []
        self.reload()

    # -- loading -----------------------------------------------------------
    def reload(self) -> None:
        res = resource_dir()
        self.hashes = {}
        for p in (res / "hashes.txt", app_dir() / "hashes_extra.txt"):
            self._load_hashes(p)
        self.ransom_exts = self._load_tokens(res / "ransomware_extensions.txt")
        self.ransom_exts |= self._load_tokens(app_dir() / "ransomware_extensions_extra.txt")
        self.note_patterns = []
        for line in self._lines(res / "ransom_notes.txt"):
            try:
                self.note_patterns.append(re.compile(line, re.IGNORECASE))
            except re.error as e:
                _LOG.warning("bad note pattern %r: %s", line, e)
        _LOG.debug("signatures: %d hashes, %d extensions, %d note patterns",
                   len(self.hashes), len(self.ransom_exts), len(self.note_patterns))

    @staticmethod
    def _lines(p: Path) -> list[str]:
        if not p.exists():
            return []
        out = []
        for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
            s = raw.strip()
            if s and not s.startswith("#"):
                out.append(s)
        return out

    def _load_hashes(self, p: Path) -> None:
        for line in self._lines(p):
            parts = line.split(None, 1)
            h = parts[0].lower()
            if re.fullmatch(r"[0-9a-f]{64}", h):
                self.hashes[h] = parts[1] if len(parts) > 1 else "known-malware"

    def _load_tokens(self, p: Path) -> set[str]:
        toks: set[str] = set()
        for line in self._lines(p):
            for t in line.split():
                t = t.lower()
                if not t.startswith("."):
                    t = "." + t
                toks.add(t)
        return toks

    # -- queries -----------------------------------------------------------
    def lookup_hash(self, sha256: str | None) -> str | None:
        return self.hashes.get(sha256.lower()) if sha256 else None

    def is_ransom_ext(self, ext: str) -> bool:
        return ext.lower() in self.ransom_exts

    def is_ransom_note_name(self, filename: str) -> bool:
        return any(p.search(filename) for p in self.note_patterns)

    def stats(self) -> dict:
        return {"hashes": len(self.hashes), "ransomware_extensions": len(self.ransom_exts),
                "note_patterns": len(self.note_patterns)}
