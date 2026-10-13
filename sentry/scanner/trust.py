"""Lazy code-signature trust checks used to suppress heuristic findings.

Only consulted for files that the heuristics *already* flagged, so the cost is a
few hundred `codesign` / PowerShell calls per scan instead of one per file.

macOS
  * Mach-O files: `codesign --verify` on the file itself, then the certificate chain
    must end at Apple Root CA (Apple platform binaries, Mac App Store, Developer ID).
  * Any other file inside a signed bundle: the bundle's `_CodeSignature/CodeResources`
    seal lists the SHA-256 of every resource.  If the file's hash is in the seal and
    the bundle's main executable has a valid signature, the file is untouched original
    content of that app.
Windows
  * `Get-AuthenticodeSignature` status must be `Valid` (embedded or catalog signature).
"""
from __future__ import annotations

import hashlib
import logging
import os
import plistlib
import threading
from pathlib import Path

from ..utils import IS_MACOS, IS_WINDOWS, run_cmd

_LOG = logging.getLogger("sentry.trust")

_APPLE_AUTHORITIES = ("Authority=Software Signing", "Authority=Apple Mac OS Application Signing",
                      "Authority=Developer ID Application")


class TrustChecker:
    def __init__(self, enabled: bool = True, platform: str | None = None) -> None:
        self.enabled = enabled
        self.platform = platform or ("darwin" if IS_MACOS else "windows" if IS_WINDOWS else "other")
        self._file_cache: dict[str, bool] = {}
        self._seal_cache: dict[str, dict | None] = {}
        self._bundle_cache: dict[str, bool] = {}
        self._lock = threading.Lock()

    # ---- public --------------------------------------------------------------
    def is_trusted(self, path: str, kind: str, sha256: str | None) -> bool:
        if not self.enabled:
            return False
        with self._lock:
            if path in self._file_cache:
                return self._file_cache[path]
        try:
            if self.platform == "darwin":
                ok = self._mac(path, kind, sha256)
            elif self.platform == "windows":
                ok = self._win(path)
            else:
                ok = False
        except Exception as e:  # noqa: BLE001
            _LOG.debug("trust check failed for %s: %s", path, e)
            ok = False
        with self._lock:
            self._file_cache[path] = ok
        return ok

    # ---- macOS --------------------------------------------------------------
    def _mac(self, path: str, kind: str, sha256: str | None) -> bool:
        if kind == "macho":
            return self._codesign_ok(path)
        root = self._seal_root(path)
        if root is None:
            return False
        seal = self._load_seal(root)
        if not seal:
            return False
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        entry = seal.get(rel)
        if entry is None:
            return False
        if isinstance(entry, dict):
            if "hash2" in entry:
                want = entry["hash2"]
                have = bytes.fromhex(sha256) if sha256 else _digest(path, "sha256")
            elif "hash" in entry:
                want, have = entry["hash"], _digest(path, "sha1")
            else:                      # nested code (cdhash) - handled by its own seal
                return False
        else:                          # legacy: bare sha1 data
            want, have = entry, _digest(path, "sha1")
        if bytes(want) != have:
            return False
        return self._bundle_signed(root)

    @staticmethod
    def _seal_root(path: str) -> Path | None:
        """Innermost ancestor directory that owns a `_CodeSignature/CodeResources` seal."""
        p = Path(path).parent
        for _ in range(12):
            if (p / "_CodeSignature" / "CodeResources").is_file():
                return p
            if p.parent == p:
                break
            p = p.parent
        return None

    def _load_seal(self, root: Path) -> dict | None:
        key = str(root)
        with self._lock:
            if key in self._seal_cache:
                return self._seal_cache[key]
        seal: dict | None = None
        try:
            with open(root / "_CodeSignature" / "CodeResources", "rb") as fh:
                data = plistlib.load(fh)
            seal = dict(data.get("files2") or {})
            for k, v in (data.get("files") or {}).items():
                seal.setdefault(k, v)
        except Exception as e:  # noqa: BLE001
            _LOG.debug("cannot read seal %s: %s", root, e)
        with self._lock:
            self._seal_cache[key] = seal
        return seal

    def _bundle_signed(self, root: Path) -> bool:
        key = str(root)
        with self._lock:
            if key in self._bundle_cache:
                return self._bundle_cache[key]
        ok = False
        exe = self._main_executable(root)
        if exe is not None:
            ok = self._codesign_ok(str(exe), seal_only=True)
        with self._lock:
            self._bundle_cache[key] = ok
        return ok

    @staticmethod
    def _main_executable(root: Path) -> Path | None:
        candidates = [root / "Info.plist", root / "Resources" / "Info.plist"]
        for info in candidates:
            if not info.is_file():
                continue
            try:
                with open(info, "rb") as fh:
                    name = plistlib.load(fh).get("CFBundleExecutable")
            except Exception:  # noqa: BLE001
                continue
            if not name:
                continue
            for exe in (root / "MacOS" / name, root / name):
                if exe.is_file():
                    return exe
        return None

    def _codesign_ok(self, path: str, seal_only: bool = False) -> bool:
        """Signature of `path` verifies and chains to Apple.

        seal_only: accept a bundle whose *resources* changed after signing (plugins
        installed, updater wrote files, ...) as long as the CodeResources seal itself
        is still authentic - the per-file hash comparison against that seal is what
        decides trust for individual files.  A tampered seal ("invalid resource
        directory") is never accepted.
        """
        ck = f"codesign:{int(seal_only)}:{path}"
        with self._lock:
            cached = self._file_cache.get(ck)
        if cached is not None:
            return cached
        ok = False
        rc, out, err = run_cmd(["codesign", "--verify", "--no-strict", path], timeout=120)
        verified = rc == 0 or (seal_only and "a sealed resource is missing or invalid" in (out + err))
        if verified:
            rc2, out, err = run_cmd(["codesign", "-dv", "--verbose=2", path], timeout=30)
            text = out + err
            ok = rc2 == 0 and "Authority=Apple Root CA" in text and any(a in text for a in _APPLE_AUTHORITIES)
        with self._lock:
            self._file_cache[ck] = ok
        return ok

    # ---- Windows ------------------------------------------------------------
    @staticmethod
    def _win(path: str) -> bool:
        ps = (f"$s=Get-AuthenticodeSignature -LiteralPath '{path.replace(chr(39), chr(39) * 2)}';"
              "if($s.Status -eq 'Valid'){'VALID'}")
        rc, out, _ = run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=30)
        return rc == 0 and "VALID" in out


def _digest(path: str, algo: str) -> bytes:
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()
