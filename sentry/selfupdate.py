"""Self-update from GitHub Releases.

Flow:  latest release (GitHub API) -> compare tag with __version__ -> download the asset
for this OS/CPU -> verify against SHA256SUMS.txt from the same release -> atomically
replace the running single-file executable -> (optionally) re-launch.

Only a PyInstaller build (``utils.is_frozen()``) can replace itself; from a source
checkout we just report the new version and point at ``git pull``.
"""
from __future__ import annotations

import json
import logging
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import __version__
from .utils import IS_MACOS, IS_WINDOWS, app_dir, is_frozen, now_iso, sha256_file

_LOG = logging.getLogger("sentry.selfupdate")
DEFAULT_REPO = "yunch0315/sentry-av"
USER_AGENT = f"sentry-av/{__version__} (+self-update)"
CHECKSUMS_NAME = "SHA256SUMS.txt"


# ---------------------------------------------------------------------------
# version helpers
def parse_version(s: str) -> tuple[int, ...] | None:
    """'v1.2.3' / '1.2.3' / '1.2.3-rc1' -> (1, 2, 3); None when it does not look like a version."""
    m = re.match(r"^v?(\d+(?:\.\d+)*)", s.strip())
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def is_newer(candidate: str, current: str = __version__) -> bool:
    a, b = parse_version(candidate), parse_version(current)
    if a is None or b is None:
        return False
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) > b + (0,) * (n - len(b))


def asset_name_for_platform(system: str | None = None, machine: str | None = None) -> str:
    """Release asset name built by .github/workflows/release.yml for this OS/CPU."""
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    arch = {"amd64": "x64", "x86_64": "x64", "x64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(machine, machine)
    if system == "windows":
        return f"sentry-windows-{arch}.exe"
    if system == "darwin":
        return f"sentry-macos-{arch}"
    return f"sentry-{system}-{arch}"


def parse_checksums(text: str) -> dict[str, str]:
    """'<sha256>  <name>' lines (sha256sum / shasum -a 256 format) -> {name: sha256}."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            out[parts[-1].lstrip("*").split("/")[-1]] = parts[0].lower()
    return out


# ---------------------------------------------------------------------------
@dataclass
class Release:
    tag: str
    version: str
    html_url: str
    assets: dict[str, dict]      # name -> {"url": api url, "browser_download_url": ..., "size": n}
    notes: str = ""

    @property
    def newer(self) -> bool:
        return is_newer(self.version)


class GitHub:
    """Tiny GitHub REST client (urllib only).  ``token`` is needed for private repos."""

    def __init__(self, repo: str = DEFAULT_REPO, token: str | None = None, timeout: float = 15.0):
        self.repo = repo
        self.token = token or os.environ.get("SENTRY_GITHUB_TOKEN") or ""
        self.timeout = timeout

    def _headers(self, accept: str) -> dict[str, str]:
        h = {"User-Agent": USER_AGENT, "Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _open(self, url: str, accept: str, timeout: float | None = None):
        """GET with manual redirect handling: the Authorization header must NOT be
        forwarded to the storage host GitHub redirects asset downloads to."""
        req = urllib.request.Request(url, headers=self._headers(accept))
        opener = urllib.request.build_opener(_NoRedirect)
        for _ in range(5):
            try:
                return opener.open(req, timeout=timeout or self.timeout)
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
                    req = urllib.request.Request(e.headers["Location"],
                                                 headers={"User-Agent": USER_AGENT, "Accept": accept})
                    continue
                raise
        raise RuntimeError("too many redirects")

    def latest_release(self) -> Release | None:
        url = f"https://api.github.com/repos/{self.repo}/releases/latest"
        try:
            with self._open(url, "application/vnd.github+json") as r:
                data = json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                _LOG.info("no release yet (or private repo without token): %s", url)
                return None
            raise
        tag = data.get("tag_name", "")
        return Release(
            tag=tag, version=tag.lstrip("v"), html_url=data.get("html_url", ""),
            assets={a["name"]: {"url": a["url"], "browser_download_url": a.get("browser_download_url"),
                                "size": a.get("size", 0)} for a in data.get("assets", [])},
            notes=data.get("body") or "",
        )

    def download_asset(self, asset: dict, dest: Path, progress=None) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with self._open(asset["url"], "application/octet-stream", timeout=max(self.timeout, 60)) as r, \
                open(dest, "wb") as f:
            done = 0
            while True:
                chunk = r.read(1 << 16)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if progress:
                    progress(done, asset.get("size") or 0)
        return dest

    def asset_text(self, asset: dict) -> str:
        with self._open(asset["url"], "application/octet-stream") as r:
            return r.read().decode("utf-8", errors="replace")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


# ---------------------------------------------------------------------------
# state: last check time / last seen version (throttles the automatic check)
def _state_path() -> Path:
    return app_dir() / "update_state.json"


def load_state() -> dict:
    try:
        return json.loads(_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(**kw) -> None:
    st = load_state()
    st.update(kw)
    try:
        _state_path().write_text(json.dumps(st, indent=2), encoding="utf-8")
    except OSError:
        pass


def check_due(interval_hours: float) -> bool:
    last = float(load_state().get("last_check", 0) or 0)
    return time.time() - last >= interval_hours * 3600


# ---------------------------------------------------------------------------
class Updater:
    def __init__(self, cfg=None, repo: str | None = None, token: str | None = None):
        get = cfg.get if cfg is not None else (lambda k, d=None: d)
        self.repo = repo or get("update_repo", DEFAULT_REPO)
        self.gh = GitHub(self.repo, token or get("update_token") or None)
        self.exe = Path(sys.executable).resolve()

    # -- check ---------------------------------------------------------------
    def check(self) -> Release | None:
        """Latest release, or None when unreachable / none published.  Records the check."""
        try:
            rel = self.gh.latest_release()
        except Exception as e:  # noqa: BLE001
            _LOG.warning("update check failed: %s", e)
            save_state(last_check=time.time(), last_error=str(e), checked_at=now_iso())
            return None
        save_state(last_check=time.time(), last_error="", checked_at=now_iso(),
                   latest=rel.version if rel else "")
        return rel

    def available(self) -> Release | None:
        rel = self.check()
        return rel if rel and rel.newer else None

    # -- apply ---------------------------------------------------------------
    def download(self, rel: Release, progress=None) -> Path:
        name = asset_name_for_platform()
        asset = rel.assets.get(name)
        if not asset:
            raise RuntimeError(f"release {rel.tag} has no build for this platform ({name}); "
                               f"assets: {', '.join(rel.assets) or 'none'}")
        sums = rel.assets.get(CHECKSUMS_NAME)
        if not sums:
            raise RuntimeError(f"release {rel.tag} has no {CHECKSUMS_NAME}; refusing unverified download")
        expected = parse_checksums(self.gh.asset_text(sums)).get(name)
        if not expected:
            raise RuntimeError(f"{CHECKSUMS_NAME} in {rel.tag} does not list {name}")

        tmpdir = Path(tempfile.mkdtemp(prefix="sentry-update-", dir=str(app_dir())))
        dest = tmpdir / name
        try:
            self.gh.download_asset(asset, dest, progress)
            actual = sha256_file(dest)
            if actual != expected:
                raise RuntimeError(f"checksum mismatch for {name}: expected {expected[:16]}…, "
                                   f"got {(actual or '?')[:16]}…")
        except BaseException:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise
        return dest

    def install(self, new_file: Path, target: Path | None = None) -> Path:
        """Replace ``target`` (default: the running executable) with ``new_file``.

        The old file is kept next to it as ``<name>.old`` until the next successful
        update (Windows cannot delete a running exe, but it can be renamed)."""
        target = (target or self.exe).resolve()
        if not is_frozen() and target == self.exe:
            raise RuntimeError("running from source: update with `git pull` (self-replace only for the built binary)")
        new_file = Path(new_file)
        if not new_file.is_file():
            raise RuntimeError(f"{new_file} missing")
        mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else 0o755
        staged = target.with_name(target.name + ".new")
        if staged.exists():
            staged.unlink()
        os.replace(new_file, staged)
        if not IS_WINDOWS:
            os.chmod(staged, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            _strip_quarantine(staged)
        backup = target.with_name(target.name + ".old")
        if backup.exists():
            try:
                backup.unlink()
            except OSError:
                pass
        if target.exists():
            os.replace(target, backup)       # rename works even while the exe is running (Windows too)
        try:
            os.replace(staged, target)
        except OSError:
            if backup.exists():
                os.replace(backup, target)   # roll back
            raise
        try:
            new_file.parent.rmdir()
        except OSError:
            pass
        save_state(installed=now_iso(), installed_from=str(new_file.name), previous_version=__version__)
        return target

    def cleanup_backup(self, target: Path | None = None) -> None:
        """Delete ``<exe>.old`` left by the previous update (no longer in use)."""
        target = (target or self.exe).resolve()
        backup = target.with_name(target.name + ".old")
        if backup.exists():
            try:
                backup.unlink()
            except OSError:
                pass

    def upgrade(self, progress=None, rel: Release | None = None) -> Release | None:
        """Check + download + install.  Returns the installed release or None (already current)."""
        rel = rel or self.available()
        if not rel:
            return None
        if not is_frozen():
            raise RuntimeError(f"new version {rel.version} available but this is a source checkout: run `git pull`")
        self.install(self.download(rel, progress))
        return rel


def _strip_quarantine(path: Path) -> None:
    if IS_MACOS:
        subprocess.call(["xattr", "-d", "com.apple.quarantine", str(path)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def relaunch(argv: list[str] | None = None) -> None:
    """Replace the current process with the (freshly installed) executable, same arguments."""
    args = [sys.executable, *(sys.argv[1:] if argv is None else argv)]
    if IS_WINDOWS:
        # the running exe file was renamed to .old; start the new one and leave
        subprocess.Popen(args, close_fds=True)
        os._exit(0)
    os.execv(sys.executable, args)


# ---------------------------------------------------------------------------
# background periodic check used by long-running `monitor`
class AutoUpdateThread(threading.Thread):
    """Every ``interval_hours``: check GitHub; when a newer build exists, install it and
    call ``on_installed`` (which typically stops the monitor and re-launches)."""

    def __init__(self, cfg, on_installed, interval_hours: float | None = None, first_delay: float = 60.0):
        super().__init__(name="sentry-autoupdate", daemon=True)
        self.updater = Updater(cfg)
        self.interval = float(interval_hours or cfg.get("update_check_interval_hours", 24))
        self.first_delay = first_delay
        self.on_installed = on_installed
        self._halt = threading.Event()   # not `_stop`: that is a Thread method used by join()

    def stop(self) -> None:
        self._halt.set()

    def run(self) -> None:
        if self._halt.wait(self.first_delay):
            return
        while not self._halt.is_set():
            try:
                if check_due(self.interval):
                    rel = self.updater.upgrade()
                    if rel:
                        _LOG.warning("updated to %s; restarting", rel.version)
                        self.on_installed(rel)
                        return
            except Exception as e:  # noqa: BLE001
                _LOG.warning("auto-update failed: %s", e)
            if self._halt.wait(min(self.interval * 3600, 3600)):
                return
