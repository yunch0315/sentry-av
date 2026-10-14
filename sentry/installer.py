"""Self-installer: the downloaded single-file exe doubles as its own setup wizard.

Running the program from Downloads/Desktop is a problem on Windows (Defender keeps
deleting the self-updating exe, and excluding those folders is unsafe).  `sentry install`
copies the running binary into a dedicated per-user folder, makes Desktop / Start-menu
shortcuts, and (Windows) registers the narrow Defender exclusion for the *installed* path.
Updates then happen in that stable folder, so the exclusion keeps working.

Source checkouts (`python -m sentry`) are not installed - there is no single file to copy.
"""
from __future__ import annotations

import os
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from . import __version__
from .utils import IS_MACOS, IS_WINDOWS, is_frozen, run_cmd, user_home

APP = "Sentry-AV"


def default_install_dir(system: bool = False) -> Path:
    if IS_WINDOWS:
        if system:
            base = os.environ.get("ProgramFiles", r"C:\Program Files")
            return Path(base) / APP
        base = os.environ.get("LOCALAPPDATA", str(user_home() / "AppData" / "Local"))
        return Path(base) / "Programs" / APP
    if IS_MACOS:
        return user_home() / "Applications" / APP
    return user_home() / ".local" / "share" / "sentry-av"


def installed_name() -> str:
    return "sentry.exe" if IS_WINDOWS else "sentry"


def _broad_dirs() -> set[str]:
    from . import defender
    return defender._broad_dirs()


def running_from_broad_dir() -> bool:
    if not is_frozen():
        return False
    return str(Path(sys.executable).resolve().parent).rstrip("\\").lower() in _broad_dirs()


def is_installed_here() -> bool:
    """True when the running exe already lives in a sane (non-broad) folder."""
    return is_frozen() and not running_from_broad_dir()


def _ps(script: str, timeout: float = 30.0) -> tuple[int, str, str]:
    return run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                    "-Command", script], timeout=timeout)


def desktop_dir() -> Path:
    if IS_WINDOWS:
        rc, out, _ = _ps("[Environment]::GetFolderPath('Desktop')")
        if rc == 0 and out.strip():
            return Path(out.strip())
    return user_home() / "Desktop"


def start_menu_dir() -> Path:
    if IS_WINDOWS:
        rc, out, _ = _ps("[Environment]::GetFolderPath('Programs')")
        if rc == 0 and out.strip():
            return Path(out.strip()) / APP
        return (Path(os.environ.get("APPDATA", str(user_home() / "AppData" / "Roaming")))
                / "Microsoft" / "Windows" / "Start Menu" / "Programs" / APP)
    return user_home() / ".local" / "share" / "applications"


def _create_windows_shortcut(target: Path, link: Path, args: str = "", desc: str = APP) -> bool:
    link.parent.mkdir(parents=True, exist_ok=True)
    def q(x: str) -> str:
        return str(x).replace("'", "''")
    script = (
        "$w=New-Object -ComObject WScript.Shell;"
        f"$s=$w.CreateShortcut('{q(link)}');"
        f"$s.TargetPath='{q(target)}';$s.Arguments='{q(args)}';"
        f"$s.WorkingDirectory='{q(target.parent)}';$s.Description='{q(desc)}';"
        f"$s.IconLocation='{q(target)},0';$s.Save()"
    )
    rc, _, _ = _ps(script)
    return rc == 0


@dataclass
class InstallResult:
    exe: Path
    desktop_shortcut: Path | None = None
    startmenu_shortcut: Path | None = None
    defender: str | None = None
    notes: list[str] = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.notes is None:
            self.notes = []


def install(dest_dir: Path | None = None, *, desktop: bool = True, start_menu: bool = True,
            exclude_defender: bool = True) -> InstallResult:
    """Copy the running exe into ``dest_dir`` and set up shortcuts / exclusion."""
    if not is_frozen():
        raise RuntimeError("소스 체크아웃에서는 설치할 수 없습니다. 릴리스의 단일 실행 파일로 실행하세요.")
    src = Path(sys.executable).resolve()
    dest_dir = (dest_dir or default_install_dir()).expanduser()
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / installed_name()

    if target.resolve() == src:
        raise RuntimeError(f"이미 {target} 에서 실행 중입니다.")
    # replace an existing install (keep a .old if it is somehow locked)
    if target.exists():
        try:
            target.unlink()
        except OSError:
            backup = target.with_name(target.name + ".old")
            backup.unlink(missing_ok=True)
            os.replace(target, backup)
    shutil.copyfile(src, target)
    if not IS_WINDOWS:
        mode = os.stat(target).st_mode
        os.chmod(target, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        _strip_quarantine(target)

    res = InstallResult(exe=target)

    if IS_WINDOWS:
        if desktop:
            lnk = desktop_dir() / f"{APP}.lnk"
            if _create_windows_shortcut(target, lnk):
                res.desktop_shortcut = lnk
        if start_menu:
            lnk = start_menu_dir() / f"{APP}.lnk"
            if _create_windows_shortcut(target, lnk):
                res.startmenu_shortcut = lnk
    elif IS_MACOS:
        # a command-line binary: offer a stable path on PATH if ~/.local/bin exists or is wanted
        res.notes.append(f"터미널에서 쓰려면 PATH 에 추가하세요: export PATH=\"{dest_dir}:$PATH\"")

    if exclude_defender and IS_WINDOWS:
        from . import defender
        # exclude the INSTALLED exe, not the one we were launched from
        import types
        try:
            orig = sys.executable
            sys.executable = str(target)      # defender.exe_path() reads sys.executable
            res.defender = defender.add_exclusions()
        except Exception as e:  # noqa: BLE001
            res.defender = f"(예외 등록 실패: {e})"
        finally:
            sys.executable = orig

    return res


def uninstall(dest_dir: Path | None = None) -> list[str]:
    dest_dir = (dest_dir or default_install_dir()).expanduser()
    removed: list[str] = []
    for lnk in (desktop_dir() / f"{APP}.lnk", start_menu_dir() / f"{APP}.lnk"):
        if lnk.exists():
            try:
                lnk.unlink()
                removed.append(str(lnk))
            except OSError:
                pass
    sm = start_menu_dir()
    if sm.exists() and sm.name == APP:
        try:
            sm.rmdir()
        except OSError:
            pass
    if IS_WINDOWS:
        from . import defender
        try:
            import types
            orig = sys.executable
            sys.executable = str(dest_dir / installed_name())
            defender.remove_exclusions()
            removed.append("Defender 예외")
        except Exception:  # noqa: BLE001
            pass
        finally:
            sys.executable = orig
    target = dest_dir / installed_name()
    if target.exists() and target.resolve() != Path(sys.executable).resolve():
        try:
            target.unlink()
            removed.append(str(target))
        except OSError:
            removed.append(f"(실행 중이라 {target} 삭제 실패 - 종료 후 폴더를 지우세요)")
    return removed


def _strip_quarantine(path: Path) -> None:
    if IS_MACOS:
        import subprocess
        subprocess.call(["xattr", "-d", "com.apple.quarantine", str(path)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
