"""Windows Defender exclusions for Sentry-AV (Windows only, always explicit / opt-in).

Sentry-AV is an unsigned executable that replaces itself when it updates - a pattern
Microsoft Defender's behaviour engine can mistake for a self-replicating threat and delete.
Until the binary is code-signed, a precise exclusion is the local workaround.

Deliberately NARROW: we exclude the *specific exe file* and the running *process name*,
plus the dedicated data folder (~/.sentry-av).  We never exclude the exe's parent folder,
because that is often Downloads/Desktop - exactly where real malware lands.
"""
from __future__ import annotations

import sys
from pathlib import Path

from .utils import IS_WINDOWS, app_dir, run_cmd, user_home

# Folders that must never be handed to Defender as an exclusion.
def _broad_dirs() -> set[str]:
    h = user_home()
    names = ["Downloads", "Desktop", "Documents", "Pictures", "Music", "Videos", "Movies", "OneDrive"]
    out = {str(h).lower()} | {str(h / n).lower() for n in names}
    out |= {"c:\\", "c:\\program files", "c:\\program files (x86)", "c:\\windows",
            "c:\\windows\\system32", "c:\\users", "c:\\users\\public"}
    return out


def exe_path() -> Path:
    return Path(sys.executable).resolve()


def data_dir() -> Path:
    return app_dir()


def install_dir() -> Path:
    return exe_path().parent


def install_dir_is_broad() -> bool:
    return str(install_dir()).rstrip("\\").lower() in _broad_dirs()


def exclusion_paths() -> list[str]:
    """File-level, not folder-level: the exact exe plus the dedicated data folder."""
    return [str(exe_path()), str(data_dir())]


def exclusion_process() -> str:
    return exe_path().name


def _ps(script: str, timeout: float = 60.0) -> tuple[int, str, str]:
    return run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                    "-Command", script], timeout=timeout)


def current_exclusions() -> dict[str, list[str]]:
    if not IS_WINDOWS:
        return {"paths": [], "processes": []}
    rc, out, _ = _ps("$p=Get-MpPreference; "
                     "($p.ExclusionPath -join \"`n\") + \"`n---`n\" + ($p.ExclusionProcess -join \"`n\")")
    if rc != 0:
        return {"paths": [], "processes": []}
    parts = out.split("---")
    paths = [l.strip() for l in parts[0].splitlines() if l.strip()]
    procs = [l.strip() for l in parts[1].splitlines() if l.strip()] if len(parts) > 1 else []
    return {"paths": paths, "processes": procs}


def status() -> dict:
    cur = current_exclusions()
    pset = {p.lower().rstrip("\\") for p in cur["paths"]}
    proc_set = {p.lower() for p in cur["processes"]}
    st = {p: (p.lower().rstrip("\\") in pset) for p in exclusion_paths()}
    st[f"process:{exclusion_process()}"] = exclusion_process().lower() in proc_set
    return st


def add_exclusions() -> str:
    if not IS_WINDOWS:
        return "Windows Defender 예외는 Windows 에서만 등록할 수 있습니다."
    if install_dir_is_broad():
        raise RuntimeError(
            f"실행 파일이 공용 폴더에 있습니다: {install_dir()}\n"
            "다운로드·바탕화면 같은 폴더는 Defender 예외로 두면 위험합니다. "
            "exe 를 전용 폴더(예: C:\\Sentry-AV)로 옮긴 뒤 다시 시도하세요. "
            "(파일 하나만 예외로 넣지만, 그 폴더에 두면 매 업데이트가 같은 위험 폴더에서 실행됩니다.)")
    paths = ", ".join(f"'{p}'" for p in exclusion_paths())
    rc, out, err = _ps(f"Add-MpPreference -ExclusionPath {paths}; "
                       f"Add-MpPreference -ExclusionProcess '{exclusion_process()}'")
    if rc != 0:
        raise RuntimeError((err or out).strip() or f"Add-MpPreference 실패 (rc={rc}); 관리자 권한이 필요합니다")
    return ("Windows Defender 예외에 등록했습니다:\n  파일 " + "\n  파일 ".join(exclusion_paths())
            + f"\n  프로세스 {exclusion_process()}")


def remove_exclusions() -> str:
    if not IS_WINDOWS:
        return "Windows Defender 예외는 Windows 에서만 다룰 수 있습니다."
    paths = ", ".join(f"'{p}'" for p in exclusion_paths())
    rc, out, err = _ps(f"Remove-MpPreference -ExclusionPath {paths}; "
                       f"Remove-MpPreference -ExclusionProcess '{exclusion_process()}'")
    if rc != 0:
        raise RuntimeError((err or out).strip() or f"Remove-MpPreference 실패 (rc={rc})")
    return "Windows Defender 예외에서 제거했습니다."
