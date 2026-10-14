"""Windows Defender helpers (Windows only, always explicit / opt-in).

Sentry-AV is an unsigned executable that kills processes, quarantines files and replaces
itself when it updates - behaviour that Microsoft Defender's heuristics can mistake for
malware, deleting the freshly updated exe.  Until the binary carries a code-signing
certificate, the reliable local fix is an exclusion for the install folder and the data
folder.  Nothing here runs automatically: the user is asked, and `sentry defender status`
shows exactly what is excluded.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from .utils import IS_WINDOWS, app_dir, run_cmd


def install_dir() -> Path:
    return Path(sys.executable).resolve().parent


def exclusion_paths() -> list[str]:
    return [str(install_dir()), str(app_dir())]


def _ps(script: str, timeout: float = 60.0) -> tuple[int, str, str]:
    return run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                    "-Command", script], timeout=timeout)


def current_exclusions() -> list[str]:
    if not IS_WINDOWS:
        return []
    rc, out, _ = _ps("(Get-MpPreference).ExclusionPath -join \"`n\"")
    return [l.strip() for l in out.splitlines() if l.strip()] if rc == 0 else []


def status() -> dict:
    cur = {p.lower().rstrip("\\") for p in current_exclusions()}
    return {p: (p.lower().rstrip("\\") in cur) for p in exclusion_paths()}


def add_exclusions() -> str:
    if not IS_WINDOWS:
        return "Windows Defender 예외는 Windows 에서만 등록할 수 있습니다."
    paths = ", ".join(f"'{p}'" for p in exclusion_paths())
    rc, out, err = _ps(f"Add-MpPreference -ExclusionPath {paths}")
    if rc != 0:
        raise RuntimeError((err or out).strip() or f"Add-MpPreference failed (rc={rc}); 관리자 권한이 필요합니다")
    return "Windows Defender 예외에 등록했습니다: " + "; ".join(exclusion_paths())


def remove_exclusions() -> str:
    if not IS_WINDOWS:
        return "Windows Defender 예외는 Windows 에서만 다룰 수 있습니다."
    paths = ", ".join(f"'{p}'" for p in exclusion_paths())
    rc, out, err = _ps(f"Remove-MpPreference -ExclusionPath {paths}")
    if rc != 0:
        raise RuntimeError((err or out).strip() or f"Remove-MpPreference failed (rc={rc})")
    return "Windows Defender 예외에서 제거했습니다: " + "; ".join(exclusion_paths())


def offer_exclusion_interactively(console) -> bool:
    """After an update was blocked: explain and ask (default No).  True when added."""
    if not IS_WINDOWS or not sys.stdin.isatty():
        return False
    console.print("[yellow]Windows Defender 가 새 실행 파일을 삭제한 것으로 보입니다.[/] "
                  "보호 기록에서 '허용' 해도 업데이트마다 새 파일이 다시 차단됩니다.\n"
                  "설치 폴더와 데이터 폴더를 Defender 예외에 등록하면 재발하지 않습니다:\n  "
                  + "\n  ".join(exclusion_paths()))
    try:
        ans = input("지금 예외로 등록할까요? (관리자 권한 필요) [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if ans not in ("y", "yes"):
        return False
    try:
        console.print(add_exclusions())
        return True
    except RuntimeError as e:
        console.print(f"[red]등록 실패:[/] {e}")
        return False
