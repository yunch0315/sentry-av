"""Run with the highest available privilege (Administrator on Windows, root on macOS/Linux)."""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys

from .utils import IS_MACOS, IS_WINDOWS, self_command


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return False
    return os.geteuid() == 0


def ensure_admin(argv: list[str] | None = None, *, use_sudo: bool = False) -> None:
    """Re-launch the current command elevated and exit; no-op if already elevated.

    Windows: always asks for Administrator via UAC (no password typing).
    macOS/Linux: never asks for a password unless ``use_sudo`` is set (``--sudo``);
    otherwise it continues as the current user.
    """
    if is_admin():
        return
    argv = list(argv if argv is not None else sys.argv[1:])
    if "--no-elevate" not in argv:
        argv.append("--no-elevate")
    py, *module_args = self_command()
    module_args = [*module_args, *argv]

    if IS_WINDOWS:
        params = " ".join(_win_quote(a) for a in module_args)
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", py, params, os.getcwd(), 1)  # type: ignore[attr-defined]
        if rc <= 32:
            print("관리자 권한 상승이 거부되었습니다. 제한된 권한으로 계속합니다.", file=sys.stderr)
            return
        sys.exit(0)

    if not use_sudo:
        # No password prompt on macOS/Linux: run as the current user.
        _continue_unprivileged(quiet=True)
        return

    env = dict(os.environ)
    env.setdefault("SENTRY_HOME", os.path.expanduser("~"))
    cmd = [py, *module_args]
    if sys.stdin.isatty() and shutil.which("sudo"):
        print("루트 권한을 요청합니다 (--sudo). 본인 로그인 암호를 입력하세요 (입력 중 글자는 보이지 않습니다).\n"
              "암호 없이 현재 사용자 권한으로 계속하려면 Ctrl+C 를 누르세요.", file=sys.stderr)
        try:
            ok = subprocess.call(["sudo", "-v", "-p", "암호: "]) == 0
        except KeyboardInterrupt:
            ok = False
        if ok:
            rc = subprocess.call(["sudo", "-E", "env", f"SENTRY_HOME={env['SENTRY_HOME']}", *cmd], env=env)
            sys.exit(rc)
        _continue_unprivileged()
        return
    if IS_MACOS:
        # GUI prompt when there is no terminal (e.g. launched by double-click)
        shell_cmd = " ".join(_sh_quote(a) for a in ["env", f"SENTRY_HOME={env['SENTRY_HOME']}", *cmd])
        script = f'do shell script "{shell_cmd}" with administrator privileges'
        r = subprocess.run(["osascript", "-e", script], stderr=subprocess.PIPE, text=True)
        if r.returncode != 0 and ("-128" in r.stderr or "canceled" in r.stderr.lower()):
            _continue_unprivileged()
            return
        sys.exit(r.returncode)
    _continue_unprivileged()


def _continue_unprivileged(quiet: bool = False) -> None:
    if quiet:
        return
    print("루트 권한 없이 현재 사용자 권한으로 계속합니다. 내 계정이 실행한 프로세스와 내 파일은 모두 보호되며,\n"
          "다른 사용자/시스템 프로세스의 제어와 시스템 전역 서비스 등록만 제한됩니다.", file=sys.stderr)


def _win_quote(a: str) -> str:
    return f'"{a}"' if (" " in a or not a) else a


def _sh_quote(a: str) -> str:
    return "'" + a.replace("'", "'\\''") + "'"


def run_elevated_and_wait(args: list[str], timeout_s: float = 120.0) -> int | None:
    """Windows: launch ``args`` with a UAC prompt (ShellExecuteEx 'runas') and wait for it.

    Returns the child's exit code, None if the user declined UAC or on error.  Used for a
    one-off admin action (Defender exclusion) without elevating the whole program."""
    if not IS_WINDOWS:
        return None
    import ctypes.wintypes as wt

    class SHELLEXECUTEINFO(ctypes.Structure):
        _fields_ = [("cbSize", wt.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wt.HWND),
                    ("lpVerb", wt.LPCWSTR), ("lpFile", wt.LPCWSTR), ("lpParameters", wt.LPCWSTR),
                    ("lpDirectory", wt.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wt.HINSTANCE),
                    ("lpIDList", ctypes.c_void_p), ("lpClass", wt.LPCWSTR), ("hkeyClass", wt.HKEY),
                    ("dwHotKey", wt.DWORD), ("hIcon", wt.HANDLE), ("hProcess", wt.HANDLE)]

    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    SEE_MASK_NO_CONSOLE = 0x00008000
    exe, *rest = args
    params = " ".join(_win_quote(a) for a in rest)
    sei = SHELLEXECUTEINFO()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE
    sei.lpVerb = "runas"
    sei.lpFile = exe
    sei.lpParameters = params
    sei.nShow = 1
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)) or not sei.hProcess:
        return None  # user declined UAC or launch failed
    try:
        ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, int(timeout_s * 1000))
        code = wt.DWORD()
        ctypes.windll.kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(code))
        return int(code.value)
    finally:
        ctypes.windll.kernel32.CloseHandle(sei.hProcess)
