"""Console / JSON reporting."""
from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .utils import human_size, now_iso, platform_label

console = Console()
_COLORS = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "clean": "green"}


def print_findings(findings, stats, roots: list[str], show_low: bool = False, suppressed: int = 0) -> None:
    console.rule("[bold]Sentry-AV scan report")
    console.print(f"platform: {platform_label()}   paths: {', '.join(roots)}")
    extra = f", signed-and-intact files ignored={suppressed}" if suppressed else ""
    console.print(f"scanned {stats.files_scanned} files ({human_size(stats.bytes_scanned)}) in "
                  f"{stats.duration:.1f}s, errors={stats.errors}{extra}")
    if not findings:
        console.print("[bold green]No threats found.[/]")
        return
    shown = [f for f in findings if show_low or f.severity != "low"]
    hidden_low = len(findings) - len(shown)
    if shown:
        t = Table(show_lines=False, expand=True)
        t.add_column("severity", width=9)
        t.add_column("category", width=22)
        t.add_column("path", overflow="fold")
        t.add_column("reasons", overflow="fold")
        for f in shown:
            t.add_row(f"[{_COLORS.get(f.severity, '')}]{f.severity}[/]", f.category, f.path,
                      "; ".join(f.reasons))
        console.print(t)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    console.print("summary: " + ", ".join(f"[{_COLORS[k]}]{k}={v}[/]" for k, v in counts.items()))
    if hidden_low:
        console.print(f"[dim]low {hidden_low}건은 표에서 생략했습니다 (JSON 보고서에는 포함, --show-low 로 표시).[/]")


def write_json(findings, stats, roots: list[str], out: Path) -> None:
    data = {
        "time": now_iso(), "platform": platform_label(), "paths": roots,
        "stats": {"files_scanned": stats.files_scanned, "bytes_scanned": stats.bytes_scanned,
                  "errors": stats.errors, "duration_s": round(stats.duration, 2)},
        "findings": [f.to_dict() for f in findings],
    }
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
