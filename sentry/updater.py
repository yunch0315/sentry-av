"""Download hash feeds into ~/.sentry-av/hashes_extra.txt."""
from __future__ import annotations

import logging
import re
import urllib.request

from .utils import app_dir, now_iso, ssl_context

_LOG = logging.getLogger("sentry.updater")
_HEX64 = re.compile(r"\b([0-9a-fA-F]{64})\b")


def update_signatures(urls: list[str], timeout: float = 30.0) -> dict:
    out = app_dir() / "hashes_extra.txt"
    existing: set[str] = set()
    if out.exists():
        for line in out.read_text(encoding="utf-8", errors="replace").splitlines():
            m = _HEX64.search(line)
            if m:
                existing.add(m.group(1).lower())
    added = 0
    results = {}
    new_lines: list[str] = []
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sentry-av/0.1 (+hash-feed)"})
            with urllib.request.urlopen(req, timeout=timeout, context=ssl_context()) as r:
                body = r.read().decode("utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001
            results[url] = f"failed: {e}"
            _LOG.warning("feed %s failed: %s", url, e)
            continue
        n = 0
        for line in body.splitlines():
            if line.lstrip().startswith("#"):
                continue
            m = _HEX64.search(line)
            if not m:
                continue
            h = m.group(1).lower()
            if h in existing:
                continue
            existing.add(h)
            new_lines.append(f"{h} feed:{url.split('/')[2]}")
            n += 1
        results[url] = f"ok (+{n} hashes)"
        added += n
    if new_lines:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"# updated {now_iso()}\n")
            f.write("\n".join(new_lines) + "\n")
    return {"added": added, "total": len(existing), "file": str(out), "feeds": results}
