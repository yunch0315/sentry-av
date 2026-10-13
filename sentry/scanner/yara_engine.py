"""Optional YARA support (only active when yara-python is installed)."""
from __future__ import annotations

import logging
from pathlib import Path

from ..utils import app_dir, resource_dir

_LOG = logging.getLogger("sentry.yara")

try:
    import yara  # type: ignore
except Exception:  # noqa: BLE001
    yara = None


class YaraEngine:
    def __init__(self) -> None:
        self.rules = None
        if yara is None:
            return
        files = {}
        for i, p in enumerate([resource_dir() / "rules.yar", *sorted(app_dir().glob("rules*.yar"))]):
            if Path(p).exists():
                files[f"ns{i}"] = str(p)
        if not files:
            return
        try:
            self.rules = yara.compile(filepaths=files)
            _LOG.debug("yara: compiled %d rule files", len(files))
        except Exception as e:  # noqa: BLE001
            _LOG.warning("yara compile failed: %s", e)

    @property
    def available(self) -> bool:
        return self.rules is not None

    def match(self, path: str) -> list[tuple[str, str]]:
        """Return [(rule_name, severity)]."""
        if not self.rules:
            return []
        try:
            out = []
            for m in self.rules.match(path, timeout=10):
                out.append((m.rule, str(m.meta.get("severity", "medium"))))
            return out
        except Exception as e:  # noqa: BLE001
            _LOG.debug("yara match error on %s: %s", path, e)
            return []
