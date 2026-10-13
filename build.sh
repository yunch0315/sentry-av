#!/bin/sh
# Build a standalone single-file executable for THIS platform (macOS/Linux) with PyInstaller.
# Result: dist/sentry   (copy it to any machine with the same OS/CPU; no Python needed there)
cd "$(dirname "$0")" || exit 1
[ -x .venv/bin/python ] || { python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt; }
.venv/bin/pip install -q pyinstaller
.venv/bin/pyinstaller --noconfirm --clean --onefile --name sentry \
  --add-data "sentry/signatures:sentry/signatures" \
  --hidden-import sentry.realtime --hidden-import sentry.scanner \
  --collect-submodules sentry \
  sentry_main.py
echo "built: $(pwd)/dist/sentry"
