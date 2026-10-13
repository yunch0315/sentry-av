#!/bin/sh
# macOS / Linux launcher: creates venv on first run, then forwards args to sentry.
cd "$(dirname "$0")" || exit 1
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt
fi
exec .venv/bin/python -m sentry "$@"
