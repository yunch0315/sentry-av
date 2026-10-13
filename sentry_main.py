"""PyInstaller entry point (relative imports in sentry/__main__.py do not work as a script)."""
from sentry.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
