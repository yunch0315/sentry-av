#!/bin/sh
# Cut a release: bump the version, commit, tag and push.  GitHub Actions (release.yml)
# then builds the Windows/macOS binaries and publishes them; installed copies pick the
# new version up through `sentry upgrade` or the monitor's auto-update.
#   ./release.sh 0.2.0
set -e
cd "$(dirname "$0")"
v="$1"
case "$v" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "usage: $0 <major.minor.patch>" >&2; exit 2 ;;
esac
[ -z "$(git status --porcelain)" ] || { echo "working tree not clean" >&2; exit 1; }
sed -i '' "s/^__version__ = .*/__version__ = \"$v\"/" sentry/__init__.py
sed -i '' "s/^version = .*/version = \"$v\"/" pyproject.toml
.venv/bin/python -m pytest -q
git add sentry/__init__.py pyproject.toml
git commit -m "Release v$v"
git tag -a "v$v" -m "Sentry-AV v$v"
git push origin main "v$v"
echo "pushed v$v - watch: gh run watch --repo yunch0315/sentry-av"
