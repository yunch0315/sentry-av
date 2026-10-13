#!/bin/sh
# Build the Windows sentry.exe *on macOS* using Wine + the official Windows Python.
#   Requirements: Homebrew `wine-stable` cask (Rosetta on Apple Silicon), internet on first run.
#   Result: dist/sentry.exe  (same output as build.bat on a real Windows PC)
set -e
cd "$(dirname "$0")" || exit 1
PYVER="${PYVER:-3.12.10}"
export WINEPREFIX="${WINEPREFIX:-$HOME/.sentry-av/wine-build}"
export WINEDEBUG=-all
export WINEDLLOVERRIDES="mscoree,mshtml="   # no Mono / Gecko download prompts
WINE="${WINE:-$(command -v wine || command -v wine64 || echo "/Applications/Wine Stable.app/Contents/Resources/wine/bin/wine")}"
[ -x "$WINE" ] || { echo "wine not found - install with: brew install --cask wine-stable"; exit 1; }

PY="$WINEPREFIX/drive_c/Python/python.exe"
if [ ! -f "$PY" ]; then
  mkdir -p "$WINEPREFIX"
  INST="${INSTALLER:-/tmp/python-$PYVER-amd64.exe}"
  if [ ! -f "$INST" ]; then
    echo "downloading Windows Python $PYVER ..."
    curl -sSL -o "$INST" "https://www.python.org/ftp/python/$PYVER/python-$PYVER-amd64.exe"
  fi
  echo "installing Windows Python into the Wine prefix ($WINEPREFIX) ..."
  "$WINE" "$INST" /quiet InstallAllUsers=0 TargetDir='C:\Python' Include_test=0 Include_doc=0 \
      Include_launcher=0 Include_tcltk=0 PrependPath=0 Shortcuts=0 AssociateFiles=0
  [ -f "$PY" ] || { echo "Windows Python install failed"; exit 1; }
fi

echo "installing build dependencies ..."
"$WINE" "$PY" -m pip install -q --upgrade pip
"$WINE" "$PY" -m pip install -q -r requirements.txt pyinstaller

echo "building sentry.exe ..."
rm -rf build/win dist/sentry.exe
"$WINE" "$PY" -m PyInstaller --noconfirm --clean --onefile --name sentry \
  --distpath dist --workpath build/win --specpath build/win \
  --add-data "$(pwd)/sentry/signatures;sentry/signatures" \
  --hidden-import sentry.realtime --hidden-import sentry.scanner \
  --collect-submodules sentry \
  --uac-admin \
  sentry_main.py
ls -la dist/sentry.exe && echo "built: $(pwd)/dist/sentry.exe"
