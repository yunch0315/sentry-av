@echo off
REM Build a standalone single-file sentry.exe for Windows with PyInstaller (run this ON Windows).
REM Result: dist\sentry.exe  (copy to any Windows PC; no Python needed there; right-click > Run as administrator or just run - it asks for UAC)
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  py -3 -m venv .venv || python -m venv .venv
  .venv\Scripts\pip install -q -r requirements.txt
)
.venv\Scripts\pip install -q pyinstaller
.venv\Scripts\pyinstaller --noconfirm --clean --onefile --noupx --name sentry ^
  --add-data "sentry\signatures;sentry\signatures" ^
  --hidden-import sentry.realtime --hidden-import sentry.scanner ^
  --collect-submodules sentry ^
  --uac-admin ^
  sentry_main.py
echo built: %cd%\dist\sentry.exe
