@echo off
REM Windows launcher: creates venv on first run, then forwards args to sentry (auto-elevates via UAC).
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  py -3 -m venv .venv || python -m venv .venv
  .venv\Scripts\pip install -q -r requirements.txt
)
.venv\Scripts\python -m sentry %*
