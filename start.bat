@echo off
REM WebStrike 1-Click Launcher for Windows
cd /d "%~dp0"

echo ==================================================
echo   WebStrike - Attack Surface Engine (Windows)
echo ==================================================

if not exist ".venv\Scripts\python.exe" (
    echo [1/3] Creating Python virtual environment (.venv)...
    python -m venv .venv
    echo [2/3] Installing dependencies...
    .venv\Scripts\python.exe -m pip install --upgrade pip -q
    .venv\Scripts\pip.exe install -r requirements.txt
    echo [3/3] Installing Playwright Chromium browser...
    .venv\Scripts\playwright.exe install chromium
)

echo Starting WebStrike on http://127.0.0.1:8777 ...
start "" http://127.0.0.1:8777
.venv\Scripts\python.exe run.py web --host 127.0.0.1 --port 8777
pause
