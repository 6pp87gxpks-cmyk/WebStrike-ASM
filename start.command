#!/bin/zsh
# WebStrike 1-Click Launcher for macOS and Linux
set -e
cd "$(dirname "$0")"

echo "=================================================="
echo "  WebStrike — Attack Surface Engine (macOS/Linux)       "
echo "=================================================="

if [ ! -x ".venv/bin/python" ]; then
  echo "[1/3] Creating Python virtual environment (.venv)..."
  python3 -m venv .venv
  echo "[2/3] Installing dependencies..."
  .venv/bin/pip install --upgrade pip -q
  .venv/bin/pip install -r requirements.txt
  echo "[3/3] Installing Playwright Chromium browser..."
  .venv/bin/playwright install chromium || true
fi

echo "Starting WebStrike on http://127.0.0.1:8777 ..."
(sleep 1.5 && open "http://127.0.0.1:8777") &
exec .venv/bin/python run.py web --host 127.0.0.1 --port 8777
