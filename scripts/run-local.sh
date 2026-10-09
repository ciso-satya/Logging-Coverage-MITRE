#!/usr/bin/env bash
# One-shot local deployment: installs dependencies (first run), builds the UI and starts the server.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${LCM_PORT:-8000}"

if [ ! -x backend/.venv/bin/python ]; then
  echo "▸ Creating Python virtualenv"
  python3 -m venv backend/.venv
  backend/.venv/bin/pip install --quiet --upgrade pip
  backend/.venv/bin/pip install --quiet -r backend/requirements.txt
fi
if [ ! -d frontend/node_modules ]; then
  echo "▸ Installing frontend dependencies"
  (cd frontend && npm install --no-audit --no-fund)
fi
echo "▸ Building frontend"
(cd frontend && npm run build)

echo "▸ Starting ATT&CK Logging Coverage on http://localhost:${PORT}"
echo "  (first start downloads the ~50 MB ATT&CK STIX bundle from MITRE)"
if command -v xdg-open >/dev/null 2>&1; then (sleep 6 && xdg-open "http://localhost:${PORT}" >/dev/null 2>&1 || true) &
elif command -v open >/dev/null 2>&1; then (sleep 6 && open "http://localhost:${PORT}" || true) &
fi
cd backend && exec ./.venv/bin/python -m uvicorn app.main:app --host "${LCM_HOST:-0.0.0.0}" --port "${PORT}"
