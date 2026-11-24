#!/usr/bin/env bash
# Start the LAPTOP 2 monitoring backend.
#
#   ./run.sh                 # proxy-only mode, port 8000
#   TG_SNIFFER=1 sudo ./run.sh   # also sniff packets (needs root + scapy)
#   TG_DEMO=1 ./run.sh       # synthetic baseline traffic for UI testing
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ ! -d .venv ]]; then
  echo "[+] creating virtualenv..."
  python3 -m venv .venv
  ./.venv/bin/pip install --quiet --upgrade pip
  ./.venv/bin/pip install --quiet -r requirements.txt
fi

export TG_HOST="${TG_HOST:-0.0.0.0}"
export TG_PORT="${TG_PORT:-8000}"
exec ./.venv/bin/uvicorn main:app --host "$TG_HOST" --port "$TG_PORT" --log-level info
