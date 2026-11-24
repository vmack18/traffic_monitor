#!/usr/bin/env bash
set -e

# Store the root project directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"

# Array to track background PIDs
PIDS=()

# Cleanup function to terminate all background processes on exit
cleanup() {
    echo ""
    echo "Shutting down all services..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait
    echo "All services stopped."
}

# Trap SIGINT (Ctrl+C) and SIGTERM to trigger cleanup
trap cleanup SIGINT SIGTERM EXIT

echo "=== 0. Setting up Python Virtual Environment ==="
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"

echo "=== 1. Setting up & starting Monitoring Backend (Port 8000) ==="
cd "$ROOT_DIR/laptop2-monitor/backend"
pip install -q -r requirements.txt
pip install -q websockets
uvicorn main:app --host 0.0.0.0 --port 8000 &
PIDS+=($!)

echo "=== 2. Starting Protected Server (Port 9000) ==="
cd "$ROOT_DIR/laptop1-server"
python protected_server.py --port 9000 &
PIDS+=($!)

echo "=== 3. Starting Detection Proxy (Port 8080 -> 9000) ==="
cd "$ROOT_DIR/laptop1-server"
python detection_proxy.py --listen-port 8080 --upstream-port 9000 --monitor-url http://127.0.0.1:8000 &
PIDS+=($!)

echo "=== 4. Setting up & starting Dashboard (Port 3000) ==="
cd "$ROOT_DIR/laptop2-monitor/frontend"
npm install --silent
npm run build
PORT=3000 BACKEND_URL=http://127.0.0.1:8000 node dist/server.js &
PIDS+=($!)

echo ""
echo "=========================================="
echo "All services are running!"
echo "- Monitoring Backend: http://127.0.0.1:8000"
echo "- Protected Server:   http://127.0.0.1:9000"
echo "- Detection Proxy:    http://127.0.0.1:8080"
echo "- Dashboard:          http://127.0.0.1:3000"
echo "Press Ctrl+C to stop all services."
echo "=========================================="

# Wait for all background processes
wait