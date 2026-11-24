#!/usr/bin/env python3
"""
protected_server.py
===================
LAPTOP 1  (Ubuntu Server VM inside VirtualBox)  --  the PROTECTED TARGET.

A small HTTP/1.1 server written directly on top of Python asyncio sockets
(no web framework) so that the whole exercise stays "socket programming".

IMPORTANT: this server is NEVER exposed directly to clients.  It binds to
127.0.0.1:9000 and only accepts connections coming from the inline detection
proxy (detection_proxy.py).  Every client request therefore has to pass
through the detection stage first:

    client  ->  detection_proxy :8080  ->  protected_server :9000

Endpoints
---------
GET  /                -> landing page (HTML)
GET  /health          -> liveness probe (JSON)
GET  /api/data        -> sample business payload (JSON)
POST /login           -> fake login endpoint (JSON)
POST /upload          -> accepts a body, echoes its size (JSON)
*                     -> 404

Run:
    python3 protected_server.py --host 127.0.0.1 --port 9000
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import time
from datetime import datetime, timezone
from pathlib import Path

LOG = logging.getLogger("protected-server")

MAX_HEADER_BYTES = 64 * 1024
MAX_BODY_BYTES = 4 * 1024 * 1024
KEEPALIVE_TIMEOUT = 15.0

START_TS = time.time()
COUNTERS = {
    "connections": 0,
    "requests": 0,
    "bytes_in": 0,
    "bytes_out": 0,
    "errors": 0,
}

LANDING_PAGE = b"""<!doctype html>
<html><head><meta charset="utf-8"><title>Protected Origin Server</title>
<style>body{font-family:system-ui,sans-serif;background:#0b1020;color:#e6edf7;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#141a2e;padding:40px 56px;border-radius:16px;border:1px solid #26304d;
box-shadow:0 20px 60px rgba(0,0,0,.5)}h1{margin:0 0 8px;font-size:24px}
p{color:#8ea0c0;margin:4px 0}.ok{color:#3ddc97;font-weight:600}</style></head>
<body><div class="card"><h1>Protected Origin Server</h1>
<p class="ok">&#9679; online &mdash; reachable only through the detection proxy</p>
<p>Host: Ubuntu Server 22.04 (VirtualBox) &middot; Port: 9000</p>
<p>Requests served: <span id="n">0</span></p></div>
<script>fetch('/health').then(r=>r.json()).then(d=>{document.getElementById('n').textContent=d.requests})</script>
</body></html>"""


def _json(payload: dict, status: int = 200) -> bytes:
    body = json.dumps(payload, indent=2).encode()
    reason = {200: "OK", 400: "Bad Request", 401: "Unauthorized",
              404: "Not Found", 405: "Method Not Allowed",
              413: "Payload Too Large"}.get(status, "OK")
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Server: ProtectedOrigin/1.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    return head + body


def _html(body: bytes, status: int = 200) -> bytes:
    reason = "OK" if status == 200 else "Error"
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Server: ProtectedOrigin/1.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    return head + body


class Request:
    __slots__ = ("method", "path", "version", "headers", "body", "raw_size")

    def __init__(self, method, path, version, headers, body, raw_size):
        self.method = method
        self.path = path
        self.version = version
        self.headers = headers
        self.body = body
        self.raw_size = raw_size


async def read_request(reader: asyncio.StreamReader) -> Request | None:
    """Read one HTTP request (head + body) from the socket."""
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=KEEPALIVE_TIMEOUT)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
        return None
    if len(head) > MAX_HEADER_BYTES:
        return None

    try:
        text = head.decode("iso-8859-1")
        lines = text.split("\r\n")
        method, path, version = lines[0].split(" ", 2)
    except Exception:
        return None

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()

    length = int(headers.get("content-length", "0") or 0)
    if length > MAX_BODY_BYTES:
        return None
    body = b""
    if length:
        try:
            body = await asyncio.wait_for(reader.readexactly(length), timeout=KEEPALIVE_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return None
    return Request(method, path, version, headers, body, len(head) + len(body))


def route(req: Request) -> bytes:
    path = req.path.split("?")[0]

    if req.method == "GET" and path in ("/", "/index.html"):
        return _html(LANDING_PAGE)

    if req.method == "GET" and path == "/health":
        return _json({
            "status": "ok",
            "service": "protected-origin",
            "uptime_seconds": round(time.time() - START_TS, 1),
            "requests": COUNTERS["requests"],
            "connections": COUNTERS["connections"],
            "bytes_in": COUNTERS["bytes_in"],
            "bytes_out": COUNTERS["bytes_out"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    if req.method == "GET" and path == "/api/data":
        return _json({
            "records": [
                {"id": 1, "customer": "ACME Corp", "revenue": 18450.00, "region": "EU"},
                {"id": 2, "customer": "Globex", "revenue": 9275.50, "region": "NA"},
                {"id": 3, "customer": "Initech", "revenue": 33110.75, "region": "APAC"},
            ],
            "served_by": "protected-origin",
        })

    if req.method == "POST" and path == "/login":
        try:
            payload = json.loads(req.body or b"{}")
        except Exception:
            return _json({"error": "invalid json"}, 400)
        user = str(payload.get("username", ""))
        # Deliberately simple: this endpoint exists so the detector has
        # something realistic to protect (credential stuffing, SQLi in body).
        if user.lower() in ("admin", "root") and payload.get("password") == "admin123":
            return _json({"authenticated": True, "token": "demo-token-abc123", "user": user})
        return _json({"authenticated": False, "error": "invalid credentials"}, 401)

    if req.method == "POST" and path == "/upload":
        return _json({"received_bytes": len(req.body), "stored": False,
                      "note": "demo endpoint - payload scanned by detection proxy"})

    return _json({"error": "not found", "path": path}, 404)


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    COUNTERS["connections"] += 1
    try:
        while True:
            req = await read_request(reader)
            if req is None:
                break
            COUNTERS["requests"] += 1
            COUNTERS["bytes_in"] += req.raw_size
            LOG.info("%s %s %s from %s (%d bytes)", req.method, req.path,
                     req.version, peer[0] if peer else "?", req.raw_size)
            response = route(req)
            COUNTERS["bytes_out"] += len(response)
            writer.write(response)
            await writer.drain()
            # Every response carries "Connection: close", so serve exactly one
            # request per TCP connection and let the peer see a clean EOF.
            break
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    except Exception as exc:  # pragma: no cover
        COUNTERS["errors"] += 1
        LOG.warning("error handling %s: %s", peer, exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main_async(host: str, port: int) -> None:
    server = await asyncio.start_server(handle_client, host, port, backlog=512)
    LOG.info("protected origin server listening on %s:%d", host, port)
    async with server:
        await server.serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser(description="Protected origin server (Laptop 1)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--log-file", default="")
    args = ap.parse_args()

    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if args.log_file:
        Path(args.log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
                        handlers=handlers)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, loop.stop)
        except NotImplementedError:
            pass
    try:
        loop.run_until_complete(main_async(args.host, args.port))
    except (KeyboardInterrupt, RuntimeError):
        pass
    finally:
        LOG.info("protected origin server stopped")


if __name__ == "__main__":
    main()
