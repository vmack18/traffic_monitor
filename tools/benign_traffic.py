#!/usr/bin/env python3
"""
Traffic Guard - benign traffic generator
========================================

Generates realistic, well-behaved HTTP traffic so the dashboard shows a live
baseline (and to prove that clean traffic is NOT blocked by the inline gate).

  python3 benign_traffic.py --host 127.0.0.1 --port 8080 --rps 5 --duration 60

All requests use normal browser User-Agents and safe paths, so the detection
engine should classify every one as "allow".
"""
from __future__ import annotations

import argparse
import random
import socket
import time

PATHS = [
    "/", "/health", "/api/data", "/index.html", "/about", "/products?page=2",
    "/api/items?limit=20", "/api/items?limit=50&sort=name", "/search?q=shoes",
    "/cart", "/api/cart", "/static/app.css", "/static/app.js",
]
UAS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like "
    "Gecko) Chrome/121.0 Safari/537.36 Edg/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


def request(host: str, port: int, path: str, timeout: float = 4.0) -> int | None:
    ua = random.choice(UAS)
    raw = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"User-Agent: {ua}\r\n"
        "Accept: text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Connection: close\r\n\r\n"
    ).encode("iso-8859-1")
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(raw)
            data = s.recv(1024)
        if not data:
            return None
        first = data.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
        parts = first.split(" ")
        return int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Benign HTTP traffic generator")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--rps", type=float, default=3.0, help="requests per second")
    ap.add_argument("--duration", type=float, default=30.0, help="seconds (0=forever)")
    args = ap.parse_args()

    interval = 1.0 / max(args.rps, 0.01)
    print(f"[benign] {args.rps} req/s -> {args.host}:{args.port} "
          f"for {args.duration or 'inf'}s")
    t0 = time.time()
    sent = ok = blocked = err = 0
    while args.duration <= 0 or time.time() - t0 < args.duration:
        path = random.choice(PATHS)
        status = request(args.host, args.port, path)
        sent += 1
        if status is None:
            err += 1
        elif status < 400:
            ok += 1
        elif status in (403, 429):
            blocked += 1
        time.sleep(interval * random.uniform(0.6, 1.4))
    print(f"[benign] sent={sent} ok={ok} blocked={blocked} errors={err}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
