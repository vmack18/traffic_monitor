#!/usr/bin/env python3
"""
Generate normal, realistic HTTP traffic for a small server.

Examples:
  python3 normal_traffic.py --rps 3 --duration 60
  python3 normal_traffic.py --sources 10 --rps 3 --duration 60
  python3 normal_traffic.py --rps 1 --duration 0
"""

import argparse
import ipaddress
import math
import random
import socket
import time

MAX_LOOPBACK_SOURCES = 253


PATHS = [
    "/",
    "/health",
    "/index.html",
    "/about",
    "/products?page=1",
    "/products?page=2",
    "/api/items?limit=20",
    "/api/items?limit=50&sort=name",
    "/search?q=shoes",
    "/cart",
    "/api/cart",
    "/static/app.css",
    "/static/app.js",
]

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) "
    "Gecko/20100101 Firefox/121.0",
]


def send_request(
    host: str, port: int, path: str, timeout: float,
    source_ip: str | None = None,
) -> tuple[int | None, bool, str | None]:
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
        "Accept: text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Connection: close\r\n\r\n"
    ).encode("iso-8859-1")

    try:
        source_address = (source_ip, 0) if source_ip else None
        with socket.create_connection(
            (host, port), timeout=timeout, source_address=source_address
        ) as connection:
            connection.settimeout(timeout)
            connection.sendall(request)
            response = bytearray()
            while b"\r\n\r\n" not in response and len(response) < 16 * 1024:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
        if not response:
            return None, False, "server closed the connection without a response"

        header, _, _body = bytes(response).partition(b"\r\n\r\n")
        status_line = header.split(b"\r\n", 1)[0].decode(
            "iso-8859-1", "replace"
        )
        parts = status_line.split(" ")
        if len(parts) < 2 or not parts[1].isdigit():
            return None, False, f"invalid HTTP status line: {status_line!r}"

        headers = {
            line.split(b":", 1)[0].strip().lower(): line.split(b":", 1)[1].strip().lower()
            for line in header.split(b"\r\n")[1:]
            if b":" in line
        }
        blocked = headers.get(b"x-blocked-by") == b"traffic-guard"
        return int(parts[1]), blocked, None
    except (OSError, TimeoutError) as exc:
        return None, False, str(exc)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate normal HTTP traffic for the TrafficGuard demo"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="TrafficGuard proxy port (default: 8080)",
    )
    parser.add_argument("--rps", type=float, default=3.0)
    parser.add_argument(
        "--sources",
        type=int,
        default=1,
        help=(
            "number of local client IPs (1-253; multiple sources require "
            "a localhost destination)"
        ),
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=60.0,
        help="Run duration in seconds; use 0 to run forever",
    )
    parser.add_argument("--timeout", type=float, default=4.0)
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not math.isfinite(args.rps) or args.rps <= 0:
        parser.error("--rps must be a positive finite number")
    if not math.isfinite(args.duration) or args.duration < 0:
        parser.error("--duration must be zero (forever) or a positive finite number")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be a positive finite number")
    if not 1 <= args.sources <= MAX_LOOPBACK_SOURCES:
        parser.error(f"--sources must be between 1 and {MAX_LOOPBACK_SOURCES}")
    if args.sources > 1:
        try:
            is_localhost = args.host.lower() == "localhost" or (
                ipaddress.ip_address(args.host).version == 4
                and ipaddress.ip_address(args.host).is_loopback
            )
        except ValueError:
            is_localhost = False
        if not is_localhost:
            parser.error(
                "multiple simulated sources are only supported for localhost; "
                "use separate machines or network namespaces for remote client IPs"
            )

    interval = 1.0 / args.rps
    duration_text = "forever" if args.duration == 0 else f"{args.duration:g}s"
    source_ips = (
        [f"127.0.0.{index + 2}" for index in range(args.sources)]
        if args.sources > 1 else [None]
    )
    print(
        f"[normal] {args.rps:g} req/s -> "
        f"{args.host}:{args.port} for {duration_text}"
    )
    if args.sources > 1:
        print(
            f"[normal] simulating {args.sources} local TCP clients "
            f"({source_ips[0]}–{source_ips[-1]}); no IP headers are spoofed"
        )

    sent = allowed = blocked = errors = 0
    first_error = None
    per_source: dict[str, int] = {}
    started_at = time.monotonic()

    try:
        while args.duration == 0 or time.monotonic() - started_at < args.duration:
            source_ip = random.choice(source_ips)
            status, was_blocked, error = send_request(
                args.host, args.port, random.choice(PATHS), args.timeout,
                source_ip=source_ip,
            )
            sent += 1
            if source_ip:
                per_source[source_ip] = per_source.get(source_ip, 0) + 1
            if status is None:
                errors += 1
                if first_error is None:
                    first_error = error
            elif was_blocked:
                blocked += 1
            else:
                allowed += 1

            remaining = interval * random.uniform(0.6, 1.4)
            if args.duration > 0:
                remaining = min(remaining, max(0, args.duration - (time.monotonic() - started_at)))
            if remaining:
                time.sleep(remaining)
    except KeyboardInterrupt:
        pass

    print(
        f"[normal] sent={sent} allowed={allowed} "
        f"blocked={blocked} errors={errors}"
    )
    if per_source:
        print(
            f"[normal] distinct source IPs used: {len(per_source)}/{args.sources}; "
            + ", ".join(f"{ip}={count}" for ip, count in sorted(per_source.items()))
        )
    if first_error:
        print(f"[normal] first request error: {first_error}")
        if allowed == 0 and blocked == 0:
            print(
                f"[normal] Could not reach {args.host}:{args.port}. "
                "Start the protected server, detection proxy, and monitor backend first."
            )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
