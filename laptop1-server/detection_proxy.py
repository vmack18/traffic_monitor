#!/usr/bin/env python3
"""
detection_proxy.py  --  INLINE DETECTION STAGE  (LAPTOP 1 / Ubuntu Server VM)
=============================================================================

Every client connection is terminated here, inspected, and only then
re-originated towards the protected origin server:

      attacker / client
             |
             v
    +-----------------------------+
    |  detection_proxy  :8080     |   <-- this file
    |                             |
    |  1. blocklist check         |
    |  2. connection-flood check  |  (slowloris / half-open)
    |  3. sliding-window rate     |  (DoS / DDoS per source IP)
    |  4. payload inspection      |  (SQLi, XSS, malware, shellcode, ...)
    |  5. verdict: allow / block  |
    +-----------------------------+
             |  (allowed traffic only)
             v
    protected_server  :9000   (bound to 127.0.0.1, never exposed)

All decisions are streamed to the monitoring backend on LAPTOP 2
(POST /api/events) which aggregates them, correlates multi-source floods
(DDoS), stores history and pushes everything to the live dashboard.

Run:
    python3 detection_proxy.py --config config.json
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import json
import logging
import os
import signal
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import malicious

LOG = logging.getLogger("detection-proxy")

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DEFAULT_CONFIG: dict[str, Any] = {
    "proxy": {"listen_host": "0.0.0.0", "listen_port": 8080, "backlog": 1024},
    "upstream": {"host": "127.0.0.1", "port": 9000, "connect_timeout": 3.0, "read_timeout": 10.0},
    "monitor": {
        "enabled": True,
        "url": "http://127.0.0.1:8000",
        "timeout": 2.0,
        "poll_blocklist_seconds": 5,
        "queue_max": 5000,
    },
    "limits": {
        "window_seconds": 10,
        "max_requests_per_ip": 40,
        "max_requests_global": 500,
        "max_concurrent_per_ip": 12,
        "max_payload_bytes": 65536,
        "header_timeout": 5.0,
        "block_ttl_seconds": 300,
    },
    "policy": {
        "block_on_malicious": True,
        "block_on_rate_limit": True,
        "block_on_conn_limit": True,
        "min_block_severity": "medium",
    },
}


def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str | None) -> dict:
    cfg = DEFAULT_CONFIG
    if path and Path(path).exists():
        with open(path, "r", encoding="utf-8") as fh:
            cfg = deep_merge(DEFAULT_CONFIG, json.load(fh))
        LOG.info("loaded configuration from %s", path)
    return cfg


# --------------------------------------------------------------------------- #
# State: rate windows, connection tracking, blocklist
# --------------------------------------------------------------------------- #

class SlidingWindow:
    """Counts events in the last N seconds, per key (source IP)."""

    def __init__(self, window_seconds: float):
        self.window = window_seconds
        self._events: dict[str, collections.deque[float]] = {}

    def add(self, key: str, now: float | None = None) -> int:
        now = now or time.monotonic()
        dq = self._events.setdefault(key, collections.deque())
        dq.append(now)
        self._trim(dq, now)
        return len(dq)

    def count(self, key: str, now: float | None = None) -> int:
        now = now or time.monotonic()
        dq = self._events.get(key)
        if not dq:
            return 0
        self._trim(dq, now)
        return len(dq)

    def total(self, now: float | None = None) -> int:
        now = now or time.monotonic()
        return sum(self.count(k, now) for k in list(self._events))

    def _trim(self, dq: collections.deque, now: float) -> None:
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def prune(self, now: float | None = None) -> None:
        now = now or time.monotonic()
        cutoff = now - self.window
        for key in list(self._events):
            dq = self._events[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del self._events[key]


class BlockList:
    """Local blocklist with TTL, merged with the dashboard's blocklist."""

    def __init__(self, ttl: float):
        self.ttl = ttl
        self._entries: dict[str, float] = {}          # ip -> expiry (monotonic)
        self._remote: dict[str, float] = {}           # ip -> expiry

    def add(self, ip: str, ttl: float | None = None) -> None:
        self._entries[ip] = time.monotonic() + (ttl if ttl is not None else self.ttl)

    def add_remote(self, ip: str, ttl: float = 600) -> None:
        self._remote[ip] = time.monotonic() + ttl

    def sync_remote(self, ips: list[str]) -> None:
        now = time.monotonic()
        for ip in ips:
            self._remote[ip] = now + 600
        for ip in list(self._remote):
            if ip not in ips and self._remote[ip] < now:
                del self._remote[ip]

    def is_blocked(self, ip: str) -> bool:
        now = time.monotonic()
        exp = self._entries.get(ip)
        if exp is not None:
            if exp > now:
                return True
            del self._entries[ip]
        exp = self._remote.get(ip)
        if exp is not None:
            if exp > now:
                return True
            del self._remote[ip]
        return False

    def prune(self) -> None:
        now = time.monotonic()
        for d in (self._entries, self._remote):
            for ip in [k for k, v in d.items() if v <= now]:
                del d[ip]

    def snapshot(self) -> list[str]:
        now = time.monotonic()
        return sorted({ip for ip, exp in {**self._entries, **self._remote}.items() if exp > now})


@dataclass
class Stats:
    started: float = field(default_factory=time.time)
    connections: int = 0
    allowed: int = 0
    blocked: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    findings: collections.Counter = field(default_factory=collections.Counter)

    def as_dict(self) -> dict:
        return {
            "uptime_seconds": round(time.time() - self.started, 1),
            "connections": self.connections,
            "allowed": self.allowed,
            "blocked": self.blocked,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "findings": dict(self.findings),
        }


# --------------------------------------------------------------------------- #
# Request parsing
# --------------------------------------------------------------------------- #

@dataclass
class ParsedRequest:
    raw: bytes
    method: str
    target: str
    version: str
    headers: dict[str, str]
    body: bytes
    is_http: bool


async def read_request(reader: asyncio.StreamReader, max_bytes: int,
                       timeout: float) -> ParsedRequest | None:
    """Read one request from the socket. Returns None on timeout/EOF."""
    buf = bytearray()
    try:
        while b"\r\n\r\n" not in buf:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                return None if not buf else _parse(bytes(buf))
            buf.extend(chunk)
            if len(buf) > max_bytes:
                break
    except asyncio.TimeoutError:
        if buf:
            # Partial request that never completed: classic slowloris signature.
            req = _parse(bytes(buf))
            req.headers["x-partial"] = "1"
            return req
        return None

    head_end = buf.find(b"\r\n\r\n")
    if head_end == -1:
        return _parse(bytes(buf))

    head = bytes(buf[: head_end + 4])
    rest = bytes(buf[head_end + 4:])
    req = _parse(head + rest)
    length = int(req.headers.get("content-length", "0") or 0)
    if length > 0:
        need = length - len(rest)
        if 0 < need <= max_bytes:
            try:
                body = await asyncio.wait_for(reader.readexactly(need), timeout=timeout)
                req.body += body
                req.raw += body
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                pass
    return req


def _parse(raw: bytes) -> ParsedRequest:
    try:
        text = raw.decode("iso-8859-1")
        lines = text.split("\r\n")
        parts = lines[0].split(" ", 2)
        if len(parts) < 2:
            raise ValueError
        method, target = parts[0], parts[1]
        version = parts[2] if len(parts) > 2 else "HTTP/1.0"
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
        body = b""
        if b"\r\n\r\n" in raw:
            body = raw.split(b"\r\n\r\n", 1)[1]
        return ParsedRequest(raw, method, target, version, headers, body, True)
    except Exception:
        return ParsedRequest(raw, "RAW", "", "", {}, raw, False)


# --------------------------------------------------------------------------- #
# Monitor reporter (async queue -> HTTP POST)
# --------------------------------------------------------------------------- #

class MonitorReporter:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.enabled = bool(cfg.get("enabled", True))
        self.url = str(cfg.get("url", "")).rstrip("/")
        self.timeout = float(cfg.get("timeout", 2.0))
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=int(cfg.get("queue_max", 5000)))
        self.dropped = 0
        self.sent = 0
        self._task: asyncio.Task | None = None

    def submit(self, event: dict) -> None:
        if not self.enabled:
            return
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1

    def start(self) -> None:
        if self.enabled:
            self._task = asyncio.create_task(self._worker(), name="monitor-reporter")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _worker(self) -> None:
        while True:
            batch = [await self.queue.get()]
            while len(batch) < 50:
                try:
                    batch.append(self.queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            try:
                await asyncio.to_thread(self._post, {"events": batch})
                self.sent += len(batch)
            except Exception as exc:
                LOG.debug("monitor unreachable (%s) - events dropped from queue", exc)
            await asyncio.sleep(0)

    def _post(self, payload: dict) -> None:
        import urllib.request
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self.url}/api/events", data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            resp.read()

    def fetch_blocklist(self) -> list[str]:
        import urllib.request
        try:
            with urllib.request.urlopen(f"{self.url}/api/blocked", timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
            return [row["ip"] for row in data.get("blocked", [])]
        except Exception:
            return []


# --------------------------------------------------------------------------- #
# The proxy
# --------------------------------------------------------------------------- #

class DetectionProxy:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.limits = cfg["limits"]
        self.policy = cfg["policy"]
        self.upstream = cfg["upstream"]

        self.window = SlidingWindow(float(self.limits["window_seconds"]))
        self.global_window = SlidingWindow(float(self.limits["window_seconds"]))
        self.blocklist = BlockList(float(self.limits["block_ttl_seconds"]))
        self.active_conns: collections.Counter = collections.Counter()
        # Per-source count of malicious payload hits. An IP is only added to
        # the blocklist after this reaches the configured threshold, which
        # avoids locking out a client on a single false positive.
        self.malicious_hits: collections.Counter = collections.Counter()
        self.stats = Stats()
        self.reporter = MonitorReporter(cfg["monitor"])
        self._tasks: list[asyncio.Task] = []
        self.local_ip = self._detect_local_ip()

    @staticmethod
    def _detect_local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    # ---------------- lifecycle ----------------

    async def start(self) -> None:
        self.reporter.start()
        self._tasks.append(asyncio.create_task(self._housekeeping(), name="housekeeping"))
        if self.reporter.enabled:
            self._tasks.append(asyncio.create_task(self._poll_blocklist(), name="blocklist-poll"))
        server = await asyncio.start_server(
            self.handle_client,
            self.cfg["proxy"]["listen_host"],
            int(self.cfg["proxy"]["listen_port"]),
            backlog=int(self.cfg["proxy"].get("backlog", 1024)),
        )
        LOG.info("detection proxy listening on %s:%s -> upstream %s:%s",
                 self.cfg["proxy"]["listen_host"], self.cfg["proxy"]["listen_port"],
                 self.upstream["host"], self.upstream["port"])
        async with server:
            await server.serve_forever()

    async def _housekeeping(self) -> None:
        while True:
            await asyncio.sleep(5)
            self.window.prune()
            self.global_window.prune()
            self.blocklist.prune()

    async def _poll_blocklist(self) -> None:
        interval = float(self.cfg["monitor"].get("poll_blocklist_seconds", 5))
        known: set[str] = set()
        while True:
            ips = await asyncio.to_thread(self.reporter.fetch_blocklist)
            if ips:
                self.blocklist.sync_remote(ips)
                current = set(ips)
                added = current - known
                removed = known - current
                if added:
                    LOG.warning("blocklist sync: +%d from dashboard %s",
                                len(added), sorted(added)[:5])
                if removed:
                    LOG.info("blocklist sync: -%d released by dashboard %s",
                             len(removed), sorted(removed)[:5])
                known = current
            await asyncio.sleep(interval)

    # ---------------- core handler ----------------

    async def handle_client(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        src_ip, src_port = peer[0], peer[1]
        # conn_ip is the real TCP peer (used for connection accounting).
        # src_ip is the *logical* client identity, which may be overridden by
        # X-Forwarded-For when trust_forwarded_for is enabled (demo/DDoS sim).
        conn_ip = src_ip
        started = time.perf_counter()
        self.stats.connections += 1

        # ---- 1. blocklist ----
        if self.blocklist.is_blocked(src_ip):
            self.stats.blocked += 1
            req = await read_request(reader, int(self.limits["max_payload_bytes"]),
                                     float(self.limits["header_timeout"]))
            await self._reject(writer, 403, "Forbidden - source IP blocked")
            self._report(src_ip, src_port, req, "block", "blocklist", "high", [],
                         started, 403)
            return

        # ---- 2. connection flood (slowloris / half-open) ----
        self.active_conns[conn_ip] += 1
        try:
            if self.active_conns[conn_ip] > int(self.limits["max_concurrent_per_ip"]):
                self.stats.blocked += 1
                if self.policy.get("block_on_conn_limit", True):
                    self.blocklist.add(conn_ip)
                await self._reject(writer, 429, "Too Many Connections")
                self._report(src_ip, src_port, None, "block", "connection_flood", "high", [],
                             started, 429)
                return

            # ---- 3. read the request ----
            req = await read_request(reader, int(self.limits["max_payload_bytes"]),
                                     float(self.limits["header_timeout"]))
            if req is None:
                return

            self.stats.bytes_in += len(req.raw)

            # Optional: honour X-Forwarded-For only behind a load balancer
            # that overwrites this header; disabled by default.
            if self.policy.get("trust_forwarded_for", False):
                xff = req.headers.get("x-forwarded-for", "")
                cand = xff.split(",")[0].strip()
                if cand:
                    src_ip = cand

            # ---- 4. rate limiting (DoS / DDoS) ----
            per_ip = self.window.add(src_ip)
            global_count = self.global_window.add("__global__")
            rate_block = per_ip > int(self.limits["max_requests_per_ip"])
            global_flood = global_count > int(self.limits["max_requests_global"])

            if rate_block and self.policy.get("block_on_rate_limit", True):
                self.blocklist.add(src_ip)
                self.stats.blocked += 1
                await self._reject(writer, 429, "Too Many Requests - rate limit exceeded")
                self._report(src_ip, src_port, req, "block", "rate_limit", "high", [],
                             started, 429, extra={"requests_in_window": per_ip,
                                                  "global_in_window": global_count})
                return

            # ---- 5. payload inspection ----
            findings = malicious.inspect(req.headers, req.body,
                                         req.target if req.is_http else "",
                                         req.method)
            verdict, severity = malicious.summarize(findings)
            if verdict == "block" and self.policy.get("block_on_malicious", True):
                self.stats.blocked += 1
                for f in findings:
                    self.stats.findings[f["rule"]] += 1
                if severity in ("high", "critical"):
                    self.malicious_hits[src_ip] += 1
                    threshold = int(self.policy.get("malicious_blocklist_threshold", 3))
                    if self.malicious_hits[src_ip] >= threshold:
                        self.blocklist.add(src_ip)
                await self._reject(writer, 403, "Forbidden - malicious payload detected")
                self._report(src_ip, src_port, req, "block", "malicious_payload",
                             severity, findings, started, 403,
                             extra={"global_in_window": global_count})
                return

            # ---- 6. allowed -> forward to the protected origin ----
            if global_flood:
                LOG.warning("GLOBAL FLOOD: %d req/%ss - forwarding but alerting",
                            global_count, self.limits["window_seconds"])

            status, resp_bytes, upstream_latency = await self._forward(req)
            self.stats.allowed += 1
            self.stats.bytes_out += len(resp_bytes)
            if resp_bytes:
                writer.write(resp_bytes)
                await writer.drain()

            if findings:
                for f in findings:
                    self.stats.findings[f["rule"]] += 1
            self._report(src_ip, src_port, req, "allow",
                         "clean" if not findings else "suspicious_allowed",
                         severity if findings else "none", findings, started, status,
                         extra={"requests_in_window": per_ip,
                                "global_in_window": global_count,
                                "upstream_ms": round(upstream_latency * 1000, 2)})
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:  # pragma: no cover
            LOG.exception("proxy error for %s: %s", src_ip, exc)
        finally:
            self.active_conns[conn_ip] -= 1
            if self.active_conns[conn_ip] <= 0:
                self.active_conns.pop(conn_ip, None)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _forward(self, req: ParsedRequest) -> tuple[int, bytes, float]:
        t0 = time.perf_counter()
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(self.upstream["host"], int(self.upstream["port"])),
                timeout=float(self.upstream.get("connect_timeout", 3.0)))
        except Exception as exc:
            LOG.warning("upstream unavailable: %s", exc)
            body = b'{"error":"origin server unavailable"}'
            head = (b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n")
            return 502, head + body, time.perf_counter() - t0

        try:
            up_writer.write(req.raw)
            await up_writer.drain()
            chunks = await self._read_response(up_reader)
            status = 200
            if chunks.startswith(b"HTTP/"):
                try:
                    status = int(bytes(chunks).split(b" ", 2)[1])
                except Exception:
                    pass
            return status, bytes(chunks), time.perf_counter() - t0
        except asyncio.TimeoutError:
            body = b'{"error":"origin timeout"}'
            head = (b"HTTP/1.1 504 Gateway Timeout\r\nContent-Type: application/json\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n")
            return 504, head + body, time.perf_counter() - t0
        finally:
            try:
                up_writer.close()
                await up_writer.wait_closed()
            except Exception:
                pass

    async def _read_response(self, reader: asyncio.StreamReader) -> bytes:
        """Read exactly one HTTP response (or a raw stream) from the origin."""
        timeout = float(self.upstream.get("read_timeout", 10.0))
        buf = bytearray()

        # --- headers ---
        while b"\r\n\r\n" not in buf:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            if not chunk:
                return bytes(buf)
            buf.extend(chunk)
            if len(buf) > 8 * 1024 * 1024:
                return bytes(buf)

        head_end = buf.find(b"\r\n\r\n") + 4
        head = bytes(buf[:head_end]).decode("iso-8859-1", "replace").lower()

        content_length: int | None = None
        for line in head.split("\r\n"):
            if line.startswith("content-length:"):
                try:
                    content_length = int(line.split(":", 1)[1].strip())
                except ValueError:
                    content_length = None

        if content_length is not None:
            while len(buf) - head_end < content_length:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                if not chunk:
                    break
                buf.extend(chunk)
            return bytes(buf)

        if "transfer-encoding: chunked" in head:
            while not bytes(buf).endswith(b"0\r\n\r\n"):
                chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                if not chunk:
                    break
                buf.extend(chunk)
            return bytes(buf)

        # Unknown framing: drain until EOF or a short idle gap.
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=1.0)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > 8 * 1024 * 1024:
                break
        return bytes(buf)

    async def _reject(self, writer: asyncio.StreamWriter, status: int, message: str) -> None:
        reason = {403: "Forbidden", 429: "Too Many Requests"}.get(status, "Blocked")
        body = json.dumps({
            "blocked": True, "status": status, "message": message,
            "served_by": "traffic-guard-detection-proxy",
            "timestamp": time.time(),
        }).encode()
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"X-Blocked-By: traffic-guard\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        try:
            writer.write(head + body)
            await writer.drain()
        except Exception:
            pass

    # ---------------- reporting ----------------

    def _report(self, src_ip: str, src_port: int, req: ParsedRequest | None,
                verdict: str, reason: str, severity: str, findings: list[dict],
                started: float, status: int, extra: dict | None = None) -> None:
        event = {
            "ts": time.time(),
            "source": "laptop1-proxy",
            "sensor": "inline-proxy",
            "event_type": "request",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": self.local_ip,
            "dst_port": int(self.upstream["port"]),
            "proto": "TCP",
            "method": req.method if req else "RAW",
            "path": (req.target[:300] if req else ""),
            "bytes_in": len(req.raw) if req else 0,
            "bytes_out": 0,
            "verdict": verdict,
            "reason": reason,
            "severity": severity,
            "findings": findings,
            "status": status,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
        }
        if extra:
            event.update(extra)
        self.reporter.submit(event)

        if verdict == "block":
            LOG.warning("BLOCK %s %s %s -> %s (%s)", src_ip,
                        event["method"], event["path"][:80], status, reason)
        else:
            LOG.info("ALLOW %s %s %s -> %s", src_ip, event["method"], event["path"][:80], status)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

async def run(cfg: dict) -> None:
    proxy = DetectionProxy(cfg)
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    server_task = asyncio.create_task(proxy.start())
    await stop.wait()
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass
    await proxy.reporter.stop()
    LOG.info("detection proxy stopped. stats=%s", proxy.stats.as_dict())


def main() -> None:
    ap = argparse.ArgumentParser(description="Inline detection proxy (Laptop 1)")
    ap.add_argument("--config", default=os.path.join(os.path.dirname(__file__), "config.json"))
    ap.add_argument("--listen-port", type=int, default=None)
    ap.add_argument("--upstream-port", type=int, default=None)
    ap.add_argument("--monitor-url", default=None)
    ap.add_argument("--log-file", default="")
    args = ap.parse_args()

    cfg = load_config(args.config)
    if args.listen_port:
        cfg["proxy"]["listen_port"] = args.listen_port
    if args.upstream_port:
        cfg["upstream"]["port"] = args.upstream_port
    if args.monitor_url:
        cfg["monitor"]["url"] = args.monitor_url

    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if args.log_file:
        Path(args.log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
                        handlers=handlers)

    asyncio.run(run(cfg))


if __name__ == "__main__":
    main()
