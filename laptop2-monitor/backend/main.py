"""
main.py -- LAPTOP 2 monitoring backend (FastAPI)
================================================

Responsibilities
----------------
1. Receive every decision made by the Laptop 1 inline proxy  (POST /api/events)
2. Feed them into the DoS/DDoS detection engine
3. Persist events, incidents and the shared blocklist in SQLite
4. Push a live snapshot + individual incidents to the dashboard over WebSocket
5. Expose the blocklist that the Laptop 1 proxy polls every 5 seconds

Run:
    uvicorn main:app --host 0.0.0.0 --port 8000
    # or
    python main.py
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import random
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

import malicious
from config import settings
from database import Database
from detector import DetectionEngine, Incident
from sniffer import PacketSniffer

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
)
LOG = logging.getLogger("monitor")

# --------------------------------------------------------------------------- #
# Global state
# --------------------------------------------------------------------------- #

db = Database(settings.db_path)
engine = DetectionEngine(settings.thresholds)
sniffer: PacketSniffer | None = None
clients: set[WebSocket] = set()
clients_lock = asyncio.Lock()
_broadcast_queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)
_started_at = time.time()


def _auto_block(inc: Incident) -> None:
    """Push high/critical incidents straight into the shared blocklist."""
    if not settings.auto_block or not inc.src_ip:
        return
    if inc.severity not in ("high", "critical"):
        return
    if inc.type in ("ddos", "http_flood"):
        for ip in inc.sources[:20]:
            if ip and not db.is_blocked(ip):
                db.add_blocked(ip, reason=f"auto:{inc.type}", ttl=settings.auto_block_ttl, auto=True)
        return
    if not db.is_blocked(inc.src_ip):
        db.add_blocked(inc.src_ip, reason=f"auto:{inc.type}",
                       ttl=settings.auto_block_ttl, auto=True)


def _on_incident(inc: Incident) -> None:
    LOG.warning("INCIDENT %s [%s] %s", inc.severity.upper(), inc.type, inc.title)
    db.upsert_incident(inc)
    _auto_block(inc)
    _queue({"type": "incident", "data": inc.to_dict()})


def _on_resolve(inc: Incident) -> None:
    LOG.info("RESOLVED %s [%s] %s", inc.severity.upper(), inc.type, inc.title)
    db.upsert_incident(inc)
    _queue({"type": "incident_resolved", "data": inc.to_dict()})


engine.on_incident = _on_incident
engine.on_resolve = _on_resolve


def _queue(message: dict) -> None:
    try:
        _broadcast_queue.put_nowait(message)
    except asyncio.QueueFull:
        pass


# --------------------------------------------------------------------------- #
# WebSocket plumbing
# --------------------------------------------------------------------------- #

async def _broadcast(message: dict) -> None:
    payload = json.dumps(message, default=str)
    async with clients_lock:
        dead = []
        for ws in clients:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            clients.discard(ws)


async def _broadcaster() -> None:
    """Drain the queue and send a full snapshot once per second."""
    last_snapshot = 0.0
    while True:
        try:
            message = await asyncio.wait_for(_broadcast_queue.get(), timeout=0.5)
            await _broadcast(message)
        except asyncio.TimeoutError:
            pass
        except Exception as exc:
            LOG.debug("broadcast error: %s", exc)

        now = time.time()
        if now - last_snapshot >= 1.0:
            last_snapshot = now
            try:
                engine.resolve_stale(now)
                await _broadcast({"type": "snapshot", "data": engine.snapshot(now)})
            except Exception as exc:
                LOG.debug("snapshot error: %s", exc)


# --------------------------------------------------------------------------- #
# Demo traffic (optional)
# --------------------------------------------------------------------------- #

DEMO_SOURCES = [f"10.10.{i // 20}.{i % 20 + 10}" for i in range(40)]
DEMO_PATHS = ["/", "/api/data", "/health", "/login", "/index.html", "/upload"]


async def _demo_traffic() -> None:
    while True:
        await asyncio.sleep(random.uniform(0.4, 1.4))
        event = {
            "ts": time.time(),
            "source": "demo",
            "sensor": "demo-generator",
            "event_type": "request",
            "src_ip": random.choice(DEMO_SOURCES),
            "src_port": random.randint(30000, 65000),
            "dst_ip": "192.168.56.10",
            "dst_port": 9000,
            "proto": "TCP",
            "method": random.choice(["GET", "GET", "GET", "POST"]),
            "path": random.choice(DEMO_PATHS),
            "bytes_in": random.randint(180, 1200),
            "verdict": "allow",
            "reason": "clean",
            "severity": "none",
            "findings": [],
            "status": 200,
            "latency_ms": round(random.uniform(1, 12), 2),
        }
        _ingest_events([event], persist=False)


# --------------------------------------------------------------------------- #
# Ingestion core
# --------------------------------------------------------------------------- #

def _ingest_events(events: list[dict], persist: bool = True) -> list[dict]:
    if persist:
        db.insert_events(events)
    incidents = []
    for event in events:
        try:
            for inc in engine.ingest_event(event):
                incidents.append(inc.to_dict())
        except Exception as exc:
            LOG.debug("engine error on event: %s", exc)
    return incidents


# --------------------------------------------------------------------------- #
# Lifespan
# --------------------------------------------------------------------------- #

@asynccontextmanager
async def lifespan(app: FastAPI):
    global sniffer
    LOG.info("starting monitoring backend on %s:%d (db=%s)",
             settings.host, settings.port, settings.db_path)

    if settings.sniffer_enabled:
        sniffer = PacketSniffer(engine, iface=settings.sniffer_iface,
                                bpf_filter=settings.sniffer_filter,
                                on_malicious=_on_sniffer_malicious)
        if not sniffer.start():
            LOG.warning("sniffer could not start: %s", sniffer.error)

    tasks = [asyncio.create_task(_broadcaster(), name="broadcaster")]
    if settings.demo_mode:
        tasks.append(asyncio.create_task(_demo_traffic(), name="demo-traffic"))
    tasks.append(asyncio.create_task(_maintenance(), name="maintenance"))

    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await t
        if sniffer:
            sniffer.stop()
        LOG.info("monitoring backend stopped")


def _on_sniffer_malicious(pkt: dict, findings: list[dict]) -> None:
    """A signature matched inside a raw packet payload."""
    event = {
        "ts": pkt.get("ts", time.time()),
        "source": "laptop2-sniffer",
        "sensor": "packet-sniffer",
        "event_type": "packet",
        "src_ip": pkt.get("src_ip"),
        "src_port": pkt.get("src_port", 0),
        "dst_ip": pkt.get("dst_ip"),
        "dst_port": pkt.get("dst_port", 0),
        "proto": pkt.get("proto", "TCP"),
        "method": "RAW",
        "path": "",
        "bytes_in": pkt.get("length", 0),
        "verdict": "block",
        "reason": "malicious_payload",
        "severity": max((f.get("severity", "low") for f in findings),
                        key=lambda s: {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0)),
        "findings": findings,
        "status": 0,
        "latency_ms": 0,
    }
    _ingest_events([event])
    _queue({"type": "packet_alert", "data": event})


async def _maintenance() -> None:
    while True:
        await asyncio.sleep(30)
        try:
            db.expire_blocks()
            db.prune_events(keep_seconds=86400)
        except Exception as exc:
            LOG.debug("maintenance error: %s", exc)


app = FastAPI(
    title="Traffic Guard Monitor",
    version="1.0.0",
    description="Real-time DoS/DDoS + malicious payload monitoring backend (Laptop 2)",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #

class EventBatch(BaseModel):
    events: list[dict[str, Any]] = Field(default_factory=list)


class BlockRequest(BaseModel):
    ip: str
    reason: str = "manual block"
    ttl: int = 600

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        v = (v or "").strip()
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            raise ValueError("not a valid IPv4/IPv6 address")

    @field_validator("ttl")
    @classmethod
    def _valid_ttl(cls, v: int) -> int:
        # 0 means "permanent" (no expiry).
        if v < 0 or v > 31_536_000:
            raise ValueError("ttl must be between 0 and 31536000 seconds")
        return v


# --------------------------------------------------------------------------- #
# REST API
# --------------------------------------------------------------------------- #

@app.get("/")
async def root():
    return {
        "service": "traffic-guard-monitor",
        "role": "Laptop 2 backend",
        "version": "1.0.0",
        "uptime_seconds": round(time.time() - _started_at, 1),
        "endpoints": ["/api/health", "/api/events", "/api/incidents", "/api/stats",
                      "/api/blocked", "/api/rules", "/api/config", "/ws"],
    }


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "uptime_seconds": round(time.time() - _started_at, 1),
        "websocket_clients": len(clients),
        "sniffer": sniffer.status() if sniffer else {"available": False, "running": False},
        "engine": {
            "window_seconds": settings.thresholds.window_seconds,
            "active_incidents": len(engine.snapshot()["active_incidents"]),
        },
        "database": db.event_counts(),
    }


@app.post("/api/events")
async def ingest_events(batch: EventBatch):
    if not batch.events:
        return {"accepted": 0, "incidents": []}
    events = batch.events[:1000]
    incidents = _ingest_events(events)
    for i in range(0, len(events), 25):
        _queue({"type": "events", "data": events[i:i + 25]})
    return {"accepted": len(events), "incidents": incidents}


@app.get("/api/events")
async def list_events(limit: int = Query(100, ge=1, le=1000),
                      verdict: str | None = None,
                      src_ip: str | None = None):
    return {"events": db.recent_events(limit=limit, verdict=verdict, src_ip=src_ip)}


@app.get("/api/context/blocked")
async def blocked_context(limit: int = Query(200, ge=1, le=1000)):
    """Everything the inline gate stopped: recent blocked requests with the
    findings/reason that triggered the block, plus roll-ups for the UI."""
    return db.blocked_context(limit=limit)


@app.get("/api/incidents")
async def list_incidents(limit: int = Query(100, ge=1, le=1000),
                         status: str | None = None):
    return {
        "incidents": db.list_incidents(limit=limit, status=status),
        # snapshot() already serialises active incidents to plain dicts.
        "active": engine.snapshot()["active_incidents"],
        "stats": db.incident_stats(),
    }


@app.post("/api/incidents/{incident_id}/ack")
async def acknowledge_incident(incident_id: str):
    if not engine.acknowledge(incident_id):
        raise HTTPException(status_code=404, detail="incident not active")
    for inc in engine.snapshot()["active_incidents"]:
        if inc["id"] == incident_id:
            db.upsert_incident(inc)
            break
    return {"acknowledged": incident_id}


@app.get("/api/stats")
async def stats():
    snap = engine.snapshot()
    snap["database"] = db.event_counts()
    snap["incident_stats"] = db.incident_stats()
    return snap


@app.get("/api/blocked")
async def list_blocked():
    blocked = db.list_blocked()
    return {"blocked": blocked, "count": len(blocked)}


@app.post("/api/blocked")
async def add_blocked(req: BlockRequest):
    row = db.add_blocked(req.ip, reason=req.reason, ttl=req.ttl, auto=False)
    LOG.info("manual block: %s (%s)", req.ip, req.reason)
    _queue({"type": "blocklist_changed", "data": {"action": "add", **row}})
    return row


@app.post("/api/blocked/server")
async def block_server(ttl: int = 600, reason: str = "manual:server-quarantine"):
    """Quarantine the protected origin (Laptop 1) with one call.

    The IP is taken from TG_SERVER_IP so the operator never has to remember it.
    """
    row = db.add_blocked(settings.server_ip, reason=reason, ttl=ttl, auto=False)
    LOG.warning("server IP quarantined: %s (%s)", settings.server_ip, reason)
    _queue({"type": "blocklist_changed", "data": {"action": "add", **row}})
    return row


@app.delete("/api/blocked/{ip}")
async def remove_blocked(ip: str):
    ok = db.remove_blocked(ip)
    if not ok:
        raise HTTPException(status_code=404, detail="ip not blocked")
    _queue({"type": "blocklist_changed", "data": {"action": "remove", "ip": ip}})
    return {"unblocked": ip}


@app.get("/api/rules")
async def list_rules():
    rules = [{"rule": r.rule_id, "category": r.category, "severity": r.severity,
              "detail": r.detail, "pattern": r.pattern.pattern}
             for r in malicious.REGEX_RULES]
    byte_rules = [{"rule": rid, "category": cat, "severity": sev, "detail": detail}
                  for rid, cat, sev, _needle, detail in malicious.BYTE_RULES]
    return {
        "regex_rules": rules,
        "byte_rules": byte_rules,
        "count": len(rules) + len(byte_rules),
        "hits": engine.rule_counts(),
    }


@app.get("/api/config")
async def get_config():
    t = settings.thresholds
    return {
        "window_seconds": t.window_seconds,
        "thresholds": {
            "dos_requests_per_ip": t.dos_requests_per_ip,
            "dos_bytes_per_ip": t.dos_bytes_per_ip,
            "ddos_unique_sources": t.ddos_unique_sources,
            "ddos_total_requests": t.ddos_total_requests,
            "syn_flood_pps": t.syn_flood_pps,
            "udp_flood_pps": t.udp_flood_pps,
            "http_flood_same_path": t.http_flood_same_path,
            "slowloris_concurrent": t.slowloris_concurrent,
            "port_scan_unique_ports": t.port_scan_unique_ports,
            "brute_force_failures": t.brute_force_failures,
        },
        "auto_block": settings.auto_block,
        "auto_block_ttl": settings.auto_block_ttl,
        "server_ip": settings.server_ip,
        "server_label": settings.server_label,
        "sniffer_enabled": settings.sniffer_enabled,
        "demo_mode": settings.demo_mode,
    }


@app.post("/api/engine/reset")
async def reset_engine():
    engine.reset()
    engine.on_incident = _on_incident
    engine.on_resolve = _on_resolve
    return {"reset": True}


# --------------------------------------------------------------------------- #
# WebSocket
# --------------------------------------------------------------------------- #

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    async with clients_lock:
        clients.add(ws)
    LOG.info("dashboard connected (%d clients)", len(clients))
    try:
        await ws.send_text(json.dumps({"type": "snapshot", "data": engine.snapshot()},
                                      default=str))
        await ws.send_text(json.dumps({"type": "hello", "data": {
            "window_seconds": settings.thresholds.window_seconds,
            "auto_block": settings.auto_block,
            "sniffer": sniffer.status() if sniffer else {"available": False},
        }}, default=str))
        while True:
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_text(json.dumps({"type": "pong", "ts": time.time()}))
            elif msg.startswith("ack:"):
                engine.acknowledge(msg[4:].strip())
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        LOG.debug("websocket error: %s", exc)
    finally:
        async with clients_lock:
            clients.discard(ws)
        LOG.info("dashboard disconnected (%d clients)", len(clients))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=False)
