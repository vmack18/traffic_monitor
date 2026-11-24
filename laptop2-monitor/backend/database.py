"""
database.py -- SQLite persistence for the LAPTOP 2 monitoring backend.

Four tables:

  events     every inspected request reported by the Laptop 1 proxy
  incidents  DoS/DDoS/malicious incidents raised by the detection engine
  blocked    shared blocklist (the Laptop 1 proxy polls this)
  meta       small key/value store (schema version, first run, ...)

SQLite is used because the whole thing has to run on a student laptop with
zero infrastructure.  WAL mode keeps reads fast while the engine writes.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    src_ip      TEXT    NOT NULL,
    src_port    INTEGER,
    dst_ip      TEXT,
    dst_port    INTEGER,
    proto       TEXT,
    method      TEXT,
    path        TEXT,
    verdict     TEXT    NOT NULL,
    reason      TEXT,
    severity    TEXT,
    status      INTEGER,
    bytes_in    INTEGER DEFAULT 0,
    latency_ms  REAL    DEFAULT 0,
    findings    TEXT    DEFAULT '[]',
    sensor      TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_src     ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict);

CREATE TABLE IF NOT EXISTS incidents (
    id           TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    severity     TEXT NOT NULL,
    title        TEXT,
    description  TEXT,
    src_ip       TEXT,
    sources      TEXT DEFAULT '[]',
    started_at   REAL,
    last_seen    REAL,
    count        INTEGER DEFAULT 1,
    status       TEXT DEFAULT 'active',
    evidence     TEXT DEFAULT '{}',
    acknowledged INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_inc_started ON incidents(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_inc_status  ON incidents(status);

CREATE TABLE IF NOT EXISTS blocked (
    ip          TEXT PRIMARY KEY,
    reason      TEXT,
    created_at  REAL,
    expires_at  REAL,
    active      INTEGER DEFAULT 1,
    auto        INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class Database:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.commit()
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version','1')")
            self._conn.commit()

    # ------------------------------------------------------------------ #
    # events
    # ------------------------------------------------------------------ #

    def insert_events(self, events: list[dict]) -> int:
        if not events:
            return 0
        rows = [(
            float(e.get("ts") or time.time()),
            str(e.get("src_ip") or "0.0.0.0"),
            int(e.get("src_port") or 0),
            str(e.get("dst_ip") or ""),
            int(e.get("dst_port") or 0),
            str(e.get("proto") or "TCP"),
            str(e.get("method") or "")[:16],
            str(e.get("path") or "")[:500],
            str(e.get("verdict") or "allow"),
            str(e.get("reason") or "")[:64],
            str(e.get("severity") or "none"),
            int(e.get("status") or 0),
            int(e.get("bytes_in") or 0),
            float(e.get("latency_ms") or 0),
            json.dumps(e.get("findings") or []),
            str(e.get("sensor") or "inline-proxy"),
        ) for e in events]
        with self._lock:
            self._conn.executemany(
                "INSERT INTO events (ts, src_ip, src_port, dst_ip, dst_port, proto, method,"
                " path, verdict, reason, severity, status, bytes_in, latency_ms, findings, sensor)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            self._conn.commit()
        return len(rows)

    def recent_events(self, limit: int = 100, verdict: str | None = None,
                      src_ip: str | None = None) -> list[dict]:
        sql = ("SELECT ts, src_ip, src_port, dst_ip, dst_port, proto, method, path,"
               " verdict, reason, severity, status, bytes_in, latency_ms, findings, sensor"
               " FROM events")
        clauses, params = [], []
        if verdict:
            clauses.append("verdict = ?")
            params.append(verdict)
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["findings"] = json.loads(d["findings"] or "[]")
            except Exception:
                d["findings"] = []
            out.append(d)
        return out

    def blocked_context(self, limit: int = 200, scan_limit: int = 2000) -> dict:
        """Full context for traffic the gate blocked.

        Returns recent blocked events (with decoded findings), plus roll-ups by
        reason, severity, signature rule and source so the dashboard can show
        *what* was stopped and *why* without issuing several queries.
        """
        limit = max(1, min(int(limit), 1000))
        scan_limit = max(limit, min(int(scan_limit), 10000))
        with self._lock:
            total = self._conn.execute(
                "SELECT COUNT(*) c FROM events WHERE verdict='block'").fetchone()["c"]
            rows = self._conn.execute(
                "SELECT ts, src_ip, src_port, dst_ip, dst_port, proto, method, path,"
                " verdict, reason, severity, status, bytes_in, latency_ms, findings, sensor"
                " FROM events WHERE verdict='block' ORDER BY ts DESC LIMIT ?",
                (limit,)).fetchall()
            reason_rows = self._conn.execute(
                "SELECT reason, COUNT(*) c, MAX(ts) last_seen FROM events"
                " WHERE verdict='block' GROUP BY reason ORDER BY c DESC").fetchall()
            sev_rows = self._conn.execute(
                "SELECT severity, COUNT(*) c FROM events WHERE verdict='block'"
                " GROUP BY severity ORDER BY c DESC").fetchall()
            src_rows = self._conn.execute(
                "SELECT src_ip, COUNT(*) c, MAX(ts) last_seen FROM events"
                " WHERE verdict='block' GROUP BY src_ip ORDER BY c DESC LIMIT 12").fetchall()
            active_blocks = self._conn.execute(
                "SELECT COUNT(*) c FROM blocked WHERE active=1").fetchone()["c"]
            scan_rows = self._conn.execute(
                "SELECT findings FROM events WHERE verdict='block'"
                " ORDER BY ts DESC LIMIT ?", (scan_limit,)).fetchall()

        recent: list[dict] = []
        for r in rows:
            d = dict(r)
            try:
                d["findings"] = json.loads(d["findings"] or "[]")
            except Exception:
                d["findings"] = []
            recent.append(d)

        # Roll up signature rules from the decoded findings.
        rules: dict[str, dict] = {}
        for r in scan_rows:
            try:
                findings = json.loads(r["findings"] or "[]")
            except Exception:
                continue
            for f in findings or []:
                rule = str(f.get("rule") or "unknown")
                entry = rules.setdefault(rule, {
                    "rule": rule,
                    "category": f.get("category") or "unknown",
                    "severity": f.get("severity") or "low",
                    "count": 0,
                })
                entry["count"] += 1

        by_rule = sorted(rules.values(), key=lambda x: x["count"], reverse=True)[:12]

        return {
            "total": total,
            "recent": recent,
            "by_reason": [{"reason": r["reason"] or "unknown", "count": r["c"],
                           "last_seen": r["last_seen"]} for r in reason_rows],
            "by_severity": [{"severity": r["severity"] or "none", "count": r["c"]}
                            for r in sev_rows],
            "by_rule": by_rule,
            "top_sources": [{"ip": r["src_ip"], "count": r["c"],
                             "last_seen": r["last_seen"]} for r in src_rows],
            "active_blocks": active_blocks,
            "generated_at": time.time(),
        }

    def event_counts(self) -> dict:
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
            blocked = self._conn.execute(
                "SELECT COUNT(*) c FROM events WHERE verdict='block'").fetchone()["c"]
            last_hour = self._conn.execute(
                "SELECT COUNT(*) c FROM events WHERE ts > ?",
                (time.time() - 3600,)).fetchone()["c"]
        return {"total": total, "blocked": blocked, "last_hour": last_hour}

    # ------------------------------------------------------------------ #
    # incidents
    # ------------------------------------------------------------------ #

    def upsert_incident(self, inc) -> None:
        d = inc.to_dict() if hasattr(inc, "to_dict") else dict(inc)
        with self._lock:
            self._conn.execute(
                "INSERT INTO incidents (id, type, severity, title, description, src_ip,"
                " sources, started_at, last_seen, count, status, evidence, acknowledged)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET"
                " severity=excluded.severity, description=excluded.description,"
                " sources=excluded.sources, last_seen=excluded.last_seen,"
                " count=excluded.count, status=excluded.status, evidence=excluded.evidence",
                (d["id"], d["type"], d["severity"], d.get("title", ""),
                 d.get("description", ""), d.get("src_ip"), json.dumps(d.get("sources", [])),
                 d.get("started_at"), d.get("last_seen"), d.get("count", 1),
                 d.get("status", "active"), json.dumps(d.get("evidence", {})),
                 1 if d.get("acknowledged") else 0))
            self._conn.commit()

    def list_incidents(self, limit: int = 100, status: str | None = None) -> list[dict]:
        sql = "SELECT * FROM incidents"
        params: list = []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["sources"] = json.loads(d["sources"] or "[]")
            d["evidence"] = json.loads(d["evidence"] or "{}")
            d["acknowledged"] = bool(d["acknowledged"])
            out.append(d)
        return out

    def incident_stats(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT type, severity, COUNT(*) c FROM incidents GROUP BY type, severity"
            ).fetchall()
            active = self._conn.execute(
                "SELECT COUNT(*) c FROM incidents WHERE status='active'").fetchone()["c"]
            total = self._conn.execute("SELECT COUNT(*) c FROM incidents").fetchone()["c"]
        by_type: dict[str, int] = {}
        by_sev: dict[str, int] = {}
        for r in rows:
            by_type[r["type"]] = by_type.get(r["type"], 0) + r["c"]
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + r["c"]
        return {"active": active, "total": total, "by_type": by_type, "by_severity": by_sev}

    # ------------------------------------------------------------------ #
    # blocklist
    # ------------------------------------------------------------------ #

    def add_blocked(self, ip: str, reason: str = "manual", ttl: int = 600,
                    auto: bool = False) -> dict:
        now = time.time()
        expires = now + ttl if ttl > 0 else 0
        with self._lock:
            self._conn.execute(
                "INSERT INTO blocked (ip, reason, created_at, expires_at, active, auto)"
                " VALUES (?,?,?,?,1,?)"
                " ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason,"
                " created_at=excluded.created_at, expires_at=excluded.expires_at,"
                " active=1, auto=excluded.auto",
                (ip, reason, now, expires, 1 if auto else 0))
            self._conn.commit()
        return {"ip": ip, "reason": reason, "created_at": now,
                "expires_at": expires, "active": True, "auto": auto}

    def remove_blocked(self, ip: str) -> bool:
        with self._lock:
            cur = self._conn.execute("UPDATE blocked SET active=0 WHERE ip=?", (ip,))
            self._conn.commit()
            return cur.rowcount > 0

    def list_blocked(self, include_expired: bool = False) -> list[dict]:
        now = time.time()
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, reason, created_at, expires_at, active, auto FROM blocked"
                " ORDER BY created_at DESC").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            if not d["active"]:
                continue
            if not include_expired and d["expires_at"] and d["expires_at"] < now:
                continue
            out.append(d)
        return out

    def is_blocked(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT expires_at, active FROM blocked WHERE ip=?", (ip,)).fetchone()
        if not row or not row["active"]:
            return False
        return not row["expires_at"] or row["expires_at"] > now

    def expire_blocks(self) -> int:
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE blocked SET active=0 WHERE active=1 AND expires_at>0 AND expires_at<?",
                (now,))
            self._conn.commit()
            return cur.rowcount

    # ------------------------------------------------------------------ #
    # maintenance
    # ------------------------------------------------------------------ #

    def prune_events(self, keep_seconds: int = 86400) -> int:
        cutoff = time.time() - keep_seconds
        with self._lock:
            cur = self._conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            self._conn.commit()
            return cur.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()
