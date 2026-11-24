"""
detector.py -- real-time DoS / DDoS detection engine (LAPTOP 2)
===============================================================

Consumes two streams:

  * application events pushed by the Laptop 1 inline proxy  (ingest_event)
  * raw packet observations from the local sniffer           (observe_packet)

and maintains sliding-window state to raise *incidents*:

  DoS            single source flooding the origin
  DDoS           many sources converging on the origin at once
  SYN flood      TCP SYN packets without completing the handshake
  UDP flood      volumetric UDP
  ICMP flood     ping flood
  HTTP flood     many requests to the same path
  Slowloris      many half-open / partial connections from one source
  Port scan      one source touching many destination ports
  Brute force    repeated 401s from one source
  Malicious      payload matched a signature (SQLi/XSS/malware/...)

Incidents are de-duplicated per (type, key) and auto-resolve when the
activity stops.  The engine is deliberately dependency-free and synchronous;
the FastAPI layer calls it from the event loop (all operations are O(window)).
"""

from __future__ import annotations

import collections
import math
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Callable, Iterable

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_LABEL = {1: "low", 2: "medium", 3: "high", 4: "critical"}


@dataclass
class Incident:
    id: str
    type: str
    severity: str
    title: str
    description: str
    src_ip: str | None
    sources: list[str]
    started_at: float
    last_seen: float
    count: int
    status: str
    evidence: dict = field(default_factory=dict)
    acknowledged: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class _SourceState:
    events: collections.deque = field(default_factory=collections.deque)
    ports: dict = field(default_factory=dict)
    failures: collections.deque = field(default_factory=collections.deque)
    active_connections: int = 0
    last_seen: float = 0.0


class DetectionEngine:
    def __init__(self, thresholds, on_incident: Callable[[Incident], None] | None = None,
                 on_resolve: Callable[[Incident], None] | None = None):
        self.t = thresholds
        self.on_incident = on_incident
        self.on_resolve = on_resolve

        self._sources: dict[str, _SourceState] = {}
        self._global_events: collections.deque = collections.deque()
        self._path_events: dict[str, collections.deque] = {}
        self._active: dict[str, Incident] = {}
        self._cooldown: dict[str, float] = {}

        self._proto = collections.defaultdict(collections.deque)
        self._syn_by_src: dict[str, collections.deque] = {}
        self._udp_by_src: dict[str, collections.deque] = {}
        self._icmp_by_src: dict[str, collections.deque] = {}

        self._series: collections.deque = collections.deque()
        self._bucket: dict | None = None

        self.started_at = time.time()
        self.totals = {"requests": 0, "allowed": 0, "blocked": 0, "bytes": 0,
                       "malicious": 0, "packets": 0}
        self._rule_counter: collections.Counter = collections.Counter()

    # ------------------------------------------------------------------ #
    # window helpers
    # ------------------------------------------------------------------ #

    def _cutoff(self, now: float) -> float:
        return now - self.t.window_seconds

    def _prune_source(self, st: _SourceState, now: float) -> None:
        cutoff = self._cutoff(now)
        while st.events and st.events[0][0] < cutoff:
            st.events.popleft()
        while st.failures and st.failures[0] < cutoff:
            st.failures.popleft()
        for port, ts in list(st.ports.items()):
            if ts < cutoff:
                del st.ports[port]

    def _prune_all(self, now: float) -> None:
        cutoff = self._cutoff(now)
        while self._global_events and self._global_events[0][0] < cutoff:
            self._global_events.popleft()
        for path, dq in list(self._path_events.items()):
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del self._path_events[path]
        for ip, st in list(self._sources.items()):
            self._prune_source(st, now)
            if not st.events and not st.ports and st.active_connections == 0:
                if now - st.last_seen > self.t.window_seconds * 3:
                    del self._sources[ip]
        for name, dq in self._proto.items():
            while dq and dq[0][0] < cutoff:
                dq.popleft()

    # ------------------------------------------------------------------ #
    # incident lifecycle
    # ------------------------------------------------------------------ #

    def _raise(self, key: str, itype: str, severity: str, title: str, description: str,
               src_ip: str | None, sources: Iterable[str], now: float,
               evidence: dict | None = None, increment: int = 1) -> Incident | None:
        existing = self._active.get(key)
        if existing:
            existing.last_seen = now
            existing.count += increment
            existing.description = description
            existing.evidence.update(evidence or {})
            if SEVERITY_ORDER[severity] > SEVERITY_ORDER[existing.severity]:
                existing.severity = severity
            return None

        if now - self._cooldown.get(key, 0) < self.t.incident_cooldown_seconds:
            return None

        incident = Incident(
            id=f"INC-{uuid.uuid4().hex[:10]}",
            type=itype,
            severity=severity,
            title=title,
            description=description,
            src_ip=src_ip,
            sources=sorted(set(sources))[:50],
            started_at=now,
            last_seen=now,
            count=increment,
            status="active",
            evidence=evidence or {},
        )
        self._active[key] = incident
        if self.on_incident:
            self.on_incident(incident)
        return incident

    def resolve_stale(self, now: float | None = None) -> list[Incident]:
        now = now or time.time()
        resolved = []
        for key, inc in list(self._active.items()):
            if now - inc.last_seen > self.t.incident_resolve_seconds:
                inc.status = "resolved"
                inc.evidence["resolved_at"] = now
                del self._active[key]
                self._cooldown[key] = now
                resolved.append(inc)
                if self.on_resolve:
                    self.on_resolve(inc)
        return resolved

    def acknowledge(self, incident_id: str) -> bool:
        for inc in self._active.values():
            if inc.id == incident_id:
                inc.acknowledged = True
                return True
        return False

    # ------------------------------------------------------------------ #
    # traffic series
    # ------------------------------------------------------------------ #

    def _roll_bucket(self, now: float) -> None:
        sec = int(now)
        if self._bucket is None or self._bucket["ts"] != sec:
            if self._bucket is not None:
                self._series.append({
                    "ts": self._bucket["ts"],
                    "requests": self._bucket["requests"],
                    "allowed": self._bucket["allowed"],
                    "blocked": self._bucket["blocked"],
                    "bytes": self._bucket["bytes"],
                    "sources": len(self._bucket["sources"]),
                    "syn": self._bucket["syn"],
                    "udp": self._bucket["udp"],
                })
                cutoff = now - self.t.series_retention_seconds
                while self._series and self._series[0]["ts"] < cutoff:
                    self._series.popleft()
            self._bucket = {"ts": sec, "requests": 0, "allowed": 0, "blocked": 0,
                            "bytes": 0, "sources": set(), "syn": 0, "udp": 0}

    # ------------------------------------------------------------------ #
    # application event ingestion
    # ------------------------------------------------------------------ #

    def ingest_event(self, event: dict) -> list[Incident]:
        now = float(event.get("ts") or time.time())
        src = str(event.get("src_ip") or "0.0.0.0")
        verdict = str(event.get("verdict") or "allow")
        nbytes = int(event.get("bytes_in") or 0)
        path = str(event.get("path") or "")[:120]
        status = int(event.get("status") or 0)
        findings = event.get("findings") or []
        severity = str(event.get("severity") or "none")

        self._roll_bucket(now)
        assert self._bucket is not None
        self._prune_all(now)

        st = self._sources.setdefault(src, _SourceState())
        st.last_seen = now
        st.events.append((now, nbytes, verdict, path, status))
        st.active_connections = int(event.get("active_connections") or st.active_connections)

        self._global_events.append((now, verdict, nbytes))
        self._path_events.setdefault(path, collections.deque()).append(now)

        self.totals["requests"] += 1
        self.totals["bytes"] += nbytes
        if verdict == "block":
            self.totals["blocked"] += 1
            self._bucket["blocked"] += 1
        else:
            self.totals["allowed"] += 1
            self._bucket["allowed"] += 1
        self._bucket["requests"] += 1
        self._bucket["bytes"] += nbytes
        self._bucket["sources"].add(src)

        if status == 401:
            st.failures.append(now)
        if findings:
            self.totals["malicious"] += 1
            for f in findings:
                self._rule_counter[f.get("rule", "?")] += 1

        raised: list[Incident] = []
        inc = self._detect_application(src, st, path, status, findings, severity, now)
        if inc:
            raised.append(inc)
        return raised

    def _detect_application(self, src, st, path, status, findings, severity, now) -> Incident | None:
        # ---- 1. malicious payload (highest priority) ----
        if findings:
            worst = max(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "low"), 1))
            rules = sorted({f.get("rule") for f in findings})
            categories = sorted({f.get("category") for f in findings})
            return self._raise(
                key=f"malicious:{src}", itype="malicious_payload",
                severity=worst.get("severity", "high"),
                title=f"Malicious payload from {src}",
                description=(f"Signature engine matched {len(findings)} rule(s) "
                             f"({', '.join(categories)}) in a request from {src}. "
                             f"Rules: {', '.join(rules[:6])}."),
                src_ip=src, sources=[src], now=now,
                evidence={"rules": rules, "categories": categories,
                          "sample": (worst.get("match") or "")[:200],
                          "path": path},
            )

        # ---- 2. per-source DoS ----
        count = len(st.events)
        if count > self.t.dos_requests_per_ip:
            sev = "critical" if count > self.t.dos_requests_per_ip * 3 else "high"
            return self._raise(
                key=f"dos:{src}", itype="dos", severity=sev,
                title=f"DoS flood from {src}",
                description=(f"{src} sent {count} requests in {self.t.window_seconds:.0f}s "
                             f"(threshold {self.t.dos_requests_per_ip}). The inline proxy is "
                             f"rate-limiting this source."),
                src_ip=src, sources=[src], now=now,
                evidence={"requests_in_window": count,
                          "threshold": self.t.dos_requests_per_ip,
                          "window_seconds": self.t.window_seconds},
            )

        # ---- 3. brute force ----
        if len(st.failures) >= self.t.brute_force_failures:
            return self._raise(
                key=f"brute:{src}", itype="brute_force", severity="high",
                title=f"Credential brute force from {src}",
                description=(f"{len(st.failures)} failed authentication attempts (HTTP 401) "
                             f"from {src} in {self.t.window_seconds:.0f}s."),
                src_ip=src, sources=[src], now=now,
                evidence={"failures": len(st.failures), "path": path},
            )

        # ---- 4. slowloris / connection flood ----
        if st.active_connections >= self.t.slowloris_concurrent:
            return self._raise(
                key=f"slowloris:{src}", itype="slowloris", severity="high",
                title=f"Connection flood / slowloris from {src}",
                description=(f"{src} holds {st.active_connections} concurrent connections "
                             f"(threshold {self.t.slowloris_concurrent})."),
                src_ip=src, sources=[src], now=now,
                evidence={"active_connections": st.active_connections},
            )

        # ---- 5. port scan (from sniffer-fed port map) ----
        if len(st.ports) >= self.t.port_scan_unique_ports:
            return self._raise(
                key=f"scan:{src}", itype="port_scan", severity="medium",
                title=f"Port scan from {src}",
                description=(f"{src} probed {len(st.ports)} distinct destination ports "
                             f"in {self.t.window_seconds:.0f}s."),
                src_ip=src, sources=[src], now=now,
                evidence={"unique_ports": len(st.ports),
                          "ports": sorted(st.ports)[:40]},
            )

        # ---- 6. HTTP flood on a single path ----
        path_count = len(self._path_events.get(path, ()))
        if path and path_count >= self.t.http_flood_same_path:
            return self._raise(
                key=f"httpflood:{path}", itype="http_flood", severity="high",
                title=f"HTTP flood on {path}",
                description=(f"{path_count} requests to {path} in "
                             f"{self.t.window_seconds:.0f}s across all sources."),
                src_ip=None, sources=[s for s in self._sources][:50], now=now,
                evidence={"path": path, "requests": path_count},
            )

        # ---- 7. DDoS fan-in (global) ----
        total = len(self._global_events)
        unique = len(self._sources)
        if unique >= self.t.ddos_unique_sources and total >= self.t.ddos_total_requests:
            sev = "critical" if unique >= self.t.ddos_unique_sources * 2 else "high"
            top = sorted(((ip, len(s.events)) for ip, s in self._sources.items()),
                         key=lambda x: x[1], reverse=True)[:10]
            return self._raise(
                key="ddos:global", itype="ddos", severity=sev,
                title="Distributed Denial of Service (DDoS)",
                description=(f"{unique} distinct source IPs generated {total} requests in "
                             f"{self.t.window_seconds:.0f}s. This is a coordinated "
                             f"multi-source flood, not a single misbehaving client."),
                src_ip=None, sources=[ip for ip, _ in top], now=now,
                evidence={"unique_sources": unique, "total_requests": total,
                          "top_sources": [{"ip": ip, "requests": n} for ip, n in top]},
                increment=1,
            )

        # ---- 8. volumetric bytes from one source ----
        src_bytes = sum(e[1] for e in st.events)
        if src_bytes > self.t.dos_bytes_per_ip:
            return self._raise(
                key=f"volumetric:{src}", itype="dos", severity="medium",
                title=f"Volumetric flood from {src}",
                description=(f"{src} pushed {src_bytes/1_000_000:.2f} MB in "
                             f"{self.t.window_seconds:.0f}s."),
                src_ip=src, sources=[src], now=now,
                evidence={"bytes_in_window": src_bytes},
            )
        return None

    # ------------------------------------------------------------------ #
    # packet observation (sniffer)
    # ------------------------------------------------------------------ #

    def observe_packet(self, pkt: dict) -> list[Incident]:
        now = float(pkt.get("ts") or time.time())
        src = str(pkt.get("src_ip") or "0.0.0.0")
        proto = str(pkt.get("proto") or "TCP").upper()
        flags = str(pkt.get("flags") or "")
        dst_port = int(pkt.get("dst_port") or 0)

        self._roll_bucket(now)
        assert self._bucket is not None
        self._prune_all(now)
        self.totals["packets"] += 1

        st = self._sources.setdefault(src, _SourceState())
        st.last_seen = now
        if dst_port:
            st.ports[dst_port] = now

        raised: list[Incident] = []
        if proto == "TCP" and "S" in flags and "A" not in flags:
            dq = self._syn_by_src.setdefault(src, collections.deque())
            dq.append(now)
            self._bucket["syn"] += 1
            self._proto["syn"].append((now, 1))
            cutoff = self._cutoff(now)
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.t.syn_flood_pps:
                inc = self._raise(
                    key=f"syn:{src}", itype="syn_flood", severity="high",
                    title=f"SYN flood from {src}",
                    description=(f"{len(dq)} TCP SYN packets from {src} in "
                                 f"{self.t.window_seconds:.0f}s without completing the "
                                 f"handshake (threshold {self.t.syn_flood_pps})."),
                    src_ip=src, sources=[src], now=now,
                    evidence={"syn_in_window": len(dq), "threshold": self.t.syn_flood_pps},
                )
                if inc:
                    raised.append(inc)
        elif proto == "UDP":
            dq = self._udp_by_src.setdefault(src, collections.deque())
            dq.append(now)
            self._bucket["udp"] += 1
            self._proto["udp"].append((now, 1))
            cutoff = self._cutoff(now)
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.t.udp_flood_pps:
                inc = self._raise(
                    key=f"udp:{src}", itype="udp_flood", severity="high",
                    title=f"UDP flood from {src}",
                    description=(f"{len(dq)} UDP datagrams from {src} in "
                                 f"{self.t.window_seconds:.0f}s (threshold {self.t.udp_flood_pps})."),
                    src_ip=src, sources=[src], now=now,
                    evidence={"udp_in_window": len(dq)},
                )
                if inc:
                    raised.append(inc)
        elif proto == "ICMP":
            dq = self._icmp_by_src.setdefault(src, collections.deque())
            dq.append(now)
            cutoff = self._cutoff(now)
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.t.icmp_flood_pps:
                inc = self._raise(
                    key=f"icmp:{src}", itype="icmp_flood", severity="medium",
                    title=f"ICMP flood from {src}",
                    description=f"{len(dq)} ICMP packets from {src} in {self.t.window_seconds:.0f}s.",
                    src_ip=src, sources=[src], now=now,
                    evidence={"icmp_in_window": len(dq)},
                )
                if inc:
                    raised.append(inc)
        return raised

    # ------------------------------------------------------------------ #
    # dashboard snapshot
    # ------------------------------------------------------------------ #

    def snapshot(self, now: float | None = None) -> dict:
        now = now or time.time()
        self._prune_all(now)
        window = self.t.window_seconds
        total = len(self._global_events)
        unique = len(self._sources)
        blocked = sum(1 for e in self._global_events if e[1] == "block")
        nbytes = sum(e[2] for e in self._global_events)

        top_sources = []
        for ip, st in self._sources.items():
            if not st.events:
                continue
            b = sum(1 for e in st.events if e[2] == "block")
            top_sources.append({
                "ip": ip,
                "requests": len(st.events),
                "blocked": b,
                "bytes": sum(e[1] for e in st.events),
                "last_seen": st.last_seen,
            })
        top_sources.sort(key=lambda x: x["requests"], reverse=True)

        top_paths = sorted(((p, len(dq)) for p, dq in self._path_events.items()),
                           key=lambda x: x[1], reverse=True)[:10]

        series = list(self._series)[-180:]
        if self._bucket:
            series.append({
                "ts": self._bucket["ts"], "requests": self._bucket["requests"],
                "allowed": self._bucket["allowed"], "blocked": self._bucket["blocked"],
                "bytes": self._bucket["bytes"], "sources": len(self._bucket["sources"]),
                "syn": self._bucket["syn"], "udp": self._bucket["udp"],
            })

        incidents = sorted(self._active.values(), key=lambda i: i.last_seen, reverse=True)
        risk = self._risk_score(total, unique, blocked, incidents)

        return {
            "ts": now,
            "uptime_seconds": round(now - self.started_at, 1),
            "window_seconds": window,
            "totals": dict(self.totals),
            "window": {
                "requests": total,
                "unique_sources": unique,
                "blocked": blocked,
                "bytes": nbytes,
                "requests_per_sec": round(total / window, 2),
                "blocked_per_sec": round(blocked / window, 2),
                "bytes_per_sec": round(nbytes / window, 1),
            },
            "protocol": {
                "syn_per_sec": round(sum(c for _, c in self._proto["syn"]) / window, 2),
                "udp_per_sec": round(sum(c for _, c in self._proto["udp"]) / window, 2),
            },
            "top_sources": top_sources[:12],
            "top_paths": [{"path": p, "requests": n} for p, n in top_paths],
            "top_rules": [{"rule": r, "count": n} for r, n in self._rule_counter.most_common(10)],
            "series": series,
            "active_incidents": [i.to_dict() for i in incidents],
            "risk_score": risk,
            "health": ("under_attack" if risk >= 70 else
                       "elevated" if risk >= 35 else "normal"),
        }

    def _risk_score(self, total: int, unique: int, blocked: int,
                    incidents: list[Incident]) -> int:
        score = 0.0
        if self.t.dos_requests_per_ip:
            score += min(35, (total / max(self.t.ddos_total_requests, 1)) * 20)
        if self.t.ddos_unique_sources:
            score += min(25, (unique / max(self.t.ddos_unique_sources, 1)) * 15)
        if total:
            score += min(15, (blocked / total) * 20)
        for inc in incidents:
            score += {"low": 3, "medium": 6, "high": 10, "critical": 15}.get(inc.severity, 0)
        return int(min(100, round(score)))

    # ------------------------------------------------------------------ #
    # misc
    # ------------------------------------------------------------------ #

    def rule_counts(self) -> dict:
        return dict(self._rule_counter)

    def reset(self) -> None:
        self.__init__(self.t, self.on_incident, self.on_resolve)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
