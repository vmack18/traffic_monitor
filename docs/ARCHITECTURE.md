# TrafficGuard — Architecture

This document describes how TrafficGuard is put together, how a single request travels through it, and how the detection engines make decisions.

## 1. Design goals

1. **Inline, not passive.** Detection must happen *before* the protected server, so a blocked request never reaches it. The origin binds to loopback and is unreachable except through the proxy.
2. **Two machines.** The protected side (Laptop 1, Ubuntu Server VM) and the monitoring side (Laptop 2, Node/TypeScript + Python) are separate processes on separate hosts, communicating over a small HTTP event API.
3. **No framework in the hot path.** The proxy and origin are written directly on top of `asyncio` streams so every byte and every connection can be inspected.
4. **Fail open for telemetry, fail closed for traffic.** If the monitoring backend is unreachable, the proxy keeps protecting the origin and simply drops telemetry (bounded queue). If the proxy itself is down, the origin is unreachable — which is the correct failure mode for an inline gate.

## 2. Components

### 2.1 Protected origin — `protected_server.py`

A minimal HTTP/1.1 server built on `asyncio.start_server`. It binds to `127.0.0.1:9000` by default. It implements a handful of endpoints (`/`, `/health`, `/api/data`, `POST /login`, `POST /upload`) and returns `Connection: close` on every response, serving exactly one request per TCP connection. It keeps counters for requests, connections, bytes in/out and uptime.

The origin deliberately has no detection logic. Its only job is to be the thing worth protecting, and to be reachable only from the proxy.

### 2.2 Inline detection proxy — `detection_proxy.py`

The heart of Laptop 1. For each accepted connection it runs a fixed pipeline:

```
accept connection
   │
   ├─ 1. blocklist check ............ if blocked -> 403, report, close
   ├─ 2. connection-flood check ..... if over cap -> 429, maybe block, report, close
   ├─ 3. read request (framing) ..... slowloris timeout -> drop
   ├─ 4. rate-limit window .......... per-IP + global; over -> 429, maybe block
   ├─ 5. malicious inspection ....... verdict=block -> 403, maybe block
   └─ 6. forward to origin .......... relay response; report allow
```

Supporting structures:

- **`SlidingWindow`** — a timestamp deque with `add`, `count`, `total`, `prune`. Used twice: once keyed by source IP, once with a single `__global__` key.
- **`BlockList`** — TTL entries, a local set plus a remote set synced from the dashboard every few seconds. `is_blocked` consults both.
- **`MonitorReporter`** — an `asyncio.Queue` of events. A background task drains it in batches of up to 50 and POSTs to `/api/events` from a worker thread (`asyncio.to_thread`) so a slow backend never blocks the event loop. The queue is bounded; overflow increments a `dropped` counter rather than applying backpressure to traffic.
- **`read_request`** — reads until `\r\n\r\n`, enforcing `max_payload_bytes` and a header timeout. A timeout produces a synthetic `x-partial` marker so slowloris attempts are still reported.
- **`_read_response`** — parses the upstream response, honouring `Content-Length` and `Transfer-Encoding: chunked`, with an idle-gap fallback. This replaced a naive drain-to-EOF loop that caused spurious `504`s when the origin kept the socket open.

Each event carries: `ts`, `source`, `sensor`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `proto`, `method`, `path`, `bytes_in`, `verdict`, `reason`, `severity`, `findings`, `status`, `latency_ms`, and extras such as `requests_in_window`, `global_in_window`, `upstream_ms`.

### 2.3 Monitoring backend — `main.py`, `detector.py`, `database.py`, `sniffer.py`

A FastAPI application on `:8000`.

- **`main.py`** wires everything together: it creates the `Database`, the `DetectionEngine`, and (optionally) the `PacketSniffer`; it exposes the REST API; and it runs an asyncio broadcaster that sends a full snapshot to every WebSocket client once per second, plus pushed `incident`, `incident_resolved`, `events`, `packet_alert` and `blocklist_changed` messages. On startup it launches background tasks for the broadcaster, the sniffer, optional demo traffic, and periodic maintenance (expire blocks, prune old events).
- **`detector.py`** is the analytics brain (see §4).
- **`database.py`** is a thread-safe SQLite store in WAL mode with four tables: `events`, `incidents`, `blocked`, `meta`, and indexes on time, source and verdict.
- **`sniffer.py`** is an optional Scapy sensor running in a background thread. It parses IP/TCP/UDP/ICMP into the same event shape and feeds `observe_packet` and the malicious engine. It degrades gracefully when Scapy or raw-socket privileges are unavailable.

### 2.4 Dashboard — `frontend/`

A Node.js + TypeScript tier with two responsibilities:

- **`src/server.ts`** serves the static UI from `public/`, reverse-proxies `/api/**` to the Python backend with `http-proxy-middleware` (root-mounted with a `pathFilter` so the full path is preserved), and bridges `/ws` with a small `ws`-based proxy that pairs each browser socket with a backend socket and relays frames both ways.
- **`public/`** is a dependency-free single-page app: `index.html`, `css/styles.css`, and `js/app.js`. The client connects to `/ws`, applies each snapshot to the DOM, draws the live chart on a `<canvas>` (no chart library), renders the threat gauge with an SVG arc, and maintains the incident feed, packet table, top lists and blocked-IP list. It auto-reconnects with exponential backoff and falls back to REST polling for events and blocks.

## 3. Request lifecycle (sequence)

```
Client            Proxy                    Origin              Backend            Dashboard
  │                 │                        │                   │                  │
  │──TCP SYN───────▶│                        │                   │                  │
  │──HTTP request──▶│                        │                   │                  │
  │                 │ blocklist? flood?      │                   │                  │
  │                 │ rate window?           │                   │                  │
  │                 │ malicious inspect?     │                   │                  │
  │                 │                        │                   │                  │
  │                 │──forward (if clean)───▶│                   │                  │
  │                 │◀────response───────────│                   │                  │
  │◀──response──────│                        │                   │                  │
  │                 │──event (batched POST)─────────────────────▶│                  │
  │                 │                        │                   │──snapshot (1/s)─▶│
  │                 │                        │                   │──incident push──▶│
```

For a blocked request, steps 5–6 are replaced by a `403`/`429` JSON response with `X-Blocked-By: traffic-guard`, and an event with `verdict=block` is reported.

## 4. Detection engine

### 4.1 State

The engine keeps, per source IP, a `_SourceState`:

- `events`: a deque of `(ts, bytes, verdict, path, status)` inside the window,
- `ports`: a dict of destination port → last-seen time,
- `failures`: a deque of 401 timestamps,
- `active_connections`: the latest reported concurrency,
- `last_seen`.

It also keeps a global event list, per-path deques, per-second buckets (for the chart series), protocol counters (SYN/UDP), and a rule counter.

### 4.2 Ordered checks (`_detect_application`)

For every ingested event the engine evaluates, in order:

1. **Malicious payload** — any `findings` produce a `malicious_payload` incident whose severity is the highest finding severity.
2. **Per-IP DoS** — `len(events) >= dos_requests_per_ip` within the window.
3. **Brute force** — `len(failures) >= brute_force_failures`.
4. **Slowloris** — `active_connections >= slowloris_concurrent`.
5. **Port scan** — `len(ports) >= port_scan_unique_ports`.
6. **HTTP flood** — same path count `>= http_flood_same_path`.
7. **DDoS fan-in** — `unique_sources >= ddos_unique_sources` **and** `total_requests >= ddos_total_requests`.
8. **Volumetric** — per-IP bytes `>= dos_bytes_per_ip`.

Raw packet observations add `syn_flood`, `udp_flood` and `icmp_flood` checks against per-second packet rates.

### 4.3 Incident lifecycle

`_raise(key, type, severity, title, description, src_ip, sources, now, evidence)`:

- computes a stable `id` from the dedup key,
- if an incident with that key is already active, increments its `count`, updates `last_seen`, and **escalates severity** if the new severity is higher,
- otherwise creates a new `Incident` and invokes the `on_incident` callback (which persists it, auto-blocks the source, and queues a WebSocket push),
- applies a cooldown so the same key cannot spam new incidents.

`resolve_stale` marks incidents resolved after `incident_resolve_seconds` of inactivity and invokes `on_resolve`. Operators can `acknowledge` an incident, which is persisted.

### 4.4 Risk score and health

`_risk_score` blends the active-incident severities, the blocked ratio and the source fan-in into a 0–100 score. The snapshot maps it to `health`:

- `>= 70` → `under_attack`
- `>= 35` → `elevated`
- otherwise → `normal`

The dashboard renders the same thresholds in the threat gauge.

### 4.5 Snapshot shape

`snapshot()` returns:

```json
{
  "ts": 0, "uptime_seconds": 0, "window_seconds": 10,
  "totals": {"requests": 0, "allowed": 0, "blocked": 0, "bytes": 0, "malicious": 0, "packets": 0},
  "window": {"requests": 0, "unique_sources": 0, "blocked": 0, "bytes": 0,
             "requests_per_sec": 0, "blocked_per_sec": 0, "bytes_per_sec": 0},
  "protocol": {"syn_per_sec": 0, "udp_per_sec": 0},
  "top_sources": [{"ip": "", "requests": 0, "blocked": 0, "bytes": 0, "last_seen": 0}],
  "top_paths": [{"path": "", "requests": 0}],
  "top_rules": [{"rule": "", "count": 0}],
  "series": [{"ts": 0, "requests": 0, "allowed": 0, "blocked": 0, "bytes": 0,
              "sources": 0, "syn": 0, "udp": 0}],
  "active_incidents": [ /* incident dicts */ ],
  "risk_score": 0,
  "health": "normal"
}
```

## 5. Malicious-content engine

`inspect(headers, body, path, method)` builds a list of finding dicts:

```json
{"rule": "SQLI-001", "category": "sqli", "severity": "critical",
 "detail": "...", "field": "path", "match": "..."}
```

It scans the request target, every header value, and the body as text and as raw bytes. It then URL-decodes and base64-decodes candidate blobs (depth 2) and rescans, so double-encoded attacks are caught. `summarize(findings)` returns `(verdict, severity)` where `verdict` is `block` if any finding is at or above `min_block_severity`, otherwise `allow`. The same module runs on the proxy (inline blocking) and on the backend (defence in depth and packet payload scanning).

## 6. Data model

```sql
events(id, ts, src_ip, src_port, dst_ip, dst_port, proto, method, path,
       verdict, reason, severity, status, bytes_in, latency_ms, findings, sensor)
incidents(id, type, severity, title, description, src_ip, sources,
          started_at, last_seen, count, status, evidence, acknowledged)
blocked(ip, reason, added_at, expires_at, source)
meta(key, value)
```

Events are pruned periodically; blocks expire on their TTL. The dashboard's blocked-IP list is the source of truth for the remote blocklist that the proxy polls.

## 7. Failure modes

| Failure | Behaviour |
|---------|-----------|
| Backend down | Proxy keeps filtering; reporter queue drops telemetry when full. |
| Proxy down | Origin is unreachable (inline gate fails closed). |
| Origin down | Proxy returns `502` and reports it. |
| WebSocket drops | Dashboard reconnects with backoff and falls back to REST polling. |
| Scapy unavailable | Backend runs without packet-level sensors. |
| Malformed request | Proxy rejects/drops and reports `RAW` if it can parse the line. |
