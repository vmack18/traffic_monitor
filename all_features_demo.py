#!/usr/bin/env python3
"""Show TrafficGuard detections on the local dashboard using synthetic events.

The demo only calls a backend on this machine. It does not send attack traffic
to the proxy or to any other host. Packet-level detections still require the
optional Scapy sensor to observe packets on its configured interface.
"""

from __future__ import annotations

import argparse
import importlib
import ipaddress
import json
import math
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent
BACKEND_DIR = ROOT / "laptop2-monitor" / "backend"
sys.path.insert(0, str(BACKEND_DIR))
payload_inspector = importlib.import_module("malicious")

MAX_DEMO_EVENTS = 1000
MAX_TEST_SOURCES = 254
TEST_SOURCE_BASE = ipaddress.ip_address("198.51.100.1")

REGEX_DEMO_PAYLOADS = {
    "SQLI-001": "id=1' OR '1'='1",
    "SQLI-002": "1 UNION SELECT username FROM users",
    "SQLI-003": "sleep(5)",
    "SQLI-004": "information_schema",
    "SQLI-005": "'--",
    "SQLI-006": "concat(1,2)",
    "XSS-001": "<script>alert(1)</script>",
    "XSS-002": "javascript:alert(1)",
    "XSS-003": "onerror=alert(1)",
    "XSS-004": "<iframe src=x>",
    "XSS-005": "document.cookie",
    "TRAV-001": "../../etc/passwd",
    "TRAV-002": "/etc/passwd",
    "CMDI-001": "; id",
    "CMDI-002": "$(id)",
    "CMDI-003": "`id`",
    "SSRF-001": "http://127.0.0.1/",
    "SSRF-002": "file:///etc/passwd",
    "XXE-001": '<!ENTITY x SYSTEM "file:///etc/passwd">',
    "SSTI-001": "{{7*7}}",
    "LOG4J-001": "${jndi:ldap://example.invalid/a}",
    "CRLF-001": "%0d%0aSet-Cookie:demo=value",
    "SMUG-001": "Transfer-Encoding: chunked Content-Length: 1",
    "WEBSHELL-001": "system('id')",
    "WEBSHELL-002": "base64_decode('dGVzdA==')",
    "REVSH-001": "/dev/tcp/127.0.0.1/4444",
    "SCAN-001": "sqlmap",
    "SCAN-002": "/probe.php?x=/etc/passwd",
}


def local_backend_url(value: str) -> str:
    """Reject non-local destinations so the demo cannot target remote systems."""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise argparse.ArgumentTypeError("backend must be an http(s) URL")
    if parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise argparse.ArgumentTypeError(
            "backend URL must not include credentials, a path, query, or fragment"
        )

    hostname = parsed.hostname.lower()
    try:
        is_loopback = hostname == "localhost" or ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        is_loopback = False
    if not is_loopback:
        raise argparse.ArgumentTypeError("backend must resolve to localhost or a loopback IP")
    return value.rstrip("/")


def api_call(base_url: str, path: str, method: str = "GET",
             payload: dict | None = None, timeout: float = 10.0) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    request = Request(
        f"{base_url}{path}",
        data=body,
        method=method,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    with urlopen(request, timeout=timeout) as response:
        result = json.loads(response.read())
    if not isinstance(result, dict):
        raise RuntimeError(f"Unexpected response from {path}: expected a JSON object")
    return result


def source_ip(index: int) -> str:
    if index < 0:
        raise ValueError("demo source index cannot be negative")
    return str(TEST_SOURCE_BASE + index % MAX_TEST_SOURCES)


def make_event(src_ip: str, *, path: str = "/demo", status: int = 200,
               bytes_in: int = 512, findings: list[dict] | None = None,
               active_connections: int = 0, verdict: str | None = None,
               reason: str | None = None) -> dict:
    findings = findings or []
    actual_verdict = verdict or ("block" if findings else "allow")
    return {
        "ts": time.time(),
        "source": "all-features-demo",
        "sensor": "synthetic-demo",
        "event_type": "request",
        "src_ip": src_ip,
        "src_port": 40000,
        "dst_ip": "127.0.0.1",
        "dst_port": 9000,
        "proto": "TCP",
        "method": "POST" if status == 401 else "GET",
        "path": path,
        "bytes_in": bytes_in,
        "verdict": actual_verdict,
        "reason": reason or ("malicious_payload" if findings else "demo"),
        "severity": max(
            (f.get("severity", "low") for f in findings),
            key=lambda severity: {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0),
            default="none",
        ),
        "findings": findings,
        "status": status if status != 200 or actual_verdict != "block" else 403,
        "latency_ms": 1,
        "active_connections": active_connections,
    }


def reset_engine(base_url: str, timeout: float) -> None:
    api_call(base_url, "/api/engine/reset", method="POST", payload={}, timeout=timeout)


def run_scenario(base_url: str, label: str, events: list[dict], timeout: float,
                 expected_incident: str | None = None) -> list[dict]:
    reset_engine(base_url, timeout)
    accepted = 0
    incidents: list[dict] = []
    for offset in range(0, len(events), 100):
        batch = events[offset:offset + 100]
        result = api_call(
            base_url, "/api/events", method="POST",
            payload={"events": batch}, timeout=timeout,
        )
        accepted += int(result.get("accepted", 0))
        incidents.extend(result.get("incidents", []))

    if accepted != len(events):
        raise RuntimeError(f"{label}: backend accepted {accepted}/{len(events)} events")
    incident_types = sorted({str(incident.get("type")) for incident in incidents})
    if expected_incident and expected_incident not in incident_types:
        raise RuntimeError(
            f"{label}: expected a {expected_incident!r} incident, got {incident_types!r}"
        )
    suffix = f" -> {', '.join(incident_types)} incident" if incident_types else ""
    print(f"[demo] {label}: {accepted} synthetic event(s){suffix}")
    return incidents


def scenario_events(count: int, make_one) -> list[dict]:
    if count > MAX_DEMO_EVENTS:
        raise ValueError(
            f"configured threshold requires {count} events; "
            f"demo limit is {MAX_DEMO_EVENTS}"
        )
    return [make_one(index) for index in range(count)]


def regex_demo_events() -> list[dict]:
    rules = {rule.rule_id: rule for rule in payload_inspector.REGEX_RULES}
    missing_samples = sorted(set(rules) - set(REGEX_DEMO_PAYLOADS))
    stale_samples = sorted(set(REGEX_DEMO_PAYLOADS) - set(rules))
    if missing_samples or stale_samples:
        raise RuntimeError(
            f"regex demo samples do not match REGEX_RULES; "
            f"missing={missing_samples}, stale={stale_samples}"
        )

    events = []
    for index, rule in enumerate(payload_inspector.REGEX_RULES):
        sample = REGEX_DEMO_PAYLOADS[rule.rule_id]
        findings = payload_inspector.inspect(
            body=sample.encode("utf-8"),
            path=f"/demo/regex/{rule.rule_id}",
            method="POST",
        )
        matched_rules = {finding.get("rule") for finding in findings}
        if rule.rule_id not in matched_rules:
            raise RuntimeError(
                f"sample for {rule.rule_id} did not match its detector: {sample!r}"
            )
        events.append(make_event(
            source_ip(index + 1),
            path=f"/demo/regex/{rule.rule_id}",
            status=403,
            findings=findings,
            verdict="block",
            reason="malicious_payload",
        ))
    return events


def show_blocklist_rejection(base_url: str, src_ip: str, label: str,
                             timeout: float) -> None:
    event = make_event(
        src_ip,
        path="/demo/blocked-by-blocklist",
        status=403,
        verdict="block",
        reason="blocklist",
    )
    run_scenario(
        base_url, label, [event], timeout,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Show TrafficGuard detections on the local dashboard"
    )
    parser.add_argument(
        "--backend",
        type=local_backend_url,
        default="http://127.0.0.1:8000",
        help="local monitor backend URL (default: http://127.0.0.1:8000)",
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--pause", type=float, default=1.0,
                        help="seconds between demo scenarios")
    args = parser.parse_args()
    if args.timeout <= 0 or args.pause < 0:
        parser.error("--timeout must be positive and --pause cannot be negative")

    try:
        health = api_call(args.backend, "/api/health", timeout=args.timeout)
        if health.get("status") != "ok":
            raise RuntimeError(f"backend health check failed: {health!r}")
        config = api_call(args.backend, "/api/config", timeout=args.timeout)
        thresholds = config.get("thresholds", {})
        rules = api_call(args.backend, "/api/rules", timeout=args.timeout)
        auto_block = bool(config.get("auto_block", False))

        print("TrafficGuard local feature demo")
        print(f"Backend: {args.backend}")
        print(f"Regex rules available: {len(rules.get('regex_rules', []))}")
        sniffer = health.get("sniffer", {})
        print(f"Packet sniffer: {'running' if sniffer.get('running') else 'not running'}")
        print("Synthetic sources use the documentation-only 198.51.100.0/24 range.")

        run_scenario(
            args.backend,
            "Allowed baseline",
            [make_event(source_ip(i), path=f"/demo/normal/{i}") for i in range(3)],
            args.timeout,
        )
        if args.pause:
            time.sleep(args.pause)

        regex_events = regex_demo_events()
        run_scenario(
            args.backend,
            f"All regex attack signatures ({len(regex_events)} rules)",
            regex_events,
            args.timeout,
            expected_incident="malicious_payload",
        )
        if args.pause:
            time.sleep(args.pause)

        dos_limit = int(thresholds.get("dos_requests_per_ip", 25))
        if 0 < dos_limit < MAX_DEMO_EVENTS:
            run_scenario(
                args.backend, "Per-source DoS threshold",
                scenario_events(
                    dos_limit + 1,
                    lambda i: make_event(
                        source_ip(220),
                        path=f"/demo/dos/{i}",
                        status=429 if i == dos_limit else 200,
                        verdict="block" if i == dos_limit else "allow",
                        reason="rate_limit" if i == dos_limit else "demo",
                    ),
                ),
                args.timeout,
                expected_incident="dos",
            )
        else:
            print(f"[demo] Skipping per-source DoS: configured threshold {dos_limit} is too high")
            run_scenario(
                args.backend, "Rate-limit rejection",
                [make_event(
                    source_ip(222), path="/demo/rate-limit", status=429,
                    verdict="block", reason="rate_limit",
                )],
                args.timeout,
            )
        if args.pause:
            time.sleep(args.pause)

        brute_limit = int(thresholds.get("brute_force_failures", 10))
        if 0 < brute_limit <= MAX_DEMO_EVENTS:
            run_scenario(
                args.backend, "Repeated authentication failures",
                scenario_events(
                    brute_limit,
                    lambda i: make_event(source_ip(30), path=f"/demo/login/{i}", status=401),
                ),
                args.timeout,
                expected_incident="brute_force",
            )
        else:
            print(f"[demo] Skipping brute-force scenario: invalid or excessive threshold {brute_limit}")
        if args.pause:
            time.sleep(args.pause)

        slow_limit = int(thresholds.get("slowloris_concurrent", 10))
        run_scenario(
            args.backend, "Concurrent-connection threshold",
            [make_event(source_ip(40), path="/demo/connections",
                        status=429, verdict="block", reason="connection_flood",
                        active_connections=max(slow_limit, 1))],
            args.timeout,
            expected_incident="slowloris" if slow_limit > 0 else None,
        )
        if args.pause:
            time.sleep(args.pause)

        path_limit = int(thresholds.get("http_flood_same_path", 40))
        dos_limit = max(dos_limit, 1)
        if 0 < path_limit <= MAX_DEMO_EVENTS:
            source_count = min(MAX_TEST_SOURCES, max(1, math.ceil(path_limit / dos_limit)))
            run_scenario(
                args.backend, "Same-path HTTP flood threshold",
                scenario_events(
                    path_limit,
                    lambda i: make_event(
                        source_ip(50 + i % source_count), path="/demo/repeated-path"
                    ),
                ),
                args.timeout,
                expected_incident="http_flood",
            )
        else:
            print(f"[demo] Skipping HTTP flood scenario: invalid or excessive threshold {path_limit}")
        if args.pause:
            time.sleep(args.pause)

        ddos_total = int(thresholds.get("ddos_total_requests", 60))
        ddos_sources = int(thresholds.get("ddos_unique_sources", 8))
        ddos_event_count = max(ddos_total, ddos_sources)
        if (0 < ddos_event_count <= MAX_DEMO_EVENTS
                and 0 < ddos_sources <= MAX_TEST_SOURCES):
            source_count = max(ddos_sources, math.ceil(ddos_event_count / dos_limit))
            if source_count <= MAX_TEST_SOURCES:
                run_scenario(
                    args.backend, "Distributed-source threshold",
                    scenario_events(
                        ddos_event_count,
                        lambda i: make_event(
                            source_ip(100 + i % source_count),
                            path=f"/demo/distributed/{i}",
                        ),
                    ),
                    args.timeout,
                    expected_incident="ddos",
                )
            else:
                print("[demo] Skipping DDoS scenario: configured thresholds require too many test sources")
        else:
            print("[demo] Skipping DDoS scenario: configured thresholds exceed safe demo limits")
        if args.pause:
            time.sleep(args.pause)

        byte_limit = int(thresholds.get("dos_bytes_per_ip", 2_000_000))
        run_scenario(
            args.backend, "Per-source byte-volume threshold",
            [make_event(source_ip(221), path="/demo/volume", bytes_in=byte_limit + 1)],
            args.timeout,
            expected_incident="dos",
        )

        auto_source = source_ip(1)
        blocked_data = api_call(args.backend, "/api/blocked", timeout=args.timeout)
        auto_blocked_ips = {
            entry.get("ip") for entry in blocked_data.get("blocked", [])
            if entry.get("active", True)
        }
        if auto_block and auto_source in auto_blocked_ips:
            show_blocklist_rejection(
                args.backend, auto_source, "Request rejected by automatic blocklist", args.timeout
            )
        else:
            print("[demo] Automatic blocklist example unavailable "
                  "(auto-block disabled or no active block was created)")

        manual_ip = source_ip(253)
        manual_block = api_call(
            args.backend, "/api/blocked", method="POST",
            payload={"ip": manual_ip, "reason": "demo:manual-block", "ttl": 600},
            timeout=args.timeout,
        )
        if manual_block.get("ip") != manual_ip:
            raise RuntimeError(f"manual block API did not block {manual_ip}")
        show_blocklist_rejection(
            args.backend, manual_ip, "Request rejected after manual IP block", args.timeout
        )

        context = api_call(
            args.backend, "/api/context/blocked?limit=300", timeout=args.timeout
        )
        displayed_rules = {
            finding.get("rule")
            for event in context.get("recent", [])
            for finding in event.get("findings", [])
        }
        expected_rules = {rule.rule_id for rule in payload_inspector.REGEX_RULES}
        missing_displayed_rules = sorted(expected_rules - displayed_rules)
        if missing_displayed_rules:
            raise RuntimeError(
                "Blocked Request Context is missing regex findings: "
                + ", ".join(missing_displayed_rules)
            )
        displayed_reasons = {event.get("reason") for event in context.get("recent", [])}
        expected_reasons = {
            "malicious_payload", "rate_limit", "connection_flood", "blocklist",
        }
        missing_reasons = sorted(expected_reasons - displayed_reasons)
        if missing_reasons:
            raise RuntimeError(
                "Blocked Request Context is missing block methods: "
                + ", ".join(missing_reasons)
            )
        print(
            f"[demo] Blocked Request Context includes all "
            f"{len(expected_rules)} regex rule signatures."
        )

        print("\n[demo] Finished. Open http://localhost:3000 to review the dashboard.")
        print("[demo] Block methods shown: malicious signatures, rate limits, "
              "connection caps, automatic blocks, and manual blocks.")
        print("[demo] Packet floods and port scans are passive Scapy-sensor features;")
        print("[demo] this script does not generate raw packets or send traffic to the proxy.")
        return 0
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, RuntimeError, ValueError) as exc:
        print(f"[demo] Failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
