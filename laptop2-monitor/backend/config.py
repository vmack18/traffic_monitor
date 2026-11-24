"""
config.py -- runtime configuration for the LAPTOP 2 monitoring backend.

Every value can be overridden with an environment variable, so the same code
runs unchanged on a laptop, in a VM, or inside Docker.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(_env(name, str(default)))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    return _env(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Thresholds:
    """Tuning knobs for the DoS / DDoS detection engine."""

    window_seconds: float = _env_float("TG_WINDOW_SECONDS", 10.0)

    # --- volumetric / rate based ---
    dos_requests_per_ip: int = _env_int("TG_DOS_REQ_PER_IP", 25)
    dos_bytes_per_ip: int = _env_int("TG_DOS_BYTES_PER_IP", 2_000_000)

    # --- distributed ---
    ddos_unique_sources: int = _env_int("TG_DDOS_UNIQUE_SOURCES", 8)
    ddos_total_requests: int = _env_int("TG_DDOS_TOTAL_REQUESTS", 60)

    # --- protocol specific (fed by the packet sniffer) ---
    syn_flood_pps: int = _env_int("TG_SYN_FLOOD_PPS", 100)
    udp_flood_pps: int = _env_int("TG_UDP_FLOOD_PPS", 200)
    icmp_flood_pps: int = _env_int("TG_ICMP_FLOOD_PPS", 100)

    # --- application layer ---
    http_flood_same_path: int = _env_int("TG_HTTP_FLOOD_SAME_PATH", 40)
    slowloris_concurrent: int = _env_int("TG_SLOWLORIS_CONNS", 10)
    port_scan_unique_ports: int = _env_int("TG_PORT_SCAN_PORTS", 15)
    brute_force_failures: int = _env_int("TG_BRUTE_FORCE_FAILS", 10)

    # --- lifecycle ---
    incident_cooldown_seconds: float = _env_float("TG_INCIDENT_COOLDOWN", 20.0)
    incident_resolve_seconds: float = _env_float("TG_INCIDENT_RESOLVE", 45.0)
    series_retention_seconds: int = _env_int("TG_SERIES_RETENTION", 3600)


@dataclass
class Settings:
    host: str = _env("TG_HOST", "0.0.0.0")
    port: int = _env_int("TG_PORT", 8000)
    db_path: str = _env("TG_DB_PATH", os.path.join(os.path.dirname(__file__), "traffic_guard.db"))
    log_level: str = _env("TG_LOG_LEVEL", "INFO")

    # auto-blocking: when the engine raises a high/critical incident the
    # source IP is pushed to the shared blocklist (the Laptop 1 proxy polls it).
    auto_block: bool = _env_bool("TG_AUTO_BLOCK", True)
    auto_block_ttl: int = _env_int("TG_AUTO_BLOCK_TTL", 600)

    # protected server identity (Laptop 1). Shown in the dashboard and used by
    # the "block server IP" shortcut so an operator can quarantine the origin
    # with one click during an incident.
    server_ip: str = _env("TG_SERVER_IP", "192.168.56.10")
    server_label: str = _env("TG_SERVER_LABEL", "Ubuntu Server (VirtualBox)")

    # packet sniffer (requires root + scapy)
    sniffer_enabled: bool = _env_bool("TG_SNIFFER", False)
    sniffer_iface: str = _env("TG_SNIFFER_IFACE", "")
    sniffer_filter: str = _env("TG_SNIFFER_FILTER", "tcp or udp or icmp")

    # demo mode generates a light synthetic baseline so the dashboard is never
    # empty while you are wiring the two laptops together.
    demo_mode: bool = _env_bool("TG_DEMO", False)

    cors_origins: list[str] = field(default_factory=lambda: _env(
        "TG_CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173").split(","))

    thresholds: Thresholds = field(default_factory=Thresholds)


settings = Settings()
