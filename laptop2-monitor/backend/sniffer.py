"""
sniffer.py -- optional packet-level sensor (LAPTOP 2)
=====================================================

The inline proxy on Laptop 1 sees *application* traffic.  This module adds a
second, network-level sensor using Scapy so the monitor can also detect
SYN floods, UDP floods, ICMP floods and port scans that never reach the proxy.

It is entirely optional:

  * needs root / CAP_NET_RAW
  * needs scapy  (pip install scapy)
  * if either is missing the backend simply runs in proxy-only mode

The sniffer runs in a background thread and pushes parsed packets into the
detection engine.  Payloads are also handed to the malicious-content engine,
so a suspicious byte pattern inside a TCP segment raises an incident even if
it was never sent through the HTTP proxy.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

LOG = logging.getLogger("sniffer")

try:  # pragma: no cover - depends on the host
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, Raw, sniff  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover
    SCAPY_AVAILABLE = False
    LOG.warning("scapy not available - packet sniffer disabled")


class PacketSniffer:
    def __init__(self, engine,
                 iface: str | None = None,
                 bpf_filter: str = "tcp or udp or icmp",
                 on_malicious: Callable[[dict, list[dict]], None] | None = None):
        self.engine = engine
        self.iface = iface or None
        self.bpf_filter = bpf_filter
        self.on_malicious = on_malicious
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.running = False
        self.error: str | None = None
        self.packets_seen = 0
        self.bytes_seen = 0
        self.last_packet_ts = 0.0

    # ------------------------------------------------------------------ #

    def start(self) -> bool:
        if not SCAPY_AVAILABLE:
            self.error = "scapy not installed"
            return False
        self._thread = threading.Thread(target=self._run, name="packet-sniffer", daemon=True)
        self._thread.start()
        self.running = True
        return True

    def stop(self) -> None:
        self._stop.set()
        self.running = False

    def status(self) -> dict:
        return {
            "available": SCAPY_AVAILABLE,
            "running": self.running,
            "interface": self.iface or "default",
            "filter": self.bpf_filter,
            "packets_seen": self.packets_seen,
            "bytes_seen": self.bytes_seen,
            "last_packet_ts": self.last_packet_ts,
            "error": self.error,
        }

    # ------------------------------------------------------------------ #

    def _run(self) -> None:
        try:
            sniff(iface=self.iface, filter=self.bpf_filter, prn=self._handle,
                  store=False, stop_filter=lambda _p: self._stop.is_set())
        except PermissionError:
            self.error = "permission denied - run the backend as root or with CAP_NET_RAW"
            LOG.error(self.error)
        except Exception as exc:  # pragma: no cover
            self.error = str(exc)
            LOG.error("sniffer stopped: %s", exc)
        finally:
            self.running = False

    def _handle(self, pkt) -> None:  # pragma: no cover - needs live traffic
        try:
            parsed = self._parse(pkt)
            if not parsed:
                return
            self.packets_seen += 1
            self.bytes_seen += parsed["length"]
            self.last_packet_ts = parsed["ts"]
            self.engine.observe_packet(parsed)

            payload = parsed.pop("_payload", b"")
            if payload and self.on_malicious:
                import malicious
                findings = malicious.inspect_payload_bytes(payload)
                if findings:
                    self.on_malicious(parsed, findings)
        except Exception as exc:
            LOG.debug("packet parse error: %s", exc)

    @staticmethod
    def _parse(pkt) -> dict | None:
        ts = float(getattr(pkt, "time", time.time()))
        length = int(len(pkt))
        src_ip = dst_ip = ""
        proto = "OTHER"
        src_port = dst_port = 0
        flags = ""
        payload = b""

        if IP in pkt:
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return None

        if TCP in pkt:
            proto = "TCP"
            src_port, dst_port = int(pkt[TCP].sport), int(pkt[TCP].dport)
            flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            proto = "UDP"
            src_port, dst_port = int(pkt[UDP].sport), int(pkt[UDP].dport)
        elif ICMP in pkt:
            proto = "ICMP"

        if Raw in pkt:
            payload = bytes(pkt[Raw].load)[:4096]

        return {
            "ts": ts, "src_ip": src_ip, "dst_ip": dst_ip, "proto": proto,
            "src_port": src_port, "dst_port": dst_port, "flags": flags,
            "length": length, "_payload": payload,
        }
