# Project: Real-Time Network Traffic Monitoring & DoS/DDoS/Malicious-Payload Detection

Two-machine ("2 set laptop") architecture:
- **Laptop 1** = Ubuntu Server VM in VirtualBox -> protected target server + inline detection proxy (Python sockets)
- **Laptop 2** = Node.js/TypeScript frontend + Python backend (detection analytics, alerting, dashboard)

## Tasks
- [x] 1. Scaffold repo structure + master README / architecture docs
- [x] 2. Laptop 1: protected TCP server (Python asyncio sockets)
- [x] 3. Laptop 1: inline detection proxy (rate/DoS checks + malicious payload scan -> forward)
- [x] 4. Laptop 1: config, requirements, Ubuntu setup script, systemd units
- [x] 5. Laptop 2 backend: malicious content engine (signatures, regex, entropy, base64 nesting)
- [x] 6. Laptop 2 backend: DoS/DDoS detection engine (sliding window, per-IP, SYN/UDP/HTTP flood, slowloris, DDoS fan-in)
- [x] 7. Laptop 2 backend: FastAPI app, SQLite store, WebSocket realtime, event ingest, block API
- [x] 8. Laptop 2 backend: packet sniffer (scapy) module
- [x] 9. Laptop 2 frontend: Node.js + TypeScript server (static + API/WS proxy)
- [x] 10. Laptop 2 frontend: dashboard UI (live charts, alerts, packets, blocked IPs)
- [x] 11. Safe tooling: benign traffic generator (attack simulator excluded from public distribution)
- [x] 12. Test end-to-end in sandbox, fix bugs
- [x] 13. Screenshot/preview of dashboard + final packaging
