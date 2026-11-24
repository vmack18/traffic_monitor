# Detection Rules

TrafficGuard combines two rule families: **malicious-content signatures** (what is in the request) and **behavioural thresholds** (how the client behaves over time). Both run on the proxy and on the backend; the proxy blocks inline, the backend correlates and alerts.

Severity ordering is `low < medium < high < critical`. By default the proxy blocks any finding at or above `medium` (`policy.min_block_severity`), and adds a source to the blocklist once it accumulates `malicious_blocklist_threshold` high/critical hits (default `3`).

## 1. Malicious-content signatures

### SQL injection

| Rule | Severity | Detects |
|------|----------|---------|
| `SQLI-001` | high | boolean-based injection (`OR 1=1`) |
| `SQLI-002` | critical | `UNION SELECT` |
| `SQLI-003` | high | time-based functions (`SLEEP`, `BENCHMARK`, `pg_sleep`) |
| `SQLI-004` | high | database metadata / file access (`information_schema`, `LOAD_FILE`) |
| `SQLI-005` | medium | SQL comment terminators (`--`, `#`, `/*`) |
| `SQLI-006` | high | extraction functions (`EXTRACTVALUE`, `UPDATEXML`) |

### Cross-site scripting

| Rule | Severity | Detects |
|------|----------|---------|
| `XSS-001` | high | `<script>` tags |
| `XSS-002` | high | `javascript:` URIs |
| `XSS-003` | high | inline event handlers (`onerror=`, `onload=`) |
| `XSS-004` | medium | active HTML elements (`<iframe>`, `<object>`, `<embed>`) |
| `XSS-005` | medium | DOM access / redirect (`document.cookie`, `window.location`) |

### Path traversal & file access

| Rule | Severity | Detects |
|------|----------|---------|
| `TRAV-001` | high | `../` directory traversal (raw or encoded) |
| `TRAV-002` | critical | sensitive files (`/etc/passwd`, `/etc/shadow`, `win.ini`) |

### Command injection

| Rule | Severity | Detects |
|------|----------|---------|
| `CMDI-001` | critical | shell command chaining (`;`, `&&`, `||`) |
| `CMDI-002` | high | `$()` command substitution |
| `CMDI-003` | high | backtick command substitution |

### SSRF, XXE, SSTI

| Rule | Severity | Detects |
|------|----------|---------|
| `SSRF-001` | critical | internal / cloud-metadata addresses (`169.254.169.254`, `127.0.0.1`, `10.x`) |
| `SSRF-002` | high | non-HTTP schemes (`file://`, `gopher://`, `dict://`) |
| `XXE-001` | critical | XML external entity declarations |
| `SSTI-001` | high | template expression evaluation (`{{7*7}}`, `${...}`) |

### Framework-specific & protocol abuse

| Rule | Severity | Detects |
|------|----------|---------|
| `LOG4J-001` | critical | Log4Shell JNDI lookup (`${jndi:ldap://...}`) |
| `CRLF-001` | high | CRLF / response splitting (`%0d%0a`) |
| `SMUG-001` | high | conflicting `Content-Length` / `Transfer-Encoding` headers |

### Webshells, reverse shells, scanners

| Rule | Severity | Detects |
|------|----------|---------|
| `WEBSHELL-001` | critical | code-execution functions (`system()`, `eval()`, `exec()`) |
| `WEBSHELL-002` | high | obfuscated payload decoders (`base64_decode`, `gzinflate`) |
| `REVSH-001` | critical | reverse-shell one-liners (`/dev/tcp/`, `nc -e`) |
| `SCAN-001` | medium | attack-tool fingerprints in User-Agent (`sqlmap`, `nikto`, `nmap`, `masscan`, `hydra`, `gobuster`, `wpscan`, `metasploit`, `acunetix`, `nessus`) |
| `SCAN-002` | low | scanner probe patterns (`/.git/`, `/wp-admin`, `/.env`) |
| `SCAN-003` | medium | suspicious User-Agent (attack tool) |
| `SCAN-004` | low | generic HTTP client User-Agent (`curl`, `wget`, `python-requests`, `go-http-client`) |

> `SCAN-004` exists so that legitimate automation using `curl` or `wget` is **not** blocked. Only real attack tools (`SCAN-003`) are blocked at medium severity.

### Byte-level signatures

| Rule | Severity | Detects |
|------|----------|---------|
| `MAL-001` | critical | EICAR antivirus test file |
| `MAL-002` | critical | NOP sled (24+ `\x90`) |
| `MAL-003` | high | shellcode jump (`\xeb\xfe`) |
| `MAL-004` | high | `cmd.exe /c` |
| `MAL-005` | high | `powershell -enc` |
| `MAL-006` | high | hidden PowerShell (`-nop -w hidden`) |
| `MAL-007` | medium | Windows PE header (`MZ\x90\x00...`) |
| `MAL-008` | medium | Linux ELF header (`\x7fELF`) |

### Heuristic checks

- **Entropy** — long blobs with Shannon entropy above the threshold are flagged as packed/encrypted payloads.
- **Nested decoding** — URL-decoded and base64-decoded candidates are rescanned up to depth 2, catching double-encoded attacks.

## 2. Behavioural thresholds (DoS / DDoS)

These are configured in `laptop2-monitor/backend/config.py` and overridable with `TG_*` environment variables.

| Incident type | Trigger | Default |
|---------------|---------|---------|
| `dos` | per-IP requests in window | `>= 25` in `10s` |
| `volumetric` | per-IP bytes in window | `>= 2,000,000` |
| `ddos` | unique sources **and** total requests | `>= 8` sources and `>= 60` requests |
| `http_flood` | requests to a single path | `>= 40` in `10s` |
| `slowloris` | concurrent connections per IP | `>= 10` |
| `port_scan` | unique destination ports per IP | `>= 15` |
| `brute_force` | `401` responses per IP | `>= 10` |
| `syn_flood` | SYN packets per second (sensor) | `>= 100` |
| `udp_flood` | UDP packets per second (sensor) | `>= 200` |
| `icmp_flood` | ICMP packets per second (sensor) | `>= 100` |
| `malicious_payload` | any malicious finding | severity of finding |

Incidents are de-duplicated by a stable key, cooled down (`incident_cooldown_seconds`, default 20s), escalated in severity on repeat, and auto-resolved after `incident_resolve_seconds` (default 45s) of inactivity.

## 3. Inline proxy limits

These are configured in `laptop1-server/config.json` and enforced before any forwarding.

| Limit | Default | Effect when exceeded |
|-------|---------|----------------------|
| `max_requests_per_ip` | 40 / 10s | `429`, optionally blocklist |
| `max_requests_global` | 500 / 10s | alert (forwarded, global flood) |
| `max_concurrent_per_ip` | 12 | `429`, optionally blocklist |
| `max_payload_bytes` | 64 KB | request rejected |
| `header_timeout` | 5 s | slowloris drop + report |
| `block_ttl_seconds` | 300 s | blocklist entry lifetime |
| `malicious_blocklist_threshold` | 3 | high/critical hits before blocklisting |

## 4. Tuning guidance

- Raise `dos_requests_per_ip` and `max_requests_per_ip` for APIs with legitimate bursty clients.
- Lower `ddos_unique_sources` for small labs; raise it for large NATed populations where many clients share an IP.
- Keep `trust_forwarded_for` **off** unless the proxy sits behind a trusted load balancer, otherwise clients can spoof their identity to evade per-IP limits.
- Add site-specific signatures to `REGEX_RULES` in `malicious.py`; the rule id, category, severity, compiled pattern and detail are all that is required.
