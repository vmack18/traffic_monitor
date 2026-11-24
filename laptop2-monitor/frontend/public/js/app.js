/* =========================================================================
   Traffic Guard dashboard client
   - Connects to the Python backend's live WebSocket (proxied by Node at /ws)
   - Renders KPIs, network topology graphs, threat gauge, incident feed,
     packet stream, top sources/paths/rules and the blocked-IP list.
   ========================================================================= */
"use strict";

const $ = (id) => document.getElementById(id);
const API = ""; // same origin; Node proxies /api -> Python backend

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------
const state = {
  incidents: new Map(),  // id -> incident dict
  packets: [],           // recent event dicts
  blocked: [],           // blocked ip rows
  snapshot: null,
  ws: null,
  reconnectDelay: 1000,

  // blocked-context feature
  blockedContext: null,   // /api/context/blocked payload
  ctxFilter: "all",       // all | malicious | rate | blocklist
  ctxQuery: "",
  ctxFiltered: [],
  ctxSelected: null,

  // topology feature
  topoLayout: "star",
  topoSelected: "proxy",
  topoNodes: [],
  topoLinks: [],
};

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
function fmt(n) {
  if (n === null || n === undefined) return "0";
  n = Number(n);
  if (n >= 1e9) return (n / 1e9).toFixed(1) + "B";
  if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "K";
  return String(Math.round(n * 10) / 10);
}

function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + " " + u[i];
}

function esc(s) {
  return String(s === null || s === undefined ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function timeAgo(ts) {
  if (!ts) return "—";
  const d = Math.max(0, Date.now() / 1000 - ts);
  if (d < 60) return Math.floor(d) + "s ago";
  if (d < 3600) return Math.floor(d / 60) + "m ago";
  if (d < 86400) return Math.floor(d / 3600) + "h ago";
  return Math.floor(d / 86400) + "d ago";
}

const SEV_COLOR = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#8ba0c4",
  info: "#22d3ee",
};

const INCIDENT_ICON = {
  dos: "⚡", ddos: "🌊", syn_flood: "🌊", udp_flood: "📡",
  icmp_flood: "📶", http_flood: "🔥", slowloris: "🐢",
  port_scan: "🔍", brute_force: "🔑", malicious_payload: "☣️",
  volumetric: "📈", default: "⚠️",
};

function iconFor(type) {
  const t = String(type || "").toLowerCase();
  for (const k of Object.keys(INCIDENT_ICON)) {
    if (t.includes(k)) return INCIDENT_ICON[k];
  }
  return INCIDENT_ICON.default;
}

// ---------------------------------------------------------------------------
// Toasts
// ---------------------------------------------------------------------------
function toast(msg, kind) {
  const host = $("toastHost");
  const el = document.createElement("div");
  el.className = "toast " + (kind || "");
  el.innerHTML = msg;
  host.appendChild(el);
  setTimeout(() => {
    el.style.transition = "opacity .4s, transform .4s";
    el.style.opacity = "0";
    el.style.transform = "translateY(8px)";
    setTimeout(() => el.remove(), 420);
  }, 5200);
}

// ---------------------------------------------------------------------------
// WebSocket connection
// ---------------------------------------------------------------------------
function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const url = `${proto}://${location.host}/ws`;
  setConn("connecting", "Connecting…");

  let ws;
  try {
    ws = new WebSocket(url);
  } catch (e) {
    setConn("down", "Offline");
    scheduleReconnect();
    return;
  }
  state.ws = ws;

  ws.onopen = () => {
    state.reconnectDelay = 1000;
    setConn("live", "Live");
    ws.send("ping");
  };

  ws.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch (_) { return; }
    handleMessage(msg);
  };

  ws.onclose = () => {
    setConn("down", "Reconnecting…");
    scheduleReconnect();
  };

  ws.onerror = () => {
    try { ws.close(); } catch (_) {}
  };
}

function scheduleReconnect() {
  setTimeout(connect, state.reconnectDelay);
  state.reconnectDelay = Math.min(state.reconnectDelay * 1.7, 12000);
}

function setConn(kind, text) {
  const el = $("conn");
  el.className = "conn " + (kind === "live" ? "live" : kind === "down" ? "down" : "");
  $("connText").textContent = text;
}

function handleMessage(msg) {
  switch (msg.type) {
    case "snapshot":
      applySnapshot(msg.data);
      break;
    case "incident":
      onIncident(msg.data);
      break;
    case "incident_resolved":
      onIncidentResolved(msg.data);
      break;
    case "events":
      if (Array.isArray(msg.data)) {
        addPackets(msg.data);
        if (msg.data.some((e) => (e.verdict || "").toLowerCase() === "block")) {
          scheduleCtxRefresh(600);
        }
      }
      break;
    case "packet_alert":
      addPackets([msg.data]);
      scheduleCtxRefresh(600);
      break;
    case "blocklist_changed":
      refreshBlocked();
      scheduleCtxRefresh(300);
      break;
    case "hello":
      break;
    default:
      break;
  }
}

// ---------------------------------------------------------------------------
// Snapshot handling
// ---------------------------------------------------------------------------
function applySnapshot(s) {
  if (!s) return;
  state.snapshot = s;

  const w = s.window || {};
  const totals = s.totals || {};

  // KPI row
  $("kpiTotal").textContent = fmt(totals.requests ?? w.requests ?? 0);
  $("kpiTotalFoot").textContent =
    fmtBytes(totals.bytes ?? w.bytes ?? 0) + " transferred";
  $("kpiRps").textContent = (w.requests_per_sec ?? 0).toFixed(1);
  $("kpiBlocked").textContent = fmt(totals.blocked ?? w.blocked ?? 0);
  $("kpiBlockedFoot").textContent =
    (w.blocked_per_sec ?? 0).toFixed(2) + " blocked/s now";
  $("kpiSources").textContent = fmt(w.unique_sources ?? 0);
  const allowed = (w.requests ?? 0) - (w.blocked ?? 0);
  $("kpiAllowed").textContent = fmt(Math.max(0, allowed));

  // Incidents KPI
  const active = s.active_incidents || [];
  $("kpiIncidents").textContent = active.length;
  $("kpiIncidentsFoot").textContent =
    (totals.incidents ?? state.incidents.size) + " total raised";

  // Risk gauge
  updateGauge(s.risk_score ?? 0, s.health || "normal");

  // Severity breakdown
  const sev = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const inc of active) {
    const k = (inc.severity || "low").toLowerCase();
    if (sev[k] !== undefined) sev[k]++;
  }
  $("sevCritical").textContent = sev.critical;
  $("sevHigh").textContent = sev.high;
  $("sevMedium").textContent = sev.medium;
  $("sevLow").textContent = sev.low;

  // Health chip
  const hc = $("healthChip");
  hc.textContent = (s.health || "normal").replace("_", " ");
  hc.style.color = s.health === "under_attack" ? "var(--red)"
    : s.health === "elevated" ? "var(--amber)" : "var(--green)";

  // Top sources / paths / rules
  renderTopSources(s.top_sources || []);
  renderTopPaths(s.top_paths || []);
  renderTopRules(s.top_rules || []);

  // Incident feed from snapshot (authoritative list of active)
  syncIncidents(active);

  // Live topology graph (sources, flows, blocked paths)
  renderTopology();
}

function updateGauge(risk, health) {
  risk = Math.max(0, Math.min(100, Number(risk) || 0));
  const C = 2 * Math.PI * 56; // 351.86
  const arc = $("gaugeArc");
  arc.style.strokeDashoffset = String(C * (1 - risk / 100));

  let color = "#34d399", label = "All Clear", desc =
    "No active threats. Traffic is flowing normally through the inline detection gate.";
  if (risk >= 70) {
    color = "#f43f5e"; label = "Under Attack";
    desc = "Active DoS/DDoS or malicious traffic detected. Mitigation is engaged.";
  } else if (risk >= 35) {
    color = "#fbbf24"; label = "Elevated";
    desc = "Suspicious activity observed. The engine is correlating sources.";
  } else if (risk >= 10) {
    color = "#22d3ee"; label = "Guarded";
    desc = "Minor anomalies seen, below attack thresholds.";
  }
  arc.setAttribute("stroke", color);
  $("riskNum").textContent = Math.round(risk);
  $("riskNum").style.color = color;
  $("riskState").textContent = label;
  $("riskState").style.color = color;
  $("riskDesc").textContent = desc;
}

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------
function syncIncidents(active) {
  // Merge active incidents into the map; keep recently resolved ones visible.
  for (const inc of active) {
    state.incidents.set(inc.id, inc);
  }
  renderIncidents();
  $("incidentChip").textContent = active.length + " active";
}

function onIncident(inc) {
  if (!inc || !inc.id) return;
  state.incidents.set(inc.id, inc);
  renderIncidents();
  const sev = (inc.severity || "medium").toLowerCase();
  toast(
    `<b>${esc(inc.title || inc.type)}</b><br/>` +
    `<span style="color:var(--text-dim)">${esc(inc.src_ip || "multiple sources")} · ${esc(sev)}</span>`,
    "attack"
  );
}

function onIncidentResolved(inc) {
  if (!inc || !inc.id) return;
  const prev = state.incidents.get(inc.id) || {};
  state.incidents.set(inc.id, { ...prev, ...inc, status: "resolved" });
  renderIncidents();
  toast(`<b>Resolved:</b> ${esc(inc.title || inc.type)}`, "ok");
}

function renderIncidents() {
  const feed = $("incidentFeed");
  const list = Array.from(state.incidents.values())
    .sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0))
    .slice(0, 40);

  if (!list.length) {
    feed.innerHTML =
      '<div class="empty"><div class="big">🛡️</div>No incidents yet.<br/>Detection engine is watching.</div>';
    return;
  }

  feed.innerHTML = list.map((inc) => {
    const sev = (inc.severity || "medium").toLowerCase();
    const color = SEV_COLOR[sev] || SEV_COLOR.medium;
    const resolved = inc.status === "resolved";
    const acked = inc.acknowledged;
    const cls = resolved ? "resolved" : acked ? "ack" : "";
    const ackBtn = (!resolved && !acked)
      ? `<button class="ack-btn" data-ack="${esc(inc.id)}">Ack</button>` : "";
    return `
      <div class="incident ${cls}" style="--sev:${color}">
        <div class="ic">${iconFor(inc.type)}</div>
        <div class="body">
          <div class="title">
            ${esc(inc.title || inc.type)}
            <span class="sev-tag" style="--sev:${color}">${esc(sev)}</span>
          </div>
          <div class="desc">${esc(inc.description || "")}</div>
          <div class="meta">
            <span>${esc(inc.src_ip || "—")}</span>
            <span>${inc.count || 1} hits</span>
            <span>${timeAgo(inc.last_seen)}</span>
            ${resolved ? "<span style='color:var(--green)'>resolved</span>" : ""}
            ${acked ? "<span style='color:var(--text-faint)'>acked</span>" : ""}
          </div>
        </div>
        ${ackBtn}
      </div>`;
  }).join("");

  feed.querySelectorAll("[data-ack]").forEach((btn) => {
    btn.addEventListener("click", () => ackIncident(btn.dataset.ack));
  });
}

async function ackIncident(id) {
  try {
    await fetch(`${API}/api/incidents/${encodeURIComponent(id)}/ack`, { method: "POST" });
    const inc = state.incidents.get(id);
    if (inc) { inc.acknowledged = true; renderIncidents(); }
  } catch (_) {}
}

// ---------------------------------------------------------------------------
// Packets
// ---------------------------------------------------------------------------
function addPackets(events) {
  if (!events || !events.length) return;
  state.packets = events.concat(state.packets).slice(0, 60);
  renderPackets();
  renderTopology();
}

function renderPackets() {
  const body = $("packetBody");
  const list = state.packets.slice(0, 14);
  $("packetChip").textContent = state.packets.length + " pkts";
  if (!list.length) {
    body.innerHTML =
      '<tr><td colspan="4" class="empty" style="padding:22px">Waiting for traffic…</td></tr>';
    return;
  }
  body.innerHTML = list.map((e) => {
    const v = (e.verdict || "allow").toLowerCase();
    const badge = v === "block" ? "block" : v === "flag" ? "flag" : "allow";
    const t = e.ts ? new Date(e.ts * 1000).toLocaleTimeString() : "—";
    const req = `${esc(e.method || "")} ${esc(e.path || "")}`.trim() || "—";
    return `<tr>
      <td class="mono" style="color:var(--text-faint)">${t}</td>
      <td class="mono"><span class="ip">${esc(e.src_ip || "—")}</span></td>
      <td class="path" title="${esc(req)}">${esc(req.length > 26 ? req.slice(0, 26) + "…" : req)}</td>
      <td><span class="badge ${badge}">${esc(v)}</span></td>
    </tr>`;
  }).join("");
}

async function loadRecentEvents() {
  try {
    const r = await fetch(`${API}/api/events?limit=40`);
    if (!r.ok) return;
    const data = await r.json();
    const events = Array.isArray(data) ? data : (data.events || []);
    if (events.length) {
      state.packets = events.slice(0, 60);
      renderPackets();
      renderTopology();
    }
  } catch (_) {}
}

// ---------------------------------------------------------------------------
// Top lists
// ---------------------------------------------------------------------------
function renderTopSources(sources) {
  const el = $("topSources");
  if (!sources.length) { el.innerHTML = '<div class="empty">No data yet.</div>'; return; }
  const max = Math.max(...sources.map((s) => s.requests || 0), 1);
  el.innerHTML = sources.slice(0, 8).map((s) => {
    const pct = Math.round(((s.requests || 0) / max) * 100);
    const blocked = s.blocked ? ` <span style="color:var(--red)">·${s.blocked}✕</span>` : "";
    return `<div class="bar-row">
      <div class="k" title="${esc(s.ip)}">${esc(s.ip)}</div>
      <div class="track"><div class="fill" style="width:${pct}%"></div></div>
      <div class="v">${fmt(s.requests)}${blocked}</div>
    </div>`;
  }).join("");
}

function renderTopPaths(paths) {
  const el = $("topPaths");
  if (!paths.length) { el.innerHTML = '<div class="empty">No data yet.</div>'; return; }
  const max = Math.max(...paths.map((p) => p.requests || 0), 1);
  el.innerHTML = paths.slice(0, 8).map((p) => {
    const pct = Math.round(((p.requests || 0) / max) * 100);
    return `<div class="bar-row">
      <div class="k" title="${esc(p.path)}">${esc(p.path)}</div>
      <div class="track"><div class="fill" style="width:${pct}%;background:linear-gradient(90deg,var(--violet),var(--magenta))"></div></div>
      <div class="v">${fmt(p.requests)}</div>
    </div>`;
  }).join("");
}

function renderTopRules(rules) {
  const el = $("topRules");
  if (!rules.length) { el.innerHTML = '<div class="empty">No signatures triggered.</div>'; return; }
  el.innerHTML = rules.slice(0, 12).map((r) =>
    `<span class="tag">${esc(r.rule)}<span class="n">${r.count}</span></span>`
  ).join("");
}

function regexAttackType(category) {
  return ATTACK_TYPE_LABEL[category]
    || String(category || "unknown").replace(/_/g, " ");
}

async function loadRegexRuleCatalog() {
  const body = $("regexRules");
  const count = $("regexRuleCount");
  try {
    const response = await fetch(`${API}/api/rules`);
    if (!response.ok) throw new Error(`rules API returned ${response.status}`);
    const data = await response.json();
    const rules = Array.isArray(data.regex_rules) ? data.regex_rules : [];
    if (!rules.length) throw new Error("rules API returned no regex rules");

    count.textContent = `${rules.length} regex rules`;
    body.innerHTML = rules.map((rule) => `
      <tr>
        <td class="sig">${esc(rule.rule)}</td>
        <td>${esc(regexAttackType(rule.category))}</td>
        <td style="color:${sevColor(rule.severity)}">${esc(rule.severity)}</td>
        <td>${esc(rule.detail)}</td>
        <td class="mono" style="max-width:420px;white-space:normal;overflow-wrap:anywhere">
          <code>${esc(rule.pattern)}</code>
        </td>
        <td class="mono">${fmt((data.hits || {})[rule.rule] || 0)}</td>
      </tr>`).join("");
  } catch (error) {
    count.textContent = "Rules unavailable";
    body.innerHTML = `<tr><td colspan="6" class="empty" style="padding:26px">
      Could not load the regex rule catalog: ${esc(error.message || String(error))}</td></tr>`;
  }
}

// ---------------------------------------------------------------------------
// Blocked IPs
// ---------------------------------------------------------------------------
async function refreshBlocked() {
  try {
    const r = await fetch(`${API}/api/blocked`);
    if (!r.ok) return;
    const data = await r.json();
    state.blocked = Array.isArray(data) ? data : (data.blocked || []);
    renderBlocked();
    renderTopology();
  } catch (_) {}
}

function renderBlocked() {
  const el = $("blockList");
  $("blockedChip").textContent = state.blocked.length;
  if (!state.blocked.length) {
    el.innerHTML = '<div class="empty">No IPs currently blocked.</div>';
    return;
  }
  el.innerHTML = state.blocked.slice(0, 30).map((b) => {
    const permanent = !b.expires_at;
    const ttl = permanent ? null : Math.max(0, Math.round(b.expires_at - Date.now() / 1000));
    return `<div class="block-item">
      <span class="ip">${esc(b.ip)}</span>
      <span class="reason" title="${esc(b.reason || "")}">${esc(b.reason || "blocked")}</span>
      ${permanent ? '<span class="ttl">∞</span>' : `<span class="ttl">${ttl}s</span>`}
      <button class="unblock-btn" data-unblock="${esc(b.ip)}">Unblock</button>
    </div>`;
  }).join("");

  el.querySelectorAll("[data-unblock]").forEach((btn) => {
    btn.addEventListener("click", () => unblock(btn.dataset.unblock));
  });
}

async function unblock(ip) {
  try {
    await fetch(`${API}/api/blocked/${encodeURIComponent(ip)}`, { method: "DELETE" });
    state.blocked = state.blocked.filter((b) => b.ip !== ip);
    renderBlocked();
    scheduleCtxRefresh(300);
    toast(`Unblocked <b>${esc(ip)}</b>`, "ok");
  } catch (_) {}
}

// ---------------------------------------------------------------------------
// Manual IP block (type any IP, or pull the protected server IP)
// ---------------------------------------------------------------------------
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function looksLikeIp(value) {
  const v = (value || "").trim();
  if (!v) return false;
  if (IPV4_RE.test(v)) return true;
  // loose IPv6 check: hex groups + colons, at least two colons
  return /^[0-9a-f:]+$/i.test(v) && (v.match(/:/g) || []).length >= 2;
}

function showBlockError(msg) {
  const el = $("blockError");
  if (!el) return;
  if (!msg) { el.hidden = true; el.textContent = ""; return; }
  el.hidden = false;
  el.textContent = msg;
}

async function submitBlock(ip, reason, ttl, { silent = false } = {}) {
  const cleanIp = (ip || "").trim();
  const input = $("blockIp");
  if (!looksLikeIp(cleanIp)) {
    if (input) input.classList.add("invalid");
    showBlockError("Enter a valid IPv4 or IPv6 address.");
    return false;
  }
  if (input) input.classList.remove("invalid");
  showBlockError("");

  const btn = $("blockSubmit") || document.querySelector(".block-submit");
  if (btn) btn.disabled = true;
  try {
    const r = await fetch(`${API}/api/blocked`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip: cleanIp,
        reason: (reason || "").trim() || "manual block",
        ttl: Number(ttl),
      }),
    });
    if (!r.ok) {
      let detail = `HTTP ${r.status}`;
      try {
        const j = await r.json();
        detail = Array.isArray(j.detail) ? j.detail[0]?.msg || detail : j.detail || detail;
      } catch (_) {}
      showBlockError("Block failed: " + detail);
      return false;
    }
    const row = await r.json();
    state.blocked = [row, ...state.blocked.filter((b) => b.ip !== row.ip)];
    renderBlocked();
    if (!silent) {
      const ttlText = Number(ttl) === 0 ? "permanently" : `for ${Number(ttl)}s`;
      toast(`Blocked <b>${esc(row.ip)}</b> ${ttlText}`, "warn");
    }
    if (input) input.value = "";
    const reasonEl = $("blockReason");
    if (reasonEl) reasonEl.value = "";
    scheduleCtxRefresh(300);
    return true;
  } catch (e) {
    showBlockError("Block failed: network error");
    return false;
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function blockServerIp() {
  const ip = state.serverIp;
  if (!ip) {
    showBlockError("Server IP unknown — set TG_SERVER_IP on the backend.");
    return;
  }
  const input = $("blockIp");
  if (input) input.value = ip;
  const reasonEl = $("blockReason");
  if (reasonEl && !reasonEl.value) reasonEl.value = "server quarantine";
  const ttl = $("blockTtl") ? $("blockTtl").value : 600;
  const ok = await submitBlock(ip, reasonEl ? reasonEl.value : "server quarantine", ttl);
  if (ok) toast(`Server <b>${esc(ip)}</b> quarantined`, "warn");
}

function wireBlockForm() {
  const form = $("blockForm");
  if (form) {
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      const ttl = $("blockTtl") ? $("blockTtl").value : 600;
      submitBlock($("blockIp")?.value, $("blockReason")?.value, ttl);
    });
  }
  const ipEl = $("blockIp");
  if (ipEl) {
    ipEl.addEventListener("input", () => {
      ipEl.classList.remove("invalid");
      showBlockError("");
    });
  }
  const srvBtn = $("blockServerBtn");
  if (srvBtn) srvBtn.addEventListener("click", blockServerIp);
}

async function loadConfig() {
  try {
    const r = await fetch(`${API}/api/config`);
    if (!r.ok) return;
    const cfg = await r.json();
    state.serverIp = cfg.server_ip || null;
    const label = $("serverIpLabel");
    if (label) label.textContent = cfg.server_ip || "not configured";
    const tag = $("serverTag");
    if (tag && cfg.server_label) tag.title = "Protected origin: " + cfg.server_label;
    const ipEl = $("blockIp");
    if (ipEl && cfg.server_ip) ipEl.placeholder = `IP to block  e.g. ${cfg.server_ip}`;
  } catch (_) {}
}

// ===========================================================================
// BLOCKED REQUEST CONTEXT
// ===========================================================================
const REASON_LABEL = {
  malicious_payload: "malicious payload",
  rate_limit: "rate limit",
  connection_flood: "connection flood",
  blocklist: "blocklist",
  http_flood: "HTTP flood",
  ddos: "DDoS",
  dos: "DoS",
};
const REASON_DESC = {
  malicious_payload:
    "A request signature matched the malicious-content engine. The gate rejected it with 403 before it could reach the protected origin.",
  rate_limit:
    "The source exceeded the per-IP sliding-window request budget. The gate returned 429 and, by policy, added the source to the blocklist.",
  connection_flood:
    "The source exceeded the concurrent-connection cap (slowloris / half-open flood). The connection was rejected with 429.",
  blocklist:
    "The source was already on the shared blocklist when it connected. It was rejected with 403 before any request was parsed.",
  http_flood:
    "The request was classified as part of an HTTP flood and blocked by the traffic detection policy.",
  ddos:
    "The request was classified as part of a distributed denial-of-service event.",
  dos:
    "The request was classified as part of a denial-of-service event.",
};
const ATTACK_TYPE_LABEL = {
  sql_injection: "SQL injection",
  xss: "Cross-site scripting (XSS)",
  path_traversal: "Path traversal",
  command_injection: "Command injection",
  ssrf: "Server-side request forgery (SSRF)",
  xxe: "XML external entity (XXE)",
  ssti: "Server-side template injection (SSTI)",
  log4shell: "Log4Shell",
  header_injection: "Header injection",
  request_smuggling: "HTTP request smuggling",
  webshell: "Webshell",
  reverse_shell: "Reverse shell",
  scanner: "Scanner activity",
  malware: "Malware",
  shellcode: "Shellcode",
  obfuscation: "Obfuscated payload",
  anomaly: "Request anomaly",
};

function reasonLabel(r) {
  return REASON_LABEL[r] || String(r || "blocked").replace(/_/g, " ");
}
function attackTypeLabel(e) {
  const findings = Array.isArray(e.findings) ? e.findings : [];
  const secondaryCategories = new Set(["scanner", "obfuscation", "anomaly"]);
  const attackFindings = findings.filter((finding) =>
    !secondaryCategories.has(String(finding.category || "").toLowerCase()));
  const categories = [...new Set((attackFindings.length ? attackFindings : findings)
    .map((finding) => finding.category)
    .filter(Boolean))];
  if (categories.length) {
    return categories.map((category) => ATTACK_TYPE_LABEL[category]
      || String(category).replace(/_/g, " ")).join(", ");
  }
  if (e.reason === "rate_limit") return "DoS / rate limit";
  if (e.reason === "connection_flood") return "Slowloris / connection flood";
  if (e.reason === "malicious_payload") return "Malicious payload";
  if (e.reason === "http_flood") return "HTTP flood (DoS)";
  if (e.reason === "ddos") return "Distributed denial of service";
  if (e.reason === "dos") return "Denial of service";
  if (e.reason === "blocklist") return "Not identified";
  return "—";
}
function signatureLabels(e) {
  const findings = Array.isArray(e.findings) ? e.findings : [];
  return [...new Set(findings.map((finding) => finding.rule).filter(Boolean))];
}
function reasonClass(r) {
  return ["malicious_payload", "rate_limit", "connection_flood", "blocklist",
    "http_flood", "ddos", "dos"].includes(r)
    ? r : "";
}
function sevColor(s) {
  return SEV_COLOR[String(s || "low").toLowerCase()] || SEV_COLOR.low;
}
function shortIp(ip) {
  ip = String(ip || "");
  return ip.length > 17 ? ip.slice(0, 15) + "…" : ip;
}

let ctxRefreshTimer = null;
function scheduleCtxRefresh(delay = 800) {
  clearTimeout(ctxRefreshTimer);
  ctxRefreshTimer = setTimeout(refreshBlockedContext, delay);
}

async function refreshBlockedContext() {
  try {
    const r = await fetch(`${API}/api/context/blocked?limit=300`);
    if (!r.ok) return;
    state.blockedContext = await r.json();
    renderBlockedContext();
    renderTopology();
  } catch (_) {}
}

function filterBlockedEvents(events) {
  const f = state.ctxFilter;
  const q = state.ctxQuery.trim().toLowerCase();
  const rateReasons = new Set([
    "rate_limit", "connection_flood", "http_flood", "ddos", "dos",
  ]);
  return events.filter((e) => {
    const reason = String(e.reason || "").toLowerCase();
    const findings = Array.isArray(e.findings) ? e.findings : [];
    if (f === "malicious" && !(reason === "malicious_payload" || findings.length)) return false;
    if (f === "rate" && !rateReasons.has(reason)) return false;
    if (f === "blocklist" && reason !== "blocklist") return false;
    if (q) {
      const hay = [
        e.src_ip, e.method, e.path, reason, e.severity, e.sensor,
        ...findings.map((x) => `${x.rule || ""} ${x.category || ""} ${x.detail || ""}`),
      ].join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function renderBlockedContext() {
  const ctx = state.blockedContext;
  const recent = (ctx && ctx.recent) || [];
  const total = ctx ? ctx.total : 0;

  $("ctxTotal").textContent = fmt(total);
  $("ctxTotalSub").textContent =
    `${state.ctxFiltered.length} shown · ${recent.length} loaded · persisted decisions`;
  $("ctxActiveBlocks").textContent = fmt((ctx && ctx.active_blocks) ?? state.blocked.length);
  const clearFilters = $("ctxClearFilters");
  if (clearFilters) {
    clearFilters.hidden = state.ctxFilter === "all" && !state.ctxQuery.trim();
  }

  const tr = ctx && ctx.by_reason && ctx.by_reason[0];
  $("ctxTopReason").textContent = tr ? reasonLabel(tr.reason) : "—";
  $("ctxTopReasonSub").textContent = tr ? `${fmt(tr.count)} events` : "no blocks recorded";

  const rule = ctx && ctx.by_rule && ctx.by_rule[0];
  $("ctxTopRule").textContent = rule ? rule.rule : "—";
  $("ctxTopRuleSub").textContent = rule
    ? `${fmt(rule.count)} findings · ${rule.category}` : "no payload findings";

  state.ctxFiltered = filterBlockedEvents(recent);
  renderCtxRows();
}

function renderCtxRows() {
  const body = $("ctxBody");
  if (!body) return;
  const rows = state.ctxFiltered;

  if (!rows.length) {
    const activeFilters = state.ctxFilter !== "all" || Boolean(state.ctxQuery.trim());
    const msg = !state.blockedContext
      ? "Waiting for blocked traffic…"
      : !state.blockedContext.recent.length
        ? "No blocked requests recorded yet."
        : activeFilters
          ? "No blocked requests match the selected filters. Use Clear filters to show all blocked requests."
          : "No blocked requests match this search.";
    body.innerHTML = `<tr><td colspan="8" class="empty" style="padding:26px">${esc(msg)}</td></tr>`;
    return;
  }

  body.innerHTML = rows.slice(0, 120).map((e, i) => {
    const sev = String(e.severity || "low").toLowerCase();
    const findings = Array.isArray(e.findings) ? e.findings : [];
    const signatures = signatureLabels(e);
    const sig = signatures.length ? signatures.join(", ") : "—";
    const type = attackTypeLabel(e);
    const t = e.ts ? new Date(e.ts * 1000).toLocaleTimeString([], { hour12: false }) : "—";
    const req = `${e.method || "RAW"} ${e.path || ""}`.trim();
    return `<tr data-ctx="${i}">
      <td class="mono" style="color:var(--text-faint)">${t}</td>
      <td class="src">${esc(e.src_ip || "—")}<span style="color:var(--text-faint);font-weight:400">:${esc(e.src_port || "")}</span></td>
      <td class="req" title="${esc(req)}"><span class="m">${esc(e.method || "RAW")}</span>${esc(e.path || "—")}</td>
      <td><span class="reason-pill ${reasonClass(e.reason)}">${esc(reasonLabel(e.reason))}</span></td>
      <td class="attack-type" title="${esc(type)}">${esc(type)}</td>
      <td style="color:${sevColor(sev)};white-space:nowrap"><span class="sev-dot"></span>${esc(sev)}</td>
      <td class="sig" title="${esc(findings.map((finding) =>
        `${finding.rule || "rule"}: ${finding.detail || ""}`).join("; "))}">${esc(sig)}</td>
      <td class="chev">›</td>
    </tr>`;
  }).join("");

  body.querySelectorAll("[data-ctx]").forEach((tr) => {
    tr.addEventListener("click", () => openCtxDrawer(rows[Number(tr.dataset.ctx)]));
  });
}

function openCtxDrawer(e) {
  if (!e) return;
  state.ctxSelected = e;
  renderCtxDrawer(e);
  $("ctxDrawer").classList.add("open");
  $("ctxDrawer").setAttribute("aria-hidden", "false");
  $("ctxBackdrop").classList.add("open");
}

function closeCtxDrawer() {
  $("ctxDrawer").classList.remove("open");
  $("ctxDrawer").setAttribute("aria-hidden", "true");
  $("ctxBackdrop").classList.remove("open");
}

function renderCtxDrawer(e) {
  const sev = String(e.severity || "low").toLowerCase();
  const findings = e.findings || [];
  const t = e.ts ? new Date(e.ts * 1000).toLocaleString() : "—";
  const isBlocked = (state.blocked || []).some((b) => b.ip === e.src_ip);
  const reason = String(e.reason || "blocked");

  const findingsHtml = findings.length
    ? findings.map((f) => `
      <div class="finding">
        <div class="head">
          <span class="rule">${esc(f.rule || "rule")}</span>
          <span class="cat">${esc(f.category || "unknown")}</span>
          <span class="sev-dot" style="color:${sevColor(f.severity)}"></span>
          <span style="font-size:10px;color:${sevColor(f.severity)};font-family:var(--mono)">${esc(f.severity || "low")}</span>
        </div>
        <div class="detail">${esc(f.detail || "Signature matched in the request.")}</div>
        ${f.field ? `<div class="field">field: ${esc(f.field)}</div>` : ""}
        ${f.match ? `<code>${esc(f.match)}</code>` : ""}
      </div>`).join("")
    : `<div class="ctx-empty-note">No payload signature fired for this decision. The gate blocked the request on the
        <b>${esc(reasonLabel(reason))}</b> rule. ${esc(REASON_DESC[reason] || "")}</div>`;

  const kv = (k, v) => `<div class="ctx-kv"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`;

  $("ctxDrawerBody").innerHTML = `
    <div class="ctx-banner">
      <div class="big">
        <span style="font-size:16px">⛔</span> BLOCKED — ${esc(reasonLabel(reason))}
        <span class="sev-tag" style="--sev:${sevColor(sev)}">${esc(sev)}</span>
      </div>
      <div class="sub">${esc(REASON_DESC[reason] || "The inline policy rejected this request at the edge.")}</div>
    </div>

    <div class="ctx-flow">
      <span class="ep src">${esc(e.src_ip || "—")}:${esc(e.src_port || "0")}</span>
      <span class="arrow">→</span>
      <span class="ep">${esc(e.dst_ip || "—")}:${esc(e.dst_port || "0")}</span>
      <span class="proto">${esc(e.proto || "TCP")}</span>
      <span style="margin-left:auto;color:var(--text-faint)">${esc(e.sensor || "inline-proxy")}</span>
    </div>

    <div class="ctx-section-title">Request context</div>
    <div class="ctx-kv-grid">
      ${kv("Time", t)}
      ${kv("Verdict", e.verdict || "block")}
      ${kv("Method", e.method || "RAW")}
      ${kv("Path", e.path || "—")}
      ${kv("Status returned", e.status || "—")}
      ${kv("Bytes in", fmtBytes(e.bytes_in || 0))}
      ${kv("Latency", `${Number(e.latency_ms || 0).toFixed(2)} ms`)}
      ${kv("Reason", reasonLabel(reason))}
    </div>

    <div class="ctx-section-title">Trigger findings (${findings.length})</div>
    ${findingsHtml}

    <div class="ctx-section-title">Raw event context</div>
    <pre class="ctx-json">${esc(JSON.stringify(e, null, 2))}</pre>

    <div class="ctx-actions">
      ${isBlocked ? "" : `<button class="ctx-action" data-act="block">Block ${esc(e.src_ip)}</button>`}
      <button class="ctx-action ghost" data-act="filter">Filter blocked requests to this source</button>
      <button class="ctx-action ghost" data-act="copy">Copy JSON</button>
    </div>`;
}

function applyCtxFilterToSource(ip) {
  state.ctxFilter = "all";
  state.ctxQuery = ip;
  const search = $("ctxSearch");
  if (search) search.value = ip;
  document.querySelectorAll("#ctxFilters button").forEach((b) =>
    b.classList.toggle("active", b.dataset.filter === "all"));
  renderBlockedContext();
  closeCtxDrawer();
  const panel = document.querySelector(".context-panel");
  if (panel) panel.scrollIntoView({ behavior: "smooth", block: "center" });
  toast(`Filtered blocked context to <b>${esc(ip)}</b>`, "ok");
}

function wireContext() {
  document.querySelectorAll("#ctxFilters button").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.ctxFilter = btn.dataset.filter;
      document.querySelectorAll("#ctxFilters button").forEach((b) =>
        b.classList.toggle("active", b === btn));
      renderBlockedContext();
    });
  });

  const search = $("ctxSearch");
  if (search) {
    search.addEventListener("input", () => {
      state.ctxQuery = search.value;
      renderBlockedContext();
    });
  }
  const clearFilters = $("ctxClearFilters");
  if (clearFilters) {
    clearFilters.addEventListener("click", () => {
      state.ctxFilter = "all";
      state.ctxQuery = "";
      if (search) search.value = "";
      document.querySelectorAll("#ctxFilters button").forEach((btn) =>
        btn.classList.toggle("active", btn.dataset.filter === "all"));
      renderBlockedContext();
    });
  }

  const close = $("ctxClose");
  if (close) close.addEventListener("click", closeCtxDrawer);
  const backdrop = $("ctxBackdrop");
  if (backdrop) backdrop.addEventListener("click", closeCtxDrawer);
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") closeCtxDrawer();
  });

  const drawerBody = $("ctxDrawerBody");
  if (drawerBody) {
    drawerBody.addEventListener("click", async (ev) => {
      const btn = ev.target.closest("[data-act]");
      if (!btn) return;
      const e = state.ctxSelected;
      if (!e) return;
      const act = btn.dataset.act;

      if (act === "block") {
        btn.disabled = true;
        const ok = await submitBlock(e.src_ip, `blocked-context:${e.reason || "block"}`, 600);
        if (ok) {
          closeCtxDrawer();
          refreshBlockedContext();
        } else {
          btn.disabled = false;
        }
      } else if (act === "filter") {
        applyCtxFilterToSource(e.src_ip);
      } else if (act === "copy") {
        try {
          await navigator.clipboard.writeText(JSON.stringify(e, null, 2));
          toast("Context JSON copied to clipboard", "ok");
        } catch (_) {}
      }
    });
  }
}

// ===========================================================================
// NETWORK TOPOLOGY GRAPH
// ===========================================================================
const TOPO_COLORS = {
  source: "#34d399", proxy: "#22d3ee", origin: "#34d399",
  backend: "#a78bfa", dashboard: "#3b82f6",
};
const TOPO_BLOCK_FLOW_TTL = 60;
const TOPO_RADII = { source: 16, proxy: 34, origin: 27, backend: 22, dashboard: 20 };
const TOPO_GLYPHS = { source: "◈", proxy: "⬢", origin: "▣", backend: "◧", dashboard: "▤" };

function buildTopologyData() {
  const snap = state.snapshot || {};
  const ctx = state.blockedContext || {};
  const now = Date.now() / 1000;
  const byIp = new Map();
  const lastBlockedByIp = new Map();
  const recentTrafficByIp = new Map();

  const add = (ip, req, blk, bytes, last) => {
    if (!ip) return;
    const cur = byIp.get(ip) || { ip, requests: 0, blocked: 0, bytes: 0, last_seen: 0 };
    cur.requests += Number(req) || 0;
    cur.blocked += Number(blk) || 0;
    cur.bytes += Number(bytes) || 0;
    cur.last_seen = Math.max(cur.last_seen, Number(last) || 0);
    byIp.set(ip, cur);
  };

  const markBlocked = (ip, ts) => {
    const time = Number(ts) || 0;
    if (!ip || !time || now - time > TOPO_BLOCK_FLOW_TTL || time > now) return;
    lastBlockedByIp.set(ip, Math.max(lastBlockedByIp.get(ip) || 0, time));
  };

  (snap.top_sources || []).forEach((s) => add(s.ip, s.requests, s.blocked, s.bytes, s.last_seen));
  (snap.top_sources || []).forEach((s) => {
    if (Number(s.blocked) > 0) markBlocked(s.ip, s.last_seen || snap.ts);
  });
  (ctx.top_sources || []).forEach((s) => {
    markBlocked(s.ip, s.last_seen);
    if (!byIp.has(s.ip) && lastBlockedByIp.has(s.ip)) {
      add(s.ip, s.count, s.count, 0, s.last_seen);
    }
  });
  (state.packets || []).forEach((e) => {
    const ts = Number(e.ts) || 0;
    const verdict = String(e.verdict || "").toLowerCase();
    if (!e.src_ip || !ts || now - ts > TOPO_BLOCK_FLOW_TTL || ts > now ||
        !["allow", "flag", "block"].includes(verdict)) return;

    const traffic = recentTrafficByIp.get(e.src_ip) ||
      { requests: 0, blocked: 0, bytes: 0, last_seen: 0 };
    traffic.requests++;
    if (verdict === "block") {
      traffic.blocked++;
      markBlocked(e.src_ip, ts);
    }
    traffic.bytes += Number(e.bytes_in) || 0;
    traffic.last_seen = Math.max(traffic.last_seen, ts);
    recentTrafficByIp.set(e.src_ip, traffic);
  });

  recentTrafficByIp.forEach((traffic, ip) => {
    if (!byIp.has(ip)) {
      add(ip, traffic.requests, traffic.blocked, traffic.bytes, traffic.last_seen);
    }
  });

  const sources = Array.from(byIp.values())
    .sort((a, b) => b.requests - a.requests)
    .slice(0, 8);

  sources.forEach((s) => {
    s.last_blocked = lastBlockedByIp.get(s.ip) || 0;
    s.isBlocked = s.last_blocked > 0;
  });

  const nodes = [
    ...sources.map((s) => ({
      id: `src:${s.ip}`, type: "source", ip: s.ip, label: shortIp(s.ip), sub: "",
      requests: s.requests, blocked: s.blocked, bytes: s.bytes, isBlocked: s.isBlocked,
    })),
    { id: "proxy", type: "proxy", label: "Inline Proxy", sub: ":8080", role: "edge gate",
      requests: snap.window ? snap.window.requests : 0,
      blocked: snap.window ? snap.window.blocked : 0 },
    { id: "origin", type: "origin", label: "Protected Origin", sub: ":9000", role: "target",
      requests: 0, blocked: 0 },
    { id: "backend", type: "backend", label: "Python Backend", sub: ":8000", role: "analytics",
      requests: 0, blocked: 0 },
    { id: "dashboard", type: "dashboard", label: "Dashboard", sub: ":3000", role: "NOC UI",
      requests: 0, blocked: 0 },
  ];

  return { sources, nodes, snap };
}

function computeTopoLayout(layout, sources) {
  const pos = {};
  const n = sources.length;
  const put = (id, x, y) => { pos[id] = { x, y }; };

  if (layout === "star") {
    put("proxy", 450, 216);
    put("origin", 705, 216);
    put("backend", 815, 108);
    put("dashboard", 880, 330);
    sources.forEach((s, i) => {
      const y = n === 1 ? 216 : 62 + (308 * i) / (n - 1);
      const x = 150 + 52 * Math.cos(((y - 216) / 308) * Math.PI * 0.9);
      put(`src:${s.ip}`, x, y);
    });
  } else if (layout === "tree") {
    put("proxy", 500, 268);
    put("origin", 380, 104);
    put("backend", 630, 104);
    put("dashboard", 860, 104);
    sources.forEach((s, i) => {
      const x = n === 1 ? 500 : 90 + (820 * i) / (n - 1);
      put(`src:${s.ip}`, x, 392);
    });
  } else if (layout === "mesh") {
    put("proxy", 420, 216);
    put("origin", 660, 216);
    put("backend", 800, 104);
    put("dashboard", 880, 330);
    sources.forEach((s, i) => {
      const y = n === 1 ? 216 : 70 + (292 * i) / (n - 1);
      put(`src:${s.ip}`, 120, y);
    });
  } else if (layout === "ring") {
    const ids = [...sources.map((s) => `src:${s.ip}`), "proxy", "origin", "backend", "dashboard"];
    const R = 172, cx = 500, cy = 216;
    ids.forEach((id, i) => {
      const a = (-90 + (360 * i) / ids.length) * Math.PI / 180;
      put(id, cx + R * Math.cos(a), cy + R * Math.sin(a));
    });
  } else if (layout === "bus") {
    sources.forEach((s, i) => {
      const x = n === 1 ? 300 : 90 + (560 * i) / (n - 1);
      put(`src:${s.ip}`, x, 92);
      put(`bus:src:${s.ip}`, x, 216);
    });
    put("proxy", 300, 330); put("bus:proxy", 300, 216);
    put("origin", 540, 330); put("bus:origin", 540, 216);
    put("backend", 760, 92); put("bus:backend", 760, 216);
    put("dashboard", 880, 330); put("bus:dashboard", 880, 216);
  } else { // hybrid
    put("proxy", 420, 216);
    put("origin", 660, 216);
    put("backend", 800, 104);
    put("dashboard", 880, 330);
    const colA = Math.ceil(n / 2);
    sources.forEach((s, i) => {
      const col = i < colA ? 0 : 1;
      const idx = col === 0 ? i : i - colA;
      const count = col === 0 ? colA : n - colA;
      const y = count <= 1 ? 216 : 80 + (272 * idx) / (count - 1);
      put(`src:${s.ip}`, 100 + col * 105, y);
    });
  }
  return pos;
}

function buildTopologyLinks(layout, data, pos) {
  const links = [];
  const snap = data.snap || {};

  data.sources.forEach((s) => {
    const cls = s.isBlocked ? "blocked" : (s.blocked > 0 ? "warn" : "allowed");
    links.push({ source: `src:${s.ip}`, target: "proxy", cls, weight: s.requests, kind: "flow" });
  });

  const allowed = Math.max(0, (snap.window ? snap.window.requests : 0) - (snap.window ? snap.window.blocked : 0));
  links.push({ source: "proxy", target: "origin", cls: "allowed", weight: Math.max(1, allowed), kind: "flow" });
  links.push({ source: "proxy", target: "backend", cls: "telemetry", weight: 1, kind: "telemetry" });
  links.push({ source: "backend", target: "dashboard", cls: "telemetry", weight: 1, kind: "telemetry" });

  if (layout === "mesh" || layout === "hybrid") {
    data.sources.forEach((s, i) => {
      const next = data.sources[i + 1];
      if (next) {
        links.push({ source: `src:${s.ip}`, target: `src:${next.ip}`,
          cls: "mesh", weight: 1, kind: "mesh", curve: 0.05 });
      }
    });
  }

  if (layout === "ring") {
    const ids = [...data.sources.map((s) => `src:${s.ip}`), "proxy", "origin", "backend", "dashboard"];
    ids.forEach((id, i) => {
      links.push({ source: id, target: ids[(i + 1) % ids.length],
        cls: "mesh", weight: 1, kind: "mesh", curve: 0.08 });
    });
  }

  if (layout === "bus") {
    const nodes = [...data.sources.map((s) => ({ id: `src:${s.ip}`, s })),
      { id: "proxy" }, { id: "origin" }, { id: "backend" }, { id: "dashboard" }];
    nodes.forEach((nd) => {
      if (!pos[nd.id]) return;
      const cls = nd.s
        ? (nd.s.isBlocked ? "blocked" : (nd.s.blocked > 0 ? "warn" : "allowed"))
        : (nd.id === "proxy" || nd.id === "origin" ? "allowed" : "telemetry");
      links.push({ source: nd.id, target: `bus:${nd.id}`, cls,
        weight: nd.s ? nd.s.requests : 1, kind: nd.s ? "flow" : "telemetry", straight: true });
    });
  }

  return links;
}

function edgePath(a, b, curve) {
  const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
  const dx = b.x - a.x, dy = b.y - a.y;
  const cx = mx - dy * (curve == null ? 0.1 : curve);
  const cy = my + dx * (curve == null ? 0.1 : curve);
  return `M${a.x.toFixed(1)},${a.y.toFixed(1)} Q${cx.toFixed(1)},${cy.toFixed(1)} ${b.x.toFixed(1)},${b.y.toFixed(1)}`;
}

function renderTopoNode(nd, p, layout) {
  const r = TOPO_RADII[nd.type] || 18;
  const color = nd.type === "source"
    ? (nd.isBlocked ? "#f43f5e" : (nd.blocked > 0 ? "#fbbf24" : "#34d399"))
    : (TOPO_COLORS[nd.type] || "#8ba0c4");
  const cls = [
    nd.isBlocked ? "blocked" : "",
    (nd.blocked > 0 && !nd.isBlocked) ? "alert" : "",
    state.topoSelected === nd.id ? "selected" : "",
  ].join(" ");

  const badge = nd.isBlocked
    ? `<g transform="translate(${(r * 0.74).toFixed(1)},${(-r * 0.74).toFixed(1)})">
         <circle r="9" fill="#f43f5e" stroke="#2a0a12" stroke-width="1.5"/>
         <text x="0" y="3.6" text-anchor="middle" font-size="10" font-weight="700" fill="#fff">✕</text>
       </g>` : "";

  const showSub = nd.type !== "source" || layout === "tree" || layout === "bus";
  const labelCls = nd.isBlocked ? "blocked" : (nd.type === "source" ? "" : "strong");

  return `<g class="topo-node ${cls}" data-node="${esc(nd.id)}" transform="translate(${p.x.toFixed(1)},${p.y.toFixed(1)})">
    <circle class="halo" r="${r + 9}" stroke="${color}"/>
    <circle class="core" r="${r}" fill="url(#tg-${nd.type})" stroke="${color}" stroke-width="${nd.type === "proxy" ? 2.4 : 1.8}"/>
    <text x="0" y="${nd.type === "source" ? 4 : 5}" text-anchor="middle"
          font-size="${nd.type === "source" ? 13 : nd.type === "proxy" ? 20 : 15}"
          fill="${color}" font-weight="700">${TOPO_GLYPHS[nd.type] || "●"}</text>
    ${badge}
    <text class="topo-label ${labelCls}" x="0" y="${r + 16}" text-anchor="middle">${esc(nd.label)}</text>
    ${showSub && nd.sub ? `<text class="topo-label faint" x="0" y="${r + 28}" text-anchor="middle">${esc(nd.sub)}</text>` : ""}
  </g>`;
}

function updateTopoSummary() {
  const data = state.topoNodes || [];
  const links = state.topoLinks || [];
  $("topoNodes").textContent = data.length;
  $("topoLinks").textContent = links.length;
  $("topoBlockedLinks").textContent = links.filter((l) => l.cls === "blocked").length;
  $("topoBlockedNodes").textContent = data.filter((n) => n.type === "source" && n.isBlocked).length;
}

function renderTopology(force) {
  const svg = $("topoGraph");
  if (!svg) return;

  const data = buildTopologyData();
  const layout = state.topoLayout;
  const positions = computeTopoLayout(layout, data.sources);
  const links = buildTopologyLinks(layout, data, positions);

  state.topoNodes = data.nodes;
  state.topoLinks = links;

  // Rebuild only when the graph structure/labels change; this keeps the
  // flowing-dash animations smooth between snapshots.
  const sig = [
    layout,
    state.topoSelected,
    data.sources.map((s) => `${s.ip}:${s.isBlocked ? 1 : 0}:${s.requests}:${s.blocked}`).join(","),
    (state.blockedContext?.top_sources || [])
      .filter((s) => Number(s.last_seen) >= Date.now() / 1000 - TOPO_BLOCK_FLOW_TTL)
      .map((s) => s.ip).join(","),
    data.snap.window ? data.snap.window.requests : 0,
    data.snap.window ? data.snap.window.blocked : 0,
    (state.blocked || []).length,
  ].join("|");

  updateTopoSummary();
  if (!force && sig === state.topoSig) return;
  state.topoSig = sig;

  const maxReq = Math.max(1, ...data.sources.map((s) => s.requests));
  let html = `<defs>
    <radialGradient id="tg-source" cx="35%" cy="30%" r="75%">
      <stop offset="0" stop-color="#173a3c"/><stop offset="1" stop-color="#08161c"/>
    </radialGradient>
    <radialGradient id="tg-proxy" cx="35%" cy="30%" r="75%">
      <stop offset="0" stop-color="#0e4a5c"/><stop offset="1" stop-color="#061a26"/>
    </radialGradient>
    <radialGradient id="tg-origin" cx="35%" cy="30%" r="75%">
      <stop offset="0" stop-color="#11463a"/><stop offset="1" stop-color="#061a16"/>
    </radialGradient>
    <radialGradient id="tg-backend" cx="35%" cy="30%" r="75%">
      <stop offset="0" stop-color="#2d2350"/><stop offset="1" stop-color="#100a24"/>
    </radialGradient>
    <radialGradient id="tg-dashboard" cx="35%" cy="30%" r="75%">
      <stop offset="0" stop-color="#152f56"/><stop offset="1" stop-color="#081428"/>
    </radialGradient>
    ${["allowed", "warn", "blocked", "telemetry", "mesh"].map((k) => {
      const col = { allowed: "#34d399", warn: "#fbbf24", blocked: "#f43f5e",
        telemetry: "#a78bfa", mesh: "#5a8cdc" }[k];
      return `<marker id="tg-arrow-${k}" viewBox="0 0 8 8" refX="6.5" refY="4"
        markerWidth="6" markerHeight="6" orient="auto-start-reverse" markerUnits="strokeWidth">
        <path d="M0,0 L8,4 L0,8 z" fill="${col}"/></marker>`;
    }).join("")}
  </defs>`;

  if (layout === "bus") {
    html += `<path class="topo-link mesh" stroke-width="3.2" d="M60,216 L940,216"/>`;
  }

  links.forEach((l) => {
    const a = positions[l.source], b = positions[l.target];
    if (!a || !b) return;
    const w = l.kind === "telemetry" || l.kind === "mesh"
      ? 1.2
      : 1.4 + 3.6 * Math.sqrt((l.weight || 1) / maxReq);
    const d = l.straight ? `M${a.x},${a.y} L${b.x},${b.y}` : edgePath(a, b, l.curve);
    html += `<path class="topo-link ${l.cls}" stroke-width="${w.toFixed(2)}" d="${d}"
      marker-end="url(#tg-arrow-${l.cls})"/>`;
  });

  data.nodes.forEach((nd) => {
    const p = positions[nd.id];
    if (p) html += renderTopoNode(nd, p, layout);
  });

  if (!data.sources.length) {
    html += `<text x="500" y="216" text-anchor="middle" class="topo-label faint">
      No client sources in the current window — waiting for traffic…</text>`;
  }

  svg.innerHTML = html;

  const nodeMap = new Map(data.nodes.map((n) => [n.id, n]));
  svg.querySelectorAll("[data-node]").forEach((g) => {
    const id = g.getAttribute("data-node");
    g.addEventListener("mouseenter", () => showTopoTip(nodeMap.get(id)));
    g.addEventListener("mousemove", moveTopoTip);
    g.addEventListener("mouseleave", () => $("topoTooltip").classList.remove("show"));
    g.addEventListener("click", () => selectTopoNode(id));
  });

  updateTopoDetail(state.topoSelected);
  renderTopoTopBlocked();
}

function showTopoTip(nd) {
  if (!nd) return;
  const tip = $("topoTooltip");
  let rows = "";
  if (nd.type === "source") {
    rows = `<div class="tt-row"><span>Requests</span><b>${fmt(nd.requests)}</b></div>
      <div class="tt-row"><span>Blocked</span><b style="color:var(--red)">${fmt(nd.blocked)}</b></div>
      <div class="tt-row"><span>Bytes</span><b>${fmtBytes(nd.bytes)}</b></div>
      <div class="tt-row"><span>State</span><b style="color:${nd.isBlocked ? "var(--red)" : "var(--green)"}">${nd.isBlocked ? "blocked" : "passing"}</b></div>`;
  } else {
    rows = `<div class="tt-row"><span>Role</span><b>${esc(nd.role || "")}</b></div>`;
    if (nd.type === "proxy") {
      rows += `<div class="tt-row"><span>Window req</span><b>${fmt(nd.requests)}</b></div>
        <div class="tt-row"><span>Blocked</span><b style="color:var(--red)">${fmt(nd.blocked)}</b></div>`;
    }
  }
  tip.innerHTML = `<div class="tt-title">${esc(nd.label)}${nd.sub ? ` <span style="color:var(--text-faint);font-weight:400">${esc(nd.sub)}</span>` : ""}</div>${rows}`;
  tip.classList.add("show");
}

function moveTopoTip(ev) {
  const stage = $("topoStage"), tip = $("topoTooltip");
  if (!stage || !tip) return;
  const r = stage.getBoundingClientRect();
  let x = ev.clientX - r.left + 14;
  let y = ev.clientY - r.top + 14;
  x = Math.min(x, r.width - tip.offsetWidth - 8);
  y = Math.min(y, r.height - tip.offsetHeight - 8);
  tip.style.left = Math.max(8, x) + "px";
  tip.style.top = Math.max(8, y) + "px";
}

function selectTopoNode(id) {
  state.topoSelected = id;
  document.querySelectorAll("#topoGraph .topo-node").forEach((g) =>
    g.classList.toggle("selected", g.getAttribute("data-node") === id));
  updateTopoDetail(id);
  const node = state.topoNodes.find((item) => item.id === id);
  if (node && node.type === "source") applyCtxFilterToSource(node.ip);
}

function updateTopoDetail(id) {
  const el = $("topoDetail");
  if (!el) return;
  const list = state.topoNodes || [];
  const nd = list.find((n) => n.id === id) || list.find((n) => n.id === "proxy");
  if (!nd) {
    el.innerHTML = `<div class="hintline">No node selected.</div>`;
    return;
  }
  const color = nd.type === "source"
    ? (nd.isBlocked ? "#f43f5e" : (nd.blocked > 0 ? "#fbbf24" : "#34d399"))
    : (TOPO_COLORS[nd.type] || "#8ba0c4");

  let rows = "";
  if (nd.type === "source") {
    rows = `<div class="kv"><span>Requests</span><b>${fmt(nd.requests)}</b></div>
      <div class="kv"><span>Blocked</span><b style="color:var(--red)">${fmt(nd.blocked)}</b></div>
      <div class="kv"><span>Bytes</span><b>${fmtBytes(nd.bytes)}</b></div>
      <div class="kv"><span>State</span><b style="color:${nd.isBlocked ? "var(--red)" : "var(--green)"}">${nd.isBlocked ? "blocked" : "passing"}</b></div>`;
  } else {
    rows = `<div class="kv"><span>Role</span><b>${esc(nd.role || "")}</b></div>`;
    if (nd.type === "proxy") {
      rows += `<div class="kv"><span>Window req</span><b>${fmt(nd.requests)}</b></div>
        <div class="kv"><span>Blocked</span><b style="color:var(--red)">${fmt(nd.blocked)}</b></div>`;
    } else if (nd.type === "origin") {
      rows += `<div class="kv"><span>Exposure</span><b>loopback only</b></div>`;
    } else if (nd.type === "backend") {
      rows += `<div class="kv"><span>Store</span><b>SQLite WAL</b></div>`;
    } else if (nd.type === "dashboard") {
      rows += `<div class="kv"><span>Transport</span><b>WebSocket</b></div>`;
    }
  }

  el.innerHTML = `<div class="name" style="color:${color}">${esc(nd.label)}${nd.sub ? ` <span style="color:var(--text-faint);font-weight:400">${esc(nd.sub)}</span>` : ""}</div>
    <div class="role">${esc(nd.type === "source" ? (nd.isBlocked ? "blocked source" : "client source") : (nd.role || ""))}</div>
    ${rows}
    <div class="hintline">${nd.type === "source"
      ? "Click the node to filter the blocked-context table to this source."
      : "Hover a source node to inspect its traffic and block state."}</div>`;
}

function renderTopoTopBlocked() {
  const el = $("topoTopBlocked");
  if (!el) return;
  const cutoff = Date.now() / 1000 - TOPO_BLOCK_FLOW_TTL;
  const srcs = ((state.blockedContext && state.blockedContext.top_sources) || [])
    .filter((s) => Number(s.last_seen) >= cutoff)
    .slice(0, 5);
  if (!srcs.length) {
    el.innerHTML = `<div class="hintline">No blocked sources yet.</div>`;
    return;
  }
  el.innerHTML = srcs.map((s) =>
    `<div class="kv"><span style="font-family:var(--mono);color:#fda4af">${esc(s.ip)}</span>
      <b style="color:var(--red)">${fmt(s.count)}</b></div>`).join("");
}

function setTopologyLayout(layout) {
  if (!document.querySelector(`#topoSwitch button[data-topo="${layout}"]`)) return;
  state.topoLayout = layout;
  document.querySelectorAll("#topoSwitch button").forEach((btn) =>
    btn.classList.toggle("active", btn.dataset.topo === layout));
  renderTopology(true);
}

function wireTopology() {
  document.querySelectorAll("#topoSwitch button").forEach((btn) => {
    btn.addEventListener("click", () => setTopologyLayout(btn.dataset.topo));
  });
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------
function tickClock() {
  const d = new Date();
  $("clock").textContent = d.toLocaleTimeString([], { hour12: false });
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
function boot() {
  tickClock();
  setInterval(tickClock, 1000);

  window.addEventListener("resize", () => {
    renderTopology(true);
  });

  connect();
  loadRecentEvents();
  refreshBlocked();
  refreshBlockedContext();
  wireBlockForm();
  wireContext();
  wireTopology();
  loadConfig();
  loadRegexRuleCatalog();

  // Periodic safety refreshes (WS is primary).
  setInterval(refreshBlocked, 10000);
  setInterval(refreshBlockedContext, 6000);
  setInterval(loadRecentEvents, 8000);

  // Keep the socket alive.
  setInterval(() => {
    if (state.ws && state.ws.readyState === WebSocket.OPEN) state.ws.send("ping");
  }, 25000);

  $("footerStatus").textContent = "Traffic Guard v1.0 · " + new Date().toLocaleDateString();
}

document.addEventListener("DOMContentLoaded", boot);
