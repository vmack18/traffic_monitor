/**
 * Traffic Guard - Node.js + TypeScript frontend server
 * -----------------------------------------------------
 * Responsibilities:
 *   1. Serve the static dashboard (HTML/CSS/JS) from ./public
 *   2. Reverse-proxy REST calls  /api/*  -> Python FastAPI backend
 *   3. Reverse-proxy WebSocket   /ws     -> Python FastAPI backend
 *
 * The Python backend does all of the detection analytics. This Node layer is
 * purely the presentation/edge tier, exactly as requested for "Laptop 2"
 * (frontend in Node.js + TypeScript, backend in Python).
 */
import express, { Request, Response, NextFunction } from "express";
import http from "http";
import path from "path";
import { createProxyMiddleware } from "http-proxy-middleware";
import { WebSocketServer, WebSocket } from "ws";

// ---------------------------------------------------------------------------
// Configuration (all overridable via environment variables)
// ---------------------------------------------------------------------------
const PORT: number = parseInt(process.env.PORT || "3000", 10);
const HOST: string = process.env.HOST || "0.0.0.0";
const BACKEND_URL: string = process.env.BACKEND_URL || "http://127.0.0.1:8000";
const PUBLIC_DIR: string = path.resolve(__dirname, "..", "public");

// Derive the ws:// equivalent of the backend http:// URL.
const BACKEND_WS: string = BACKEND_URL.replace(/^http/, "ws") + "/ws";

const app = express();

// Basic request logging (kept lightweight on purpose).
app.use((req: Request, _res: Response, next: NextFunction) => {
  if (!req.path.startsWith("/api") && req.path !== "/ws") {
    console.log(`[frontend] ${req.method} ${req.path}`);
  }
  next();
});

// ---------------------------------------------------------------------------
// REST proxy: /api/*  ->  Python backend
// ---------------------------------------------------------------------------
app.use(
  createProxyMiddleware({
    target: BACKEND_URL,
    changeOrigin: true,
    ws: false,
    pathFilter: "/api/**",
    proxyTimeout: 15000,
    timeout: 15000,
    on: {
      error: (err: Error, _req, res) => {
        console.error(`[proxy] backend error: ${err.message}`);
        const r = res as Response;
        if (typeof r.status === "function" && !r.headersSent) {
          r.status(502).json({
            error: "backend_unreachable",
            detail: `Cannot reach Python backend at ${BACKEND_URL}`,
          });
        }
      },
    },
  })
);

// ---------------------------------------------------------------------------
// Static dashboard
// ---------------------------------------------------------------------------
app.use(
  express.static(PUBLIC_DIR, {
    extensions: ["html"],
    maxAge: process.env.NODE_ENV === "production" ? "1h" : 0,
  })
);

// SPA-style fallback for any non-API route (but let /healthz through).
app.get("*", (req: Request, res: Response, next: NextFunction) => {
  if (req.path === "/healthz") return next();
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

// ---------------------------------------------------------------------------
// HTTP + WebSocket server
// ---------------------------------------------------------------------------
const server = http.createServer(app);

// Manual WebSocket reverse proxy. We bridge each browser socket to a fresh
// backend socket and relay frames in both directions. This keeps the Node
// layer stateless and resilient (a dropped backend socket only closes its
// paired browser socket, which the UI auto-reconnects).
const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (req, socket, head) => {
  if (!req.url || !req.url.startsWith("/ws")) {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (client: WebSocket) => {
    wss.emit("connection", client, req);
  });
});

wss.on("connection", (client: WebSocket) => {
  console.log("[ws] browser connected -> opening backend socket");
  const upstream = new WebSocket(BACKEND_WS);

  const pending: string[] = [];
  let upstreamOpen = false;

  upstream.on("open", () => {
    upstreamOpen = true;
    // Flush any frames the browser sent before the backend was ready.
    for (const msg of pending) upstream.send(msg);
    pending.length = 0;
  });

  upstream.on("message", (data: Buffer) => {
    if (client.readyState === WebSocket.OPEN) client.send(data.toString());
  });

  upstream.on("close", () => {
    console.log("[ws] backend closed");
    if (client.readyState === WebSocket.OPEN) client.close();
  });

  upstream.on("error", (err: Error) => {
    console.error(`[ws] backend error: ${err.message}`);
    if (client.readyState === WebSocket.OPEN) client.close();
  });

  client.on("message", (data: Buffer) => {
    const text = data.toString();
    if (upstreamOpen) upstream.send(text);
    else pending.push(text);
  });

  client.on("close", () => {
    console.log("[ws] browser disconnected");
    if (upstream.readyState === WebSocket.OPEN) upstream.close();
  });

  client.on("error", () => {
    if (upstream.readyState === WebSocket.OPEN) upstream.close();
  });
});

// ---------------------------------------------------------------------------
// Health / readiness endpoint for the Node tier itself.
// ---------------------------------------------------------------------------
app.get("/healthz", async (_req: Request, res: Response) => {
  let backendOk = false;
  let backendDetail = "";
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 3000);
    const r = await fetch(`${BACKEND_URL}/api/health`, {
      signal: controller.signal,
    });
    clearTimeout(t);
    backendOk = r.ok;
    backendDetail = `HTTP ${r.status}`;
  } catch (e) {
    backendDetail = (e as Error).message;
  }
  res.json({
    status: backendOk ? "ok" : "degraded",
    frontend: "traffic-guard-node",
    backend: { url: BACKEND_URL, reachable: backendOk, detail: backendDetail },
    uptime_seconds: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

server.listen(PORT, HOST, () => {
  console.log("============================================================");
  console.log("  Traffic Guard - Node.js/TypeScript frontend");
  console.log(`  Dashboard : http://${HOST}:${PORT}`);
  console.log(`  Backend   : ${BACKEND_URL}`);
  console.log(`  WS bridge : /ws -> ${BACKEND_WS}`);
  console.log("============================================================");
});

// Graceful shutdown.
function shutdown(sig: string): void {
  console.log(`\n[frontend] received ${sig}, shutting down...`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
