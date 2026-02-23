/**
 * HTTP relay that tunnels requests through WAF WebSocket connections.
 *
 * When the signal server receives an HTTP request (not /health, not WebSocket, not API),
 * it serializes the request and sends it to a WAF over its existing WebSocket.
 * The WAF processes the request locally and sends the response back.
 */

import { randomUUID } from "crypto";
import type { IncomingMessage, ServerResponse } from "http";
import type { Registry } from "../signaling/registry.js";

const RELAY_TIMEOUT_MS = 30_000;

interface PendingRequest {
  resolve: (response: RelayResponse) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
  wafId: string;
}

interface RelayResponse {
  statusCode: number;
  headers: Record<string, string | string[]>;
  body: string; // base64
}

// Pending requests waiting for WAF response
const pending = new Map<string, PendingRequest>();

// ── Cookie helpers ───────────────────────────────────────────────

function parseCookie(header: string | undefined, name: string): string | null {
  if (!header) return null;
  for (const pair of header.split(";")) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    if (pair.slice(0, eq).trim() === name) {
      return pair.slice(eq + 1).trim();
    }
  }
  return null;
}

// ── Body collection with size limit ──────────────────────────────

function collectBody(stream: import("stream").Readable, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalSize = 0;
    stream.on("data", (chunk: Buffer) => {
      totalSize += chunk.length;
      if (totalSize > maxBytes) {
        stream.destroy();
        reject(new Error("Request body too large"));
        return;
      }
      chunks.push(chunk);
    });
    stream.on("end", () => resolve(Buffer.concat(chunks)));
    stream.on("error", reject);
  });
}

// ── Relay handler ────────────────────────────────────────────────

export function createHttpRelay(registry: Registry, useTls = false) {
  return async function handleRelayRequest(
    req: IncomingMessage,
    res: ServerResponse
  ): Promise<void> {
    // Find target WAF (session affinity via cookie, then realm-based, then load-balance)
    const wafId = parseCookie(req.headers.cookie, "waf_relay");
    let waf = wafId ? registry.getWaf(wafId) : undefined;

    if (!waf) {
      // Try realm-based routing from URL path:
      //   /realms/<name>/...
      //   /resources/<name>/...
      //   /admin/<name>/...
      const realmMatch = req.url?.match(/\/(?:realms|resources|admin)\/([^/]+)\//);
      if (realmMatch) {
        waf = registry.getWafByRealm(realmMatch[1]);
      }
    }

    if (!waf) {
      waf = registry.getAvailableWaf();
    }

    if (!waf) {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "No WAF available" }));
      return;
    }

    // Buffer request body (10 MB limit)
    let body: string;
    try {
      const bodyBuf = await collectBody(req, 10 * 1024 * 1024);
      body = bodyBuf.toString("base64");
    } catch {
      res.writeHead(413, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Request body too large" }));
      return;
    }

    // Build relay message
    const requestId = randomUUID();
    const headers = { ...req.headers } as Record<string, string | string[] | undefined>;
    if (useTls && !headers["x-forwarded-proto"]) {
      headers["x-forwarded-proto"] = "https";
    }
    const relayMsg = {
      type: "http_request",
      id: requestId,
      method: req.method || "GET",
      url: req.url || "/",
      headers,
      body,
    };

    // Send to WAF via WebSocket
    try {
      if (waf.ws.readyState !== waf.ws.OPEN) {
        throw new Error("WAF WebSocket not open");
      }
      waf.ws.send(JSON.stringify(relayMsg));
    } catch {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Failed to reach WAF" }));
      return;
    }

    // Check pending map size
    if (pending.size >= 5000) {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Too many pending requests" }));
      return;
    }

    // Wait for response
    try {
      const response = await waitForResponse(requestId, waf.id);

      // Strip CORS headers the WAF may have added — CORS is handled at the top level
      for (const key of Object.keys(response.headers)) {
        if (key.toLowerCase().startsWith("access-control-")) {
          delete response.headers[key];
        }
      }

      // Set WAF affinity cookie (SameSite=None so cross-site iframes can route)
      const setCookies: string[] = [];
      setCookies.push(`waf_relay=${waf.id}; Path=/; HttpOnly; SameSite=None; Secure`);

      // Merge WAF's Set-Cookie headers with our affinity cookie
      const wafSetCookie = response.headers["set-cookie"];
      if (wafSetCookie) {
        if (Array.isArray(wafSetCookie)) {
          setCookies.push(...wafSetCookie);
        } else {
          setCookies.push(wafSetCookie);
        }
      }

      const responseHeaders = { ...response.headers, "set-cookie": setCookies };
      const responseBody = Buffer.from(response.body, "base64");

      res.writeHead(response.statusCode, responseHeaders);
      res.end(responseBody);
    } catch {
      if (!res.headersSent) {
        res.writeHead(504, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "WAF response timeout" }));
      }
    }
  };
}

function waitForResponse(requestId: string, wafId: string): Promise<RelayResponse> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(requestId);
      reject(new Error("Relay timeout"));
    }, RELAY_TIMEOUT_MS);

    pending.set(requestId, { resolve, reject, timer, wafId });
  });
}

/**
 * Handle an http_response message from a WAF.
 * Called by the signaling WebSocket server when it receives this message type.
 */
export function handleHttpResponse(msg: {
  id: string;
  statusCode: number;
  headers: Record<string, string | string[]>;
  body: string;
}): void {
  const entry = pending.get(msg.id);
  if (!entry) return;

  clearTimeout(entry.timer);
  pending.delete(msg.id);

  entry.resolve({
    statusCode: msg.statusCode,
    headers: msg.headers,
    body: msg.body,
  });
}

/**
 * Reject all pending requests for a given WAF.
 * Called when the WAF disconnects so requests don't wait for timeout.
 */
export function rejectPendingForWaf(wafId: string): void {
  for (const [requestId, entry] of pending) {
    if (entry.wafId === wafId) {
      clearTimeout(entry.timer);
      pending.delete(requestId);
      entry.reject(new Error("WAF disconnected"));
    }
  }
}
