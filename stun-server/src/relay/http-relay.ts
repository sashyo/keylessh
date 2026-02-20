/**
 * HTTP relay that tunnels requests through WAF WebSocket connections.
 *
 * When the STUN server receives an HTTP request (not /health, not WebSocket),
 * it serializes the request and sends it to a WAF over its existing WebSocket.
 * The WAF processes the request locally and sends the response back.
 */

import { randomUUID } from "crypto";
import type { IncomingMessage, ServerResponse } from "http";
import type { Registry } from "../signaling/registry.js";

const RELAY_TIMEOUT_MS = 30_000;

interface PendingRequest {
  resolve: (response: RelayResponse) => void;
  timer: ReturnType<typeof setTimeout>;
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

// ── Relay handler ────────────────────────────────────────────────

export function createHttpRelay(registry: Registry, useTls = false) {
  return async function handleRelayRequest(
    req: IncomingMessage,
    res: ServerResponse
  ): Promise<void> {
    // Find target WAF (session affinity via cookie)
    const wafId = parseCookie(req.headers.cookie, "waf_relay");
    let waf = wafId ? registry.getWaf(wafId) : undefined;

    if (!waf) {
      waf = registry.getAvailableWaf();
    }

    if (!waf) {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "No WAF available" }));
      return;
    }

    // Buffer request body
    const bodyChunks: Buffer[] = [];
    for await (const chunk of req) {
      bodyChunks.push(chunk as Buffer);
    }
    const body = Buffer.concat(bodyChunks).toString("base64");

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

    // Wait for response
    try {
      const response = await waitForResponse(requestId);

      // Set session affinity cookie
      const setCookies: string[] = [];
      setCookies.push(`waf_relay=${waf.id}; Path=/; HttpOnly; SameSite=Lax`);

      // Merge WAF's Set-Cookie headers with our affinity cookie
      const wafSetCookie = response.headers["set-cookie"];
      if (wafSetCookie) {
        if (Array.isArray(wafSetCookie)) {
          setCookies.push(...wafSetCookie);
        } else {
          setCookies.push(wafSetCookie);
        }
      }

      const headers = { ...response.headers, "set-cookie": setCookies };
      const responseBody = Buffer.from(response.body, "base64");

      res.writeHead(response.statusCode, headers);
      res.end(responseBody);
    } catch {
      if (!res.headersSent) {
        res.writeHead(504, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "WAF response timeout" }));
      }
    }
  };
}

function waitForResponse(requestId: string): Promise<RelayResponse> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(requestId);
      reject(new Error("Relay timeout"));
    }, RELAY_TIMEOUT_MS);

    pending.set(requestId, { resolve, timer });
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
