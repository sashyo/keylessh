/**
 * HTTP relay that tunnels requests through gateway WebSocket connections.
 *
 * When the signal server receives an HTTP request (not /health, not WebSocket, not API),
 * it serializes the request and sends it to a gateway over its existing WebSocket.
 * The gateway processes the request locally and sends the response back.
 *
 * Supports two response modes:
 * 1. Buffered: gateway sends a single `http_response` with full body (default)
 * 2. Streaming: gateway sends `http_response_start` (headers) + `http_response_chunk`*
 *    + `http_response_end` (for SSE and long-running responses)
 */

import { randomUUID } from "crypto";
import type { IncomingMessage, ServerResponse } from "http";
import type { WebSocket } from "ws";
import type { Registry } from "../signaling/registry.js";

const RELAY_TIMEOUT_MS = 30_000;
const STREAM_CHUNK_TIMEOUT_MS = 60_000; // 1 min between chunks for streaming

interface PendingRequest {
  res: ServerResponse;
  gatewayWs: WebSocket;
  timer: ReturnType<typeof setTimeout>;
  gatewayId: string;
  headersSent: boolean;
}

// Pending requests waiting for gateway response
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

/** Add gateway affinity cookie + merge gateway's Set-Cookie headers */
function addAffinityCookie(
  headers: Record<string, string | string[]>,
  gatewayId: string,
): Record<string, string | string[]> {
  const setCookies: string[] = [];
  setCookies.push(`gateway_relay=${gatewayId}; Path=/; HttpOnly; SameSite=None; Secure`);

  const gatewaySetCookie = headers["set-cookie"];
  if (gatewaySetCookie) {
    if (Array.isArray(gatewaySetCookie)) {
      setCookies.push(...gatewaySetCookie);
    } else {
      setCookies.push(gatewaySetCookie);
    }
  }

  return { ...headers, "set-cookie": setCookies };
}

/** Strip CORS headers the gateway may have added (handled at top level) */
function stripCorsHeaders(headers: Record<string, string | string[]>): void {
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase().startsWith("access-control-")) {
      delete headers[key];
    }
  }
}

function cleanupPending(requestId: string): void {
  const entry = pending.get(requestId);
  if (entry) {
    clearTimeout(entry.timer);
    pending.delete(requestId);
  }
}

function sendAbort(entry: PendingRequest, requestId: string): void {
  try {
    if (entry.gatewayWs.readyState === entry.gatewayWs.OPEN) {
      entry.gatewayWs.send(JSON.stringify({ type: "http_request_abort", id: requestId }));
    }
  } catch {
    // ignore
  }
}

// ── Relay handler ────────────────────────────────────────────────

export function createHttpRelay(registry: Registry, useTls = false) {
  return async function handleRelayRequest(
    req: IncomingMessage,
    res: ServerResponse
  ): Promise<void> {
    // Find target gateway (session affinity via cookie, then realm-based, then load-balance)
    const gatewayId = parseCookie(req.headers.cookie, "gateway_relay");
    let gateway = gatewayId ? registry.getGateway(gatewayId) : undefined;

    if (!gateway) {
      const realmMatch = req.url?.match(/\/(?:realms|resources|admin)\/([^/]+)\//);
      if (realmMatch) {
        gateway = registry.getGatewayByRealm(realmMatch[1]);
      }
    }

    if (!gateway) {
      gateway = registry.getAvailableGateway();
    }

    if (!gateway) {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "No gateway available" }));
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

    // Send to gateway via WebSocket
    try {
      if (gateway.ws.readyState !== gateway.ws.OPEN) {
        throw new Error("Gateway WebSocket not open");
      }
      gateway.ws.send(JSON.stringify({
        type: "http_request",
        id: requestId,
        method: req.method || "GET",
        url: req.url || "/",
        headers,
        body,
      }));
    } catch {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Failed to reach gateway" }));
      return;
    }

    if (pending.size >= 5000) {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Too many pending requests" }));
      return;
    }

    // Register pending request
    const timer = setTimeout(() => {
      const entry = pending.get(requestId);
      if (entry && !entry.headersSent && !res.headersSent) {
        res.writeHead(504, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Gateway response timeout" }));
      } else if (entry && entry.headersSent) {
        // Streaming timed out — just end the response
        res.end();
      }
      pending.delete(requestId);
    }, RELAY_TIMEOUT_MS);

    pending.set(requestId, {
      res,
      gatewayWs: gateway.ws,
      timer,
      gatewayId: gateway.id,
      headersSent: false,
    });

    // Clean up on client disconnect (important for SSE)
    res.on("close", () => {
      const entry = pending.get(requestId);
      if (entry) {
        sendAbort(entry, requestId);
        cleanupPending(requestId);
      }
    });
  };
}

// ── Response handlers (called from signaling message handler) ────

/**
 * Handle a single `http_response` from a gateway (buffered mode).
 * Writes headers + body + end in one shot.
 */
export function handleHttpResponse(msg: {
  id: string;
  statusCode: number;
  headers: Record<string, string | string[]>;
  body: string;
}): void {
  const entry = pending.get(msg.id);
  if (!entry) return;

  cleanupPending(msg.id);

  if (entry.res.headersSent) return;

  stripCorsHeaders(msg.headers);
  const responseHeaders = addAffinityCookie(msg.headers, entry.gatewayId);
  const responseBody = Buffer.from(msg.body, "base64");

  entry.res.writeHead(msg.statusCode, responseHeaders);
  entry.res.end(responseBody);
}

/**
 * Handle `http_response_start` — beginning of a streaming response.
 * Writes headers immediately, switches to streaming mode.
 */
export function handleHttpResponseStart(msg: {
  id: string;
  statusCode: number;
  headers: Record<string, string | string[]>;
}): void {
  const entry = pending.get(msg.id);
  if (!entry || entry.res.headersSent) return;

  // Switch timeout to streaming mode (longer, per-chunk)
  clearTimeout(entry.timer);
  entry.timer = setTimeout(() => {
    entry.res.end();
    pending.delete(msg.id);
  }, STREAM_CHUNK_TIMEOUT_MS);

  stripCorsHeaders(msg.headers);
  const responseHeaders = addAffinityCookie(msg.headers, entry.gatewayId);

  entry.res.writeHead(msg.statusCode, responseHeaders);
  entry.headersSent = true;
}

/**
 * Handle `http_response_chunk` — a chunk of streaming response data.
 */
export function handleHttpResponseChunk(msg: {
  id: string;
  data: string; // base64
}): void {
  const entry = pending.get(msg.id);
  if (!entry || !entry.headersSent) return;

  // Reset streaming timeout on each chunk
  clearTimeout(entry.timer);
  entry.timer = setTimeout(() => {
    entry.res.end();
    pending.delete(msg.id);
  }, STREAM_CHUNK_TIMEOUT_MS);

  const chunk = Buffer.from(msg.data, "base64");
  entry.res.write(chunk);
}

/**
 * Handle `http_response_end` — end of a streaming response.
 */
export function handleHttpResponseEnd(msg: { id: string }): void {
  const entry = pending.get(msg.id);
  if (!entry) return;

  cleanupPending(msg.id);
  entry.res.end();
}

/**
 * Reject all pending requests for a given gateway.
 * Called when the gateway disconnects so requests don't wait for timeout.
 */
export function rejectPendingForGateway(gatewayId: string): void {
  for (const [requestId, entry] of pending) {
    if (entry.gatewayId === gatewayId) {
      clearTimeout(entry.timer);
      pending.delete(requestId);
      if (!entry.res.headersSent) {
        entry.res.writeHead(502, { "Content-Type": "application/json" });
        entry.res.end(JSON.stringify({ error: "Gateway disconnected" }));
      } else {
        entry.res.end();
      }
    }
  }
}
