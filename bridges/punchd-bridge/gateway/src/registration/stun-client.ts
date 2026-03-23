/**
 * WebSocket client that registers with the STUN signaling server
 * and handles pairing/candidate messages.
 *
 * Also handles HTTP relay: the STUN server tunnels HTTP requests
 * from remote clients through this WebSocket connection.
 */

import WebSocket from "ws";
import { request as httpRequest } from "http";
import { request as httpsRequest } from "https";
import type { JWTPayload } from "jose";
import { createPeerHandler, type PeerHandler } from "../webrtc/peer-handler.js";
import type { BackendEntry } from "../config.js";

export interface StunRegistrationOptions {
  stunServerUrl: string;
  gatewayId: string;
  addresses: string[];
  /** Gateway listen port — used for local HTTP relay requests */
  listenPort: number;
  /** ICE servers for WebRTC, e.g. ["stun:relay.example.com:3478"] */
  iceServers?: string[];
  /** TURN server URL, e.g. "turn:host:3478" */
  turnServer?: string;
  /** Shared secret for TURN REST API ephemeral credentials */
  turnSecret?: string;
  /** Whether the gateway's HTTP server uses TLS */
  useTls?: boolean;
  /** Shared secret for STUN server API authentication */
  apiSecret?: string;
  /** Metadata for portal display and realm-based routing */
  metadata?: { displayName?: string; description?: string; backends?: { name: string; protocol?: string; auth?: string }[]; realm?: string };
  /** Backend configurations (needed by peer handler for TCP tunnels) */
  backends?: BackendEntry[];
  /** JWT verification function (for RDCleanPath auth) */
  verifyToken?: (token: string) => Promise<JWTPayload | null>;
  /** TideCloak client ID for dest: role extraction */
  tcClientId?: string;
  onPaired?: (client: { id: string; reflexiveAddress: string | null }) => void;
  onCandidate?: (fromId: string, candidate: unknown) => void;
}

export interface StunRegistration {
  close: () => void;
}

export function registerWithStun(
  options: StunRegistrationOptions
): StunRegistration {
  let ws: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let pingTimer: ReturnType<typeof setInterval> | null = null;
  let closed = false;
  let peerHandler: PeerHandler | null = null;
  let reconnectDelay = 1000; // Exponential backoff: 1s → 30s max
  let pongReceived = true;

  function connect() {
    if (closed) return;

    console.log(`[STUN-Reg] Connecting to ${options.stunServerUrl}...`);
    ws = new WebSocket(options.stunServerUrl);

    ws.on("open", () => {
      console.log("[STUN-Reg] Connected to STUN server");
      reconnectDelay = 1000; // Reset backoff on successful connection

      // Start client-side ping heartbeat to detect dead connections early
      pongReceived = true;
      if (pingTimer) clearInterval(pingTimer);
      pingTimer = setInterval(() => {
        if (!pongReceived) {
          console.warn("[STUN-Reg] No pong received — connection dead, reconnecting");
          ws?.terminate();
          return;
        }
        pongReceived = false;
        ws?.ping();
      }, 30_000);

      // Initialize WebRTC peer handler
      if (options.iceServers?.length) {
        peerHandler?.cleanup();
        peerHandler = createPeerHandler({
          iceServers: options.iceServers,
          turnServer: options.turnServer,
          turnSecret: options.turnSecret,
          listenPort: options.listenPort,
          useTls: options.useTls,
          gatewayId: options.gatewayId,
          sendSignaling: safeSend,
          backends: options.backends || [],
          verifyToken: options.verifyToken,
          tcClientId: options.tcClientId,
        });
        console.log("[STUN-Reg] WebRTC peer handler ready");
      }

      // Register as gateway
      safeSend({
        type: "register",
        role: "gateway",
        id: options.gatewayId,
        secret: options.apiSecret || undefined,
        addresses: options.addresses,
        metadata: options.metadata,
      });
    });

    ws.on("pong", () => { pongReceived = true; });

    ws.on("message", (data) => {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(data.toString());
      } catch {
        return;
      }

      switch (msg.type) {
        case "registered":
          console.log(`[STUN-Reg] Registered as gateway: ${options.gatewayId}`);
          break;

        case "paired":
          if (msg.client && typeof msg.client === "object") {
            const client = msg.client as {
              id: string;
              reflexiveAddress: string | null;
            };
            console.log(`[STUN-Reg] Paired with client: ${client.id}`);
            options.onPaired?.(client);
          }
          break;

        case "candidate":
          if (msg.fromId && msg.candidate) {
            // Forward to WebRTC peer handler if the candidate has mid (WebRTC ICE)
            const cand = msg.candidate as { candidate?: string; mid?: string };
            if (peerHandler && cand.candidate !== undefined && cand.mid !== undefined) {
              peerHandler.handleCandidate(msg.fromId as string, cand.candidate, cand.mid);
            }
            options.onCandidate?.(msg.fromId as string, msg.candidate);
          }
          break;

        case "sdp_offer":
          if (peerHandler && msg.fromId && msg.sdp) {
            peerHandler.handleSdpOffer(msg.fromId as string, msg.sdp as string);
          }
          break;

        case "http_request":
          handleHttpRequest(msg);
          break;

        case "http_request_abort":
          handleHttpRequestAbort(msg);
          break;

        case "error":
          console.error(`[STUN-Reg] Error: ${msg.message}`);
          break;
      }
    });

    ws.on("close", () => {
      console.log("[STUN-Reg] Disconnected from STUN server");
      if (pingTimer) { clearInterval(pingTimer); pingTimer = null; }
      scheduleReconnect();
    });

    ws.on("error", (err) => {
      console.error("[STUN-Reg] WebSocket error:", err.message);
    });
  }

  /**
   * Handle an HTTP request tunneled from the STUN server.
   * Makes a local request to the gateway's own HTTP server, collects the
   * response, and sends it back over WebSocket.
   */
  const ALLOWED_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

  // Track in-flight requests so the signal server can abort them (e.g. client disconnected)
  const pendingRequests = new Map<string, import("http").ClientRequest>();

  /** Content types that should be streamed chunk-by-chunk instead of buffered */
  function isStreamingResponse(res: import("http").IncomingMessage): boolean {
    const ct = (res.headers["content-type"] || "").toLowerCase();
    return ct.includes("text/event-stream")
      || ct.includes("application/x-ndjson")
      || (ct.includes("text/plain") && res.headers["transfer-encoding"] === "chunked");
  }

  function handleHttpRequestAbort(msg: Record<string, unknown>): void {
    const req = pendingRequests.get(msg.id as string);
    if (req) {
      req.destroy();
      pendingRequests.delete(msg.id as string);
    }
  }

  function handleHttpRequest(msg: Record<string, unknown>): void {
    const requestId = msg.id as string;
    const method = (msg.method as string) || "GET";
    const url = (msg.url as string) || "/";
    const headers = (msg.headers as Record<string, string | string[]>) || {};
    const bodyB64 = (msg.body as string) || "";

    // Validate URL path — must start with / and contain no CRLF (header injection)
    if (!url.startsWith("/") || /[\r\n]/.test(url)) {
      safeSend({
        type: "http_response",
        id: requestId,
        statusCode: 400,
        headers: { "content-type": "application/json" },
        body: Buffer.from(JSON.stringify({ error: "Invalid URL" })).toString("base64"),
      });
      return;
    }

    // Validate HTTP method
    if (!ALLOWED_METHODS.has(method.toUpperCase())) {
      safeSend({
        type: "http_response",
        id: requestId,
        statusCode: 405,
        headers: { "content-type": "application/json" },
        body: Buffer.from(JSON.stringify({ error: "Method not allowed" })).toString("base64"),
      });
      return;
    }

    console.log(`[STUN-Reg] Relay: ${method} ${url} (id: ${requestId})`);

    // Limit decoded body size to 10MB to prevent OOM
    const MAX_BODY_SIZE = 10 * 1024 * 1024;
    if (bodyB64 && bodyB64.length > MAX_BODY_SIZE * 1.37) { // base64 overhead ~37%
      safeSend({
        type: "http_response",
        id: requestId,
        statusCode: 413,
        headers: { "content-type": "application/json" },
        body: Buffer.from(JSON.stringify({ error: "Request body too large" })).toString("base64"),
      });
      return;
    }
    const bodyBuf = bodyB64 ? Buffer.from(bodyB64, "base64") : undefined;

    // Sanitize relay headers — strip internal routing headers that only
    // the gateway should set, to prevent the STUN server from injecting them
    const sanitizedHeaders = { ...headers };
    for (const h of ["x-forwarded-user", "x-forwarded-for", "x-forwarded-proto",
                      "x-forwarded-host", "x-forwarded-port", "x-dc-request",
                      "x-gateway-backend"]) {
      delete sanitizedHeaders[h];
    }

    // Make local request to the gateway's own HTTP server
    const makeReq = options.useTls ? httpsRequest : httpRequest;
    const req = makeReq(
      {
        hostname: "127.0.0.1",
        port: options.listenPort,
        path: url,
        method,
        headers: sanitizedHeaders as Record<string, string | string[]>,
        rejectUnauthorized: false, // self-signed cert
      },
      (res) => {
        // Normalize response headers
        const responseHeaders: Record<string, string | string[]> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (value !== undefined) {
            responseHeaders[key] = value as string | string[];
          }
        }

        if (isStreamingResponse(res)) {
          // Streaming mode: forward chunks as they arrive (SSE, NDJSON, etc.)
          console.log(`[STUN-Reg] Streaming relay: ${res.statusCode} for ${url}`);
          safeSend({
            type: "http_response_start",
            id: requestId,
            statusCode: res.statusCode || 200,
            headers: responseHeaders,
          });

          res.on("data", (chunk: Buffer) => {
            safeSend({
              type: "http_response_chunk",
              id: requestId,
              data: chunk.toString("base64"),
            });
          });

          res.on("end", () => {
            pendingRequests.delete(requestId);
            safeSend({ type: "http_response_end", id: requestId });
          });
        } else {
          // Buffered mode: collect full response then send
          const chunks: Buffer[] = [];
          let totalResponseSize = 0;
          const MAX_RESPONSE = 50 * 1024 * 1024; // 50MB
          let aborted = false;
          res.on("data", (chunk: Buffer) => {
            totalResponseSize += chunk.length;
            if (totalResponseSize > MAX_RESPONSE) {
              if (!aborted) {
                aborted = true;
                req.destroy();
                pendingRequests.delete(requestId);
                safeSend({
                  type: "http_response", id: requestId, statusCode: 502,
                  headers: { "content-type": "application/json" },
                  body: Buffer.from(JSON.stringify({ error: "Response too large" })).toString("base64"),
                });
              }
              return;
            }
            chunks.push(chunk);
          });
          res.on("end", () => {
            if (aborted) return;
            pendingRequests.delete(requestId);
            const responseBody = Buffer.concat(chunks);

            // If response body > 512KB, send as chunked to stay under WS maxPayload.
            // Base64 of 512KB ≈ 700KB which fits in a 1MB WS frame with headroom.
            const MAX_SINGLE_WS = 512 * 1024;
            if (responseBody.length > MAX_SINGLE_WS) {
              console.log(`[STUN-Reg] Relay response (chunked): ${res.statusCode} for ${url} (${responseBody.length} bytes)`);
              safeSend({
                type: "http_response_start",
                id: requestId,
                statusCode: res.statusCode || 200,
                headers: responseHeaders,
              });
              const CHUNK_SIZE = 256 * 1024;
              for (let i = 0; i < responseBody.length; i += CHUNK_SIZE) {
                safeSend({
                  type: "http_response_chunk",
                  id: requestId,
                  data: responseBody.subarray(i, Math.min(i + CHUNK_SIZE, responseBody.length)).toString("base64"),
                });
              }
              safeSend({ type: "http_response_end", id: requestId });
            } else {
              const bodyB64 = responseBody.toString("base64");
              console.log(`[STUN-Reg] Relay response: ${res.statusCode} for ${url} (${bodyB64.length} bytes b64)`);
              safeSend({
                type: "http_response",
                id: requestId,
                statusCode: res.statusCode || 500,
                headers: responseHeaders,
                body: bodyB64,
              });
            }
          });
        }

        res.on("error", () => {
          pendingRequests.delete(requestId);
        });
      }
    );

    pendingRequests.set(requestId, req);

    // Timeout only applies to non-streaming (initial response). Streaming responses
    // clear the timeout once headers arrive (handled by node http client).
    req.setTimeout(30000, () => {
      req.destroy();
      pendingRequests.delete(requestId);
      safeSend({
        type: "http_response",
        id: requestId,
        statusCode: 504,
        headers: { "content-type": "application/json" },
        body: Buffer.from(JSON.stringify({ error: "Gateway timeout" })).toString("base64"),
      });
    });

    req.on("error", (err) => {
      pendingRequests.delete(requestId);
      console.error(`[STUN-Reg] Relay request failed: ${err.message}`);
      safeSend({
        type: "http_response",
        id: requestId,
        statusCode: 502,
        headers: { "content-type": "application/json" },
        body: Buffer.from(
          JSON.stringify({ error: "Gateway internal error" })
        ).toString("base64"),
      });
    });

    if (bodyBuf && bodyBuf.length > 0) {
      req.end(bodyBuf);
    } else {
      req.end();
    }
  }

  function scheduleReconnect() {
    if (closed) return;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    // Exponential backoff with 20% jitter: 1s → 2s → 4s → ... → 30s max
    const jitter = 1 + (Math.random() - 0.5) * 0.4; // 0.8x–1.2x
    const delay = Math.min(reconnectDelay * jitter, 30000);
    reconnectTimer = setTimeout(() => {
      console.log(`[STUN-Reg] Reconnecting (delay: ${Math.round(delay)}ms)...`);
      connect();
    }, delay);
    reconnectDelay = Math.min(reconnectDelay * 2, 30000);
  }

  function safeSend(data: unknown) {
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(data));
    }
  }

  // Start initial connection
  connect();

  return {
    close() {
      closed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (pingTimer) { clearInterval(pingTimer); pingTimer = null; }
      peerHandler?.cleanup();
      peerHandler = null;
      if (ws) {
        ws.close();
        ws = null;
      }
    },
  };
}
