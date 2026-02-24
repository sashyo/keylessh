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
import { createPeerHandler, type PeerHandler } from "../webrtc/peer-handler.js";

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
  metadata?: { displayName?: string; description?: string; backends?: { name: string }[]; realm?: string };
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

  function handleHttpRequest(msg: Record<string, unknown>): void {
    const requestId = msg.id as string;
    const method = (msg.method as string) || "GET";
    const url = (msg.url as string) || "/";
    const headers = (msg.headers as Record<string, string | string[]>) || {};
    const bodyB64 = (msg.body as string) || "";

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

    const bodyBuf = bodyB64 ? Buffer.from(bodyB64, "base64") : undefined;

    // Make local request to the gateway's own listen port
    const makeReq = options.useTls ? httpsRequest : httpRequest;
    const req = makeReq(
      {
        hostname: "127.0.0.1",
        port: options.listenPort,
        path: url,
        method,
        headers: headers as Record<string, string | string[]>,
        rejectUnauthorized: false, // self-signed cert
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const responseBody = Buffer.concat(chunks).toString("base64");

          // Normalize headers: convert arrays for Set-Cookie
          const responseHeaders: Record<string, string | string[]> = {};
          for (const [key, value] of Object.entries(res.headers)) {
            if (value !== undefined) {
              responseHeaders[key] = value as string | string[];
            }
          }

          console.log(`[STUN-Reg] Relay response: ${res.statusCode} for ${url} (${responseBody.length} bytes b64)`);
          safeSend({
            type: "http_response",
            id: requestId,
            statusCode: res.statusCode || 500,
            headers: responseHeaders,
            body: responseBody,
          });
        });
      }
    );

    req.setTimeout(30000, () => {
      req.destroy();
      safeSend({
        type: "http_response",
        id: requestId,
        statusCode: 504,
        headers: { "content-type": "application/json" },
        body: Buffer.from(JSON.stringify({ error: "Gateway timeout" })).toString("base64"),
      });
    });

    req.on("error", (err) => {
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
