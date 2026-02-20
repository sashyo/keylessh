/**
 * WebSocket server for registration, signaling, and admin monitoring.
 *
 * Handles messages:
 *   { type: "register", role: "waf"|"client", id, addresses?, metadata?, targetWafId? }
 *   { type: "candidate", targetId, candidate }
 *   { type: "sdp_offer"|"sdp_answer", targetId, fromId, sdp }
 *   { type: "subscribe_stats" }
 *   { type: "admin_action", action: "disconnect_client"|"drain_waf", targetId }
 */

import { WebSocketServer, WebSocket } from "ws";
import type { IncomingMessage } from "http";
import type { Server as HttpServer } from "http";
import type { Registry } from "./registry.js";
import type { WafMetadata, ConnectionType } from "./registry.js";
import { pairClient, pairClientWithWaf, forwardCandidate, forwardSdp } from "./pairing.js";
import { handleHttpResponse } from "../relay/http-relay.js";

interface SignalMessage {
  type: string;
  role?: "waf" | "client";
  id?: string;
  addresses?: string[];
  metadata?: WafMetadata;
  targetId?: string;
  targetWafId?: string;
  fromId?: string;
  candidate?: unknown;
  sdp?: string;
  sdpType?: string;
  action?: string;
  clientId?: string;
  connectionType?: ConnectionType;
}

export function createSignalingServer(
  httpServer: HttpServer,
  registry: Registry
): WebSocketServer {
  const wss = new WebSocketServer({ server: httpServer });
  const adminSubscribers = new Set<WebSocket>();

  // Broadcast stats to admin subscribers every 3 seconds
  const statsInterval = setInterval(() => {
    if (adminSubscribers.size === 0) return;
    const stats = { type: "stats_update", ...registry.getDetailedStats() };
    const payload = JSON.stringify(stats);
    for (const sub of adminSubscribers) {
      try {
        if (sub.readyState === sub.OPEN) {
          sub.send(payload);
        } else {
          adminSubscribers.delete(sub);
        }
      } catch {
        adminSubscribers.delete(sub);
      }
    }
  }, 3000);

  wss.on("close", () => {
    clearInterval(statsInterval);
  });

  wss.on("connection", (ws: WebSocket, req: IncomingMessage) => {
    // Capture client IP for reflexive address (x-forwarded-for behind proxy, else socket)
    const clientIp = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim()
      || req.socket.remoteAddress
      || undefined;

    // Store IP so we can set it on client registration
    (ws as unknown as Record<string, unknown>).__clientIp = clientIp;

    ws.on("message", (data) => {
      let msg: SignalMessage;
      try {
        msg = JSON.parse(data.toString());
      } catch {
        return;
      }

      switch (msg.type) {
        case "register":
          handleRegister(ws, msg, registry);
          break;
        case "candidate":
          handleCandidate(ws, msg, registry);
          break;
        case "sdp_offer":
        case "sdp_answer":
          handleSdp(ws, msg, registry);
          break;
        case "http_response":
          handleHttpResponse(msg as unknown as {
            id: string;
            statusCode: number;
            headers: Record<string, string | string[]>;
            body: string;
          });
          break;
        case "subscribe_stats":
          adminSubscribers.add(ws);
          safeSend(ws, { type: "stats_update", ...registry.getDetailedStats() });
          break;
        case "admin_action":
          handleAdminAction(ws, msg, registry);
          break;
        case "client_status":
          // WAF reports a client's connection type (p2p, turn, relay)
          if (msg.clientId && msg.connectionType) {
            registry.updateClientConnection(msg.clientId, msg.connectionType);
          }
          break;
        default:
          safeSend(ws, { type: "error", message: `Unknown message type: ${msg.type}` });
      }
    });

    ws.on("close", () => {
      adminSubscribers.delete(ws);
      registry.removeByWs(ws);
    });

    ws.on("error", () => {
      adminSubscribers.delete(ws);
      registry.removeByWs(ws);
    });
  });

  return wss;
}

function handleRegister(
  ws: WebSocket,
  msg: SignalMessage,
  registry: Registry
): void {
  if (!msg.id || !msg.role) {
    safeSend(ws, { type: "error", message: "Missing id or role" });
    return;
  }

  if (msg.role === "waf") {
    registry.registerWaf(msg.id, msg.addresses || [], ws, msg.metadata);
    safeSend(ws, { type: "registered", role: "waf", id: msg.id });
  } else if (msg.role === "client") {
    registry.registerClient(msg.id, ws);
    // Set reflexive address from the WebSocket connection IP
    const ip = (ws as unknown as Record<string, unknown>).__clientIp as string | undefined;
    if (ip) {
      registry.updateClientReflexive(msg.id, ip);
    }
    safeSend(ws, { type: "registered", role: "client", id: msg.id });

    // Explicit WAF selection or auto-pair
    if (msg.targetWafId) {
      pairClientWithWaf(registry, msg.id, msg.targetWafId);
    } else {
      pairClient(registry, msg.id);
    }
  } else {
    safeSend(ws, { type: "error", message: `Unknown role: ${msg.role}` });
  }
}

function handleSdp(
  ws: WebSocket,
  msg: SignalMessage,
  registry: Registry
): void {
  if (!msg.targetId || !msg.sdp || !msg.fromId) {
    safeSend(ws, { type: "error", message: "Missing targetId, fromId, or sdp" });
    return;
  }

  forwardSdp(registry, msg.fromId, msg.targetId, msg.type, msg.sdp, msg.sdpType);
}

function handleCandidate(
  ws: WebSocket,
  msg: SignalMessage,
  registry: Registry
): void {
  if (!msg.targetId || !msg.candidate) {
    safeSend(ws, { type: "error", message: "Missing targetId or candidate" });
    return;
  }

  const fromId = msg.fromId || "unknown";
  forwardCandidate(registry, fromId, msg.targetId, msg.candidate);
}

function handleAdminAction(
  ws: WebSocket,
  msg: SignalMessage,
  registry: Registry
): void {
  if (!msg.action || !msg.targetId) {
    safeSend(ws, { type: "error", message: "Missing action or targetId" });
    return;
  }

  let success = false;
  if (msg.action === "disconnect_client") {
    success = registry.forceDisconnectClient(msg.targetId);
  } else if (msg.action === "drain_waf") {
    success = registry.drainWaf(msg.targetId);
  }

  safeSend(ws, {
    type: "admin_result",
    action: msg.action,
    targetId: msg.targetId,
    success,
  });
}

function safeSend(ws: WebSocket, data: unknown): void {
  try {
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify(data));
    }
  } catch {
    // Connection lost
  }
}
