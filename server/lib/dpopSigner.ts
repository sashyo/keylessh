/**
 * Server-side DPoP proof requester.
 *
 * Maintains WebSocket connections to browsers. When the server needs to call
 * TideCloak with DPoP, it asks the connected browser to sign a proof for the
 * specific URL + method, waits for the response, then uses it.
 *
 * Flow:
 *   Server needs proof → WS message to browser → browser signs → WS response → server uses proof
 */

import { WebSocketServer, WebSocket } from "ws";
import type { Server as HTTPServer } from "http";
import crypto from "crypto";
import { verifyTideCloakToken } from "./auth/tideJWT";

// Connected signers keyed by user ID
const signers = new Map<string, WebSocket>();

// Pending proof requests keyed by request ID
const pendingRequests = new Map<string, {
  resolve: (proof: string) => void;
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
}>();

/**
 * Set up the DPoP signer WebSocket endpoint.
 * Browsers connect here after login to act as signing oracles.
 */
export function setupDPoPSigner(httpServer: HTTPServer): void {
  const wss = new WebSocketServer({ server: httpServer, path: "/ws/dpop-signer" });

  wss.on("connection", async (ws: WebSocket, req) => {
    const url = new URL(req.url || "/", `http://${req.headers.host}`);
    const token = url.searchParams.get("token");

    if (!token) {
      ws.close(4001, "Missing token");
      return;
    }

    // Verify the token to get the user ID
    const payload = await verifyTideCloakToken(token, []);
    if (!payload?.sub) {
      ws.close(4002, "Invalid token");
      return;
    }

    const userId = payload.sub;

    // Close any existing connection for this user (only one signer per user)
    const existing = signers.get(userId);
    if (existing && existing.readyState === WebSocket.OPEN) {
      existing.close(4003, "Replaced by new connection");
    }

    signers.set(userId, ws);
    console.log(`[DPoP-Signer] User ${payload.preferred_username || userId} connected`);

    ws.on("message", (data) => {
      try {
        const msg = JSON.parse(data.toString());

        if (msg.type === "dpop_proof" && msg.requestId && msg.proof) {
          const pending = pendingRequests.get(msg.requestId);
          if (pending) {
            clearTimeout(pending.timer);
            pendingRequests.delete(msg.requestId);
            pending.resolve(msg.proof);
          }
        } else if (msg.type === "dpop_error" && msg.requestId) {
          const pending = pendingRequests.get(msg.requestId);
          if (pending) {
            clearTimeout(pending.timer);
            pendingRequests.delete(msg.requestId);
            pending.reject(new Error(msg.error || "DPoP signing failed"));
          }
        }
      } catch {
        // Ignore malformed messages
      }
    });

    ws.on("close", () => {
      if (signers.get(userId) === ws) {
        signers.delete(userId);
        console.log(`[DPoP-Signer] User ${payload.preferred_username || userId} disconnected`);
      }
    });

    ws.on("error", () => {
      if (signers.get(userId) === ws) {
        signers.delete(userId);
      }
    });
  });
}

/**
 * Request a DPoP proof from the browser for a specific TideCloak URL.
 *
 * @param userId - The authenticated user's sub claim
 * @param url - TideCloak URL to sign for (htu)
 * @param method - HTTP method (htm)
 * @param timeoutMs - How long to wait for the proof (default 5s)
 * @returns The signed DPoP proof JWT, or undefined if signer unavailable
 */
export async function requestDPoPProof(
  userId: string,
  url: string,
  method: string,
  timeoutMs = 5000,
): Promise<string | undefined> {
  const ws = signers.get(userId);
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return undefined; // No signer connected — fallback to Bearer
  }

  const requestId = crypto.randomUUID();

  return new Promise<string | undefined>((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingRequests.delete(requestId);
      resolve(undefined); // Timeout — fallback to Bearer
    }, timeoutMs);

    pendingRequests.set(requestId, {
      resolve: (proof) => resolve(proof),
      reject,
      timer,
    });

    // Ask the browser to sign
    ws.send(JSON.stringify({
      type: "dpop_request",
      requestId,
      url,
      method: method.toUpperCase(),
    }));
  });
}

/**
 * Check if a DPoP signer is connected for a user.
 */
export function hasSignerConnected(userId: string): boolean {
  const ws = signers.get(userId);
  return !!ws && ws.readyState === WebSocket.OPEN;
}
