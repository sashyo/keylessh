/**
 * Client-side DPoP signing oracle.
 *
 * Connects to the server via WebSocket. When the server needs a DPoP proof
 * for a TideCloak API call, it sends a signing request over the WebSocket.
 * The browser signs it with the Heimdall key and sends the proof back.
 *
 * The DPoP private key never leaves the browser.
 */

import { IAMService } from "@tidecloak/js";
import { isDpopEnabled } from "./appFetch";

let ws: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

/**
 * Connect the DPoP signer WebSocket.
 * Call this after login when the user is authenticated.
 */
export function connectDPoPSigner(): void {
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    return; // Already connected
  }

  if (!isDpopEnabled()) return;

  const token = localStorage.getItem("access_token");
  if (!token) return;

  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${proto}//${window.location.host}/ws/dpop-signer?token=${encodeURIComponent(token)}`;

  ws = new WebSocket(url);

  ws.onopen = () => {
    console.log("[DPoP-Signer] Connected");
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  };

  ws.onmessage = async (event) => {
    try {
      const msg = JSON.parse(event.data);

      if (msg.type === "dpop_request" && msg.requestId && msg.url && msg.method) {
        try {
          const provider = (IAMService as any)._dpopProvider;
          if (!provider?.generateDPoPProof) {
            throw new Error("DPoP provider not available");
          }

          const currentToken = await IAMService.getToken();
          const proof = await provider.generateDPoPProof(
            msg.url,
            msg.method,
            currentToken || undefined,
          );

          ws?.send(JSON.stringify({
            type: "dpop_proof",
            requestId: msg.requestId,
            proof,
          }));
        } catch (e) {
          ws?.send(JSON.stringify({
            type: "dpop_error",
            requestId: msg.requestId,
            error: e instanceof Error ? e.message : String(e),
          }));
        }
      }
    } catch {
      // Ignore malformed messages
    }
  };

  ws.onclose = () => {
    console.log("[DPoP-Signer] Disconnected");
    ws = null;
    // Reconnect after 5 seconds
    if (!reconnectTimer) {
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        connectDPoPSigner();
      }, 5000);
    }
  };

  ws.onerror = () => {
    // onclose will fire after this
  };
}

/**
 * Disconnect the DPoP signer.
 * Call this on logout.
 */
export function disconnectDPoPSigner(): void {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  if (ws) {
    ws.close();
    ws = null;
  }
}
