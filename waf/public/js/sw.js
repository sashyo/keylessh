/**
 * Service Worker for WebRTC DataChannel HTTP tunneling.
 *
 * Intercepts same-origin fetch requests and tries to route them through
 * the page's WebRTC DataChannel. If the DataChannel isn't available
 * (no page client, DC not open), falls back to normal fetch (HTTP relay).
 *
 * Stateless design — no in-memory flags. The page decides whether to use
 * the DataChannel or respond with an error (triggering relay fallback).
 * This avoids issues with browser terminating idle SWs and losing state.
 */

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
  // Only intercept same-origin requests
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  // Skip SW scripts and endpoints that need cookies via relay
  if (url.pathname === "/js/sw.js" || url.pathname === "/js/webrtc-upgrade.js") return;
  if (url.pathname === "/auth/session-token") return;
  if (url.pathname === "/webrtc-config") return;
  if (url.pathname.startsWith("/auth/")) return;
  if (url.pathname === "/login") return;

  event.respondWith(handleViaDataChannel(event.request));
});

async function handleViaDataChannel(request) {
  // Clone before consuming, so fallback fetch() still works
  const fallbackRequest = request.clone();

  try {
    // Find a window client with an active DataChannel
    const clients = await self.clients.matchAll({ type: "window" });
    if (clients.length === 0) {
      return fetch(fallbackRequest);
    }

    // Read request body (consumes the original request)
    let body = "";
    if (request.method !== "GET" && request.method !== "HEAD") {
      const buf = await request.arrayBuffer();
      if (buf.byteLength > 0) {
        body = btoa(String.fromCharCode(...new Uint8Array(buf)));
      }
    }

    // Send request to page via MessageChannel
    const { port1, port2 } = new MessageChannel();

    const headers = {};
    for (const [key, value] of request.headers) {
      headers[key] = value;
    }

    clients[0].postMessage(
      {
        type: "dc_fetch",
        url: new URL(request.url).pathname + new URL(request.url).search,
        method: request.method,
        headers,
        body,
      },
      [port2]
    );

    // Wait for response from page — short timeout since page responds fast
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        console.log(`[SW] datachannel timeout, fallback: ${request.url}`);
        resolve(fetch(fallbackRequest));
      }, 10000);

      port1.onmessage = (e) => {
        clearTimeout(timer);
        if (e.data.error) {
          // DataChannel not open — fall back to relay
          resolve(fetch(fallbackRequest));
          return;
        }

        // Decode base64 body
        const bodyBytes = Uint8Array.from(atob(e.data.body), (c) =>
          c.charCodeAt(0)
        );

        // Build response headers
        const responseHeaders = new Headers();
        for (const [key, value] of Object.entries(e.data.headers || {})) {
          try {
            if (Array.isArray(value)) {
              value.forEach((v) => responseHeaders.append(key, v));
            } else {
              responseHeaders.set(key, value);
            }
          } catch {
            // Some headers can't be set in Service Worker responses
          }
        }

        console.log(`[SW] datachannel: ${new URL(request.url).pathname} → ${e.data.statusCode}`);
        resolve(
          new Response(bodyBytes, {
            status: e.data.statusCode,
            headers: responseHeaders,
          })
        );
      };
    });
  } catch {
    // Any error — fall back to relay
    return fetch(fallbackRequest);
  }
}
