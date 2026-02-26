/**
 * Service Worker for WebRTC DataChannel HTTP tunneling.
 *
 * Intercepts same-origin sub-resource requests and routes them through
 * the page's WebRTC DataChannel when available. Navigation requests
 * always use the network (relay) since they load new pages that need
 * to establish their own DataChannel.
 *
 * The page signals DC readiness via postMessage({ type: "dc_ready" }).
 * Only clients that have signaled are used for DataChannel routing.
 *
 * Also handles path-based backend routing: if the requesting page is
 * under /__b/<name>/, prefixless absolute paths are rewritten to
 * include the prefix.
 */

// Clients that have signaled an active DataChannel
var dcClients = new Set();

// Callbacks waiting for a specific client's DC to become ready
var dcWaiters = new Map(); // clientId → [resolve, ...]

self.addEventListener("install", function () {
  self.skipWaiting();
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    self.clients.claim().then(function () {
      // After claiming all clients, ask each if it has an active DataChannel.
      // Clients with an active DC will respond with dc_ready, rebuilding
      // dcClients after a SW update (skipWaiting clears the old SW's state).
      return self.clients.matchAll({ type: "window" }).then(function (allClients) {
        allClients.forEach(function (client) {
          client.postMessage({ type: "dc_check" });
        });
      });
    })
  );
});

// Listen for DC ready/closed signals from pages
self.addEventListener("message", function (event) {
  var clientId = event.source && event.source.id;
  if (!clientId) return;
  if (event.data && event.data.type === "dc_ready") {
    dcClients.add(clientId);
    // Wake up any fetch handlers waiting for this client's DC
    var waiters = dcWaiters.get(clientId);
    if (waiters) {
      waiters.forEach(function (resolve) { resolve(true); });
      dcWaiters.delete(clientId);
    }
  } else if (event.data && event.data.type === "dc_closed") {
    dcClients.delete(clientId);
  }
});

/** Wait for a client's DataChannel to become ready, with timeout. */
function waitForDc(clientId, timeoutMs) {
  if (dcClients.has(clientId)) return Promise.resolve(true);
  return new Promise(function (resolve) {
    var timer = setTimeout(function () { resolve(false); }, timeoutMs);
    var wrapped = function (ready) {
      clearTimeout(timer);
      resolve(ready);
    };
    var list = dcWaiters.get(clientId);
    if (!list) {
      list = [];
      dcWaiters.set(clientId, list);
    }
    list.push(wrapped);
  });
}

/** Gateway-internal paths — skip DataChannel, go through relay. */
var GATEWAY_PATHS = /^\/(js\/|auth\/|login|webrtc-config|_idp\/|realms\/|resources\/|portal|health)/;

function extractPrefix(pathname) {
  var m = pathname.match(/^\/__b\/[^/]+/);
  return m ? m[0] : null;
}

function stripPrefix(pathname) {
  var m = pathname.match(/^\/__b\/[^/]+(\/.*)/);
  return m ? m[1] : pathname;
}

self.addEventListener("fetch", function (event) {
  // Navigation requests (page loads) always use relay — new pages
  // need to establish their own DataChannel
  if (event.request.mode === "navigate") return;

  var url = new URL(event.request.url);

  // Intercept requests to localhost (any port) that target TideCloak
  // paths (/realms/*, /resources/*). The SDK/adapter may construct
  // absolute URLs using the TideCloak's internal localhost address.
  // Rewrite them to same-origin so they route through the gateway proxy.
  if (
    url.origin !== self.location.origin &&
    (url.hostname === "localhost" || url.hostname === "127.0.0.1") &&
    (url.pathname.startsWith("/realms/") || url.pathname.startsWith("/resources/"))
  ) {
    console.log("[SW] Rewriting localhost request:", event.request.url);
    var rewrittenUrl = self.location.origin + url.pathname + url.search;
    event.respondWith(
      fetch(new Request(rewrittenUrl, {
        method: event.request.method,
        headers: event.request.headers,
        body: event.request.method !== "GET" && event.request.method !== "HEAD"
          ? event.request.body
          : undefined,
        credentials: "same-origin",
        redirect: event.request.redirect,
      }))
    );
    return;
  }

  if (url.origin !== self.location.origin) return;

  // Skip gateway-internal paths (strip prefix first for matching)
  if (GATEWAY_PATHS.test(stripPrefix(url.pathname))) return;

  // If DC is already active, route through it immediately.
  // If not yet ready, wait up to 8s for it — this prevents the burst
  // of sub-resource requests from flooding the STUN relay while
  // WebRTC is still connecting. Falls back to network on timeout.
  if (!event.clientId) return;

  if (dcClients.has(event.clientId)) {
    event.respondWith(rewriteAndHandle(event));
    return;
  }

  event.respondWith(
    waitForDc(event.clientId, 8000).then(function (ready) {
      if (ready) {
        return rewriteAndHandle(event);
      }
      // DC didn't connect in time — fall back to network (relay)
      return fetch(event.request);
    })
  );
});

async function rewriteAndHandle(event) {
  var request = event.request;
  var url = new URL(request.url);

  // Prepend /__b/<name> prefix from requesting client if needed
  if (!url.pathname.startsWith("/__b/") && event.clientId) {
    try {
      var client = await self.clients.get(event.clientId);
      if (client) {
        var prefix = extractPrefix(new URL(client.url).pathname);
        if (prefix && !GATEWAY_PATHS.test(url.pathname)) {
          var newUrl = new URL(request.url);
          newUrl.pathname = prefix + newUrl.pathname;
          request = new Request(newUrl.toString(), request);
        }
      }
    } catch (e) {
      // proceed with original
    }
  }

  return handleViaDataChannel(event.clientId, request);
}

async function handleViaDataChannel(clientId, request) {
  var fallbackRequest = request.clone();

  try {
    var client = await self.clients.get(clientId);
    if (!client) {
      dcClients.delete(clientId);
      return fetch(fallbackRequest);
    }

    // Read request body
    var body = "";
    if (request.method !== "GET" && request.method !== "HEAD") {
      var buf = await request.arrayBuffer();
      if (buf.byteLength > 0) {
        body = btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
      }
    }

    var mc = new MessageChannel();
    var headers = {};
    for (var pair of request.headers) {
      headers[pair[0]] = pair[1];
    }

    client.postMessage(
      {
        type: "dc_fetch",
        url: new URL(request.url).pathname + new URL(request.url).search,
        method: request.method,
        headers: headers,
        body: body,
      },
      [mc.port2]
    );

    return new Promise(function (resolve) {
      var timer = setTimeout(function () {
        resolve(fetch(fallbackRequest));
      }, 10000);

      mc.port1.onmessage = function (e) {
        // Progress signal: large response started downloading, extend timeout
        if (e.data && e.data.type === "progress") {
          clearTimeout(timer);
          timer = setTimeout(function () {
            resolve(fetch(fallbackRequest));
          }, 300000); // 5 minutes for large downloads (video segments)
          return;
        }
        clearTimeout(timer);
        if (e.data.error) {
          resolve(fetch(fallbackRequest));
          return;
        }

        var responseHeaders = new Headers();
        for (var key in e.data.headers || {}) {
          try {
            var val = e.data.headers[key];
            if (Array.isArray(val)) {
              val.forEach(function (v) { responseHeaders.append(key, v); });
            } else {
              responseHeaders.set(key, val);
            }
          } catch (err) {
            // skip forbidden headers
          }
        }

        if (e.data.streaming) {
          // Live streaming response (SSE, NDJSON) — return a ReadableStream
          // so the browser can consume data progressively.
          var stream = new ReadableStream({
            start: function (controller) {
              mc.port1.onmessage = function (ev) {
                if (ev.data.type === "chunk" && ev.data.data) {
                  try {
                    if (ev.data.data instanceof ArrayBuffer) {
                      controller.enqueue(new Uint8Array(ev.data.data));
                    } else {
                      var raw = atob(ev.data.data);
                      var bytes = new Uint8Array(raw.length);
                      for (var i = 0; i < raw.length; i++) {
                        bytes[i] = raw.charCodeAt(i);
                      }
                      controller.enqueue(bytes);
                    }
                  } catch (err) {
                    // Stream may have been cancelled
                  }
                } else if (ev.data.type === "end") {
                  try { controller.close(); } catch (err) {}
                }
              };
            },
            cancel: function () {
              mc.port1.onmessage = null;
            },
          });
          resolve(
            new Response(stream, {
              status: e.data.statusCode,
              headers: responseHeaders,
            })
          );
          return;
        }

        var bodyBytes;
        if (e.data.binaryBody instanceof ArrayBuffer) {
          bodyBytes = new Uint8Array(e.data.binaryBody);
        } else {
          bodyBytes = Uint8Array.from(atob(e.data.body || ""), function (c) {
            return c.charCodeAt(0);
          });
        }

        console.log("[SW] DC response:", e.data.statusCode,
          "body:", bodyBytes.length, "bytes",
          "content-range:", responseHeaders.get("content-range"),
          "via:", e.data.binaryBody ? "ArrayBuffer" : "base64");

        resolve(
          new Response(bodyBytes, {
            status: e.data.statusCode,
            headers: responseHeaders,
          })
        );
      };
    });
  } catch (e) {
    return fetch(fallbackRequest);
  }
}
