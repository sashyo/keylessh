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

self.addEventListener("install", function () {
  self.skipWaiting();
});

self.addEventListener("activate", function (event) {
  event.waitUntil(self.clients.claim());
});

// Listen for DC ready/closed signals from pages
self.addEventListener("message", function (event) {
  var clientId = event.source && event.source.id;
  if (!clientId) return;
  if (event.data && event.data.type === "dc_ready") {
    dcClients.add(clientId);
  } else if (event.data && event.data.type === "dc_closed") {
    dcClients.delete(clientId);
  }
});

/** WAF-internal paths — skip DataChannel, go through relay. */
var WAF_PATHS = /^\/(js\/|auth\/|login|webrtc-config|realms\/|resources\/|portal|health)/;

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
  if (url.origin !== self.location.origin) return;

  // Skip WAF-internal paths (strip prefix first for matching)
  if (WAF_PATHS.test(stripPrefix(url.pathname))) return;

  event.respondWith(rewriteAndHandle(event));
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
        if (prefix && !WAF_PATHS.test(url.pathname)) {
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

  // Only try DataChannel if the requesting client has signaled readiness
  if (!clientId || !dcClients.has(clientId)) {
    return fetch(fallbackRequest);
  }

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
        clearTimeout(timer);
        if (e.data.error) {
          resolve(fetch(fallbackRequest));
          return;
        }

        var bodyBytes = Uint8Array.from(atob(e.data.body), function (c) {
          return c.charCodeAt(0);
        });

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
