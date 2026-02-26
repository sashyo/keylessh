/**
 * WebRTC DataChannel upgrade script.
 *
 * After the page loads (via HTTP relay), this script attempts to
 * establish a direct WebRTC DataChannel to the gateway. If successful,
 * it registers a Service Worker that routes subsequent HTTP requests
 * through the DataChannel for lower latency.
 *
 * Falls back gracefully — if WebRTC fails, HTTP relay continues working.
 * Automatically reconnects when the DataChannel or signaling drops.
 */

(function () {
  "use strict";

  // Detect /__b/<name> prefix from current page URL so gateway-internal
  // fetches (session-token, webrtc-config) route through the STUN relay
  const BACKEND_PREFIX = (function () {
    const m = location.pathname.match(/^\/__b\/[^/]+/);
    return m ? m[0] : "";
  })();
  const CONFIG_ENDPOINT = BACKEND_PREFIX + "/webrtc-config";
  const NativeWebSocket = window.WebSocket;
  const RECONNECT_DELAY = 5000;
  const MAX_RECONNECT_DELAY = 60000;

  let signalingWs = null;
  let peerConnection = null;
  let dataChannel = null;
  let clientId = "client-" + Math.random().toString(36).slice(2, 10);
  let pairedGatewayId = null;
  let config = null;
  let sessionToken = null;
  let tokenRefreshTimer = null;
  let reconnectAttempts = 0;
  let reconnectTimer = null;
  let swRegistered = false;
  let dcReadySignaled = false;

  // Pending requests waiting for DataChannel responses
  const pendingRequests = new Map();
  // In-flight chunked responses being reassembled
  const chunkedResponses = new Map();
  // MessagePorts for streaming responses (SSE, NDJSON) back to SW
  const streamingPorts = new Map();
  // Active WebSocket connections tunneled through DataChannel
  const dcWebSockets = new Map();

  async function init() {
    try {
      const res = await fetch(CONFIG_ENDPOINT);
      if (!res.ok) {
        console.log("[WebRTC] Config not available, skipping upgrade");
        return;
      }
      config = await res.json();
      console.log("[WebRTC] Config loaded:", config);

      await fetchSessionToken();
      connectSignaling();
    } catch (err) {
      console.log("[WebRTC] Upgrade not available:", err.message);
    }
  }

  /** Clean up peer connection and DataChannel without triggering reconnect. */
  function cleanupPeer() {
    if (dataChannel) {
      try { dataChannel.onclose = null; dataChannel.onerror = null; dataChannel.close(); } catch {}
      dataChannel = null;
    }
    if (peerConnection) {
      try { peerConnection.onicecandidate = null; peerConnection.onconnectionstatechange = null; peerConnection.close(); } catch {}
      peerConnection = null;
    }
    pairedGatewayId = null;
    if (tokenRefreshTimer) { clearInterval(tokenRefreshTimer); tokenRefreshTimer = null; }
    // Reject pending requests so they fall back to relay
    for (const [id, entry] of pendingRequests) {
      entry.resolve({ statusCode: 502, headers: {}, body: "" });
    }
    pendingRequests.clear();
    chunkedResponses.clear();
    // End any in-flight streaming responses so SW promises don't hang
    for (var [id, port] of streamingPorts) {
      port.postMessage({ type: "end" });
    }
    streamingPorts.clear();
    // Close all DataChannel-tunneled WebSocket connections
    for (const [id, ws] of dcWebSockets) {
      ws._fireClose(1001, "DataChannel closed");
    }
    dcWebSockets.clear();
    // Tell SW this client no longer has DataChannel
    dcReadySignaled = false;
    if (navigator.serviceWorker.controller) {
      navigator.serviceWorker.controller.postMessage({ type: "dc_closed" });
    }
  }

  /** Schedule a reconnection attempt with exponential backoff. */
  function scheduleReconnect() {
    if (reconnectTimer) return;
    const delay = Math.min(RECONNECT_DELAY * Math.pow(1.5, reconnectAttempts), MAX_RECONNECT_DELAY);
    reconnectAttempts++;
    console.log(`[WebRTC] Reconnecting in ${Math.round(delay / 1000)}s (attempt ${reconnectAttempts})...`);
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      reconnect();
    }, delay);
  }

  /** Reconnect: refresh token, new client ID, clean state, reconnect signaling. */
  async function reconnect() {
    cleanupPeer();
    if (signalingWs) {
      try { signalingWs.onclose = null; signalingWs.close(); } catch {}
      signalingWs = null;
    }
    // Get a fresh session token (the old one may have expired)
    await fetchSessionToken();
    if (!sessionToken) {
      console.log("[WebRTC] No session token — skipping reconnect");
      return;
    }
    // New client ID so the signal server doesn't confuse with old state
    clientId = "client-" + Math.random().toString(36).slice(2, 10);
    connectSignaling();
  }

  function connectSignaling() {
    if (!config?.signalingUrl) return;

    console.log("[WebRTC] Connecting to signaling:", config.signalingUrl);
    signalingWs = new NativeWebSocket(config.signalingUrl);

    signalingWs.onopen = () => {
      console.log("[WebRTC] Signaling connected");
      if (!sessionToken) {
        console.log("[WebRTC] No session token — cannot authenticate with signal server");
        signalingWs.close();
        return;
      }
      const registerMsg = {
        type: "register",
        role: "client",
        id: clientId,
        token: sessionToken,
      };
      if (config.targetGatewayId) {
        registerMsg.targetGatewayId = config.targetGatewayId;
        console.log("[WebRTC] Targeting gateway:", config.targetGatewayId);
      }
      signalingWs.send(JSON.stringify(registerMsg));
    };

    signalingWs.onmessage = (event) => {
      let msg;
      try {
        msg = JSON.parse(event.data);
      } catch {
        return;
      }
      handleSignalingMessage(msg);
    };

    signalingWs.onclose = () => {
      console.log("[WebRTC] Signaling disconnected");
      cleanupPeer();
      scheduleReconnect();
    };

    signalingWs.onerror = () => {
      console.log("[WebRTC] Signaling error");
    };
  }

  function handleSignalingMessage(msg) {
    switch (msg.type) {
      case "registered":
        console.log("[WebRTC] Registered as client:", msg.id);
        break;

      case "paired":
        pairedGatewayId = msg.gateway?.id;
        console.log("[WebRTC] Paired with gateway:", pairedGatewayId);
        startWebRTC();
        break;

      case "sdp_answer":
        if (peerConnection && msg.sdp) {
          console.log("[WebRTC] Received SDP answer");
          peerConnection
            .setRemoteDescription(
              new RTCSessionDescription({ type: msg.sdpType || "answer", sdp: msg.sdp })
            )
            .catch((err) => console.error("[WebRTC] setRemoteDescription error:", err));
        }
        break;

      case "candidate":
        if (peerConnection && msg.candidate) {
          const c = msg.candidate;
          console.log("[WebRTC] Remote ICE candidate:", c.candidate);
          peerConnection
            .addIceCandidate(
              new RTCIceCandidate({ candidate: c.candidate, sdpMid: c.mid })
            )
            .catch((err) => console.error("[WebRTC] addIceCandidate error:", err));
        }
        break;

      case "error":
        console.error("[WebRTC] Signaling error:", msg.message);
        // Retry pairing if gateway was temporarily unavailable
        if (msg.message && msg.message.indexOf("No gateway") !== -1 && !pairedGatewayId) {
          var retryDelay = Math.min(3000 * Math.pow(1.5, reconnectAttempts), 30000);
          reconnectAttempts++;
          console.log("[WebRTC] Will retry pairing in " + Math.round(retryDelay / 1000) + "s...");
          setTimeout(function () {
            if (signalingWs && signalingWs.readyState === WebSocket.OPEN && !pairedGatewayId) {
              console.log("[WebRTC] Retrying registration/pairing...");
              var registerMsg = {
                type: "register",
                role: "client",
                id: clientId,
                token: sessionToken,
              };
              if (config.targetGatewayId) {
                registerMsg.targetGatewayId = config.targetGatewayId;
              }
              signalingWs.send(JSON.stringify(registerMsg));
            }
          }, retryDelay);
        }
        break;
    }
  }

  function startWebRTC() {
    if (!pairedGatewayId) return;

    // Save gateway ID before cleanup (cleanupPeer resets pairedGatewayId)
    const targetGateway = pairedGatewayId;
    cleanupPeer();
    pairedGatewayId = targetGateway;

    console.log("[WebRTC] Starting WebRTC handshake with gateway:", pairedGatewayId);

    const iceServers = [];
    if (config.stunServer) {
      iceServers.push({ urls: config.stunServer });
    }
    if (config.turnServer) {
      iceServers.push({
        urls: config.turnServer,
        username: config.turnUsername || "",
        credential: config.turnPassword || "",
      });
    }
    console.log("[WebRTC] ICE servers:", JSON.stringify(iceServers));

    peerConnection = new RTCPeerConnection({
      iceServers: iceServers.length > 0 ? iceServers : undefined,
    });

    dataChannel = peerConnection.createDataChannel("http-tunnel", {
      ordered: true,
    });
    dataChannel.binaryType = "arraybuffer";

    dataChannel.onopen = async () => {
      console.log("[WebRTC] DataChannel OPEN — direct connection established!");
      reconnectAttempts = 0; // Reset backoff on success
      // Refresh session token before DC requests start (token may have expired since page load)
      await fetchSessionToken();
      // Refresh token every 4 minutes to stay ahead of 5-minute expiry
      if (tokenRefreshTimer) clearInterval(tokenRefreshTimer);
      tokenRefreshTimer = setInterval(fetchSessionToken, 4 * 60 * 1000);
      installWebSocketShim();
      await registerServiceWorker();

      // Only signal dc_ready if we have a valid session token — without it,
      // DC requests would 401 and fall back to relay anyway (wasted round-trip)
      if (!sessionToken) {
        console.warn("[WebRTC] No session token — DC routing deferred until token acquired");
        return;
      }

      // Wait for SW to claim this page (clients.claim() may still be pending)
      if (!navigator.serviceWorker.controller) {
        await navigator.serviceWorker.ready;
        if (!navigator.serviceWorker.controller) {
          await new Promise(function (resolve) {
            navigator.serviceWorker.addEventListener("controllerchange", resolve, { once: true });
            setTimeout(resolve, 3000); // don't wait forever
          });
        }
      }
      signalDcReady();
    };

    dataChannel.onmessage = (event) => {
      // Binary message — could be a streaming chunk OR a JSON control message
      // sent as binary (to avoid SCTP PPID confusion when interleaving).
      // JSON messages start with '{'; chunk data starts with a UUID (hex digit).
      if (typeof event.data !== "string") {
        const buf = new Uint8Array(event.data);
        if (buf.length === 0) return;

        // Check if this is a JSON control message sent as binary
        // (0x7B = '{' — JSON objects always start with this)
        if (buf[0] === 0x7B) {
          try {
            const msg = JSON.parse(new TextDecoder().decode(buf));
            handleDcMessage(msg);
          } catch {
            console.error("[WebRTC] Failed to parse binary-JSON DC message");
          }
          return;
        }

        // Binary streaming chunk: 36-byte requestId prefix + raw bytes
        if (buf.length < 36) return;
        const requestId = new TextDecoder().decode(buf.subarray(0, 36));
        const entry = chunkedResponses.get(requestId);
        if (!entry || !entry.streaming) return;
        if (entry.live) {
          // Live stream (SSE/NDJSON) — forward chunk to SW immediately
          const port = streamingPorts.get(requestId);
          if (port) {
            const chunkBytes = buf.slice(36).buffer;
            port.postMessage({ type: "chunk", data: chunkBytes }, [chunkBytes]);
          }
        } else {
          // Finite response (video, etc) — buffer chunk on page side
          entry.chunks.push(buf.slice(36));
        }
        return;
      }

      // Text message = JSON control message
      try {
        const msg = JSON.parse(event.data);
        handleDcMessage(msg);
      } catch {
        console.error("[WebRTC] Failed to parse DataChannel message");
      }
    };

    function handleDcMessage(msg) {
      if (msg.type === "http_response" && msg.id) {
        // Single buffered response
        const pending = pendingRequests.get(msg.id);
        if (pending) {
          pendingRequests.delete(msg.id);
          pending.resolve(msg);
        }
      } else if (msg.type === "http_response_start" && msg.id) {
        if (msg.streaming) {
          var isLive = !!msg.live;
          if (isLive) {
            // Live stream (SSE, NDJSON) — resolve immediately with ReadableStream.
            // Client consumes data progressively as it arrives.
            const pending = pendingRequests.get(msg.id);
            if (pending) {
              pendingRequests.delete(msg.id);
              pending.resolve({
                statusCode: msg.statusCode,
                headers: msg.headers,
                streaming: true,
              });
            }
          }
          // live=true: forward chunks to SW via ReadableStream
          // live=false: buffer chunks page-side, deliver complete Response on end
          //   (Chrome's media pipeline doesn't handle ReadableStream 206 from SW)
          chunkedResponses.set(msg.id, {
            streaming: true,
            live: isLive,
            statusCode: msg.statusCode,
            headers: msg.headers,
            chunks: isLive ? undefined : [],
          });
        } else {
          // Size-chunked reassembly (large buffered responses)
          chunkedResponses.set(msg.id, {
            statusCode: msg.statusCode,
            headers: msg.headers,
            totalChunks: msg.totalChunks,
            received: 0,
            chunks: new Array(msg.totalChunks),
          });
        }
      } else if (msg.type === "http_response_chunk" && msg.id) {
        const entry = chunkedResponses.get(msg.id);
        if (!entry) return;

        if (entry.streaming) {
          // Forward chunk to SW via the streaming port
          const port = streamingPorts.get(msg.id);
          if (port) {
            port.postMessage({ type: "chunk", data: msg.data });
          }
        } else {
          // Size-chunked reassembly
          entry.chunks[msg.index] = msg.data;
          entry.received++;
          console.log(`[WebRTC] Chunk ${entry.received}/${entry.totalChunks} received for ${msg.id}`);
          if (entry.received === entry.totalChunks) {
            console.log(`[WebRTC] All chunks received for ${msg.id}, reassembling`);
            chunkedResponses.delete(msg.id);
            const pending = pendingRequests.get(msg.id);
            if (pending) {
              pendingRequests.delete(msg.id);
              pending.resolve({
                statusCode: entry.statusCode,
                headers: entry.headers,
                body: entry.chunks.join(""),
              });
            }
          }
        }
      } else if (msg.type === "http_response_end" && msg.id) {
        const entry = chunkedResponses.get(msg.id);
        chunkedResponses.delete(msg.id);

        if (entry && !entry.live && entry.chunks) {
          // Buffered finite response — concatenate chunks and encode as base64.
          // Uses the same proven path as small responses (body field).
          const totalLength = entry.chunks.reduce((sum, c) => sum + c.length, 0);
          const merged = new Uint8Array(totalLength);
          let offset = 0;
          for (const chunk of entry.chunks) {
            merged.set(chunk, offset);
            offset += chunk.length;
          }
          console.log(`[WebRTC] Buffered response complete: ${msg.id} (${totalLength} bytes)`);
          const pending = pendingRequests.get(msg.id);
          if (pending) {
            pendingRequests.delete(msg.id);
            pending.resolve({
              statusCode: entry.statusCode,
              headers: entry.headers,
              binaryBody: merged.buffer,
            });
          }
        } else {
          // Live stream — close the ReadableStream
          const port = streamingPorts.get(msg.id);
          if (port) {
            port.postMessage({ type: "end" });
            streamingPorts.delete(msg.id);
          }
        }
      } else if (msg.type === "ws_opened" && msg.id) {
        const ws = dcWebSockets.get(msg.id);
        if (ws) ws._fireOpen(msg.protocol);
      } else if (msg.type === "ws_message" && msg.id) {
        const ws = dcWebSockets.get(msg.id);
        if (ws) ws._fireMessage(msg.data, msg.binary);
      } else if (msg.type === "ws_close" && msg.id) {
        const ws = dcWebSockets.get(msg.id);
        if (ws) ws._fireClose(msg.code, msg.reason);
      } else if (msg.type === "ws_error" && msg.id) {
        const ws = dcWebSockets.get(msg.id);
        if (ws) ws._fireError(msg.message);
      }
    }

    dataChannel.onclose = () => {
      console.log("[WebRTC] DataChannel closed");
      cleanupPeer();
      // Only reconnect if signaling is still open (otherwise signaling.onclose handles it)
      if (signalingWs && signalingWs.readyState === WebSocket.OPEN) {
        scheduleReconnect();
      }
    };

    dataChannel.onerror = (err) => {
      console.error("[WebRTC] DataChannel error:", err);
    };

    // ICE candidate handling
    peerConnection.onicecandidate = (event) => {
      if (event.candidate) {
        console.log("[WebRTC] Local ICE candidate:", event.candidate.candidate);
        if (signalingWs?.readyState === WebSocket.OPEN) {
          signalingWs.send(
            JSON.stringify({
              type: "candidate",
              fromId: clientId,
              targetId: pairedGatewayId,
              candidate: {
                candidate: event.candidate.candidate,
                mid: event.candidate.sdpMid,
              },
            })
          );
        }
      } else {
        console.log("[WebRTC] ICE gathering complete (null candidate)");
      }
    };

    peerConnection.oniceconnectionstatechange = () => {
      console.log("[WebRTC] ICE connection state:", peerConnection.iceConnectionState);
      if (peerConnection.iceConnectionState === "failed") {
        console.log("[WebRTC] ICE failed — closing peer");
        cleanupPeer();
        scheduleReconnect();
      }
    };

    peerConnection.onconnectionstatechange = () => {
      console.log("[WebRTC] Connection state:", peerConnection.connectionState);
    };

    // Create and send SDP offer
    peerConnection
      .createOffer()
      .then((offer) => peerConnection.setLocalDescription(offer))
      .then(() => {
        signalingWs.send(
          JSON.stringify({
            type: "sdp_offer",
            fromId: clientId,
            targetId: pairedGatewayId,
            sdp: peerConnection.localDescription.sdp,
            sdpType: peerConnection.localDescription.type,
          })
        );
        console.log("[WebRTC] SDP offer sent");
      })
      .catch((err) => {
        console.error("[WebRTC] Failed to create offer:", err);
      });
  }

  async function registerServiceWorker() {
    if (swRegistered || !("serviceWorker" in navigator)) {
      return;
    }

    try {
      await navigator.serviceWorker.register("/js/sw.js", { scope: "/", updateViaCache: "none" });
      console.log("[WebRTC] Service Worker registered");
      swRegistered = true;

      // When a new SW takes control mid-session (e.g., after SW update),
      // re-signal dc_ready so the new SW knows this client has an active DC.
      navigator.serviceWorker.addEventListener("controllerchange", function () {
        console.log("[WebRTC] New Service Worker took control");
        // New SW needs to be told about our DC — reset flag and re-signal
        dcReadySignaled = false;
        if (sessionToken && dataChannel && dataChannel.readyState === "open") {
          signalDcReady();
        }
      });

      navigator.serviceWorker.addEventListener("message", (event) => {
        if (event.data?.type === "dc_fetch") {
          handleSwFetch(event.data, event.ports[0]);
        } else if (event.data?.type === "dc_check") {
          // New SW is asking if we have an active DC — re-signal readiness
          dcReadySignaled = false;
          if (sessionToken && dataChannel && dataChannel.readyState === "open") {
            signalDcReady();
          }
        }
      });
      navigator.serviceWorker.startMessages();
    } catch (err) {
      console.error("[WebRTC] Service Worker registration failed:", err);
    }
  }

  function signalDcReady() {
    if (dcReadySignaled) return;
    if (!navigator.serviceWorker.controller) return;
    if (!dataChannel || dataChannel.readyState !== "open") return;
    navigator.serviceWorker.controller.postMessage({ type: "dc_ready" });
    dcReadySignaled = true;
    window.__dcReady = true;
    window.dispatchEvent(new CustomEvent("dc-ready"));
    console.log("[WebRTC] Signaled dc_ready to Service Worker");
  }

  async function fetchSessionToken() {
    try {
      const res = await fetch(BACKEND_PREFIX + "/auth/session-token", {
        headers: { "X-Requested-With": "XMLHttpRequest" },
      });
      if (!res.ok) {
        console.log("[WebRTC] No session token available");
        sessionToken = null;
        return;
      }
      const data = await res.json();
      sessionToken = data.token;
      console.log("[WebRTC] Session token acquired");
      // If dc_ready was deferred because we had no token, signal now
      // Only when SW is already registered (avoid signaling old SW before update)
      if (!dcReadySignaled && swRegistered && dataChannel && dataChannel.readyState === "open") {
        signalDcReady();
      }
    } catch (err) {
      console.log("[WebRTC] Failed to fetch session token:", err.message);
      sessionToken = null;
    }
  }

  function handleSwFetch(request, responsePort) {
    if (!dataChannel || dataChannel.readyState !== "open") {
      responsePort.postMessage({ error: "DataChannel not open" });
      return;
    }

    const requestId = crypto.randomUUID();

    // Inject session cookie that the SW can't read (HttpOnly).
    // Merge with any existing cookies from the request (non-HttpOnly cookies
    // the browser may have set). The gateway's backend cookie jar handles
    // HttpOnly cookies server-side for DataChannel sessions.
    const headers = { ...request.headers };
    if (sessionToken) {
      const existing = headers.cookie || "";
      headers.cookie = existing
        ? `${existing}; gateway_access=${sessionToken}`
        : `gateway_access=${sessionToken}`;
    }

    dataChannel.send(
      JSON.stringify({
        type: "http_request",
        id: requestId,
        method: request.method,
        url: request.url,
        headers: headers,
        body: request.body || "",
      })
    );

    const timeout = setTimeout(() => {
      pendingRequests.delete(requestId);
      streamingPorts.delete(requestId);
      responsePort.postMessage({ error: "Timeout" });
    }, 15000);

    pendingRequests.set(requestId, {
      resolve: (msg) => {
        clearTimeout(timeout);
        if (msg.streaming) {
          // Live streaming response (SSE, NDJSON) — keep the port open for chunks
          streamingPorts.set(requestId, responsePort);
          responsePort.postMessage({
            statusCode: msg.statusCode,
            headers: msg.headers,
            streaming: true,
          });
        } else if (msg.binaryBody) {
          // Transfer raw ArrayBuffer — avoids base64 encode/decode overhead
          responsePort.postMessage({
            statusCode: msg.statusCode,
            headers: msg.headers,
            binaryBody: msg.binaryBody,
          }, [msg.binaryBody]);
        } else {
          responsePort.postMessage({
            statusCode: msg.statusCode,
            headers: msg.headers,
            body: msg.body,
          });
        }
      },
    });
  }

  // --- WebSocket shim: tunnels same-origin WS connections through DataChannel ---

  function bufToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  class DCWebSocket {
    constructor(url, protocols) {
      this._id = crypto.randomUUID();
      this._listeners = {};
      this.readyState = 0; // CONNECTING
      this.protocol = "";
      this.extensions = "";
      this.bufferedAmount = 0;
      this.binaryType = "blob";
      this.onopen = null;
      this.onmessage = null;
      this.onclose = null;
      this.onerror = null;

      const parsed = new URL(url, window.location.origin);
      this.url = parsed.href;

      // Prepend /__b/<name> prefix from current page if needed
      let wsPath = parsed.pathname + parsed.search;
      if (!wsPath.startsWith("/__b/")) {
        const prefixMatch = window.location.pathname.match(/^\/__b\/[^/]+/);
        if (prefixMatch) wsPath = prefixMatch[0] + wsPath;
      }

      dcWebSockets.set(this._id, this);

      const headers = {};
      if (sessionToken) {
        headers.cookie = "gateway_access=" + sessionToken;
      }

      dataChannel.send(JSON.stringify({
        type: "ws_open",
        id: this._id,
        url: wsPath,
        protocols: Array.isArray(protocols) ? protocols : protocols ? [protocols] : [],
        headers: headers,
      }));
    }

    addEventListener(type, fn) {
      if (!this._listeners[type]) this._listeners[type] = [];
      if (this._listeners[type].indexOf(fn) === -1) this._listeners[type].push(fn);
    }

    removeEventListener(type, fn) {
      if (!this._listeners[type]) return;
      this._listeners[type] = this._listeners[type].filter(function (f) { return f !== fn; });
    }

    _dispatch(type, event) {
      if (typeof this["on" + type] === "function") this["on" + type](event);
      const listeners = this._listeners[type];
      if (listeners) listeners.forEach(function (fn) { fn(event); });
    }

    send(data) {
      if (this.readyState !== 1) throw new DOMException("WebSocket not open", "InvalidStateError");
      if (typeof data === "string") {
        dataChannel.send(JSON.stringify({ type: "ws_message", id: this._id, data: data, binary: false }));
      } else if (data instanceof ArrayBuffer) {
        dataChannel.send(JSON.stringify({ type: "ws_message", id: this._id, data: bufToBase64(new Uint8Array(data)), binary: true }));
      } else if (ArrayBuffer.isView(data)) {
        dataChannel.send(JSON.stringify({ type: "ws_message", id: this._id, data: bufToBase64(new Uint8Array(data.buffer, data.byteOffset, data.byteLength)), binary: true }));
      } else if (data instanceof Blob) {
        const wsId = this._id;
        const ws = this;
        data.arrayBuffer().then(function (buf) {
          if (ws.readyState !== 1) return;
          dataChannel.send(JSON.stringify({ type: "ws_message", id: wsId, data: bufToBase64(new Uint8Array(buf)), binary: true }));
        });
      }
    }

    close(code, reason) {
      if (this.readyState >= 2) return;
      this.readyState = 2; // CLOSING
      if (dataChannel && dataChannel.readyState === "open") {
        dataChannel.send(JSON.stringify({ type: "ws_close", id: this._id, code: code || 1000, reason: reason || "" }));
      }
    }

    _fireOpen(protocol) {
      this.readyState = 1;
      this.protocol = protocol || "";
      this._dispatch("open", new Event("open"));
    }

    _fireMessage(data, binary) {
      let payload;
      if (binary) {
        const raw = atob(data);
        const bytes = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
        payload = this.binaryType === "arraybuffer" ? bytes.buffer : new Blob([bytes]);
      } else {
        payload = data;
      }
      this._dispatch("message", new MessageEvent("message", { data: payload }));
    }

    _fireClose(code, reason) {
      if (this.readyState === 3) return;
      this.readyState = 3;
      dcWebSockets.delete(this._id);
      this._dispatch("close", new CloseEvent("close", { code: code || 1000, reason: reason || "", wasClean: code !== 1006 }));
    }

    _fireError(message) {
      dcWebSockets.delete(this._id);
      this._dispatch("error", new Event("error"));
      this._fireClose(1006, message || "Connection failed");
    }
  }

  function installWebSocketShim() {
    window.WebSocket = function (url, protocols) {
      const parsed = new URL(url, window.location.origin);
      if (parsed.origin !== window.location.origin || !dataChannel || dataChannel.readyState !== "open") {
        return new NativeWebSocket(url, protocols);
      }
      return new DCWebSocket(url, protocols);
    };
    window.WebSocket.CONNECTING = 0;
    window.WebSocket.OPEN = 1;
    window.WebSocket.CLOSING = 2;
    window.WebSocket.CLOSED = 3;
    window.WebSocket.prototype = NativeWebSocket.prototype;
  }

  // Start upgrade after page load
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
