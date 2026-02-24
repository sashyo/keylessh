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

  const CONFIG_ENDPOINT = "/webrtc-config";
  const RECONNECT_DELAY = 5000;
  const MAX_RECONNECT_DELAY = 60000;

  let signalingWs = null;
  let peerConnection = null;
  let dataChannel = null;
  let clientId = "client-" + Math.random().toString(36).slice(2, 10);
  let pairedGatewayId = null;
  let config = null;
  let sessionToken = null;
  let reconnectAttempts = 0;
  let reconnectTimer = null;
  let swRegistered = false;

  // Pending requests waiting for DataChannel responses
  const pendingRequests = new Map();
  // In-flight chunked responses being reassembled
  const chunkedResponses = new Map();

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
    // Reject pending requests so they fall back to relay
    for (const [id, entry] of pendingRequests) {
      entry.resolve({ statusCode: 502, headers: {}, body: "" });
    }
    pendingRequests.clear();
    chunkedResponses.clear();
    // Tell SW this client no longer has DataChannel
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
    signalingWs = new WebSocket(config.signalingUrl);

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
        break;
    }
  }

  function startWebRTC() {
    if (!pairedGatewayId) return;

    // Clean up any previous peer before starting fresh
    cleanupPeer();

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

    dataChannel.onopen = async () => {
      console.log("[WebRTC] DataChannel OPEN — direct connection established!");
      reconnectAttempts = 0; // Reset backoff on success
      await registerServiceWorker();
      if (navigator.serviceWorker.controller) {
        navigator.serviceWorker.controller.postMessage({ type: "dc_ready" });
      }
    };

    dataChannel.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);

        if (msg.type === "http_response" && msg.id) {
          const pending = pendingRequests.get(msg.id);
          if (pending) {
            pendingRequests.delete(msg.id);
            pending.resolve(msg);
          }
        } else if (msg.type === "http_response_start" && msg.id) {
          chunkedResponses.set(msg.id, {
            statusCode: msg.statusCode,
            headers: msg.headers,
            totalChunks: msg.totalChunks,
            received: 0,
            chunks: new Array(msg.totalChunks),
          });
        } else if (msg.type === "http_response_chunk" && msg.id) {
          const entry = chunkedResponses.get(msg.id);
          if (entry) {
            entry.chunks[msg.index] = msg.data;
            entry.received++;
            if (entry.received === entry.totalChunks) {
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
        }
      } catch {
        console.error("[WebRTC] Failed to parse DataChannel message");
      }
    };

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

      navigator.serviceWorker.addEventListener("message", (event) => {
        if (event.data?.type === "dc_fetch") {
          handleSwFetch(event.data, event.ports[0]);
        }
      });
      navigator.serviceWorker.startMessages();
    } catch (err) {
      console.error("[WebRTC] Service Worker registration failed:", err);
    }
  }

  async function fetchSessionToken() {
    try {
      const res = await fetch("/auth/session-token");
      if (!res.ok) {
        console.log("[WebRTC] No session token available");
        sessionToken = null;
        return;
      }
      const data = await res.json();
      sessionToken = data.token;
      console.log("[WebRTC] Session token acquired");
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
      responsePort.postMessage({ error: "Timeout" });
    }, 15000);

    pendingRequests.set(requestId, {
      resolve: (msg) => {
        clearTimeout(timeout);
        responsePort.postMessage({
          statusCode: msg.statusCode,
          headers: msg.headers,
          body: msg.body,
        });
      },
    });
  }

  // Start upgrade after page load
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
