/**
 * WebRTC DataChannel upgrade script.
 *
 * After the page loads (via HTTP relay), this script attempts to
 * establish a direct WebRTC DataChannel to the WAF. If successful,
 * it registers a Service Worker that routes subsequent HTTP requests
 * through the DataChannel for lower latency.
 *
 * Falls back gracefully — if WebRTC fails, HTTP relay continues working.
 */

(function () {
  "use strict";

  // Configuration is injected by the WAF via a global or fetched from an endpoint
  const CONFIG_ENDPOINT = "/webrtc-config";
  const RECONNECT_DELAY = 5000;

  let signalingWs = null;
  let peerConnection = null;
  let dataChannel = null;
  let clientId = "client-" + Math.random().toString(36).slice(2, 10);
  let pairedWafId = null;
  let config = null;
  let sessionToken = null;

  // Pending requests waiting for DataChannel responses
  const pendingRequests = new Map();
  // In-flight chunked responses being reassembled
  const chunkedResponses = new Map();

  async function init() {
    try {
      // Fetch WebRTC config from WAF
      const res = await fetch(CONFIG_ENDPOINT);
      if (!res.ok) {
        console.log("[WebRTC] Config not available, skipping upgrade");
        return;
      }
      config = await res.json();
      console.log("[WebRTC] Config loaded:", config);

      // Connect to signaling server
      connectSignaling();
    } catch (err) {
      console.log("[WebRTC] Upgrade not available:", err.message);
    }
  }

  function connectSignaling() {
    if (!config?.signalingUrl) return;

    console.log("[WebRTC] Connecting to signaling:", config.signalingUrl);
    signalingWs = new WebSocket(config.signalingUrl);

    signalingWs.onopen = () => {
      console.log("[WebRTC] Signaling connected");
      // Register as client
      signalingWs.send(
        JSON.stringify({
          type: "register",
          role: "client",
          id: clientId,
        })
      );
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
      // Don't reconnect — the HTTP relay still works
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
        pairedWafId = msg.waf?.id;
        console.log("[WebRTC] Paired with WAF:", pairedWafId);
        // Start WebRTC handshake
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
    if (!pairedWafId) return;

    console.log("[WebRTC] Starting WebRTC handshake with WAF:", pairedWafId);

    // Create peer connection with STUN/TURN servers
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

    // Create DataChannel
    dataChannel = peerConnection.createDataChannel("http-tunnel", {
      ordered: true,
    });

    dataChannel.onopen = async () => {
      console.log("[WebRTC] DataChannel OPEN — direct connection established!");
      // Fetch session token (via relay, cookies attached) BEFORE registering SW
      await fetchSessionToken();
      registerServiceWorker();
    };

    dataChannel.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);

        if (msg.type === "http_response" && msg.id) {
          // Single (non-chunked) response
          const pending = pendingRequests.get(msg.id);
          if (pending) {
            pendingRequests.delete(msg.id);
            pending.resolve(msg);
          }
        } else if (msg.type === "http_response_start" && msg.id) {
          // Start of a chunked response — store metadata
          chunkedResponses.set(msg.id, {
            statusCode: msg.statusCode,
            headers: msg.headers,
            totalChunks: msg.totalChunks,
            received: 0,
            chunks: new Array(msg.totalChunks),
          });
        } else if (msg.type === "http_response_chunk" && msg.id) {
          // Body chunk — store and check completion
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
              targetId: pairedWafId,
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

    peerConnection.onicegatheringstatechange = () => {
      console.log("[WebRTC] ICE gathering state:", peerConnection.iceGatheringState);
    };

    peerConnection.oniceconnectionstatechange = () => {
      console.log("[WebRTC] ICE connection state:", peerConnection.iceConnectionState);
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
            targetId: pairedWafId,
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
    if (!("serviceWorker" in navigator)) {
      console.log("[WebRTC] Service Worker not supported");
      return;
    }

    try {
      await navigator.serviceWorker.register("/js/sw.js", { scope: "/" });
      console.log("[WebRTC] Service Worker registered");

      // Listen for fetch requests from Service Worker
      navigator.serviceWorker.addEventListener("message", (event) => {
        if (event.data?.type === "dc_fetch") {
          handleSwFetch(event.data, event.ports[0]);
        }
      });
    } catch (err) {
      console.error("[WebRTC] Service Worker registration failed:", err);
    }
  }

  async function fetchSessionToken() {
    try {
      const res = await fetch("/auth/session-token");
      if (!res.ok) {
        console.log("[WebRTC] No session token available");
        return;
      }
      const data = await res.json();
      sessionToken = data.token;
      console.log("[WebRTC] Session token acquired");
    } catch (err) {
      console.log("[WebRTC] Failed to fetch session token:", err.message);
    }
  }

  function handleSwFetch(request, responsePort) {
    if (!dataChannel || dataChannel.readyState !== "open") {
      responsePort.postMessage({ error: "DataChannel not open" });
      return;
    }

    const requestId = crypto.randomUUID();

    // Inject session cookie that the SW can't read (HttpOnly)
    const headers = { ...request.headers };
    if (sessionToken) {
      headers.cookie = `waf_access=${sessionToken}`;
    }

    // Send HTTP request over DataChannel
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

    // Wait for response
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
