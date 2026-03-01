/**
 * RDP client over DataChannel TCP tunnel.
 *
 * Establishes a WebRTC DataChannel to the punchd gateway, opens a TCP
 * tunnel to a configured rdp:// backend, and feeds the raw RDP bytes
 * to/from an RDP protocol handler (IronRDP WASM or similar).
 *
 * The signaling flow mirrors webrtc-upgrade.js but without the Service
 * Worker — this page uses the DataChannel exclusively for TCP tunneling.
 */

(function () {
  "use strict";

  // ── Constants ─────────────────────────────────────────────────

  var CONFIG_ENDPOINT = "/webrtc-config";
  var SESSION_TOKEN_ENDPOINT = "/auth/session-token";
  var LOGIN_ENDPOINT = "/auth/login";
  var TCP_TUNNEL_MAGIC = 0x03;
  var RECONNECT_DELAY = 5000;
  var MAX_RECONNECT_DELAY = 60000;

  // ── DOM elements ──────────────────────────────────────────────

  var statusBar = document.getElementById("status-bar");
  var statusDot = document.getElementById("status-dot");
  var statusText = document.getElementById("status-text");
  var disconnectBtn = document.getElementById("disconnect-btn");
  var connectForm = document.getElementById("connect-form");
  var connectBtn = document.getElementById("connect-btn");
  var formError = document.getElementById("form-error");
  var rdpCanvas = document.getElementById("rdp-canvas");
  var usernameInput = document.getElementById("rdp-username");
  var passwordInput = document.getElementById("rdp-password");

  // ── State ─────────────────────────────────────────────────────

  var config = null;
  var sessionToken = null;
  var signalingWs = null;
  var peerConnection = null;
  var controlChannel = null;
  var bulkChannel = null;
  var clientId = "rdp-" + crypto.randomUUID().replace(/-/g, "").slice(0, 8);
  var pairedGatewayId = null;
  var reconnectAttempts = 0;
  var reconnectTimer = null;
  var tunnelId = null;
  var tunnelReady = false;
  var backendName = null;

  // Callbacks for the RDP protocol handler
  var onTcpData = null;    // Called with Uint8Array of incoming TCP data
  var onTcpOpen = null;    // Called when tunnel is established
  var onTcpClose = null;   // Called when tunnel closes

  // ── Initialization ────────────────────────────────────────────

  function init() {
    // Extract backend name from URL query param
    var params = new URLSearchParams(location.search);
    backendName = params.get("backend");
    if (!backendName) {
      setStatus("error", "No backend specified. Use ?backend=<name>");
      return;
    }

    setStatus("connecting", "Loading configuration...");
    fetchConfig();
  }

  async function fetchConfig() {
    try {
      var res = await fetch(CONFIG_ENDPOINT);
      if (!res.ok) throw new Error("Config endpoint returned " + res.status);
      config = await res.json();
      console.log("[RDP] Config loaded:", config);
      await fetchSessionToken();
    } catch (err) {
      setStatus("error", "Failed to load config: " + err.message);
    }
  }

  async function fetchSessionToken() {
    try {
      var res = await fetch(SESSION_TOKEN_ENDPOINT, {
        credentials: "same-origin",
        headers: { "X-Requested-With": "XMLHttpRequest" },
      });
      if (res.status === 401) {
        // Not authenticated — redirect to login
        location.href = LOGIN_ENDPOINT + "?redirect=" + encodeURIComponent(location.pathname + location.search);
        return;
      }
      if (!res.ok) throw new Error("Session token returned " + res.status);
      var data = await res.json();
      sessionToken = data.token || data.access_token;
      if (!sessionToken) throw new Error("No token in response");
      console.log("[RDP] Session token acquired");
      connectSignaling();
    } catch (err) {
      setStatus("error", "Auth failed: " + err.message);
    }
  }

  // ── Signaling ─────────────────────────────────────────────────

  function connectSignaling() {
    if (!config || !config.signalingUrl) {
      setStatus("error", "No signaling URL in config");
      return;
    }

    setStatus("connecting", "Connecting to signaling server...");
    signalingWs = new WebSocket(config.signalingUrl);

    signalingWs.onopen = function () {
      console.log("[RDP] Signaling connected");
      var msg = {
        type: "register",
        role: "client",
        id: clientId,
        token: sessionToken,
      };
      if (config.targetGatewayId) {
        msg.targetGatewayId = config.targetGatewayId;
      }
      signalingWs.send(JSON.stringify(msg));
      setStatus("connecting", "Waiting for gateway pairing...");
    };

    signalingWs.onmessage = function (event) {
      try {
        var msg = JSON.parse(event.data);
        handleSignalingMessage(msg);
      } catch (e) {
        // ignore
      }
    };

    signalingWs.onclose = function () {
      console.log("[RDP] Signaling disconnected");
      cleanup();
      scheduleReconnect();
    };

    signalingWs.onerror = function () {
      console.log("[RDP] Signaling error");
    };
  }

  function handleSignalingMessage(msg) {
    switch (msg.type) {
      case "registered":
        console.log("[RDP] Registered as client:", msg.id);
        break;

      case "paired":
        pairedGatewayId = msg.gateway && msg.gateway.id;
        console.log("[RDP] Paired with gateway:", pairedGatewayId);
        startWebRTC();
        break;

      case "sdp_answer":
        if (peerConnection && msg.sdp) {
          peerConnection
            .setRemoteDescription(new RTCSessionDescription({ type: msg.sdpType || "answer", sdp: msg.sdp }))
            .catch(function (err) { console.error("[RDP] setRemoteDescription error:", err); });
        }
        break;

      case "candidate":
        if (peerConnection && msg.candidate) {
          peerConnection
            .addIceCandidate(new RTCIceCandidate({ candidate: msg.candidate.candidate, sdpMid: msg.candidate.mid }))
            .catch(function (err) { console.error("[RDP] addIceCandidate error:", err); });
        }
        break;

      case "error":
        console.error("[RDP] Signaling error:", msg.message);
        if (msg.message && msg.message.indexOf("No gateway") !== -1) {
          setStatus("error", "No gateway available. Retrying...");
          scheduleReconnect();
        }
        break;
    }
  }

  // ── WebRTC ────────────────────────────────────────────────────

  function startWebRTC() {
    if (!pairedGatewayId) return;

    setStatus("connecting", "Establishing P2P connection...");

    var iceServers = [];
    if (config.stunServer) {
      iceServers.push({ urls: config.stunServer });
    }
    if (config.turnServer && config.turnUsername && config.turnPassword) {
      iceServers.push({
        urls: config.turnServer,
        username: config.turnUsername,
        credential: config.turnPassword,
      });
    }

    peerConnection = new RTCPeerConnection({ iceServers: iceServers });

    // Create dual DataChannels (same as webrtc-upgrade.js)
    controlChannel = peerConnection.createDataChannel("http-tunnel", { ordered: true });
    bulkChannel = peerConnection.createDataChannel("bulk-data", { ordered: true });
    bulkChannel.binaryType = "arraybuffer";

    setupControlChannel();
    setupBulkChannel();

    peerConnection.onicecandidate = function (event) {
      if (event.candidate && signalingWs && signalingWs.readyState === WebSocket.OPEN) {
        signalingWs.send(JSON.stringify({
          type: "candidate",
          fromId: clientId,
          targetId: pairedGatewayId,
          candidate: { candidate: event.candidate.candidate, mid: event.candidate.sdpMid },
        }));
      }
    };

    peerConnection.onconnectionstatechange = function () {
      var state = peerConnection.connectionState;
      console.log("[RDP] Connection state:", state);
      if (state === "failed" || state === "disconnected") {
        cleanup();
        scheduleReconnect();
      }
    };

    peerConnection.createOffer()
      .then(function (offer) { return peerConnection.setLocalDescription(offer); })
      .then(function () {
        signalingWs.send(JSON.stringify({
          type: "sdp_offer",
          fromId: clientId,
          targetId: pairedGatewayId,
          sdp: peerConnection.localDescription.sdp,
          sdpType: peerConnection.localDescription.type,
        }));
        console.log("[RDP] SDP offer sent");
      })
      .catch(function (err) {
        console.error("[RDP] Offer creation failed:", err);
        setStatus("error", "WebRTC offer failed");
      });
  }

  function setupControlChannel() {
    controlChannel.onopen = function () {
      console.log("[RDP] Control channel open");
      // Send capabilities
      controlChannel.send(JSON.stringify({
        type: "capabilities",
        version: 2,
        features: ["bulk-channel", "tcp-tunnel"],
      }));
      setStatus("connecting", "DataChannel open, ready to connect...");
      showConnectForm();
    };

    controlChannel.onmessage = function (event) {
      try {
        var msg = JSON.parse(event.data);
        handleControlMessage(msg);
      } catch (e) {
        // ignore
      }
    };

    controlChannel.onclose = function () {
      console.log("[RDP] Control channel closed");
      closeTunnel();
    };
  }

  function setupBulkChannel() {
    bulkChannel.onopen = function () {
      console.log("[RDP] Bulk channel open");
    };

    bulkChannel.onmessage = function (event) {
      var buf = new Uint8Array(event.data);
      if (buf.length < 37) return;

      // TCP tunnel fast-path: [0x03][36-byte tunnelId][payload]
      if (buf[0] === TCP_TUNNEL_MAGIC) {
        var id = new TextDecoder().decode(buf.subarray(1, 37));
        if (id === tunnelId && onTcpData) {
          onTcpData(buf.subarray(37));
        }
      }
    };

    bulkChannel.onclose = function () {
      console.log("[RDP] Bulk channel closed");
    };
  }

  function handleControlMessage(msg) {
    switch (msg.type) {
      case "capabilities":
        console.log("[RDP] Gateway capabilities:", msg.features);
        break;

      case "tcp_opened":
        if (msg.id === tunnelId) {
          console.log("[RDP] TCP tunnel opened");
          tunnelReady = true;
          setStatus("connected", "Connected to " + backendName);
          statusBar.classList.add("connected");
          disconnectBtn.classList.remove("hidden");
          if (onTcpOpen) onTcpOpen();
        }
        break;

      case "tcp_error":
        console.error("[RDP] TCP tunnel error:", msg.message);
        if (msg.id === tunnelId) {
          tunnelReady = false;
          tunnelId = null;
          setStatus("error", "Connection failed: " + msg.message);
          showConnectForm();
        }
        break;

      case "tcp_close":
        if (msg.id === tunnelId) {
          console.log("[RDP] TCP tunnel closed by gateway");
          closeTunnel();
          setStatus("error", "Connection closed by remote host");
          showConnectForm();
        }
        break;
    }
  }

  // ── TCP Tunnel ────────────────────────────────────────────────

  function openTunnel() {
    if (!controlChannel || controlChannel.readyState !== "open") {
      setStatus("error", "DataChannel not ready");
      return;
    }

    tunnelId = crypto.randomUUID();
    tunnelReady = false;

    controlChannel.send(JSON.stringify({
      type: "tcp_open",
      id: tunnelId,
      backend: backendName,
    }));

    setStatus("connecting", "Opening TCP tunnel to " + backendName + "...");
    console.log("[RDP] Opening TCP tunnel:", tunnelId, "→", backendName);
  }

  /** Send raw bytes through the TCP tunnel via bulk channel. */
  function sendTcpData(data) {
    if (!tunnelReady || !bulkChannel || bulkChannel.readyState !== "open") return;

    var idBytes = new TextEncoder().encode(tunnelId);
    var frame = new Uint8Array(1 + 36 + data.length);
    frame[0] = TCP_TUNNEL_MAGIC;
    frame.set(idBytes, 1);
    frame.set(data instanceof Uint8Array ? data : new Uint8Array(data), 37);
    bulkChannel.send(frame.buffer);
  }

  function closeTunnel() {
    if (tunnelId && controlChannel && controlChannel.readyState === "open") {
      controlChannel.send(JSON.stringify({ type: "tcp_close", id: tunnelId }));
    }
    tunnelReady = false;
    tunnelId = null;
    if (onTcpClose) onTcpClose();
  }

  // ── UI ────────────────────────────────────────────────────────

  function setStatus(state, text) {
    statusDot.className = "dot " + state;
    statusText.textContent = text;
    statusBar.classList.remove("connected");
  }

  function showConnectForm() {
    connectForm.classList.remove("hidden");
    rdpCanvas.classList.add("hidden");
    connectBtn.disabled = false;
    formError.textContent = "";
  }

  function hideConnectForm() {
    connectForm.classList.add("hidden");
    rdpCanvas.classList.remove("hidden");
  }

  // ── RDP Protocol Integration ──────────────────────────────────
  //
  // This section is the integration point for IronRDP WASM or any
  // other browser-side RDP protocol handler. The TCP tunnel provides
  // raw byte-level transport:
  //
  //   sendTcpData(Uint8Array)  — send bytes to RDP server
  //   onTcpData = fn(Uint8Array) — receive bytes from RDP server
  //   onTcpOpen = fn()          — tunnel established
  //   onTcpClose = fn()         — tunnel closed
  //
  // For now, a placeholder canvas message is shown until the IronRDP
  // WASM module is integrated.

  function startRdpSession(username, password) {
    hideConnectForm();

    // Set up TCP data handler — forward incoming bytes to RDP handler
    onTcpData = function (data) {
      // TODO: Feed data to IronRDP WASM session
      // ironrdpSession.processIncoming(data);
      console.log("[RDP] Received", data.length, "bytes from server");
    };

    onTcpOpen = function () {
      console.log("[RDP] TCP tunnel ready — starting RDP handshake");

      // TODO: Initialize IronRDP WASM session:
      // 1. import { Session } from "ironrdp-wasm";
      // 2. const session = new Session({ username, password, ... });
      // 3. session.onOutput = (bytes) => sendTcpData(bytes);
      // 4. session.onBitmap = (x, y, w, h, pixels) => drawToCanvas(...);
      // 5. session.start();

      // Placeholder: draw status on canvas
      var ctx = rdpCanvas.getContext("2d");
      rdpCanvas.width = window.innerWidth;
      rdpCanvas.height = window.innerHeight;
      ctx.fillStyle = "#0f0f23";
      ctx.fillRect(0, 0, rdpCanvas.width, rdpCanvas.height);
      ctx.fillStyle = "#4ecca3";
      ctx.font = "24px system-ui";
      ctx.textAlign = "center";
      ctx.fillText("TCP tunnel connected to " + backendName, rdpCanvas.width / 2, rdpCanvas.height / 2 - 20);
      ctx.fillStyle = "#aaa";
      ctx.font = "16px system-ui";
      ctx.fillText("IronRDP WASM integration pending", rdpCanvas.width / 2, rdpCanvas.height / 2 + 20);
      ctx.fillText("Raw TCP tunnel is functional", rdpCanvas.width / 2, rdpCanvas.height / 2 + 50);
    };

    onTcpClose = function () {
      console.log("[RDP] RDP session ended");
      // TODO: Clean up IronRDP session
    };

    openTunnel();
  }

  // ── Input Capture ─────────────────────────────────────────────
  //
  // These will forward keyboard/mouse events to the RDP session
  // once IronRDP WASM is integrated.

  rdpCanvas.addEventListener("mousemove", function (e) {
    if (!tunnelReady) return;
    // TODO: ironrdpSession.sendMouseMove(e.offsetX, e.offsetY);
  });

  rdpCanvas.addEventListener("mousedown", function (e) {
    if (!tunnelReady) return;
    // TODO: ironrdpSession.sendMouseButton(e.button, true);
  });

  rdpCanvas.addEventListener("mouseup", function (e) {
    if (!tunnelReady) return;
    // TODO: ironrdpSession.sendMouseButton(e.button, false);
  });

  rdpCanvas.addEventListener("wheel", function (e) {
    if (!tunnelReady) return;
    e.preventDefault();
    // TODO: ironrdpSession.sendMouseWheel(e.deltaY);
  }, { passive: false });

  document.addEventListener("keydown", function (e) {
    if (!tunnelReady || connectForm.style.display !== "none" && !connectForm.classList.contains("hidden")) return;
    e.preventDefault();
    // TODO: ironrdpSession.sendKeyDown(e.code);
  });

  document.addEventListener("keyup", function (e) {
    if (!tunnelReady || connectForm.style.display !== "none" && !connectForm.classList.contains("hidden")) return;
    e.preventDefault();
    // TODO: ironrdpSession.sendKeyUp(e.code);
  });

  // Resize canvas with window
  window.addEventListener("resize", function () {
    if (!rdpCanvas.classList.contains("hidden")) {
      rdpCanvas.width = window.innerWidth;
      rdpCanvas.height = window.innerHeight;
      // TODO: ironrdpSession.resize(window.innerWidth, window.innerHeight);
    }
  });

  // ── Cleanup / Reconnect ───────────────────────────────────────

  function cleanup() {
    closeTunnel();
    if (controlChannel) {
      try { controlChannel.onclose = null; controlChannel.close(); } catch (e) {}
      controlChannel = null;
    }
    if (bulkChannel) {
      try { bulkChannel.onclose = null; bulkChannel.close(); } catch (e) {}
      bulkChannel = null;
    }
    if (peerConnection) {
      try { peerConnection.onicecandidate = null; peerConnection.onconnectionstatechange = null; peerConnection.close(); } catch (e) {}
      peerConnection = null;
    }
    pairedGatewayId = null;
  }

  function scheduleReconnect() {
    if (reconnectTimer) return;
    var delay = Math.min(RECONNECT_DELAY * Math.pow(1.5, reconnectAttempts), MAX_RECONNECT_DELAY);
    reconnectAttempts++;
    console.log("[RDP] Reconnecting in " + Math.round(delay / 1000) + "s...");
    reconnectTimer = setTimeout(function () {
      reconnectTimer = null;
      doReconnect();
    }, delay);
  }

  async function doReconnect() {
    cleanup();
    if (signalingWs) {
      try { signalingWs.onclose = null; signalingWs.close(); } catch (e) {}
      signalingWs = null;
    }
    clientId = "rdp-" + crypto.randomUUID().replace(/-/g, "").slice(0, 8);
    await fetchSessionToken();
  }

  // ── Event Handlers ────────────────────────────────────────────

  connectBtn.addEventListener("click", function () {
    var username = usernameInput.value.trim();
    var password = passwordInput.value;
    if (!username) {
      formError.textContent = "Username is required";
      return;
    }
    connectBtn.disabled = true;
    formError.textContent = "";
    startRdpSession(username, password);
  });

  passwordInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter") connectBtn.click();
  });

  disconnectBtn.addEventListener("click", function () {
    closeTunnel();
    setStatus("connecting", "Disconnected");
    showConnectForm();
  });

  // ── Start ─────────────────────────────────────────────────────

  init();
})();
