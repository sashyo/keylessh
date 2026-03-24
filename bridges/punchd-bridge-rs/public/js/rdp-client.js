/**
 * RDP client over DataChannel with IronRDP WASM.
 *
 * Establishes a WebRTC DataChannel to the punchd gateway, installs a
 * DCWebSocket shim so IronRDP WASM's internal WebSocket connection is
 * transparently tunneled over the DataChannel, and uses the gateway's
 * RDCleanPath handler for TLS negotiation with the RDP server.
 *
 * Flow: IronRDP WASM → new WebSocket("/ws/rdcleanpath")
 *       → DCWebSocket shim → ws_open over DataChannel
 *       → gateway peer-handler → RDCleanPath virtual WS
 *       → TCP + TLS to RDP server → bidirectional relay
 */

(function () {
  "use strict";

  // ── Constants ─────────────────────────────────────────────────

  var CONFIG_ENDPOINT = "/webrtc-config";
  var SESSION_TOKEN_ENDPOINT = "/auth/session-token";
  var LOGIN_ENDPOINT = "/auth/login";
  var BINARY_WS_MAGIC = 0x02;
  var RECONNECT_DELAY = 5000;
  var MAX_RECONNECT_DELAY = 60000;

  // Save native WebSocket before shim (signaling uses it directly)
  var NativeWebSocket = window.WebSocket;

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
  var autoConnectSpinner = document.getElementById("auto-connect-spinner");
  var reconnectPanel = document.getElementById("reconnect-panel");
  var reconnectMessage = document.getElementById("reconnect-message");
  var reconnectBtn = document.getElementById("reconnect-btn");

  // ── State ─────────────────────────────────────────────────────

  var config = null;
  var sessionToken = null;
  var signalingWs = null;
  var peerConnection = null;
  var controlChannel = null;
  var bulkChannel = null;
  var clientId = "rdp-" + crypto.randomUUID().replace(/-/g, "").slice(0, 8);
  var pairedGatewayId = null;
  var pendingCandidates = [];
  var remoteDescriptionSet = false;
  var reconnectAttempts = 0;
  var reconnectTimer = null;
  var backendName = null;
  var bulkEnabled = false;
  var rdpSession = null;
  var isEddsaSession = false;
  var eddsaUsername = "";

  // ── Helpers ─────────────────────────────────────────────────────

  // Extract RDP username from dest: roles in JWT payload.
  // Looks for dest:<gateway>:<endpoint>:<username> format.
  function extractRdpUsername(jwtPayload, endpoint) {
    var allRoles = [];
    if (jwtPayload.realm_access && jwtPayload.realm_access.roles) {
      allRoles = allRoles.concat(jwtPayload.realm_access.roles);
    }
    if (jwtPayload.resource_access) {
      for (var key in jwtPayload.resource_access) {
        var res = jwtPayload.resource_access[key];
        if (res && res.roles) allRoles = allRoles.concat(res.roles);
      }
    }
    for (var i = 0; i < allRoles.length; i++) {
      var r = allRoles[i];
      if (typeof r !== "string" || r.indexOf("dest:") !== 0) continue;
      var parts = r.substring(5).split(":");
      // dest:<gateway>:<endpoint>:<username>
      if (parts.length === 3 && parts[1].toLowerCase() === endpoint.toLowerCase()) {
        return parts[2];
      }
    }
    return null;
  }

  // ── DCWebSocket shim ──────────────────────────────────────────
  //
  // Intercepts same-origin WebSocket connections and routes them
  // through the DataChannel using the ws_open/ws_message/ws_close
  // protocol and binary WS fast-path (0x02 magic byte).

  var dcWebSockets = new Map();

  function sendBinaryWsFrame(wsId, payload) {
    if (!bulkChannel || bulkChannel.readyState !== "open") return;
    var idBytes = new TextEncoder().encode(wsId);
    var frame = new Uint8Array(1 + 36 + payload.length);
    frame[0] = BINARY_WS_MAGIC;
    frame.set(idBytes, 1);
    frame.set(payload, 37);
    bulkChannel.send(frame);
  }

  function DCWebSocket(url, protocols) {
    this._id = crypto.randomUUID();
    this._listeners = {};
    this.readyState = 0; // CONNECTING
    this.protocol = "";
    this.extensions = "";
    this.bufferedAmount = 0;
    this.binaryType = "arraybuffer";
    this.onopen = null;
    this.onmessage = null;
    this.onclose = null;
    this.onerror = null;

    var parsed = new URL(url, window.location.origin);
    this.url = parsed.href;
    var wsPath = parsed.pathname + parsed.search;

    dcWebSockets.set(this._id, this);

    var headers = {};
    if (sessionToken) {
      headers.cookie = "gateway_access=" + sessionToken;
    }

    console.log("[RDP] DCWebSocket sending ws_open:", wsPath, "id:", this._id);
    controlChannel.send(JSON.stringify({
      type: "ws_open",
      id: this._id,
      url: wsPath,
      protocols: Array.isArray(protocols) ? protocols : protocols ? [protocols] : [],
      headers: headers,
    }));
  }

  DCWebSocket.prototype.addEventListener = function (type, fn) {
    if (!this._listeners[type]) this._listeners[type] = [];
    if (this._listeners[type].indexOf(fn) === -1) this._listeners[type].push(fn);
  };

  DCWebSocket.prototype.removeEventListener = function (type, fn) {
    if (!this._listeners[type]) return;
    this._listeners[type] = this._listeners[type].filter(function (f) { return f !== fn; });
  };

  DCWebSocket.prototype._dispatch = function (type, event) {
    if (typeof this["on" + type] === "function") this["on" + type](event);
    var listeners = this._listeners[type];
    if (listeners) listeners.forEach(function (fn) { fn(event); });
  };

  DCWebSocket.prototype.send = function (data) {
    if (this.readyState !== 1) throw new DOMException("WebSocket not open", "InvalidStateError");
    console.log("[RDP] DCWebSocket send, id:", this._id, "type:", typeof data, "isArrayBuffer:", data instanceof ArrayBuffer, "isView:", ArrayBuffer.isView(data), "size:", data.byteLength || data.length || 0);
    if (typeof data === "string") {
      controlChannel.send(JSON.stringify({ type: "ws_message", id: this._id, data: data, binary: false }));
    } else if (bulkEnabled && bulkChannel && bulkChannel.readyState === "open") {
      // Binary fast-path via bulk channel
      if (data instanceof ArrayBuffer) {
        sendBinaryWsFrame(this._id, new Uint8Array(data));
      } else if (ArrayBuffer.isView(data)) {
        sendBinaryWsFrame(this._id, new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
      } else if (data instanceof Blob) {
        var wsId = this._id;
        var ws = this;
        data.arrayBuffer().then(function (buf) {
          if (ws.readyState !== 1 || !bulkChannel || bulkChannel.readyState !== "open") return;
          sendBinaryWsFrame(wsId, new Uint8Array(buf));
        });
      }
    } else {
      // Fallback: JSON+base64
      var wsId = this._id;
      if (data instanceof ArrayBuffer) {
        controlChannel.send(JSON.stringify({ type: "ws_message", id: wsId, data: bufToBase64(new Uint8Array(data)), binary: true }));
      } else if (ArrayBuffer.isView(data)) {
        controlChannel.send(JSON.stringify({ type: "ws_message", id: wsId, data: bufToBase64(new Uint8Array(data.buffer, data.byteOffset, data.byteLength)), binary: true }));
      } else if (data instanceof Blob) {
        data.arrayBuffer().then(function (buf) {
          controlChannel.send(JSON.stringify({ type: "ws_message", id: wsId, data: bufToBase64(new Uint8Array(buf)), binary: true }));
        });
      }
    }
  };

  DCWebSocket.prototype.close = function (code, reason) {
    if (this.readyState >= 2) return;
    this.readyState = 2; // CLOSING
    if (controlChannel && controlChannel.readyState === "open") {
      controlChannel.send(JSON.stringify({ type: "ws_close", id: this._id, code: code || 1000, reason: reason || "" }));
    }
  };

  DCWebSocket.prototype._fireOpen = function (protocol) {
    console.log("[RDP] DCWebSocket _fireOpen, id:", this._id);
    this.readyState = 1;
    this.protocol = protocol || "";
    this._dispatch("open", new Event("open"));
  };

  DCWebSocket.prototype._fireMessage = function (data, binary) {
    var payload;
    if (binary) {
      var raw = atob(data);
      var bytes = new Uint8Array(raw.length);
      for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
      payload = this.binaryType === "arraybuffer" ? bytes.buffer : new Blob([bytes]);
    } else {
      payload = data;
    }
    this._dispatch("message", new MessageEvent("message", { data: payload }));
  };

  DCWebSocket.prototype._fireMessageBinary = function (arrayBuffer) {
    console.log("[RDP] DCWebSocket _fireMessageBinary, id:", this._id, "bytes:", arrayBuffer.byteLength);
    var payload = this.binaryType === "arraybuffer" ? arrayBuffer : new Blob([arrayBuffer]);
    this._dispatch("message", new MessageEvent("message", { data: payload }));
  };

  DCWebSocket.prototype._fireClose = function (code, reason) {
    console.log("[RDP] DCWebSocket _fireClose, id:", this._id, "code:", code, "reason:", reason);
    if (this.readyState === 3) return;
    this.readyState = 3;
    dcWebSockets.delete(this._id);
    this._dispatch("close", new CloseEvent("close", { code: code || 1000, reason: reason || "", wasClean: code !== 1006 }));
  };

  DCWebSocket.prototype._fireError = function (message) {
    console.error("[RDP] DCWebSocket _fireError, id:", this._id, "message:", message);
    dcWebSockets.delete(this._id);
    this._dispatch("error", new Event("error"));
    this._fireClose(1006, message || "Connection failed");
  };

  function bufToBase64(bytes) {
    var binary = "";
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function installWebSocketShim() {
    window.WebSocket = function (url, protocols) {
      var parsed = new URL(url, window.location.origin);
      // Compare hostname+port only — wss:// vs https:// have different scheme
      // but should be treated as same-origin for our DataChannel tunnel
      var parsedPort = parsed.port || (parsed.protocol === "wss:" ? "443" : parsed.protocol === "ws:" ? "80" : "");
      var locPort = window.location.port || (window.location.protocol === "https:" ? "443" : "80");
      var sameHost = parsed.hostname === window.location.hostname && parsedPort === locPort;
      if (!sameHost || !controlChannel || controlChannel.readyState !== "open") {
        return new NativeWebSocket(url, protocols);
      }
      console.log("[RDP] DCWebSocket shim intercepting:", url);
      return new DCWebSocket(url, protocols);
    };
    window.WebSocket.CONNECTING = 0;
    window.WebSocket.OPEN = 1;
    window.WebSocket.CLOSING = 2;
    window.WebSocket.CLOSED = 3;
    window.WebSocket.prototype = NativeWebSocket.prototype;
    console.log("[RDP] WebSocket shim installed");
  }

  // ── Initialization ────────────────────────────────────────────

  function init() {
    var params = new URLSearchParams(location.search);
    backendName = (params.get("backend") || "").replace(/\/+$/, "");
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

  async function refreshSessionToken() {
    try {
      var res = await fetch(SESSION_TOKEN_ENDPOINT, {
        credentials: "same-origin",
        headers: { "X-Requested-With": "XMLHttpRequest" },
      });
      if (res.status === 401) {
        throw new Error("Session expired — please reload and log in again");
      }
      if (!res.ok) throw new Error("Session token returned " + res.status);
      var data = await res.json();
      var newToken = data.token || data.access_token;
      if (!newToken) throw new Error("No token in response");
      sessionToken = newToken;
      console.log("[RDP] Session token refreshed");
    } catch (err) {
      throw new Error("Auth refresh failed: " + err.message);
    }
  }

  // ── Signaling ─────────────────────────────────────────────────

  function connectSignaling() {
    if (!config || !config.signalingUrl) {
      setStatus("error", "No signaling URL in config");
      return;
    }

    setStatus("connecting", "Connecting to signaling server...");
    signalingWs = new NativeWebSocket(config.signalingUrl);

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
            .then(function () {
              remoteDescriptionSet = true;
              // Flush queued ICE candidates
              pendingCandidates.forEach(function (c) {
                peerConnection.addIceCandidate(c)
                  .catch(function (err) { console.error("[RDP] addIceCandidate (queued) error:", err); });
              });
              pendingCandidates = [];
            })
            .catch(function (err) { console.error("[RDP] setRemoteDescription error:", err); });
        }
        break;

      case "candidate":
        if (peerConnection && msg.candidate) {
          var iceCandidate = new RTCIceCandidate({ candidate: msg.candidate.candidate, sdpMid: msg.candidate.mid });
          if (remoteDescriptionSet) {
            peerConnection
              .addIceCandidate(iceCandidate)
              .catch(function (err) { console.error("[RDP] addIceCandidate error:", err); });
          } else {
            pendingCandidates.push(iceCandidate);
          }
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

    pendingCandidates = [];
    remoteDescriptionSet = false;
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

    controlChannel = peerConnection.createDataChannel("http-tunnel", { ordered: true });
    bulkChannel = peerConnection.createDataChannel("bulk-data", { ordered: true });
    bulkChannel.binaryType = "arraybuffer";

    setupControlChannel();
    setupBulkChannel();

    peerConnection.onicecandidate = function (event) {
      if (event.candidate && signalingWs && signalingWs.readyState === NativeWebSocket.OPEN) {
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
      if (state === "failed") {
        cleanup();
        scheduleReconnect();
      }
      // Note: "disconnected" is transient — ICE often recovers. Don't tear down.
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
    controlChannel.binaryType = "arraybuffer";

    controlChannel.onopen = function () {
      console.log("[RDP] Control channel open");
      controlChannel.send(JSON.stringify({
        type: "capabilities",
        version: 2,
        features: ["bulk-channel", "binary-ws", "tcp-tunnel"],
      }));
      // Install WebSocket shim now that the DataChannel is open
      installWebSocketShim();
      // Show spinner while deciding auth flow
      connectForm.classList.add("hidden");
      autoConnectSpinner.classList.remove("hidden");
      // For EdDSA backends, auto-connect using username from JWT (no password needed)
      var backendAuth = config && config.backendAuth && config.backendAuth[backendName];
      if (backendAuth === "eddsa" && sessionToken) {
        try {
          var jwtParts = sessionToken.split(".");
          var jwtPayload = JSON.parse(atob(jwtParts[1].replace(/-/g, "+").replace(/_/g, "/")));
          // Extract RDP username from dest: role (dest:gw:endpoint:username)
          var jwtUsername = extractRdpUsername(jwtPayload, backendName) || jwtPayload.preferred_username || jwtPayload.sub || "user";
          isEddsaSession = true;
          eddsaUsername = jwtUsername;
          console.log("[RDP] EdDSA backend - auto-connecting as:", jwtUsername);
          startRdpSession(jwtUsername, "");
        } catch (e) {
          console.warn("[RDP] Failed to extract username from JWT, showing form:", e);
          autoConnectSpinner.classList.add("hidden");
          showConnectForm();
        }
      } else {
        setStatus("connecting", "DataChannel open, ready to connect...");
        autoConnectSpinner.classList.add("hidden");
        showConnectForm();
      }
    };

    controlChannel.onmessage = function (event) {
      try {
        var data = event.data;
        if (data instanceof ArrayBuffer) {
          data = new TextDecoder().decode(data);
        }
        var msg = JSON.parse(data);
        handleControlMessage(msg);
      } catch (e) {
        // ignore
      }
    };

    controlChannel.onclose = function () {
      console.log("[RDP] Control channel closed");
      closeAllDcWebSockets();
    };
  }

  function setupBulkChannel() {
    bulkChannel.onopen = function () {
      console.log("[RDP] Bulk channel open");
    };

    bulkChannel.onmessage = function (event) {
      var buf = new Uint8Array(event.data);
      if (buf.length < 37) return;

      // Binary WS fast-path: [0x02][36-byte WS UUID][payload]
      if (buf[0] === BINARY_WS_MAGIC) {
        var wsId = new TextDecoder().decode(buf.subarray(1, 37));
        var ws = dcWebSockets.get(wsId);
        if (ws) {
          // IMPORTANT: slice() (not subarray) creates a NEW ArrayBuffer copy.
          // subarray().buffer returns the FULL original buffer including the header.
          ws._fireMessageBinary(buf.slice(37).buffer);
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
        if (msg.features && msg.features.indexOf("binary-ws") !== -1) {
          bulkEnabled = true;
        }
        break;

      case "ws_opened": {
        var ws = dcWebSockets.get(msg.id);
        if (ws) ws._fireOpen(msg.protocol);
        break;
      }

      case "ws_message": {
        var ws = dcWebSockets.get(msg.id);
        if (ws) ws._fireMessage(msg.data, msg.binary);
        break;
      }

      case "ws_close": {
        var ws = dcWebSockets.get(msg.id);
        if (ws) ws._fireClose(msg.code, msg.reason);
        break;
      }

      case "ws_error": {
        var ws = dcWebSockets.get(msg.id);
        if (ws) ws._fireError(msg.message);
        break;
      }
    }
  }

  function closeAllDcWebSockets() {
    dcWebSockets.forEach(function (ws) {
      try { ws._fireClose(1006, "DataChannel closed"); } catch (e) {}
    });
    dcWebSockets.clear();
  }

  // ── UI ────────────────────────────────────────────────────────

  function setStatus(state, text) {
    statusDot.className = "dot " + state;
    statusText.textContent = text;
    statusBar.classList.remove("connected");
  }

  function showConnectForm() {
    if (isEddsaSession) {
      showReconnectPanel("Session ended");
      return;
    }
    connectForm.classList.remove("hidden");
    rdpCanvas.classList.add("hidden");
    connectBtn.disabled = false;
    formError.textContent = "";
  }

  function showReconnectPanel(message) {
    connectForm.classList.add("hidden");
    rdpCanvas.classList.add("hidden");
    autoConnectSpinner.classList.add("hidden");
    reconnectPanel.classList.remove("hidden");
    reconnectMessage.textContent = message || "Session ended";
  }

  function hideConnectForm() {
    connectForm.classList.add("hidden");
    autoConnectSpinner.classList.add("hidden");
    reconnectPanel.classList.add("hidden");
    rdpCanvas.classList.remove("hidden");
  }

  // ── IronRDP WASM Integration ──────────────────────────────────

  var wasmModule = null;

  async function loadWasm() {
    if (wasmModule) return wasmModule;
    try {
      wasmModule = await import("/wasm/ironrdp_web.js");
      await wasmModule.default("/wasm/ironrdp_web_bg.wasm");
      wasmModule.setup("info");
      console.log("[RDP] IronRDP WASM loaded");
      return wasmModule;
    } catch (err) {
      console.error("[RDP] Failed to load IronRDP WASM:", err);
      throw err;
    }
  }

  async function startRdpSession(username, password) {
    hideConnectForm();
    setStatus("connecting", "Loading IronRDP WASM...");

    try {
      var wasm = await loadWasm();

      // Refresh session token right before connecting (tokens expire after 5 min)
      setStatus("connecting", "Refreshing auth token...");
      await refreshSessionToken();

      setStatus("connecting", "Connecting to " + backendName + "...");

      var proxyAddress = "wss://" + location.host + "/ws/rdcleanpath";
      console.log("[RDP] Proxy address:", proxyAddress);
      console.log("[RDP] Destination:", backendName);

      // Use device pixels for crisp rendering on HiDPI/Retina displays
      var dpr = window.devicePixelRatio || 1;
      var canvasWidth = Math.floor(window.innerWidth * dpr);
      var canvasHeight = Math.floor(window.innerHeight * dpr);
      rdpCanvas.width = canvasWidth;
      rdpCanvas.height = canvasHeight;
      console.log("[RDP] Canvas size:", canvasWidth, "x", canvasHeight, "dpr:", dpr);

      var builder = new wasm.SessionBuilder();
      builder = builder.username(username);
      builder = builder.password(password);
      builder = builder.destination(backendName);
      builder = builder.proxyAddress(proxyAddress);
      builder = builder.authToken(sessionToken);
      builder = builder.renderCanvas(rdpCanvas);
      builder = builder.desktopSize(new wasm.DesktopSize(canvasWidth, canvasHeight));
      builder = builder.setCursorStyleCallback(function (kind, data, hotspotX, hotspotY) {
        if (kind === "default") {
          rdpCanvas.style.cursor = "default";
        } else if (kind === "hidden") {
          rdpCanvas.style.cursor = "none";
        } else if (kind === "url" && data) {
          rdpCanvas.style.cursor = "url(" + data + ") " + (hotspotX || 0) + " " + (hotspotY || 0) + ", auto";
        }
      });
      builder = builder.setCursorStyleCallbackContext(window);

      console.log("[RDP] Connecting via RDCleanPath...");
      rdpSession = await builder.connect();

      setStatus("connected", "Connected to " + backendName);
      statusBar.classList.add("connected");
      disconnectBtn.classList.remove("hidden");
      console.log("[RDP] RDP session connected");

      // Set up input handling
      setupInputHandlers();

      // Run the session (blocks until session ends)
      var termInfo = await rdpSession.run();
      console.log("[RDP] Session ended:", termInfo ? termInfo.reason() : "unknown");

      rdpSession = null;
      setStatus("error", "Session ended");
      showConnectForm();
    } catch (err) {
      var errMsg = "";
      if (err && typeof err.backtrace === "function") {
        // IronError from WASM
        var kind = err.kind !== undefined ? err.kind() : "unknown";
        var bt = err.backtrace();
        console.error("[RDP] IronError kind:", kind, "backtrace:", bt);
        var details = typeof err.rdcleanpathDetails === "function" ? err.rdcleanpathDetails() : undefined;
        if (details) {
          console.error("[RDP] RDCleanPath details - HTTP:", details.httpStatusCode, "TLS:", details.tlsAlertCode, "WSA:", details.wsaErrorCode);
        }
        errMsg = "IronRDP error (kind " + kind + "): " + bt.split("\n")[0];
      } else {
        errMsg = err.message || String(err);
      }
      console.error("[RDP] RDP session error:", errMsg, err);
      rdpSession = null;
      setStatus("error", "Connection failed: " + errMsg);
      showConnectForm();
    }
  }

  // ── Input Handling ────────────────────────────────────────────

  function setupInputHandlers() {
    if (!wasmModule || !rdpSession) return;

    var DeviceEvent = wasmModule.DeviceEvent;
    var InputTransaction = wasmModule.InputTransaction;
    if (!DeviceEvent || !InputTransaction) {
      console.warn("[RDP] DeviceEvent/InputTransaction not available in WASM module");
      return;
    }

    rdpCanvas.addEventListener("mousemove", function (e) {
      if (!rdpSession) return;
      try {
        var rect = rdpCanvas.getBoundingClientRect();
        var scaleX = rdpCanvas.width / rect.width;
        var scaleY = rdpCanvas.height / rect.height;
        var x = Math.round((e.clientX - rect.left) * scaleX);
        var y = Math.round((e.clientY - rect.top) * scaleY);
        var tx = new InputTransaction();
        tx.addEvent(DeviceEvent.mouseMove(x, y));
        rdpSession.applyInputs(tx);
      } catch (err) { /* ignore input errors */ }
    });

    rdpCanvas.addEventListener("mousedown", function (e) {
      if (!rdpSession) return;
      e.preventDefault();
      try {
        var tx = new InputTransaction();
        tx.addEvent(DeviceEvent.mouseButtonPressed(e.button));
        rdpSession.applyInputs(tx);
      } catch (err) { /* ignore */ }
    });

    rdpCanvas.addEventListener("mouseup", function (e) {
      if (!rdpSession) return;
      try {
        var tx = new InputTransaction();
        tx.addEvent(DeviceEvent.mouseButtonReleased(e.button));
        rdpSession.applyInputs(tx);
      } catch (err) { /* ignore */ }
    });

    rdpCanvas.addEventListener("wheel", function (e) {
      if (!rdpSession) return;
      e.preventDefault();
      try {
        var tx = new InputTransaction();
        // vertical=true, amount, unit=0 (pixel)
        tx.addEvent(DeviceEvent.wheelRotations(true, e.deltaY, 0));
        rdpSession.applyInputs(tx);
      } catch (err) { /* ignore */ }
    }, { passive: false });

    rdpCanvas.addEventListener("contextmenu", function (e) {
      e.preventDefault();
    });

    document.addEventListener("keydown", function (e) {
      if (!rdpSession || !connectForm.classList.contains("hidden")) return;
      e.preventDefault();
      try {
        var tx = new InputTransaction();
        tx.addEvent(DeviceEvent.keyPressed(browserKeyToScancode(e.code)));
        rdpSession.applyInputs(tx);
      } catch (err) { /* ignore */ }
    });

    document.addEventListener("keyup", function (e) {
      if (!rdpSession || !connectForm.classList.contains("hidden")) return;
      e.preventDefault();
      try {
        var tx = new InputTransaction();
        tx.addEvent(DeviceEvent.keyReleased(browserKeyToScancode(e.code)));
        rdpSession.applyInputs(tx);
      } catch (err) { /* ignore */ }
    });
  }

  // ── Keyboard Scancode Mapping ─────────────────────────────────
  // Maps browser KeyboardEvent.code to USB HID scancode values
  // used by IronRDP's DeviceEvent.keyPressed/keyReleased.

  var SCANCODE_MAP = {
    Escape: 0x01, Digit1: 0x02, Digit2: 0x03, Digit3: 0x04, Digit4: 0x05,
    Digit5: 0x06, Digit6: 0x07, Digit7: 0x08, Digit8: 0x09, Digit9: 0x0A,
    Digit0: 0x0B, Minus: 0x0C, Equal: 0x0D, Backspace: 0x0E, Tab: 0x0F,
    KeyQ: 0x10, KeyW: 0x11, KeyE: 0x12, KeyR: 0x13, KeyT: 0x14,
    KeyY: 0x15, KeyU: 0x16, KeyI: 0x17, KeyO: 0x18, KeyP: 0x19,
    BracketLeft: 0x1A, BracketRight: 0x1B, Enter: 0x1C, ControlLeft: 0x1D,
    KeyA: 0x1E, KeyS: 0x1F, KeyD: 0x20, KeyF: 0x21, KeyG: 0x22,
    KeyH: 0x23, KeyJ: 0x24, KeyK: 0x25, KeyL: 0x26, Semicolon: 0x27,
    Quote: 0x28, Backquote: 0x29, ShiftLeft: 0x2A, Backslash: 0x2B,
    KeyZ: 0x2C, KeyX: 0x2D, KeyC: 0x2E, KeyV: 0x2F, KeyB: 0x30,
    KeyN: 0x31, KeyM: 0x32, Comma: 0x33, Period: 0x34, Slash: 0x35,
    ShiftRight: 0x36, NumpadMultiply: 0x37, AltLeft: 0x38, Space: 0x39,
    CapsLock: 0x3A, F1: 0x3B, F2: 0x3C, F3: 0x3D, F4: 0x3E,
    F5: 0x3F, F6: 0x40, F7: 0x41, F8: 0x42, F9: 0x43, F10: 0x44,
    NumLock: 0x45, ScrollLock: 0x46,
    Numpad7: 0x47, Numpad8: 0x48, Numpad9: 0x49, NumpadSubtract: 0x4A,
    Numpad4: 0x4B, Numpad5: 0x4C, Numpad6: 0x4D, NumpadAdd: 0x4E,
    Numpad1: 0x4F, Numpad2: 0x50, Numpad3: 0x51, Numpad0: 0x52,
    NumpadDecimal: 0x53, F11: 0x57, F12: 0x58,
    // Extended keys (set bit 0x100 for extended scancode flag)
    NumpadEnter: 0x11C, ControlRight: 0x11D, NumpadDivide: 0x135,
    PrintScreen: 0x137, AltRight: 0x138, Home: 0x147, ArrowUp: 0x148,
    PageUp: 0x149, ArrowLeft: 0x14B, ArrowRight: 0x14D, End: 0x14F,
    ArrowDown: 0x150, PageDown: 0x151, Insert: 0x152, Delete: 0x153,
    MetaLeft: 0x15B, MetaRight: 0x15C, ContextMenu: 0x15D,
  };

  function browserKeyToScancode(code) {
    return SCANCODE_MAP[code] || 0;
  }

  // ── Cleanup / Reconnect ───────────────────────────────────────

  function cleanup() {
    if (rdpSession) {
      try { rdpSession.shutdown(); } catch (e) {}
      rdpSession = null;
    }
    closeAllDcWebSockets();
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
    bulkEnabled = false;
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

  reconnectBtn.addEventListener("click", function () {
    reconnectPanel.classList.add("hidden");
    autoConnectSpinner.classList.remove("hidden");
    startRdpSession(eddsaUsername, "");
  });

  disconnectBtn.addEventListener("click", function () {
    if (rdpSession) {
      try { rdpSession.shutdown(); } catch (e) {}
      rdpSession = null;
    }
    closeAllDcWebSockets();
    setStatus("connecting", "Disconnected");
    showConnectForm();
  });

  // Resize canvas with window
  window.addEventListener("resize", function () {
    if (rdpSession && !rdpCanvas.classList.contains("hidden")) {
      try {
        var dpr = window.devicePixelRatio || 1;
        var w = Math.floor(window.innerWidth * dpr);
        var h = Math.floor(window.innerHeight * dpr);
        rdpCanvas.width = w;
        rdpCanvas.height = h;
        rdpSession.resize(w, h);
      } catch (e) { /* ignore */ }
    }
  });

  // ── Start ─────────────────────────────────────────────────────

  init();
})();
