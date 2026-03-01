/**
 * VNC client over DataChannel with native RFB protocol.
 *
 * Establishes a WebRTC DataChannel to the punchd gateway, opens a raw
 * TCP tunnel to a VNC server (port 5900), and implements the RFB protocol
 * directly in JavaScript — no external libraries needed.
 *
 * Flow: vnc-client.js → tcp_open on control DataChannel
 *       → gateway peer-handler → raw TCP to VNC server
 *       → bidirectional relay via 0x03 magic on bulk DataChannel
 *       → browser-side RFB handshake + framebuffer rendering
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
  var PROGRESSIVE_PAINT_ROWS = 50; // paint every N rows during streaming

  var NativeWebSocket = window.WebSocket;

  // ── DOM elements ──────────────────────────────────────────────

  var statusBar = document.getElementById("status-bar");
  var statusDot = document.getElementById("status-dot");
  var statusText = document.getElementById("status-text");
  var disconnectBtn = document.getElementById("disconnect-btn");
  var connectForm = document.getElementById("connect-form");
  var connectBtn = document.getElementById("connect-btn");
  var formError = document.getElementById("form-error");
  var vncCanvas = document.getElementById("vnc-canvas");
  var passwordInput = document.getElementById("vnc-password");
  var scaleSelect = document.getElementById("vnc-scale");

  // ── State ─────────────────────────────────────────────────────

  var config = null;
  var sessionToken = null;
  var signalingWs = null;
  var peerConnection = null;
  var controlChannel = null;
  var bulkChannel = null;
  var clientId = "vnc-" + crypto.randomUUID().replace(/-/g, "").slice(0, 8);
  var pairedGatewayId = null;
  var reconnectAttempts = 0;
  var reconnectTimer = null;
  var backendName = null;
  var bulkEnabled = false;

  // TCP tunnel state
  var tunnelId = null;
  var tunnelOpen = false;
  var vncPassword = "";

  // RFB state
  var RFB_VERSION = 0;
  var RFB_SECURITY = 1;
  var RFB_VNC_AUTH_CHALLENGE = 2;
  var RFB_SECURITY_RESULT = 3;
  var RFB_SERVER_INIT = 4;
  var RFB_CONNECTED = 5;

  var rfbState = RFB_VERSION;
  var recvBuf = new Uint8Array(0);
  var fbWidth = 0;
  var fbHeight = 0;
  var serverName = "";
  var ctx = null;
  var imageData = null;
  var imageData32 = null; // Uint32Array view over imageData.data.buffer for fast pixel writes
  var updateTimer = null;
  var buttonMask = 0;

  // Framebuffer update parsing state
  var fbUpdateRemaining = 0;
  var fbUpdateRect = null;
  var fbUpdatePixelsLeft = 0;
  var fbUpdateBusy = false; // true while processing a FramebufferUpdate
  var resyncSkipped = 0; // bytes skipped while resyncing after unknown message type

  // Server pixel format (populated from ServerInit, updated by SetPixelFormat)
  var serverBpp = 32; // bytes per pixel component (bits)
  var serverBytesPerPixel = 4;
  var serverRShift = 0;
  var serverGShift = 8;
  var serverBShift = 16;
  var serverBigEndian = false;

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
      console.log("[VNC] Config loaded:", config);
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
      console.log("[VNC] Session token acquired");
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
    signalingWs = new NativeWebSocket(config.signalingUrl);

    signalingWs.onopen = function () {
      console.log("[VNC] Signaling connected");
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
        console.debug("[VNC] Signaling parse error:", e);
      }
    };

    signalingWs.onclose = function () {
      console.log("[VNC] Signaling disconnected");
      cleanup();
      scheduleReconnect();
    };

    signalingWs.onerror = function () {
      console.log("[VNC] Signaling error");
    };
  }

  function handleSignalingMessage(msg) {
    switch (msg.type) {
      case "registered":
        console.log("[VNC] Registered as client:", msg.id);
        break;

      case "paired":
        pairedGatewayId = msg.gateway && msg.gateway.id;
        console.log("[VNC] Paired with gateway:", pairedGatewayId);
        startWebRTC();
        break;

      case "sdp_answer":
        if (peerConnection && msg.sdp) {
          peerConnection
            .setRemoteDescription(new RTCSessionDescription({ type: msg.sdpType || "answer", sdp: msg.sdp }))
            .catch(function (err) { console.error("[VNC] setRemoteDescription error:", err); });
        }
        break;

      case "candidate":
        if (peerConnection && msg.candidate) {
          peerConnection
            .addIceCandidate(new RTCIceCandidate({ candidate: msg.candidate.candidate, sdpMid: msg.candidate.mid }))
            .catch(function (err) { console.error("[VNC] addIceCandidate error:", err); });
        }
        break;

      case "error":
        console.error("[VNC] Signaling error:", msg.message);
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
      console.log("[VNC] Connection state:", state);
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
        console.log("[VNC] SDP offer sent");
      })
      .catch(function (err) {
        console.error("[VNC] Offer creation failed:", err);
        setStatus("error", "WebRTC offer failed");
      });
  }

  function setupControlChannel() {
    controlChannel.binaryType = "arraybuffer";

    controlChannel.onopen = function () {
      console.log("[VNC] Control channel open");
      controlChannel.send(JSON.stringify({
        type: "capabilities",
        version: 2,
        features: ["bulk-channel", "binary-ws", "tcp-tunnel"],
      }));
      setStatus("connecting", "DataChannel open, ready to connect...");
      showConnectForm();
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
        console.debug("[VNC] Control message parse error:", e);
      }
    };

    controlChannel.onclose = function () {
      console.log("[VNC] Control channel closed");
    };
  }

  function setupBulkChannel() {
    bulkChannel.onopen = function () {
      console.log("[VNC] Bulk channel open");
    };

    bulkChannel.onmessage = function (event) {
      var buf = new Uint8Array(event.data);
      if (buf.length < 37) return;

      // TCP tunnel fast-path: [0x03][36-byte tunnel UUID][payload]
      if (buf[0] === TCP_TUNNEL_MAGIC) {
        var id = new TextDecoder().decode(buf.subarray(1, 37));
        if (id === tunnelId) {
          onTcpData(buf.slice(37));
        }
      }
    };

    bulkChannel.onclose = function () {
      console.log("[VNC] Bulk channel closed");
    };
  }

  function handleControlMessage(msg) {
    switch (msg.type) {
      case "capabilities":
        console.log("[VNC] Gateway capabilities:", msg.features);
        if (msg.features && msg.features.indexOf("binary-ws") !== -1) {
          bulkEnabled = true;
        }
        break;

      case "tcp_opened":
        if (msg.id === tunnelId) {
          console.log("[VNC] TCP tunnel opened");
          tunnelOpen = true;
          rfbState = RFB_VERSION;
          recvBuf = new Uint8Array(0);
          // RFB handshake starts — server sends version string first
        }
        break;

      case "tcp_close":
        if (msg.id === tunnelId) {
          console.log("[VNC] TCP tunnel closed by server");
          disconnectVnc("Connection closed by server");
        }
        break;

      case "tcp_error":
        if (msg.id === tunnelId) {
          console.error("[VNC] TCP tunnel error:", msg.message);
          disconnectVnc("Connection error: " + (msg.message || "unknown"));
        }
        break;
    }
  }

  // ── TCP Tunnel ────────────────────────────────────────────────

  function sendTcpData(data) {
    if (!tunnelOpen || !bulkChannel || bulkChannel.readyState !== "open") return;
    var payload = data instanceof Uint8Array ? data : new Uint8Array(data);
    var idBytes = new TextEncoder().encode(tunnelId);
    var frame = new Uint8Array(1 + 36 + payload.length);
    frame[0] = TCP_TUNNEL_MAGIC;
    frame.set(idBytes, 1);
    frame.set(payload, 37);
    bulkChannel.send(frame);
  }

  var tcpBytesReceived = 0;
  function onTcpData(data) {
    tcpBytesReceived += data.length;
    // Append to receive buffer (avoid copy when recvBuf is empty)
    if (recvBuf.length === 0) {
      recvBuf = data;
    } else {
      var newBuf = new Uint8Array(recvBuf.length + data.length);
      newBuf.set(recvBuf);
      newBuf.set(data, recvBuf.length);
      recvBuf = newBuf;
    }

    // Log periodically (debug level to avoid console spam)
    if (rfbState === RFB_CONNECTED && tcpBytesReceived % 500000 < data.length) {
      console.debug("[VNC] TCP bytes received:", (tcpBytesReceived / 1048576).toFixed(1) + "MB",
        "recvBuf:", recvBuf.length, "pixelsLeft:", fbUpdatePixelsLeft);
    }

    // Process as much of the buffer as possible
    processRfb();
  }

  // ── RFB Protocol ──────────────────────────────────────────────

  function processRfb() {
    while (recvBuf.length > 0) {
      var consumed = 0;

      switch (rfbState) {
        case RFB_VERSION:
          consumed = handleVersion();
          break;
        case RFB_SECURITY:
          consumed = handleSecurity();
          break;
        case RFB_VNC_AUTH_CHALLENGE:
          consumed = handleVncAuthChallenge();
          break;
        case RFB_SECURITY_RESULT:
          consumed = handleSecurityResult();
          break;
        case RFB_SERVER_INIT:
          consumed = handleServerInit();
          break;
        case RFB_CONNECTED:
          consumed = handleServerMessage();
          break;
      }

      if (consumed <= 0) break; // Need more data
      recvBuf = recvBuf.subarray(consumed);
    }
  }

  function handleVersion() {
    // Server sends "RFB 003.00X\n" (12 bytes)
    if (recvBuf.length < 12) return 0;
    var version = new TextDecoder().decode(recvBuf.subarray(0, 12));
    console.log("[VNC] Server version:", version.trim());

    // Reply with RFB 003.008
    sendTcpData(new TextEncoder().encode("RFB 003.008\n"));
    rfbState = RFB_SECURITY;
    setStatus("connecting", "Negotiating security...");
    return 12;
  }

  function handleSecurity() {
    // Server sends: [numTypes:u8][type1, type2, ...]
    if (recvBuf.length < 1) return 0;
    var numTypes = recvBuf[0];

    // numTypes=0 means server rejected connection — read reason string
    if (numTypes === 0) {
      if (recvBuf.length < 5) return 0;
      var reasonLen = (recvBuf[1] << 24) | (recvBuf[2] << 16) | (recvBuf[3] << 8) | recvBuf[4];
      if (recvBuf.length < 5 + reasonLen) return 0;
      var reason = new TextDecoder().decode(recvBuf.subarray(5, 5 + reasonLen));
      disconnectVnc("Server rejected: " + reason);
      return 5 + reasonLen;
    }

    if (recvBuf.length < 1 + numTypes) return 0;
    var types = recvBuf.subarray(1, 1 + numTypes);
    console.log("[VNC] Security types:", Array.from(types));

    // Prefer VNC Auth (2), fall back to None (1)
    var hasVncAuth = false;
    var hasNone = false;
    for (var i = 0; i < types.length; i++) {
      if (types[i] === 2) hasVncAuth = true;
      if (types[i] === 1) hasNone = true;
    }

    if (hasVncAuth && vncPassword) {
      sendTcpData(new Uint8Array([2]));
      rfbState = RFB_VNC_AUTH_CHALLENGE;
      return 1 + numTypes;
    } else if (hasNone) {
      sendTcpData(new Uint8Array([1]));
      rfbState = RFB_SECURITY_RESULT;
      return 1 + numTypes;
    } else {
      disconnectVnc("No supported security type");
      return 1 + numTypes;
    }
  }

  function handleVncAuthChallenge() {
    // Server sends 16-byte challenge
    if (recvBuf.length < 16) return 0;
    var challenge = new Uint8Array(recvBuf.subarray(0, 16));
    console.log("[VNC] Got VNC auth challenge, computing response...");
    var response = vncAuthResponse(challenge, vncPassword);
    console.log("[VNC] Sending auth response");
    sendTcpData(response);
    rfbState = RFB_SECURITY_RESULT;
    return 16;
  }

  function handleSecurityResult() {
    // SecurityResult: [status:u32] — 0=OK, 1=failed
    if (recvBuf.length < 4) return 0;
    var status = (recvBuf[0] << 24) | (recvBuf[1] << 16) | (recvBuf[2] << 8) | recvBuf[3];

    if (status !== 0) {
      // RFB 3.8: failure includes a reason string
      if (recvBuf.length < 8) return 0;
      var reasonLen = (recvBuf[4] << 24) | (recvBuf[5] << 16) | (recvBuf[6] << 8) | recvBuf[7];
      if (recvBuf.length < 8 + reasonLen) return 0;
      var reason = new TextDecoder().decode(recvBuf.subarray(8, 8 + reasonLen));
      disconnectVnc("Auth failed: " + reason);
      return 8 + reasonLen;
    }

    console.log("[VNC] Auth OK");
    // Send ClientInit — shared flag = 1 (allow other clients)
    sendTcpData(new Uint8Array([1]));
    rfbState = RFB_SERVER_INIT;
    setStatus("connecting", "Waiting for server init...");
    return 4;
  }

  function handleServerInit() {
    // ServerInit: [width:u16][height:u16][pixel_format:16][name_len:u32][name...]
    if (recvBuf.length < 24) return 0;
    var nameLen = (recvBuf[20] << 24) | (recvBuf[21] << 16) | (recvBuf[22] << 8) | recvBuf[23];
    if (recvBuf.length < 24 + nameLen) return 0;

    fbWidth = (recvBuf[0] << 8) | recvBuf[1];
    fbHeight = (recvBuf[2] << 8) | recvBuf[3];
    serverName = new TextDecoder().decode(recvBuf.subarray(24, 24 + nameLen));

    // Log server's default pixel format
    console.log("[VNC] ServerInit:", fbWidth, "x", fbHeight, "name:", serverName);
    console.log("[VNC] Server pixel format: bpp=" + recvBuf[4], "depth=" + recvBuf[5],
      "bigEndian=" + recvBuf[6], "trueColor=" + recvBuf[7],
      "rMax=" + ((recvBuf[8] << 8) | recvBuf[9]),
      "gMax=" + ((recvBuf[10] << 8) | recvBuf[11]),
      "bMax=" + ((recvBuf[12] << 8) | recvBuf[13]),
      "rShift=" + recvBuf[14], "gShift=" + recvBuf[15], "bShift=" + recvBuf[16]);

    // Set up canvas
    setupCanvas();

    // Send SetPixelFormat — request 32-bit BGRX TrueColor
    // BGRX matches Windows native format so TightVNC doesn't need to convert.
    // Byte order on wire (little-endian): [B, G, R, X]
    var spf = new Uint8Array(20);
    spf[0] = 0; // message type: SetPixelFormat
    // [1..3] padding
    spf[4] = 32; // bpp
    spf[5] = 24; // depth
    spf[6] = 0;  // big-endian = false
    spf[7] = 1;  // true-color = true
    spf[8] = 0; spf[9] = 255;   // r-max = 255
    spf[10] = 0; spf[11] = 255; // g-max = 255
    spf[12] = 0; spf[13] = 255; // b-max = 255
    spf[14] = 16; // r-shift = 16 (R in bits 16-23 → byte 2)
    spf[15] = 8;  // g-shift = 8  (G in bits 8-15  → byte 1)
    spf[16] = 0;  // b-shift = 0  (B in bits 0-7   → byte 0)
    // [17..19] padding
    sendTcpData(spf);
    console.log("[VNC] Sent SetPixelFormat: 32bpp BGRX little-endian");

    // Update our pixel format tracking
    serverBpp = 32;
    serverBytesPerPixel = 4;
    serverRShift = 16;
    serverGShift = 8;
    serverBShift = 0;
    serverBigEndian = false;

    // Send SetEncodings: CopyRect(1), Raw(0), DesktopSize(-223)
    var se = new Uint8Array(16);
    se[0] = 2; // message type: SetEncodings
    // [1] padding
    se[2] = 0; se[3] = 3; // number of encodings
    // CopyRect = 1 (preferred — server can use it to optimize scrolling)
    se[4] = 0; se[5] = 0; se[6] = 0; se[7] = 1;
    // Raw = 0 (fallback — always supported)
    se[8] = 0; se[9] = 0; se[10] = 0; se[11] = 0;
    // DesktopSize = -223 (0xFFFFFF21) pseudo-encoding
    se[12] = 0xFF; se[13] = 0xFF; se[14] = 0xFF; se[15] = 0x21;
    sendTcpData(se);

    rfbState = RFB_CONNECTED;
    setStatus("connected", "Connected to " + serverName);
    statusBar.classList.add("connected");
    disconnectBtn.classList.remove("hidden");

    // Request full framebuffer update
    console.log("[VNC] Requesting full framebuffer update");
    requestFramebufferUpdate(false);

    // Set up input handlers
    setupInputHandlers();

    // Diagnostic: periodic status check to detect stalls
    var lastTcpCheck = 0;
    var stallTimer = setInterval(function () {
      if (rfbState !== RFB_CONNECTED) { clearInterval(stallTimer); return; }
      var stalled = (tcpBytesReceived === lastTcpCheck && fbUpdatePixelsLeft > 0);
      var rateMBs = ((tcpBytesReceived - lastTcpCheck) / 1048576 / 5).toFixed(2);
      if (fbUpdatePixelsLeft > 0 || stalled) {
        console.log("[VNC] Status: pixelsLeft=" + fbUpdatePixelsLeft +
          " TCP=" + (tcpBytesReceived / 1048576).toFixed(1) + "MB" +
          " rate=" + rateMBs + "MB/s" + (stalled ? " STALLED" : ""));
      }
      lastTcpCheck = tcpBytesReceived;
    }, 5000);

    return 24 + nameLen;
  }

  function requestFramebufferUpdate(incremental) {
    var msg = new Uint8Array(10);
    msg[0] = 3; // FramebufferUpdateRequest
    msg[1] = incremental ? 1 : 0;
    // x=0, y=0
    msg[2] = 0; msg[3] = 0;
    msg[4] = 0; msg[5] = 0;
    // width, height
    msg[6] = (fbWidth >> 8) & 0xFF; msg[7] = fbWidth & 0xFF;
    msg[8] = (fbHeight >> 8) & 0xFF; msg[9] = fbHeight & 0xFF;
    sendTcpData(msg);
  }

  function handleServerMessage() {
    // We may be in the middle of parsing a framebuffer update
    if (fbUpdateRemaining > 0) {
      return handleFbUpdateRect();
    }

    if (recvBuf.length < 1) return 0;
    var msgType = recvBuf[0];

    switch (msgType) {
      case 0: resyncSkipped = 0; return handleFbUpdate();
      case 1: resyncSkipped = 0; return handleSetColourMap();
      case 2: resyncSkipped = 0; return handleBell();
      case 3: resyncSkipped = 0; return handleServerCutText();
      default:
        // Unknown message type — parser misalignment or unsupported server extension.
        // Scan forward for a valid FramebufferUpdate header by checking:
        //   [type=0x00][pad=0x00][nRects:u16] with 1 <= nRects <= 1000
        //   + first rect encoding must be a known value
        if (resyncSkipped === 0) {
          console.warn("[VNC] Unknown message type:", msgType,
            "hex:", Array.from(recvBuf.subarray(0, Math.min(20, recvBuf.length)))
              .map(function(b) { return ("0" + b.toString(16)).slice(-2); }).join(" "));
        }
        for (var skip = 1; skip < recvBuf.length - 15; skip++) {
          if (recvBuf[skip] !== 0x00 || recvBuf[skip + 1] !== 0x00) continue;
          var nRects = (recvBuf[skip + 2] << 8) | recvBuf[skip + 3];
          if (nRects < 1 || nRects > 1000) continue;
          // Validate first rect header: encoding must be known
          var enc = (recvBuf[skip + 12] << 24) | (recvBuf[skip + 13] << 16) |
                    (recvBuf[skip + 14] << 8) | recvBuf[skip + 15];
          if (enc !== 0 && enc !== 1 && enc !== -223 && enc !== -224 &&
              enc !== -232 && enc !== -239 && enc !== -240) continue;
          // Validate first rect dimensions are within framebuffer
          var rw = (recvBuf[skip + 8] << 8) | recvBuf[skip + 9];
          var rh = (recvBuf[skip + 10] << 8) | recvBuf[skip + 11];
          if (rw === 0 || rh === 0 || rw > 8192 || rh > 8192) continue;
          console.warn("[VNC] Resynced after skipping", skip, "bytes");
          resyncSkipped += skip;
          return skip;
        }
        // Could not resync in current buffer — discard and wait for more data
        resyncSkipped += recvBuf.length;
        if (resyncSkipped > 1048576) {
          disconnectVnc("Parser cannot resync after 1MB of unknown data");
          return 0;
        }
        return recvBuf.length;
    }
  }

  function handleFbUpdate() {
    // FramebufferUpdate: [0][pad:1][numRects:u16]
    if (recvBuf.length < 4) return 0;
    fbUpdateRemaining = (recvBuf[2] << 8) | recvBuf[3];
    fbUpdateRect = null;
    fbUpdatePixelsLeft = 0;
    fbUpdateBusy = true;
    console.debug("[VNC] FramebufferUpdate:", fbUpdateRemaining, "rects");
    return 4;
  }

  function onFbUpdateComplete() {
    fbUpdateBusy = false;
    // Restore connected status (clears "Loading..." text)
    if (rfbState === RFB_CONNECTED) {
      setStatus("connected", "Connected to " + serverName);
      statusBar.classList.add("connected");
      disconnectBtn.classList.remove("hidden");
      // Request next incremental update
      requestFramebufferUpdate(true);
    }
  }

  function finishRect() {
    fbUpdateRect = null;
    fbUpdateRemaining--;
    if (fbUpdateRemaining <= 0) {
      onFbUpdateComplete();
    }
  }

  function handleFbUpdateRect() {
    // Parse rectangle header if we haven't yet
    if (!fbUpdateRect) {
      if (recvBuf.length < 12) return 0;
      var encoding = (recvBuf[8] << 24) | (recvBuf[9] << 16) | (recvBuf[10] << 8) | recvBuf[11];

      // CopyRect needs 16 bytes total — check BEFORE setting fbUpdateRect
      // to avoid stuck-state when we have 12-15 bytes
      if (encoding === 1 && recvBuf.length < 16) return 0;

      // Pre-check buffer for variable-length pseudo-encodings before committing
      if (encoding === -239) { // Cursor: pixels + bitmask
        var _cw = (recvBuf[4] << 8) | recvBuf[5];
        var _ch = (recvBuf[6] << 8) | recvBuf[7];
        var _cursorNeed = 12 + _cw * _ch * serverBytesPerPixel + Math.ceil(_cw / 8) * _ch;
        if (recvBuf.length < _cursorNeed) return 0;
      }
      if (encoding === -240) { // XCursor: fg/bg RGB + bitmap + mask
        var _xw = (recvBuf[4] << 8) | recvBuf[5];
        var _xh = (recvBuf[6] << 8) | recvBuf[7];
        if (_xw > 0 && _xh > 0) {
          var _xcursorNeed = 12 + 6 + Math.ceil(_xw / 8) * _xh * 2;
          if (recvBuf.length < _xcursorNeed) return 0;
        }
      }

      fbUpdateRect = {
        x: (recvBuf[0] << 8) | recvBuf[1],
        y: (recvBuf[2] << 8) | recvBuf[3],
        w: (recvBuf[4] << 8) | recvBuf[5],
        h: (recvBuf[6] << 8) | recvBuf[7],
        encoding: encoding,
        pixelRow: 0,
        pixelCol: 0,
        pixelByte: 0,
        lastPaintRow: 0,
      };

      // Handle pseudo-encodings
      if (encoding === -223 || encoding === (0xFFFFFF21 | 0)) {
        console.log("[VNC] Desktop resize:", fbUpdateRect.w, "x", fbUpdateRect.h);
        fbWidth = fbUpdateRect.w;
        fbHeight = fbUpdateRect.h;
        setupCanvas();
        fbUpdateRect = null;
        fbUpdateRemaining--;
        if (fbUpdateRemaining <= 0) {
          requestFramebufferUpdate(false);
        }
        return 12;
      }

      // Cursor pseudo-encoding (-239 = 0xFFFFFF11) — skip pixel + mask data
      if (encoding === -239) {
        var pxBytes = fbUpdateRect.w * fbUpdateRect.h * serverBytesPerPixel;
        var maskBytes = Math.ceil(fbUpdateRect.w / 8) * fbUpdateRect.h;
        var cursorSkip = 12 + pxBytes + maskBytes;
        console.debug("[VNC] Cursor pseudo-encoding:", fbUpdateRect.w + "x" + fbUpdateRect.h,
          "skipping", cursorSkip, "bytes");
        finishRect();
        return cursorSkip;
      }

      // XCursor pseudo-encoding (-240 = 0xFFFFFF10) — skip fg/bg + bitmaps
      if (encoding === -240) {
        var xcSkip = 12;
        if (fbUpdateRect.w > 0 && fbUpdateRect.h > 0) {
          var bitmapBytes = Math.ceil(fbUpdateRect.w / 8) * fbUpdateRect.h;
          xcSkip += 6 + bitmapBytes * 2;
        }
        console.debug("[VNC] XCursor pseudo-encoding:", fbUpdateRect.w + "x" + fbUpdateRect.h);
        finishRect();
        return xcSkip;
      }

      // LastRect pseudo-encoding (-224 = 0xFFFFFF20) — no more rects follow
      if (encoding === -224) {
        console.debug("[VNC] LastRect pseudo-encoding");
        fbUpdateRect = null;
        fbUpdateRemaining = 0;
        onFbUpdateComplete();
        return 12;
      }

      // CursorPos pseudo-encoding (-232 = 0xFFFFFF18) — no extra data
      if (encoding === -232) {
        console.debug("[VNC] CursorPos:", fbUpdateRect.x + "," + fbUpdateRect.y);
        finishRect();
        return 12;
      }

      if (encoding === 1) {
        // CopyRect: [srcX:u16][srcY:u16]
        if (recvBuf.length < 16) return 0;
        var srcX = (recvBuf[12] << 8) | recvBuf[13];
        var srcY = (recvBuf[14] << 8) | recvBuf[15];
        var rw = fbUpdateRect.w;
        var rh = fbUpdateRect.h;
        var dx = fbUpdateRect.x;
        var dy = fbUpdateRect.y;
        if (imageData && rw > 0 && rh > 0) {
          // Copy within imageData buffer (handle overlapping regions)
          var data = imageData.data;
          var rowBytes = rw * 4;
          if (dy > srcY || (dy === srcY && dx > srcX)) {
            for (var r = rh - 1; r >= 0; r--) {
              var sOff = ((srcY + r) * fbWidth + srcX) * 4;
              var dOff = ((dy + r) * fbWidth + dx) * 4;
              data.copyWithin(dOff, sOff, sOff + rowBytes);
            }
          } else {
            for (var r = 0; r < rh; r++) {
              var sOff = ((srcY + r) * fbWidth + srcX) * 4;
              var dOff = ((dy + r) * fbWidth + dx) * 4;
              data.copyWithin(dOff, sOff, sOff + rowBytes);
            }
          }
          ctx.putImageData(imageData, 0, 0, dx, dy, rw, rh);
        }
        finishRect();
        return 16;
      }

      if (encoding !== 0) {
        // Unknown encoding — can't determine data length, so abandon this
        // FramebufferUpdate and let the resync scanner find the next valid one.
        console.warn("[VNC] Unsupported encoding:", encoding,
          "(0x" + (encoding >>> 0).toString(16) + ")",
          "rect:", fbUpdateRect.x + "," + fbUpdateRect.y,
          fbUpdateRect.w + "x" + fbUpdateRect.h);
        fbUpdateRect = null;
        fbUpdateRemaining = 0;
        fbUpdatePixelsLeft = 0;
        fbUpdateBusy = false;
        // Skip just the 12-byte rect header; remaining data will be handled
        // by the resync scanner in handleServerMessage which validates
        // FramebufferUpdate headers properly before resyncing.
        return 12;
      }

      // Raw encoding — need w*h*bpp bytes of pixel data
      fbUpdatePixelsLeft = fbUpdateRect.w * fbUpdateRect.h * serverBytesPerPixel;

      // Zero-size rect: nothing to render, finish immediately
      if (fbUpdatePixelsLeft <= 0) {
        finishRect();
      }

      return 12;
    }

    // Raw encoding: consume pixel data using Uint32Array fast path
    if (fbUpdatePixelsLeft > 0) {
      var available = Math.min(recvBuf.length, fbUpdatePixelsLeft);
      if (available <= 0) return 0;

      if (imageData && ctx && imageData32) {
        var rect = fbUpdateRect;
        var img32 = imageData32;
        var imgPixels = imageData.data;
        var rw = rect.w;
        var row = rect.pixelRow;
        var col = rect.pixelCol;
        var pb = rect.pixelByte;
        var i = 0;

        // Phase 1: finish any partial leading pixel (max 3 bytes)
        if (pb > 0) {
          var off = ((rect.y + row) * fbWidth + rect.x + col) * 4;
          while (pb < 4 && i < available) {
            switch (pb) {
              case 1: imgPixels[off + 1] = recvBuf[i]; break; // G
              case 2: imgPixels[off]     = recvBuf[i]; break; // R
              case 3: imgPixels[off + 3] = 255;        break; // A (discard X)
            }
            pb++; i++;
          }
          if (pb >= 4) { pb = 0; col++; if (col >= rw) { col = 0; row++; } }
        }

        // Phase 2: fast path — write complete pixels via Uint32Array
        // BGRX wire → little-endian uint32: 0xAA_BB_GG_RR = 0xFF_B_G_R
        var idx = (rect.y + row) * fbWidth + rect.x + col;
        while (i + 4 <= available) {
          img32[idx] = 0xFF000000 | (recvBuf[i] << 16) | (recvBuf[i + 1] << 8) | recvBuf[i + 2];
          i += 4; idx++;
          col++;
          if (col >= rw) { col = 0; row++; idx = (rect.y + row) * fbWidth + rect.x; }
        }

        // Phase 3: trailing partial pixel (max 3 bytes)
        if (i < available) {
          var off = ((rect.y + row) * fbWidth + rect.x + col) * 4;
          while (i < available) {
            switch (pb) {
              case 0: imgPixels[off + 2] = recvBuf[i]; break; // B
              case 1: imgPixels[off + 1] = recvBuf[i]; break; // G
              case 2: imgPixels[off]     = recvBuf[i]; break; // R
              case 3: imgPixels[off + 3] = 255;        break; // A (discard X)
            }
            pb++; i++;
          }
        }

        rect.pixelRow = row;
        rect.pixelCol = col;
        rect.pixelByte = pb;
      }

      fbUpdatePixelsLeft -= available;

      // Progressive rendering: paint every N rows or when done
      if (imageData && ctx) {
        var rect = fbUpdateRect;
        var currentRow = rect.pixelRow;
        if (fbUpdatePixelsLeft <= 0 || currentRow - rect.lastPaintRow >= PROGRESSIVE_PAINT_ROWS) {
          var paintY = rect.y + rect.lastPaintRow;
          var paintH = (fbUpdatePixelsLeft <= 0 ? rect.h : currentRow) - rect.lastPaintRow;
          if (paintH > 0) {
            ctx.putImageData(imageData, 0, 0, rect.x, paintY, rect.w, paintH);
            rect.lastPaintRow = fbUpdatePixelsLeft <= 0 ? rect.h : currentRow;
            // Show loading progress for large rects
            if (fbUpdatePixelsLeft > 0) {
              var totalBytes = rect.w * rect.h * serverBytesPerPixel;
              var pct = Math.round(((totalBytes - fbUpdatePixelsLeft) / totalBytes) * 100);
              statusText.textContent = "Loading desktop... " + pct + "%";
            }
          }
        }
      }

      if (fbUpdatePixelsLeft <= 0) {
        finishRect();
      }

      return available;
    }

    return 0;
  }

  function handleSetColourMap() {
    // SetColourMapEntries: [1][pad:1][firstColor:u16][numColors:u16][r,g,b * numColors (each u16)]
    if (recvBuf.length < 6) return 0;
    var numColors = (recvBuf[4] << 8) | recvBuf[5];
    var totalLen = 6 + numColors * 6;
    if (recvBuf.length < totalLen) return 0;
    // We use TrueColor, so ignore color map entries
    return totalLen;
  }

  function handleBell() {
    // Bell: [2] — just 1 byte
    return 1;
  }

  function handleServerCutText() {
    // ServerCutText: [3][pad:3][length:u32][text...]
    if (recvBuf.length < 8) return 0;
    var textLen = (recvBuf[4] << 24) | (recvBuf[5] << 16) | (recvBuf[6] << 8) | recvBuf[7];
    if (recvBuf.length < 8 + textLen) return 0;
    var text = new TextDecoder("latin1").decode(recvBuf.subarray(8, 8 + textLen));
    try {
      navigator.clipboard.writeText(text);
    } catch (e) {
      console.debug("[VNC] Clipboard write failed:", e);
    }
    return 8 + textLen;
  }

  // ── VNC DES Authentication ───────────────────────────────────
  //
  // VNC uses a non-standard DES: each byte of the 8-byte key is
  // bit-reversed before encryption. The 16-byte challenge is
  // encrypted as two 8-byte DES-ECB blocks.
  //
  // This DES implementation is ported from noVNC (which itself is
  // ported from Flashlight VNC). The key schedule has VNC's
  // bit-reversal baked into its PC1 permutation, so raw password
  // bytes are passed directly — no external reverseBits() needed.

  function vncAuthResponse(challenge, password) {
    // Pad/truncate password to 8 bytes
    var rawKey = new Uint8Array(8);
    for (var i = 0; i < 8 && i < password.length; i++) {
      rawKey[i] = password.charCodeAt(i);
    }
    // noVNC DES handles VNC bit-reversal internally via PC1
    var keys = desKeySchedule(rawKey);
    var response = new Uint8Array(16);
    response.set(desEncryptBlock(keys, challenge.subarray(0, 8)), 0);
    response.set(desEncryptBlock(keys, challenge.subarray(8, 16)), 8);
    return response;
  }

  // ── DES Implementation (ported from noVNC) ─────────────────────
  //
  // Ported from noVNC (https://github.com/novnc/noVNC)
  // core/crypto/des.js — MPL-2.0 license
  //
  // Originally ported from Flashlight VNC ActionScript implementation:
  //   http://www.wizhelp.com/flashlight-vnc/
  //
  // DES class extracted from package Acme.Crypto for use in VNC.
  // Copyright (C) 1999 AT&T Laboratories Cambridge. All Rights Reserved.
  // DesCipher by Dave Zimmerman <dzimm@widget.com>
  // Copyright (c) 1996 Widget Workshop, Inc. All Rights Reserved.
  // Copyright (C) 1996 by Jef Poskanzer <jef@acme.com>. All rights reserved.
  //
  // SP-boxes combine S-box lookup + P permutation for speed.

  var PC2 = [13,16,10,23, 0, 4, 2,27,14, 5,20, 9,22,18,11, 3,
             25, 7,15, 6,26,19,12, 1,40,51,30,36,46,54,29,39,
             50,44,32,47,43,48,38,55,33,52,45,41,49,35,28,31];
  var TOTROT = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];

  var SP1=[0x01010400,0x00000000,0x00010000,0x01010404,0x01010004,0x00010404,0x00000004,0x00010000,0x00000400,0x01010400,0x01010404,0x00000400,0x01000404,0x01010004,0x01000000,0x00000004,0x00000404,0x01000400,0x01000400,0x00010400,0x00010400,0x01010000,0x01010000,0x01000404,0x00010004,0x01000004,0x01000004,0x00010004,0x00000000,0x00000404,0x00010404,0x01000000,0x00010000,0x01010404,0x00000004,0x01010000,0x01010400,0x01000000,0x01000000,0x00000400,0x01010004,0x00010000,0x00010400,0x01000004,0x00000400,0x00000004,0x01000404,0x00010404,0x01010404,0x00010004,0x01010000,0x01000404,0x01000004,0x00000404,0x00010404,0x01010400,0x00000404,0x01000400,0x01000400,0x00000000,0x00010004,0x00010400,0x00000000,0x01010004];
  var SP2=[0x80108020,0x80008000,0x00008000,0x00108020,0x00100000,0x00000020,0x80100020,0x80008020,0x80000020,0x80108020,0x80108000,0x80000000,0x80008000,0x00100000,0x00000020,0x80100020,0x00108000,0x00100020,0x80008020,0x00000000,0x80000000,0x00008000,0x00108020,0x80100000,0x00100020,0x80000020,0x00000000,0x00108000,0x00008020,0x80108000,0x80100000,0x00008020,0x00000000,0x00108020,0x80100020,0x00100000,0x80008020,0x80100000,0x80108000,0x00008000,0x80100000,0x80008000,0x00000020,0x80108020,0x00108020,0x00000020,0x00008000,0x80000000,0x00008020,0x80108000,0x00100000,0x80000020,0x00100020,0x80008020,0x80000020,0x00100020,0x00108000,0x00000000,0x80008000,0x00008020,0x80000000,0x80100020,0x80108020,0x00108000];
  var SP3=[0x00000208,0x08020200,0x00000000,0x08020008,0x08000200,0x00000000,0x00020208,0x08000200,0x00020008,0x08000008,0x08000008,0x00020000,0x08020208,0x00020008,0x08020000,0x00000208,0x08000000,0x00000008,0x08020200,0x00000200,0x00020200,0x08020000,0x08020008,0x00020208,0x08000208,0x00020200,0x00020000,0x08000208,0x00000008,0x08020208,0x00000200,0x08000000,0x08020200,0x08000000,0x00020008,0x00000208,0x00020000,0x08020200,0x08000200,0x00000000,0x00000200,0x00020008,0x08020208,0x08000200,0x08000008,0x00000200,0x00000000,0x08020008,0x08000208,0x00020000,0x08000000,0x08020208,0x00000008,0x00020208,0x00020200,0x08000008,0x08020000,0x08000208,0x00000208,0x08020000,0x00020208,0x00000008,0x08020008,0x00020200];
  var SP4=[0x00802001,0x00002081,0x00002081,0x00000080,0x00802080,0x00800081,0x00800001,0x00002001,0x00000000,0x00802000,0x00802000,0x00802081,0x00000081,0x00000000,0x00800080,0x00800001,0x00000001,0x00002000,0x00800000,0x00802001,0x00000080,0x00800000,0x00002001,0x00002080,0x00800081,0x00000001,0x00002080,0x00800080,0x00002000,0x00802080,0x00802081,0x00000081,0x00800080,0x00800001,0x00802000,0x00802081,0x00000081,0x00000000,0x00000000,0x00802000,0x00002080,0x00800080,0x00800081,0x00000001,0x00802001,0x00002081,0x00002081,0x00000080,0x00802081,0x00000081,0x00000001,0x00002000,0x00800001,0x00002001,0x00802080,0x00800081,0x00002001,0x00002080,0x00800000,0x00802001,0x00000080,0x00800000,0x00002000,0x00802080];
  var SP5=[0x00000100,0x02080100,0x02080000,0x42000100,0x00080000,0x00000100,0x40000000,0x02080000,0x40080100,0x00080000,0x02000100,0x40080100,0x42000100,0x42080000,0x00080100,0x40000000,0x02000000,0x40080000,0x40080000,0x00000000,0x40000100,0x42080100,0x42080100,0x02000100,0x42080000,0x40000100,0x00000000,0x42000000,0x02080100,0x02000000,0x42000000,0x00080100,0x00080000,0x42000100,0x00000100,0x02000000,0x40000000,0x02080000,0x42000100,0x40080100,0x02000100,0x40000000,0x42080000,0x02080100,0x40080100,0x00000100,0x02000000,0x42080000,0x42080100,0x00080100,0x42000000,0x42080100,0x02080000,0x00000000,0x40080000,0x42000000,0x00080100,0x02000100,0x40000100,0x00080000,0x00000000,0x40080000,0x02080100,0x40000100];
  var SP6=[0x20000010,0x20400000,0x00004000,0x20404010,0x20400000,0x00000010,0x20404010,0x00400000,0x20004000,0x00404010,0x00400000,0x20000010,0x00400010,0x20004000,0x20000000,0x00004010,0x00000000,0x00400010,0x20004010,0x00004000,0x00404000,0x20004010,0x00000010,0x20400010,0x20400010,0x00000000,0x00404010,0x20404000,0x00004010,0x00404000,0x20404000,0x20000000,0x20004000,0x00000010,0x20400010,0x00404000,0x20404010,0x00400000,0x00004010,0x20000010,0x00400000,0x20004000,0x20000000,0x00004010,0x20000010,0x20404010,0x00404000,0x20400000,0x00404010,0x20404000,0x00000000,0x20400010,0x00000010,0x00004000,0x20400000,0x00404010,0x00004000,0x00400010,0x20004010,0x00000000,0x20404000,0x20000000,0x00400010,0x20004010];
  var SP7=[0x00200000,0x04200002,0x04000802,0x00000000,0x00000800,0x04000802,0x00200802,0x04200800,0x04200802,0x00200000,0x00000000,0x04000002,0x00000002,0x04000000,0x04200002,0x00000802,0x04000800,0x00200802,0x00200002,0x04000800,0x04000002,0x04200000,0x04200800,0x00200002,0x04200000,0x00000800,0x00000802,0x04200802,0x00200800,0x00000002,0x04000000,0x00200800,0x04000000,0x00200800,0x00200000,0x04000802,0x04000802,0x04200002,0x04200002,0x00000002,0x00200002,0x04000000,0x04000800,0x00200000,0x04200800,0x00000802,0x00200802,0x04200800,0x00000802,0x04000002,0x04200802,0x04200000,0x00200800,0x00000000,0x00000002,0x04200802,0x00000000,0x00200802,0x04200000,0x00000800,0x04000002,0x04000800,0x00000800,0x00200002];
  var SP8=[0x10001040,0x00001000,0x00040000,0x10041040,0x10000000,0x10001040,0x00000040,0x10000000,0x00040040,0x10040000,0x10041040,0x00041000,0x10041000,0x00041040,0x00001000,0x00000040,0x10040000,0x10000040,0x10001000,0x00001040,0x00041000,0x00040040,0x10040040,0x10041000,0x00001040,0x00000000,0x00000000,0x10040040,0x10000040,0x10001000,0x00041040,0x00040000,0x00041040,0x00040000,0x10041000,0x00001000,0x00000040,0x10040040,0x00001000,0x00041040,0x10001000,0x00000040,0x10000040,0x10040000,0x10040040,0x10000000,0x00040000,0x10001040,0x00000000,0x10041040,0x00040040,0x10000040,0x10040000,0x10001000,0x10001040,0x00000000,0x10041040,0x00041000,0x00041000,0x00001040,0x00001040,0x00040040,0x10000000,0x10041000];

  /** Generate 32-entry key schedule from 8-byte password (VNC bit-reversal is built into PC1) */
  function desKeySchedule(password) {
    var pc1m = new Array(56);
    var pcr = new Array(56);
    var kn = new Array(32);
    var keys = new Array(32);
    var j, l, m, n, o, i;

    // PC1 permutation (with VNC bit-reversal baked in)
    for (j = 0, l = 56; j < 56; ++j, l -= 8) {
      l += l < -5 ? 65 : l < -3 ? 31 : l < -1 ? 63 : l === 27 ? 35 : 0;
      m = l & 0x7;
      pc1m[j] = ((password[l >>> 3] & (1 << m)) !== 0) ? 1 : 0;
    }

    for (i = 0; i < 16; ++i) {
      m = i << 1;
      n = m + 1;
      kn[m] = kn[n] = 0;
      for (o = 28; o < 59; o += 28) {
        for (j = o - 28; j < o; ++j) {
          l = j + TOTROT[i];
          pcr[j] = l < o ? pc1m[l] : pc1m[l - 28];
        }
      }
      for (j = 0; j < 24; ++j) {
        if (pcr[PC2[j]] !== 0) { kn[m] |= 1 << (23 - j); }
        if (pcr[PC2[j + 24]] !== 0) { kn[n] |= 1 << (23 - j); }
      }
    }

    // cookey: cook the raw key schedule into the format the cipher uses
    for (i = 0; i < 32; i += 2) {
      var raw0 = kn[i];
      var raw1 = kn[i + 1];
      keys[i] = (raw0 & 0x00fc0000) << 6;
      keys[i] |= (raw0 & 0x00000fc0) << 10;
      keys[i] |= (raw1 & 0x00fc0000) >>> 10;
      keys[i] |= (raw1 & 0x00000fc0) >>> 6;
      keys[i + 1] = (raw0 & 0x0003f000) << 12;
      keys[i + 1] |= (raw0 & 0x0000003f) << 16;
      keys[i + 1] |= (raw1 & 0x0003f000) >>> 4;
      keys[i + 1] |= (raw1 & 0x0000003f);
    }
    return keys;
  }

  /** Encrypt 8 bytes using precomputed key schedule */
  function desEncryptBlock(keys, blockBytes) {
    var b = new Uint8Array(blockBytes);
    var l, r, x, i;

    // Squash 8 bytes to 2 ints
    l = b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3];
    r = b[4] << 24 | b[5] << 16 | b[6] << 8 | b[7];

    // Initial permutation
    x = ((l >>> 4) ^ r) & 0x0f0f0f0f; r ^= x; l ^= (x << 4);
    x = ((l >>> 16) ^ r) & 0x0000ffff; r ^= x; l ^= (x << 16);
    x = ((r >>> 2) ^ l) & 0x33333333; l ^= x; r ^= (x << 2);
    x = ((r >>> 8) ^ l) & 0x00ff00ff; l ^= x; r ^= (x << 8);
    r = (r << 1) | ((r >>> 31) & 1);
    x = (l ^ r) & 0xaaaaaaaa; l ^= x; r ^= x;
    l = (l << 1) | ((l >>> 31) & 1);

    // 16 rounds (8 iterations of 2 rounds each)
    for (i = 0; i < 32; i += 4) {
      x = (r << 28) | (r >>> 4);
      x ^= keys[i];
      var fval = SP7[x & 0x3f];
      fval |= SP5[(x >>> 8) & 0x3f];
      fval |= SP3[(x >>> 16) & 0x3f];
      fval |= SP1[(x >>> 24) & 0x3f];
      x = r ^ keys[i + 1];
      fval |= SP8[x & 0x3f];
      fval |= SP6[(x >>> 8) & 0x3f];
      fval |= SP4[(x >>> 16) & 0x3f];
      fval |= SP2[(x >>> 24) & 0x3f];
      l ^= fval;
      x = (l << 28) | (l >>> 4);
      x ^= keys[i + 2];
      fval = SP7[x & 0x3f];
      fval |= SP5[(x >>> 8) & 0x3f];
      fval |= SP3[(x >>> 16) & 0x3f];
      fval |= SP1[(x >>> 24) & 0x3f];
      x = l ^ keys[i + 3];
      fval |= SP8[x & 0x3f];
      fval |= SP6[(x >>> 8) & 0x3f];
      fval |= SP4[(x >>> 16) & 0x3f];
      fval |= SP2[(x >>> 24) & 0x3f];
      r ^= fval;
    }

    // Final permutation (inverse of IP)
    r = (r << 31) | (r >>> 1);
    x = (l ^ r) & 0xaaaaaaaa; l ^= x; r ^= x;
    l = (l << 31) | (l >>> 1);
    x = ((l >>> 8) ^ r) & 0x00ff00ff; r ^= x; l ^= (x << 8);
    x = ((l >>> 2) ^ r) & 0x33333333; r ^= x; l ^= (x << 2);
    x = ((r >>> 16) ^ l) & 0x0000ffff; l ^= x; r ^= (x << 16);
    x = ((r >>> 4) ^ l) & 0x0f0f0f0f; l ^= x; r ^= (x << 4);

    // Spread ints to bytes
    var out = new Uint8Array(8);
    var rl = [r, l];
    for (i = 0; i < 8; i++) {
      out[i] = (rl[i >>> 2] >>> (8 * (3 - (i % 4)))) & 0xff;
    }
    return out;
  }

  // ── Canvas Setup ──────────────────────────────────────────────

  function setupCanvas() {
    console.log("[VNC] setupCanvas:", fbWidth, "x", fbHeight);
    vncCanvas.width = fbWidth;
    vncCanvas.height = fbHeight;
    ctx = vncCanvas.getContext("2d");
    imageData = ctx.createImageData(fbWidth, fbHeight);
    imageData32 = new Uint32Array(imageData.data.buffer);
    // Initialize all pixels to opaque black (0xFF000000 on little-endian = RGBA(0,0,0,255))
    imageData32.fill(0xFF000000);
    applyScaleMode();
  }

  function applyScaleMode() {
    var mode = scaleSelect ? scaleSelect.value : "fit";
    if (mode === "fit") {
      // Scale to fit viewport while preserving aspect ratio
      var winW = window.innerWidth;
      var winH = window.innerHeight;
      var scale = Math.min(winW / fbWidth, winH / fbHeight);
      vncCanvas.style.width = Math.floor(fbWidth * scale) + "px";
      vncCanvas.style.height = Math.floor(fbHeight * scale) + "px";
    } else if (mode === "stretch") {
      vncCanvas.style.width = window.innerWidth + "px";
      vncCanvas.style.height = window.innerHeight + "px";
    } else {
      // actual — 1:1 pixels
      vncCanvas.style.width = fbWidth + "px";
      vncCanvas.style.height = fbHeight + "px";
    }
  }

  window.addEventListener("resize", function () {
    if (fbWidth > 0 && fbHeight > 0) applyScaleMode();
  });

  // ── Input Handling ────────────────────────────────────────────

  function setupInputHandlers() {
    vncCanvas.addEventListener("mousemove", function (e) {
      if (rfbState !== RFB_CONNECTED) return;
      var pos = canvasPos(e);
      sendPointerEvent(pos.x, pos.y, buttonMask);
    });

    vncCanvas.addEventListener("mousedown", function (e) {
      if (rfbState !== RFB_CONNECTED) return;
      e.preventDefault();
      buttonMask |= (1 << e.button);
      var pos = canvasPos(e);
      sendPointerEvent(pos.x, pos.y, buttonMask);
    });

    vncCanvas.addEventListener("mouseup", function (e) {
      if (rfbState !== RFB_CONNECTED) return;
      buttonMask &= ~(1 << e.button);
      var pos = canvasPos(e);
      sendPointerEvent(pos.x, pos.y, buttonMask);
    });

    vncCanvas.addEventListener("wheel", function (e) {
      if (rfbState !== RFB_CONNECTED) return;
      e.preventDefault();
      var pos = canvasPos(e);
      // Scroll up = button 4, scroll down = button 5
      var btn = e.deltaY < 0 ? 8 : 16; // bit 3 = button 4, bit 4 = button 5
      sendPointerEvent(pos.x, pos.y, buttonMask | btn);
      sendPointerEvent(pos.x, pos.y, buttonMask); // release
    }, { passive: false });

    vncCanvas.addEventListener("contextmenu", function (e) {
      e.preventDefault();
    });

    document.addEventListener("keydown", function (e) {
      if (rfbState !== RFB_CONNECTED || !connectForm.classList.contains("hidden")) return;
      e.preventDefault();
      var keysym = keyToKeysym(e);
      if (keysym) sendKeyEvent(keysym, true);
    });

    document.addEventListener("keyup", function (e) {
      if (rfbState !== RFB_CONNECTED || !connectForm.classList.contains("hidden")) return;
      e.preventDefault();
      var keysym = keyToKeysym(e);
      if (keysym) sendKeyEvent(keysym, false);
    });
  }

  function canvasPos(e) {
    var rect = vncCanvas.getBoundingClientRect();
    var scaleX = fbWidth / rect.width;
    var scaleY = fbHeight / rect.height;
    return {
      x: Math.max(0, Math.min(fbWidth - 1, Math.round((e.clientX - rect.left) * scaleX))),
      y: Math.max(0, Math.min(fbHeight - 1, Math.round((e.clientY - rect.top) * scaleY))),
    };
  }

  function sendPointerEvent(x, y, mask) {
    var msg = new Uint8Array(6);
    msg[0] = 5; // PointerEvent
    msg[1] = mask & 0xFF;
    msg[2] = (x >> 8) & 0xFF; msg[3] = x & 0xFF;
    msg[4] = (y >> 8) & 0xFF; msg[5] = y & 0xFF;
    sendTcpData(msg);
  }

  function sendKeyEvent(keysym, down) {
    var msg = new Uint8Array(8);
    msg[0] = 4; // KeyEvent
    msg[1] = down ? 1 : 0;
    // [2..3] padding
    msg[4] = (keysym >> 24) & 0xFF;
    msg[5] = (keysym >> 16) & 0xFF;
    msg[6] = (keysym >> 8) & 0xFF;
    msg[7] = keysym & 0xFF;
    sendTcpData(msg);
  }

  // ── Key → X11 Keysym Mapping ──────────────────────────────────

  var SPECIAL_KEYSYMS = {
    Backspace: 0xFF08, Tab: 0xFF09, Enter: 0xFF0D, Escape: 0xFF1B,
    Delete: 0xFFFF, Home: 0xFF50, End: 0xFF57, PageUp: 0xFF55,
    PageDown: 0xFF56, ArrowLeft: 0xFF51, ArrowUp: 0xFF52,
    ArrowRight: 0xFF53, ArrowDown: 0xFF54, Insert: 0xFF63,
    F1: 0xFFBE, F2: 0xFFBF, F3: 0xFFC0, F4: 0xFFC1,
    F5: 0xFFC2, F6: 0xFFC3, F7: 0xFFC4, F8: 0xFFC5,
    F9: 0xFFC6, F10: 0xFFC7, F11: 0xFFC8, F12: 0xFFC9,
    ShiftLeft: 0xFFE1, ShiftRight: 0xFFE2,
    ControlLeft: 0xFFE3, ControlRight: 0xFFE4,
    AltLeft: 0xFFE9, AltRight: 0xFFEA,
    MetaLeft: 0xFFEB, MetaRight: 0xFFEC,
    CapsLock: 0xFFE5, NumLock: 0xFF7F, ScrollLock: 0xFF14,
    PrintScreen: 0xFF61, Pause: 0xFF13, ContextMenu: 0xFF67,
    NumpadEnter: 0xFF8D, NumpadMultiply: 0xFFAA, NumpadAdd: 0xFFAB,
    NumpadSubtract: 0xFFAD, NumpadDecimal: 0xFFAE, NumpadDivide: 0xFFAF,
    Numpad0: 0xFFB0, Numpad1: 0xFFB1, Numpad2: 0xFFB2, Numpad3: 0xFFB3,
    Numpad4: 0xFFB4, Numpad5: 0xFFB5, Numpad6: 0xFFB6, Numpad7: 0xFFB7,
    Numpad8: 0xFFB8, Numpad9: 0xFFB9, Space: 0x0020,
  };

  function keyToKeysym(e) {
    // Check special keys by code first
    if (SPECIAL_KEYSYMS[e.code]) return SPECIAL_KEYSYMS[e.code];

    // For printable characters, use the key value
    if (e.key && e.key.length === 1) {
      var code = e.key.charCodeAt(0);
      // Latin-1 characters map directly to X11 keysyms
      if (code >= 0x20 && code <= 0xFF) return code;
      // Unicode beyond Latin-1: use Unicode keysym range (0x01000000 + codepoint)
      if (code > 0xFF) return 0x01000000 | code;
    }

    console.debug("[VNC] Unmapped key:", e.code, e.key);
    return 0;
  }

  // ── UI ────────────────────────────────────────────────────────

  function setStatus(state, text) {
    statusDot.className = "dot " + state;
    statusText.textContent = text;
    statusBar.classList.remove("connected");
  }

  function showConnectForm() {
    connectForm.classList.remove("hidden");
    vncCanvas.classList.add("hidden");
    connectBtn.disabled = false;
    formError.textContent = "";
  }

  function hideConnectForm() {
    connectForm.classList.add("hidden");
    vncCanvas.classList.remove("hidden");
  }

  // ── Connect / Disconnect ──────────────────────────────────────

  function startVncSession(password) {
    hideConnectForm();
    setStatus("connecting", "Opening TCP tunnel to " + backendName + "...");

    vncPassword = password || "";
    tunnelId = crypto.randomUUID();
    tunnelOpen = false;
    rfbState = RFB_VERSION;
    recvBuf = new Uint8Array(0);
    fbUpdateRemaining = 0;
    fbUpdateRect = null;
    fbUpdatePixelsLeft = 0;
    fbUpdateBusy = false;
    buttonMask = 0;

    controlChannel.send(JSON.stringify({
      type: "tcp_open",
      id: tunnelId,
      backend: backendName,
    }));
  }

  function disconnectVnc(reason) {
    if (updateTimer) {
      clearInterval(updateTimer);
      updateTimer = null;
    }

    if (tunnelId && controlChannel && controlChannel.readyState === "open") {
      try {
        controlChannel.send(JSON.stringify({ type: "tcp_close", id: tunnelId }));
      } catch (e) {}
    }

    tunnelOpen = false;
    tunnelId = null;
    rfbState = RFB_VERSION;
    recvBuf = new Uint8Array(0);
    ctx = null;
    imageData = null;
    imageData32 = null;

    setStatus("error", reason || "Disconnected");
    showConnectForm();
  }

  // ── Cleanup / Reconnect ───────────────────────────────────────

  function cleanup() {
    if (updateTimer) {
      clearInterval(updateTimer);
      updateTimer = null;
    }
    tunnelOpen = false;
    tunnelId = null;
    rfbState = RFB_VERSION;
    recvBuf = new Uint8Array(0);
    ctx = null;
    imageData = null;
    imageData32 = null;

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
    console.log("[VNC] Reconnecting in " + Math.round(delay / 1000) + "s...");
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
    clientId = "vnc-" + crypto.randomUUID().replace(/-/g, "").slice(0, 8);
    await fetchSessionToken();
  }

  // ── Event Handlers ────────────────────────────────────────────

  connectBtn.addEventListener("click", function () {
    var password = passwordInput.value;
    connectBtn.disabled = true;
    formError.textContent = "";
    startVncSession(password);
  });

  passwordInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter") connectBtn.click();
  });

  disconnectBtn.addEventListener("click", function () {
    disconnectVnc("Disconnected by user");
  });

  if (scaleSelect) {
    scaleSelect.addEventListener("change", function () {
      if (fbWidth > 0 && fbHeight > 0) applyScaleMode();
    });
  }

  // ── Start ─────────────────────────────────────────────────────

  init();
})();
