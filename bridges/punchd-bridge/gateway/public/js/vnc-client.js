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
  var FRAMEBUFFER_UPDATE_INTERVAL = 50; // ms between incremental update requests

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
  var updateTimer = null;
  var buttonMask = 0;

  // Framebuffer update parsing state
  var fbUpdateRemaining = 0;
  var fbUpdateRect = null;
  var fbUpdatePixelsLeft = 0;

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

  function onTcpData(data) {
    // Append to receive buffer
    var newBuf = new Uint8Array(recvBuf.length + data.length);
    newBuf.set(recvBuf);
    newBuf.set(data, recvBuf.length);
    recvBuf = newBuf;

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
    var challenge = recvBuf.subarray(0, 16);
    console.log("[VNC] Got VNC auth challenge");
    var response = vncAuthResponse(challenge, vncPassword);
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

    console.log("[VNC] ServerInit:", fbWidth, "x", fbHeight, "name:", serverName);

    // Set up canvas
    setupCanvas();

    // Send SetPixelFormat — request 32-bit RGBX TrueColor
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
    spf[14] = 0;  // r-shift = 0
    spf[15] = 8;  // g-shift = 8
    spf[16] = 16; // b-shift = 16
    // [17..19] padding
    sendTcpData(spf);

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
    requestFramebufferUpdate(false);

    // Set up input handlers
    setupInputHandlers();

    // Start incremental update loop
    updateTimer = setInterval(function () {
      if (rfbState === RFB_CONNECTED) {
        requestFramebufferUpdate(true);
      }
    }, FRAMEBUFFER_UPDATE_INTERVAL);

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
      case 0: return handleFbUpdate();
      case 1: return handleSetColourMap();
      case 2: return handleBell();
      case 3: return handleServerCutText();
      default:
        console.warn("[VNC] Unknown server message type:", msgType);
        disconnectVnc("Unknown server message: " + msgType);
        return 0;
    }
  }

  function handleFbUpdate() {
    // FramebufferUpdate: [0][pad:1][numRects:u16]
    if (recvBuf.length < 4) return 0;
    fbUpdateRemaining = (recvBuf[2] << 8) | recvBuf[3];
    fbUpdateRect = null;
    fbUpdatePixelsLeft = 0;
    return 4;
  }

  function handleFbUpdateRect() {
    // Parse rectangle header if we haven't yet
    if (!fbUpdateRect) {
      if (recvBuf.length < 12) return 0;
      fbUpdateRect = {
        x: (recvBuf[0] << 8) | recvBuf[1],
        y: (recvBuf[2] << 8) | recvBuf[3],
        w: (recvBuf[4] << 8) | recvBuf[5],
        h: (recvBuf[6] << 8) | recvBuf[7],
        encoding: (recvBuf[8] << 24) | (recvBuf[9] << 16) | (recvBuf[10] << 8) | recvBuf[11],
      };

      // Handle pseudo-encodings
      if (fbUpdateRect.encoding === -223 || fbUpdateRect.encoding === (0xFFFFFF21 | 0)) {
        // DesktopSize pseudo-encoding — server resized
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

      if (fbUpdateRect.encoding === 1) {
        // CopyRect: [srcX:u16][srcY:u16]
        if (recvBuf.length < 16) return 0;
        var srcX = (recvBuf[12] << 8) | recvBuf[13];
        var srcY = (recvBuf[14] << 8) | recvBuf[15];
        if (ctx && fbUpdateRect.w > 0 && fbUpdateRect.h > 0) {
          ctx.drawImage(vncCanvas, srcX, srcY, fbUpdateRect.w, fbUpdateRect.h,
            fbUpdateRect.x, fbUpdateRect.y, fbUpdateRect.w, fbUpdateRect.h);
        }
        fbUpdateRect = null;
        fbUpdateRemaining--;
        return 16;
      }

      if (fbUpdateRect.encoding !== 0) {
        console.warn("[VNC] Unsupported encoding:", fbUpdateRect.encoding);
        disconnectVnc("Unsupported encoding: " + fbUpdateRect.encoding);
        return 0;
      }

      // Raw encoding — need w*h*4 bytes of pixel data
      fbUpdatePixelsLeft = fbUpdateRect.w * fbUpdateRect.h * 4;
      return 12;
    }

    // Raw encoding: consume pixel data
    if (fbUpdatePixelsLeft > 0) {
      var available = Math.min(recvBuf.length, fbUpdatePixelsLeft);
      if (available <= 0) return 0;

      // Write pixels to canvas ImageData
      if (imageData && ctx) {
        var rect = fbUpdateRect;
        var pixelsDone = (rect.w * rect.h * 4) - fbUpdatePixelsLeft;
        var startRow = Math.floor(pixelsDone / (rect.w * 4));
        var startCol = (pixelsDone % (rect.w * 4));

        // Copy pixel data into imageData
        var imgPixels = imageData.data;
        var srcOff = 0;
        var dstRow = startRow;
        var dstCol = startCol;

        while (srcOff < available) {
          // Calculate position in imageData
          var imgY = rect.y + dstRow;
          var imgX = rect.x + Math.floor(dstCol / 4);
          var imgOff = (imgY * fbWidth + imgX) * 4;
          var component = dstCol % 4;

          // How many bytes until end of this row in the rect?
          var rowRemaining = rect.w * 4 - dstCol;
          var toCopy = Math.min(available - srcOff, rowRemaining);

          // Bulk copy this chunk of the row
          for (var i = 0; i < toCopy; i++) {
            var c = (component + i) % 4;
            var pixel = Math.floor((dstCol + i) / 4);
            var destOff = ((rect.y + dstRow) * fbWidth + rect.x + pixel) * 4;
            if (c === 0) imgPixels[destOff] = recvBuf[srcOff + i];     // R
            else if (c === 1) imgPixels[destOff + 1] = recvBuf[srcOff + i]; // G
            else if (c === 2) imgPixels[destOff + 2] = recvBuf[srcOff + i]; // B
            else imgPixels[destOff + 3] = 255; // A (ignore server's padding byte, force opaque)
          }

          srcOff += toCopy;
          dstCol += toCopy;
          if (dstCol >= rect.w * 4) {
            dstCol = 0;
            dstRow++;
          }
        }

        fbUpdatePixelsLeft -= available;

        // When this rect is complete, paint it
        if (fbUpdatePixelsLeft <= 0) {
          ctx.putImageData(imageData, 0, 0, rect.x, rect.y, rect.w, rect.h);
          fbUpdateRect = null;
          fbUpdateRemaining--;
        }
      } else {
        // No canvas — just skip pixel data
        fbUpdatePixelsLeft -= available;
        if (fbUpdatePixelsLeft <= 0) {
          fbUpdateRect = null;
          fbUpdateRemaining--;
        }
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

  // ── VNC DES Authentication ────────────────────────────────────
  //
  // VNC uses a non-standard DES: each byte of the 8-byte key is
  // bit-reversed before encryption. We implement minimal single-block
  // DES (only encrypt, no CBC/padding needed — challenge is exactly 16 bytes
  // encrypted as two 8-byte blocks).

  function vncAuthResponse(challenge, password) {
    // Pad/truncate password to 8 bytes
    var key = new Uint8Array(8);
    for (var i = 0; i < 8 && i < password.length; i++) {
      key[i] = password.charCodeAt(i);
    }
    // Bit-reverse each byte (VNC's non-standard DES key schedule)
    for (var i = 0; i < 8; i++) {
      key[i] = reverseBits(key[i]);
    }

    // Encrypt two 8-byte blocks
    var response = new Uint8Array(16);
    var block1 = desEncrypt(key, challenge.subarray(0, 8));
    var block2 = desEncrypt(key, challenge.subarray(8, 16));
    response.set(block1, 0);
    response.set(block2, 8);
    return response;
  }

  function reverseBits(b) {
    var r = 0;
    for (var i = 0; i < 8; i++) {
      r = (r << 1) | (b & 1);
      b >>= 1;
    }
    return r;
  }

  // ── Minimal DES Implementation ────────────────────────────────
  // Single-block DES encrypt only (no decrypt, no modes).

  // Initial Permutation
  var IP = [
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,  59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
  ];

  // Final Permutation (IP inverse)
  var FP = [
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25
  ];

  // Expansion
  var E = [
    32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25, 24,25,26,27,28,29, 28,29,30,31,32,1
  ];

  // Permutation
  var P = [
    16,7,20,21,29,12,28,17, 1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9, 19,13,30,6,22,11,4,25
  ];

  // S-boxes
  var S = [
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8, 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5, 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1, 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9, 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6, 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8, 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6, 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,2,0,14,9,11, 7,0,1,13,11,4,14,8,6,2,10,15,3,9,12,5, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
  ];

  // PC-1 (key schedule)
  var PC1 = [
    57,49,41,33,25,17,9, 1,58,50,42,34,26,18,
    10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14,6,61,53,45,37,29, 21,13,5,28,20,12,4
  ];

  // PC-2
  var PC2 = [
    14,17,11,24,1,5, 3,28,15,6,21,10,
    23,19,12,4,26,8, 16,7,27,20,13,2,
    41,52,31,37,47,55, 30,40,51,45,33,48,
    44,49,39,56,34,53, 46,42,50,36,29,32
  ];

  var SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

  function getBit(data, bitPos) {
    var byteIdx = (bitPos - 1) >> 3;
    var bitIdx = 7 - ((bitPos - 1) & 7);
    return (data[byteIdx] >> bitIdx) & 1;
  }

  function setBit(data, bitPos, val) {
    var byteIdx = (bitPos - 1) >> 3;
    var bitIdx = 7 - ((bitPos - 1) & 7);
    if (val) data[byteIdx] |= (1 << bitIdx);
    else data[byteIdx] &= ~(1 << bitIdx);
  }

  function permute(input, table, outBits) {
    var out = new Uint8Array(Math.ceil(outBits / 8));
    for (var i = 0; i < table.length; i++) {
      setBit(out, i + 1, getBit(input, table[i]));
    }
    return out;
  }

  function leftShift28(half, count) {
    // half is stored in 4 bytes, but only bits 1-28 matter
    var val = ((half[0] << 20) | (half[1] << 12) | (half[2] << 4) | (half[3] >> 4)) & 0x0FFFFFFF;
    val = ((val << count) | (val >>> (28 - count))) & 0x0FFFFFFF;
    half[0] = (val >> 20) & 0xFF;
    half[1] = (val >> 12) & 0xFF;
    half[2] = (val >> 4) & 0xFF;
    half[3] = ((val & 0xF) << 4);
  }

  function xorBytes(a, b, len) {
    var out = new Uint8Array(len);
    for (var i = 0; i < len; i++) out[i] = a[i] ^ b[i];
    return out;
  }

  function desEncrypt(key, block) {
    // Generate 16 subkeys
    var cd = permute(key, PC1, 56);
    var c = new Uint8Array(4);
    var d = new Uint8Array(4);
    // C = bits 1-28, D = bits 29-56
    c[0] = cd[0]; c[1] = cd[1]; c[2] = cd[2]; c[3] = cd[3] & 0xF0;
    d[0] = ((cd[3] & 0x0F) << 4) | (cd[4] >> 4);
    d[1] = ((cd[4] & 0x0F) << 4) | (cd[5] >> 4);
    d[2] = ((cd[5] & 0x0F) << 4) | (cd[6] >> 4);
    d[3] = ((cd[6] & 0x0F) << 4);

    var subkeys = [];
    for (var round = 0; round < 16; round++) {
      leftShift28(c, SHIFTS[round]);
      leftShift28(d, SHIFTS[round]);
      // Combine C and D
      var combined = new Uint8Array(7);
      combined[0] = c[0]; combined[1] = c[1]; combined[2] = c[2];
      combined[3] = (c[3] & 0xF0) | ((d[0] >> 4) & 0x0F);
      combined[4] = ((d[0] & 0x0F) << 4) | ((d[1] >> 4) & 0x0F);
      combined[5] = ((d[1] & 0x0F) << 4) | ((d[2] >> 4) & 0x0F);
      combined[6] = ((d[2] & 0x0F) << 4) | ((d[3] >> 4) & 0x0F);
      subkeys.push(permute(combined, PC2, 48));
    }

    // Initial permutation
    var data = permute(block, IP, 64);

    // Split into L and R (each 32 bits = 4 bytes)
    var L = data.subarray(0, 4).slice();
    var R = data.subarray(4, 8).slice();

    // 16 rounds
    for (var round = 0; round < 16; round++) {
      var expanded = permute(R, E, 48);
      var xored = xorBytes(expanded, subkeys[round], 6);

      // S-box substitution
      var sOut = new Uint8Array(4);
      for (var s = 0; s < 8; s++) {
        var bitOff = s * 6;
        var b0 = (xored[bitOff >> 3] >> (7 - (bitOff & 7))) & 1;
        var b1 = (xored[(bitOff+1) >> 3] >> (7 - ((bitOff+1) & 7))) & 1;
        var b2 = (xored[(bitOff+2) >> 3] >> (7 - ((bitOff+2) & 7))) & 1;
        var b3 = (xored[(bitOff+3) >> 3] >> (7 - ((bitOff+3) & 7))) & 1;
        var b4 = (xored[(bitOff+4) >> 3] >> (7 - ((bitOff+4) & 7))) & 1;
        var b5 = (xored[(bitOff+5) >> 3] >> (7 - ((bitOff+5) & 7))) & 1;
        var row = (b0 << 1) | b5;
        var col = (b1 << 3) | (b2 << 2) | (b3 << 1) | b4;
        var val = S[s][row * 16 + col];
        // Pack 4-bit value into sOut
        var outBit = s * 4;
        for (var bi = 0; bi < 4; bi++) {
          setBit(sOut, outBit + bi + 1, (val >> (3 - bi)) & 1);
        }
      }

      var pOut = permute(sOut, P, 32);
      var newR = xorBytes(L, pOut, 4);
      L = R;
      R = newR;
    }

    // Combine R + L (note: reversed) and apply final permutation
    var preOutput = new Uint8Array(8);
    preOutput.set(R, 0);
    preOutput.set(L, 4);
    return permute(preOutput, FP, 64);
  }

  // ── Canvas Setup ──────────────────────────────────────────────

  function setupCanvas() {
    vncCanvas.width = fbWidth;
    vncCanvas.height = fbHeight;
    ctx = vncCanvas.getContext("2d");
    imageData = ctx.createImageData(fbWidth, fbHeight);
    // Initialize alpha to 255 (fully opaque)
    var data = imageData.data;
    for (var i = 3; i < data.length; i += 4) {
      data[i] = 255;
    }
    applyScaleMode();
  }

  function applyScaleMode() {
    var mode = scaleSelect ? scaleSelect.value : "fit";
    if (mode === "fit") {
      vncCanvas.style.width = "100vw";
      vncCanvas.style.height = "100vh";
      vncCanvas.style.objectFit = "contain";
    } else if (mode === "stretch") {
      vncCanvas.style.width = "100vw";
      vncCanvas.style.height = "100vh";
      vncCanvas.style.objectFit = "fill";
    } else {
      // actual — 1:1 pixels
      vncCanvas.style.width = fbWidth + "px";
      vncCanvas.style.height = fbHeight + "px";
      vncCanvas.style.objectFit = "";
    }
  }

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
