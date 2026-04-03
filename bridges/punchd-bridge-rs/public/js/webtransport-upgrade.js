/**
 * WebTransport upgrade script — QUIC-based replacement for WebRTC DataChannels.
 *
 * After the page loads (via HTTP relay), this script attempts to establish
 * a direct WebTransport connection to the gateway via QUIC. If successful,
 * it registers a Service Worker that routes subsequent HTTP requests through
 * the QUIC streams for lower latency.
 *
 * Falls back to WebRTC DataChannel (webrtc-upgrade.js) if WebTransport
 * is not supported (Safari) or if the connection fails.
 */

(function () {
  "use strict";

  // Check WebTransport support — fall back to WebRTC if not available
  if (typeof WebTransport === "undefined") {
    console.log("[QUIC] WebTransport not supported — using WebRTC fallback");
    return; // webrtc-upgrade.js handles it
  }

  const BACKEND_PREFIX = (function () {
    const m = location.pathname.match(/^\/__b\/[^/]+/);
    return m ? m[0] : "";
  })();
  const CONFIG_ENDPOINT = BACKEND_PREFIX + "/webrtc-config";
  const NativeWebSocket = window.WebSocket;
  const RECONNECT_DELAY = 5000;
  const MAX_RECONNECT_DELAY = 60000;

  let config = null;
  let signalingWs = null;
  let transport = null;
  let clientId = "qt-" + Math.random().toString(36).slice(2, 10);
  let pairedGatewayId = null;
  let sessionToken = null;
  let reconnectAttempts = 0;
  let reconnectTimer = null;
  let controlWriter = null;
  let controlReader = null;

  // Stream type bytes (must match gateway's quic::transport::stream_type)
  const STREAM_AUTH = 0x01;
  const STREAM_HTTP = 0x02;
  const STREAM_WEBSOCKET = 0x03;

  // ── Initialization ─────────────────────────────────────────────

  async function init() {
    try {
      const res = await fetch(CONFIG_ENDPOINT);
      if (!res.ok) return;
      config = await res.json();
      console.log("[QUIC] Config loaded:", config);
    } catch (e) {
      console.warn("[QUIC] Failed to load config:", e);
      return;
    }

    await fetchSessionToken();
    if (!sessionToken || !config?.signalingUrl) return;

    connectSignaling();
  }

  async function fetchSessionToken() {
    try {
      const res = await fetch(BACKEND_PREFIX + "/auth/session-token", {
        headers: { "X-Requested-With": "XMLHttpRequest" },
      });
      if (res.ok) {
        const data = await res.json();
        sessionToken = data.token || data.access_token;
      }
    } catch {}
  }

  // ── Signaling ──────────────────────────────────────────────────

  function connectSignaling() {
    if (!config?.signalingUrl) return;

    console.log("[QUIC] Connecting to signaling:", config.signalingUrl);
    signalingWs = new NativeWebSocket(config.signalingUrl);

    signalingWs.onopen = () => {
      console.log("[QUIC] Signaling connected");
      const msg = {
        type: "register",
        role: "client",
        id: clientId,
        token: sessionToken,
      };
      if (config.targetGatewayId) {
        msg.targetGatewayId = config.targetGatewayId;
      }
      signalingWs.send(JSON.stringify(msg));
    };

    signalingWs.onmessage = (event) => {
      try {
        handleSignalingMessage(JSON.parse(event.data));
      } catch {}
    };

    signalingWs.onclose = () => {
      console.log("[QUIC] Signaling disconnected");
      cleanup();
      scheduleReconnect();
    };

    signalingWs.onerror = () => {
      console.log("[QUIC] Signaling error");
    };
  }

  function handleSignalingMessage(msg) {
    switch (msg.type) {
      case "registered":
        console.log("[QUIC] Registered:", msg.id);
        break;

      case "paired":
        pairedGatewayId = msg.gateway?.id;
        console.log("[QUIC] Paired with gateway:", pairedGatewayId);
        // Send our address (not needed for WebTransport — we connect to gateway)
        break;

      case "quic_address":
        // Gateway sent its QUIC address + cert hash
        if (msg.address && msg.certHash) {
          console.log("[QUIC] Gateway QUIC address:", msg.address, "cert:", msg.certHash.slice(0, 16) + "...");
          connectWebTransport(msg.address, msg.certHash);
        } else if (msg.address) {
          console.log("[QUIC] Gateway QUIC address:", msg.address, "(no cert hash — trying direct)");
          connectWebTransport(msg.address, null);
        }
        break;

      case "error":
        console.error("[QUIC] Signaling error:", msg.message);
        break;
    }
  }

  // ── WebTransport Connection ────────────────────────────────────

  async function connectWebTransport(address, certHash) {
    cleanup();

    // Build URL — WebTransport needs https://
    const url = "https://" + address;
    console.log("[QUIC] Connecting WebTransport to", url);

    const options = {};
    if (certHash) {
      // Pin the self-signed cert hash so browser accepts it
      const hashBytes = hexToBytes(certHash);
      options.serverCertificateHashes = [{
        algorithm: "sha-256",
        value: hashBytes.buffer,
      }];
    }

    try {
      transport = new WebTransport(url, options);
      await transport.ready;
      console.log("[QUIC] WebTransport connected!");
      reconnectAttempts = 0;

      // Authenticate — open first bidi stream with JWT
      await authenticate();

      // Set up HTTP/WS tunneling
      acceptStreams();

      // Install WebSocket shim + Service Worker (same as WebRTC version)
      installWebSocketShim();

    } catch (e) {
      console.error("[QUIC] WebTransport failed:", e);
      console.log("[QUIC] Falling back to WebRTC...");
      // Let webrtc-upgrade.js handle it on next page load
      cleanup();
    }
  }

  async function authenticate() {
    const stream = await transport.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();

    // [type=AUTH][token_len:u16][token_bytes]
    const tokenBytes = new TextEncoder().encode(sessionToken);
    const header = new Uint8Array(1 + 2 + tokenBytes.length);
    header[0] = STREAM_AUTH;
    header[1] = (tokenBytes.length >> 8) & 0xff;
    header[2] = tokenBytes.length & 0xff;
    header.set(tokenBytes, 3);

    await writer.write(header);
    await writer.close();

    // Read response
    const { value } = await reader.read();
    const resp = new TextDecoder().decode(value);
    if (resp !== "OK") {
      throw new Error("Auth rejected: " + resp);
    }
    console.log("[QUIC] Authenticated with gateway");
    reader.releaseLock();
  }

  // ── HTTP Tunneling over QUIC Streams ───────────────────────────

  async function tunnelHttpRequest(method, url, headers, body) {
    const stream = await transport.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();

    // [type=HTTP][method_len:u8][method][url_len:u16][url][headers_len:u32][headers_json][body]
    const methodBytes = new TextEncoder().encode(method);
    const urlBytes = new TextEncoder().encode(url);
    const headersJson = JSON.stringify(headers || {});
    const headersBytes = new TextEncoder().encode(headersJson);
    const bodyBytes = body ? new Uint8Array(body) : new Uint8Array(0);

    const packet = new Uint8Array(
      1 + 1 + methodBytes.length + 2 + urlBytes.length + 4 + headersBytes.length + bodyBytes.length
    );
    let offset = 0;
    packet[offset++] = STREAM_HTTP;
    packet[offset++] = methodBytes.length;
    packet.set(methodBytes, offset); offset += methodBytes.length;
    packet[offset++] = (urlBytes.length >> 8) & 0xff;
    packet[offset++] = urlBytes.length & 0xff;
    packet.set(urlBytes, offset); offset += urlBytes.length;
    const hl = headersBytes.length;
    packet[offset++] = (hl >> 24) & 0xff;
    packet[offset++] = (hl >> 16) & 0xff;
    packet[offset++] = (hl >> 8) & 0xff;
    packet[offset++] = hl & 0xff;
    packet.set(headersBytes, offset); offset += headersBytes.length;
    packet.set(bodyBytes, offset);

    await writer.write(packet);
    await writer.close();

    // Read response: [status:u16][headers_len:u32][headers_json][body]
    const chunks = [];
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
    }

    const respBuf = concatUint8Arrays(chunks);
    if (respBuf.length < 6) throw new Error("Short QUIC HTTP response");

    const status = (respBuf[0] << 8) | respBuf[1];
    const respHeadersLen = (respBuf[2] << 24) | (respBuf[3] << 16) | (respBuf[4] << 8) | respBuf[5];
    const respHeaders = JSON.parse(new TextDecoder().decode(respBuf.slice(6, 6 + respHeadersLen)));
    const respBody = respBuf.slice(6 + respHeadersLen);

    return { status, headers: respHeaders, body: respBody };
  }

  // ── WebSocket Shim (same as WebRTC version) ────────────────────

  function installWebSocketShim() {
    const origWS = window.WebSocket;

    window.WebSocket = function (url, protocols) {
      const parsed = new URL(url, window.location.origin);
      const parsedPort = parsed.port || (parsed.protocol === "wss:" ? "443" : "80");
      const locPort = window.location.port || (window.location.protocol === "https:" ? "443" : "80");
      const sameHost = parsed.hostname === window.location.hostname && parsedPort === locPort;

      if (!sameHost || !transport) {
        return new origWS(url, protocols);
      }

      console.log("[QUIC] WebSocket shim intercepting:", url);
      return new QuicWebSocket(url, protocols);
    };
    window.WebSocket.CONNECTING = 0;
    window.WebSocket.OPEN = 1;
    window.WebSocket.CLOSING = 2;
    window.WebSocket.CLOSED = 3;
    window.WebSocket.prototype = origWS.prototype;
    console.log("[QUIC] WebSocket shim installed");
  }

  // WebSocket implementation over QUIC bidi stream
  function QuicWebSocket(url, protocols) {
    this.readyState = 0;
    this.protocol = "";
    this.extensions = "";
    this.bufferedAmount = 0;
    this.binaryType = "arraybuffer";
    this.url = url;
    this.onopen = null;
    this.onmessage = null;
    this.onclose = null;
    this.onerror = null;
    this._listeners = {};
    this._writer = null;
    this._reader = null;

    const parsed = new URL(url, window.location.origin);
    const wsPath = parsed.pathname + parsed.search;
    const self = this;

    // Open a QUIC bidi stream for this WebSocket
    transport.createBidirectionalStream().then(async (stream) => {
      self._writer = stream.writable.getWriter();
      self._reader = stream.readable.getReader();

      // Send: [type=WEBSOCKET][path_len:u16][path]
      const pathBytes = new TextEncoder().encode(wsPath);
      const header = new Uint8Array(1 + 2 + pathBytes.length);
      header[0] = STREAM_WEBSOCKET;
      header[1] = (pathBytes.length >> 8) & 0xff;
      header[2] = pathBytes.length & 0xff;
      header.set(pathBytes, 3);
      await self._writer.write(header);

      // Now open
      self.readyState = 1;
      self.protocol = (Array.isArray(protocols) ? protocols[0] : protocols) || "";
      self._dispatch("open", new Event("open"));

      // Read loop
      self._readLoop();
    }).catch((err) => {
      console.error("[QUIC] WS stream failed:", err);
      self._dispatch("error", new Event("error"));
      self.readyState = 3;
      self._dispatch("close", new CloseEvent("close", { code: 1006, reason: err.message }));
    });
  }

  QuicWebSocket.prototype._readLoop = async function () {
    try {
      while (this.readyState === 1) {
        const { value, done } = await this._reader.read();
        if (done) break;
        const payload = this.binaryType === "arraybuffer"
          ? value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength)
          : new Blob([value]);
        this._dispatch("message", new MessageEvent("message", { data: payload }));
      }
    } catch (e) {
      if (this.readyState < 2) {
        console.warn("[QUIC] WS read error:", e);
      }
    }
    if (this.readyState < 3) {
      this.readyState = 3;
      this._dispatch("close", new CloseEvent("close", { code: 1000, reason: "" }));
    }
  };

  QuicWebSocket.prototype.send = function (data) {
    if (this.readyState !== 1 || !this._writer) {
      throw new DOMException("WebSocket not open", "InvalidStateError");
    }
    let bytes;
    if (typeof data === "string") {
      bytes = new TextEncoder().encode(data);
    } else if (data instanceof ArrayBuffer) {
      bytes = new Uint8Array(data);
    } else if (ArrayBuffer.isView(data)) {
      bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    } else {
      return; // Blob — would need async
    }
    this._writer.write(bytes).catch(() => {});
  };

  QuicWebSocket.prototype.close = function (code, reason) {
    if (this.readyState >= 2) return;
    this.readyState = 2;
    if (this._writer) {
      this._writer.close().catch(() => {});
    }
  };

  QuicWebSocket.prototype.addEventListener = function (type, fn) {
    if (!this._listeners[type]) this._listeners[type] = [];
    this._listeners[type].push(fn);
  };

  QuicWebSocket.prototype.removeEventListener = function (type, fn) {
    if (!this._listeners[type]) return;
    this._listeners[type] = this._listeners[type].filter((f) => f !== fn);
  };

  QuicWebSocket.prototype._dispatch = function (type, event) {
    if (typeof this["on" + type] === "function") this["on" + type](event);
    const listeners = this._listeners[type];
    if (listeners) listeners.forEach((fn) => fn(event));
  };

  // ── Helpers ────────────────────────────────────────────────────

  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  function concatUint8Arrays(arrays) {
    let totalLen = 0;
    for (const a of arrays) totalLen += a.length;
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const a of arrays) {
      result.set(a, offset);
      offset += a.length;
    }
    return result;
  }

  function acceptStreams() {
    // Gateway may open streams to us (server push, VPN blocked notifications, etc.)
    // For now just log
    (async () => {
      try {
        const reader = transport.incomingBidirectionalStreams.getReader();
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          console.log("[QUIC] Incoming stream from gateway");
          // TODO: handle server-initiated streams
        }
      } catch {}
    })();
  }

  function cleanup() {
    if (transport) {
      try { transport.close(); } catch {}
      transport = null;
    }
    controlWriter = null;
    controlReader = null;
    pairedGatewayId = null;
  }

  function scheduleReconnect() {
    if (reconnectTimer) return;
    const delay = Math.min(RECONNECT_DELAY * Math.pow(1.5, reconnectAttempts), MAX_RECONNECT_DELAY);
    reconnectAttempts++;
    console.log("[QUIC] Reconnecting in", Math.round(delay / 1000), "s...");
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      init();
    }, delay);
  }

  // ── Start ──────────────────────────────────────────────────────

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
