/**
 * TideE2E — End-to-end encrypted RDP tunnel over DataChannel TCP tunnel.
 *
 * Performs X25519 key exchange with TideProxy, then encrypts/decrypts
 * all RDP traffic with AES-256-GCM. The gateway sees only opaque bytes.
 *
 * Wire protocol:
 *   Handshake:
 *     Client → Proxy:  [0x01][jwt_len LE16][JWT][client_x25519_pub 32B]
 *     Proxy → Client:  [0x02][server_x25519_pub 32B]
 *
 *   Data (both directions):
 *     [4-byte payload_len LE][12B nonce][16B GCM tag][ciphertext]
 *     Nonces: client=even (0,2,4,...), server=odd (1,3,5,...)
 *
 * Usage:
 *   const e2e = new TideE2E(sendRawBytes, jwt);
 *   e2e.onready = () => { ... RDP handshake can start ... };
 *   e2e.ondata = (plaintext) => { ... forward to IronRDP ... };
 *   e2e.onerror = (err) => { ... };
 *
 *   // When raw bytes arrive from the TCP tunnel:
 *   e2e.feed(rawBytes);
 *
 *   // To send RDP data (plaintext → encrypted → tunnel):
 *   e2e.send(plainBytes);
 */

(function (exports) {
  "use strict";

  var GCM_NONCE_SIZE = 12;
  var GCM_TAG_SIZE = 16;
  var HEADER_SIZE = GCM_NONCE_SIZE + GCM_TAG_SIZE;
  var MSG_CLIENT_HELLO = 0x01;
  var MSG_SERVER_HELLO = 0x02;

  /**
   * @param {function(Uint8Array): void} sendRaw - Send raw bytes into the TCP tunnel
   * @param {string} jwt - JWT token for authentication
   */
  function TideE2E(sendRaw, jwt) {
    this._sendRaw = sendRaw;
    this._jwt = jwt;
    this._state = "init"; // init → handshake → ready
    this._sessionKey = null;
    this._clientNonce = 0; // even: 0, 2, 4, ...
    this._recvBuf = new Uint8Array(0);
    this._draining = false; // guard against concurrent _drainRecvBuf calls
    this._clientPriv = null;

    // Callbacks
    this.onready = null;
    this.ondata = null;
    this.onerror = null;

    this._startHandshake();
  }

  TideE2E.prototype._startHandshake = async function () {
    try {
      // Generate X25519 keypair
      var keyPair = await crypto.subtle.generateKey(
        { name: "X25519" },
        false,
        ["deriveBits"]
      );
      this._clientPriv = keyPair.privateKey;

      // Export public key (raw 32 bytes)
      var pubRaw = new Uint8Array(
        await crypto.subtle.exportKey("raw", keyPair.publicKey)
      );

      // Build client hello: [0x01][jwt_len LE16][JWT bytes][pubkey 32B]
      var jwtBytes = new TextEncoder().encode(this._jwt);
      var msg = new Uint8Array(1 + 2 + jwtBytes.length + 32);
      msg[0] = MSG_CLIENT_HELLO;
      msg[1] = jwtBytes.length & 0xff;
      msg[2] = (jwtBytes.length >> 8) & 0xff;
      msg.set(jwtBytes, 3);
      msg.set(pubRaw, 3 + jwtBytes.length);

      this._state = "handshake";
      this._sendRaw(msg);
    } catch (err) {
      this._error("Handshake init failed: " + err.message);
    }
  };

  TideE2E.prototype._processServerHello = async function (data) {
    if (data.length < 1 + 32) {
      this._error("Server hello too short: " + data.length);
      return;
    }
    if (data[0] !== MSG_SERVER_HELLO) {
      this._error("Expected server hello (0x02), got 0x" + data[0].toString(16));
      return;
    }

    var serverPub = data.slice(1, 33);

    try {
      // Import server's X25519 public key
      var serverKey = await crypto.subtle.importKey(
        "raw",
        serverPub,
        { name: "X25519" },
        false,
        []
      );

      // X25519 DH → shared secret
      var sharedBits = await crypto.subtle.deriveBits(
        { name: "X25519", public: serverKey },
        this._clientPriv,
        256
      );

      // SHA-256(shared_secret) → AES-256-GCM key
      var sharedHash = await crypto.subtle.digest("SHA-256", sharedBits);

      this._sessionKey = await crypto.subtle.importKey(
        "raw",
        sharedHash,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );

      this._clientPriv = null; // no longer needed
      this._state = "ready";
      console.log("[TideE2E] Session key established");

      // Process any buffered data beyond the 33-byte server hello
      if (data.length > 33) {
        this._recvBuf = concatBytes(this._recvBuf, data.slice(33));
        this._drainRecvBuf();
      }

      if (this.onready) this.onready();
    } catch (err) {
      this._error("Key derivation failed: " + err.message);
    }
  };

  /**
   * Feed raw bytes from the TCP tunnel into the E2E layer.
   * @param {Uint8Array} data
   */
  TideE2E.prototype.feed = function (data) {
    if (this._state === "handshake") {
      this._recvBuf = concatBytes(this._recvBuf, data);
      if (this._recvBuf.length >= 33) {
        var hello = this._recvBuf.slice(0, 33);
        this._recvBuf = this._recvBuf.slice(33);
        this._processServerHello(hello);
      }
      return;
    }

    if (this._state === "ready") {
      this._recvBuf = concatBytes(this._recvBuf, data);
      this._drainRecvBuf();
      return;
    }
  };

  TideE2E.prototype._drainRecvBuf = async function () {
    if (this._draining) return; // another drain is in progress; it will pick up new data
    this._draining = true;
    try {
      for (;;) {
        if (this._recvBuf.length < 4) break;

        // Read frame length (4-byte LE)
        var frameLen =
          this._recvBuf[0] |
          (this._recvBuf[1] << 8) |
          (this._recvBuf[2] << 16) |
          (this._recvBuf[3] << 24);

        if (frameLen > 1024 * 1024) {
          this._error("Frame too large: " + frameLen);
          return;
        }

        if (this._recvBuf.length < 4 + frameLen) break;

        var frame = this._recvBuf.slice(4, 4 + frameLen);
        this._recvBuf = this._recvBuf.slice(4 + frameLen);

        try {
          var plain = await this._decrypt(frame);
          if (this.ondata) this.ondata(plain);
        } catch (err) {
          this._error("Decrypt failed: " + err.message);
          return;
        }
        // Loop continues — will check for more data that may have arrived during await
      }
    } finally {
      this._draining = false;
    }
  };

  /**
   * Send RDP data (plaintext) through the encrypted tunnel.
   * @param {Uint8Array} plain
   */
  TideE2E.prototype.send = async function (plain) {
    if (this._state !== "ready") {
      this._error("Cannot send before handshake complete");
      return;
    }

    try {
      // Build counter-based nonce (client uses even: 0, 2, 4, ...)
      var nonce = new Uint8Array(GCM_NONCE_SIZE);
      var ctr = this._clientNonce;
      this._clientNonce += 2;
      // Write counter as little-endian into first 8 bytes
      for (var i = 0; i < 8; i++) {
        nonce[i] = Number((BigInt(ctr) >> BigInt(i * 8)) & 0xffn);
      }

      var ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: nonce, tagLength: 128 },
          this._sessionKey,
          plain
        )
      );

      // AES-GCM output = [ciphertext + tag (appended)]
      // We need: [nonce 12B][tag 16B][ciphertext]
      // WebCrypto appends tag at end, so split it
      var ctLen = ciphertext.length - GCM_TAG_SIZE;
      var tag = ciphertext.slice(ctLen);
      var ct = ciphertext.slice(0, ctLen);

      var payloadLen = GCM_NONCE_SIZE + GCM_TAG_SIZE + ct.length;
      var frame = new Uint8Array(4 + payloadLen);

      // 4-byte length LE
      frame[0] = payloadLen & 0xff;
      frame[1] = (payloadLen >> 8) & 0xff;
      frame[2] = (payloadLen >> 16) & 0xff;
      frame[3] = (payloadLen >> 24) & 0xff;

      // [nonce][tag][ciphertext]
      frame.set(nonce, 4);
      frame.set(tag, 4 + GCM_NONCE_SIZE);
      frame.set(ct, 4 + GCM_NONCE_SIZE + GCM_TAG_SIZE);

      this._sendRaw(frame);
    } catch (err) {
      this._error("Encrypt failed: " + err.message);
    }
  };

  /**
   * Decrypt a frame: [12B nonce][16B tag][ciphertext]
   * @param {Uint8Array} frame
   * @returns {Promise<Uint8Array>}
   */
  TideE2E.prototype._decrypt = async function (frame) {
    if (frame.length < HEADER_SIZE) throw new Error("Frame too short");

    var nonce = frame.slice(0, GCM_NONCE_SIZE);
    var tag = frame.slice(GCM_NONCE_SIZE, GCM_NONCE_SIZE + GCM_TAG_SIZE);
    var ct = frame.slice(HEADER_SIZE);

    // WebCrypto expects [ciphertext + tag] concatenated
    var ctWithTag = new Uint8Array(ct.length + GCM_TAG_SIZE);
    ctWithTag.set(ct);
    ctWithTag.set(tag, ct.length);

    var plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, tagLength: 128 },
      this._sessionKey,
      ctWithTag
    );

    return new Uint8Array(plain);
  };

  TideE2E.prototype._error = function (msg) {
    console.error("[TideE2E] " + msg);
    this._state = "error";
    if (this.onerror) this.onerror(new Error(msg));
  };

  /* Helper: concatenate two Uint8Arrays */
  function concatBytes(a, b) {
    if (a.length === 0) return b;
    if (b.length === 0) return a;
    var c = new Uint8Array(a.length + b.length);
    c.set(a);
    c.set(b, a.length);
    return c;
  }

  // Export
  if (typeof module !== "undefined" && module.exports) {
    module.exports = TideE2E;
  } else {
    exports.TideE2E = TideE2E;
  }
})(typeof window !== "undefined" ? window : this);
