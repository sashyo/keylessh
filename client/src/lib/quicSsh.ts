/**
 * QUIC SSH connection — establishes a WebTransport connection to the gateway
 * via signaling, then opens an SSH bidi stream.
 *
 * Returns a WebSocket-compatible object that the SSH library can use.
 */

const STREAM_AUTH = 0x01;
const STREAM_SSH = 0x05;

interface QuicSshOptions {
  signalUrl: string;
  gatewayId: string;
  backendName: string;
  token: string;
  host: string;
  port: number;
}

/**
 * Connect to a gateway via QUIC WebTransport and open an SSH stream.
 * Returns a fake WebSocket that wraps the QUIC bidi stream.
 */
export async function connectQuicSsh(options: QuicSshOptions): Promise<WebSocket> {
  if (typeof WebTransport === "undefined") {
    throw new Error("WebTransport not supported — use WebSocket fallback");
  }

  const { signalUrl, gatewayId, token, backendName, host, port } = options;

  // Step 1: Connect to signaling
  const wsProto = signalUrl.startsWith("https") ? "wss" : "ws";
  const wsHost = signalUrl.replace(/^https?:\/\//, "").replace(/\/$/, "");
  const signalingUrl = `${wsProto}://${wsHost}`;
  const clientId = `ssh-${Math.random().toString(36).slice(2, 10)}`;

  const sigWs = new WebSocket(signalingUrl);

  // Step 2: Register and wait for quic_address
  const gatewayInfo = await new Promise<{ address: string; certHash?: string; relayUrl?: string }>((resolve, reject) => {
    const timeout = setTimeout(() => {
      sigWs.close();
      reject(new Error("Timeout waiting for gateway QUIC address"));
    }, 15000);

    sigWs.onopen = () => {
      sigWs.send(JSON.stringify({
        type: "register",
        role: "client",
        id: clientId,
        targetGatewayId: gatewayId,
        token,
      }));
    };

    sigWs.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === "quic_address" && msg.address) {
          clearTimeout(timeout);
          resolve({ address: msg.address, certHash: msg.certHash, relayUrl: msg.relayUrl });
        } else if (msg.type === "error") {
          clearTimeout(timeout);
          reject(new Error(msg.message || "Signaling error"));
        }
      } catch {}
    };

    sigWs.onerror = () => {
      clearTimeout(timeout);
      reject(new Error("Signaling connection failed"));
    };
  });

  sigWs.close();

  // Step 3: Coordinated hole-punch then direct QUIC, relay as fallback
  let transport: WebTransport;

  const directUrl = `https://${gatewayInfo.address}`;
  const directOptions: any = {};
  if (gatewayInfo.certHash) {
    const hashBytes = hexToBytes(gatewayInfo.certHash);
    directOptions.serverCertificateHashes = [{
      algorithm: "sha-256",
      value: hashBytes.buffer,
    }];
  }

  // Connect to relay first to trigger coordinated hole-punch
  let relayTransport: WebTransport | null = null;
  if (gatewayInfo.relayUrl) {
    try {
      console.log("[SSH] Connecting to relay for hole-punch:", gatewayInfo.relayUrl);
      const relayGwParam = gatewayId ? `?gateway=${encodeURIComponent(gatewayId)}` : "";
      relayTransport = new WebTransport(`https://${gatewayInfo.relayUrl}${relayGwParam}`);
      await Promise.race([
        relayTransport.ready,
        new Promise((_, reject) => setTimeout(() => reject(new Error("Relay timeout")), 5000)),
      ]);
      console.log("[SSH] Relay connected — hole-punch triggered, waiting 2s...");
      // Wait for gateway to send punch packets through NAT
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (relayErr) {
      console.warn("[SSH] Relay connect failed:", relayErr);
      relayTransport = null;
    }
  }

  // Now try direct QUIC (NAT pinhole should be open)
  try {
    console.log("[SSH] Trying direct QUIC:", gatewayInfo.address);
    const directTransport = new WebTransport(directUrl, directOptions);
    await Promise.race([
      directTransport.ready,
      new Promise((_, reject) => setTimeout(() => reject(new Error("Direct QUIC timeout")), 5000)),
    ]);
    transport = directTransport;
    console.log("[SSH] Direct QUIC connected (P2P)!");
    // Close relay — not needed
    if (relayTransport) {
      try { relayTransport.close(); } catch {}
    }
  } catch (directErr) {
    console.warn("[SSH] Direct QUIC failed:", directErr);

    // Fall back to relay (already connected)
    if (relayTransport) {
      transport = relayTransport;
      console.log("[SSH] Using QUIC relay as fallback");
    } else {
      throw directErr; // No relay available, fall back to WebSocket
    }
  }

  // Step 4: Auth stream
  const authStream = await transport.createBidirectionalStream();
  const authWriter = authStream.writable.getWriter();
  const authReader = authStream.readable.getReader();

  const tokenBytes = new TextEncoder().encode(token);
  const authHeader = new Uint8Array(1 + 2 + tokenBytes.length);
  authHeader[0] = STREAM_AUTH;
  authHeader[1] = (tokenBytes.length >> 8) & 0xff;
  authHeader[2] = tokenBytes.length & 0xff;
  authHeader.set(tokenBytes, 3);

  await authWriter.write(authHeader);
  await authWriter.close();

  const { value: authResp } = await authReader.read();
  const resp = new TextDecoder().decode(authResp);
  if (resp !== "OK") {
    transport.close();
    throw new Error(`Gateway auth failed: ${resp}`);
  }
  authReader.releaseLock();

  // Step 5: Open SSH stream
  const sshStream = await transport.createBidirectionalStream();
  const sshWriter = sshStream.writable.getWriter();
  const sshReader = sshStream.readable.getReader();

  // Send: [type=SSH][host_len:u16][host][port:u16]
  const hostBytes = new TextEncoder().encode(host);
  const sshHeader = new Uint8Array(1 + 2 + hostBytes.length + 2);
  let offset = 0;
  sshHeader[offset++] = STREAM_SSH;
  sshHeader[offset++] = (hostBytes.length >> 8) & 0xff;
  sshHeader[offset++] = hostBytes.length & 0xff;
  sshHeader.set(hostBytes, offset); offset += hostBytes.length;
  sshHeader[offset++] = (port >> 8) & 0xff;
  sshHeader[offset++] = port & 0xff;

  await sshWriter.write(sshHeader);

  // Read response: 0x01 = ok, 0x00 = error
  const { value: sshResp } = await sshReader.read();
  if (!sshResp || sshResp[0] !== 0x01) {
    transport.close();
    throw new Error("Gateway SSH connection failed");
  }

  // Step 6: Wrap as WebSocket-compatible object
  return createQuicWebSocket(sshWriter, sshReader, transport);
}

function createQuicWebSocket(
  writer: WritableStreamDefaultWriter,
  reader: ReadableStreamDefaultReader,
  transport: WebTransport,
): WebSocket {
  // Create a fake WebSocket that wraps the QUIC bidi stream
  const ws = Object.create(WebSocket.prototype) as WebSocket;
  const listeners: Record<string, Function[]> = {};

  Object.defineProperties(ws, {
    readyState: { value: WebSocket.OPEN, writable: true, configurable: true },
    protocol: { value: "", writable: true },
    extensions: { value: "" },
    bufferedAmount: { value: 0 },
    binaryType: { value: "arraybuffer", writable: true },
    url: { value: "quic://gateway/ssh" },
    onopen: { value: null, writable: true },
    onmessage: { value: null, writable: true },
    onclose: { value: null, writable: true },
    onerror: { value: null, writable: true },
  });

  // Override send
  (ws as any).send = (data: string | ArrayBuffer | ArrayBufferView) => {
    let bytes: Uint8Array;
    if (typeof data === "string") {
      bytes = new TextEncoder().encode(data);
    } else if (data instanceof ArrayBuffer) {
      bytes = new Uint8Array(data);
    } else if (ArrayBuffer.isView(data)) {
      bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    } else {
      return;
    }
    writer.write(bytes).catch(() => {});
  };

  // Override close
  (ws as any).close = (code?: number, reason?: string) => {
    (ws as any).readyState = WebSocket.CLOSING;
    writer.close().catch(() => {});
    transport.close();
    (ws as any).readyState = WebSocket.CLOSED;
    dispatch("close", new CloseEvent("close", { code: code || 1000, reason: reason || "", wasClean: true }));
  };

  (ws as any).addEventListener = (type: string, fn: Function) => {
    if (!listeners[type]) listeners[type] = [];
    listeners[type].push(fn);
  };

  (ws as any).removeEventListener = (type: string, fn: Function) => {
    if (!listeners[type]) return;
    listeners[type] = listeners[type].filter(f => f !== fn);
  };

  function dispatch(type: string, event: Event) {
    const handler = (ws as any)[`on${type}`];
    if (typeof handler === "function") handler.call(ws, event);
    (listeners[type] || []).forEach(fn => fn.call(ws, event));
  }

  // Fire open immediately (already connected)
  setTimeout(() => dispatch("open", new Event("open")), 0);

  // Read loop
  (async () => {
    try {
      while ((ws as any).readyState === WebSocket.OPEN) {
        const { value, done } = await reader.read();
        if (done) break;
        const payload = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
        dispatch("message", new MessageEvent("message", { data: payload }));
      }
    } catch {}
    if ((ws as any).readyState !== WebSocket.CLOSED) {
      (ws as any).readyState = WebSocket.CLOSED;
      dispatch("close", new CloseEvent("close", { code: 1000, reason: "", wasClean: true }));
    }
  })();

  return ws;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}
