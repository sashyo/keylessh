/**
 * WebRTC DataChannel connection for SSH — same P2P path as RDP.
 *
 * Establishes a WebRTC DataChannel to the gateway via signaling,
 * then opens a WS tunnel to /ws/ssh through the DataChannel.
 * Returns a WebSocket-compatible object for the SSH library.
 */

interface WebRtcSshOptions {
  signalUrl: string;
  gatewayId: string;
  host: string;
  port: number;
  token: string;
}

const NativeWebSocket = window.WebSocket;

export async function connectWebRtcSsh(options: WebRtcSshOptions): Promise<WebSocket> {
  const { signalUrl, gatewayId, host, port, token } = options;

  // Step 1: Fetch TURN/STUN config from signal server
  const configUrl = signalUrl.replace(/\/$/, "") + "/webrtc-config";
  let turnConfig: any = {};
  try {
    const res = await fetch(configUrl);
    if (res.ok) turnConfig = await res.json();
  } catch {}

  // Step 2: Connect to signaling
  const wsProto = signalUrl.startsWith("https") ? "wss" : "ws";
  const wsHost = signalUrl.replace(/^https?:\/\//, "").replace(/\/$/, "");
  const signalingUrl = `${wsProto}://${wsHost}`;
  const clientId = `ssh-${Math.random().toString(36).slice(2, 10)}`;

  const sigWs = new NativeWebSocket(signalingUrl);

  // Step 3: Register and wait for pairing + set up WebRTC
  const { peerConnection, controlChannel } = await new Promise<{
    peerConnection: RTCPeerConnection;
    controlChannel: RTCDataChannel;
  }>((resolve, reject) => {
    const timeout = setTimeout(() => {
      sigWs.close();
      reject(new Error("WebRTC signaling timeout"));
    }, 30000);

    let pc: RTCPeerConnection | null = null;
    let pendingCandidates: RTCIceCandidate[] = [];
    let remoteDescSet = false;

    sigWs.onopen = () => {
      sigWs.send(JSON.stringify({
        type: "register",
        role: "client",
        id: clientId,
        targetGatewayId: gatewayId,
        token,
      }));
    };

    sigWs.onmessage = async (event) => {
      try {
        const msg = JSON.parse(event.data);

        switch (msg.type) {
          case "paired": {
            console.log("[SSH-WebRTC] Paired with gateway:", msg.gateway?.id);

            // Build ICE servers
            const iceServers: RTCIceServer[] = [];
            if (turnConfig.stunServer) {
              iceServers.push({ urls: turnConfig.stunServer });
            }
            if (turnConfig.turnServer && turnConfig.turnUsername && turnConfig.turnPassword) {
              iceServers.push({
                urls: turnConfig.turnServer,
                username: turnConfig.turnUsername,
                credential: turnConfig.turnPassword,
              });
            }

            pc = new RTCPeerConnection({ iceServers });

            // Create DataChannels
            const control = pc.createDataChannel("http-tunnel", { ordered: true });
            pc.createDataChannel("bulk-data", { ordered: false });

            pc.onicecandidate = (e) => {
              if (e.candidate) {
                sigWs.send(JSON.stringify({
                  type: "candidate",
                  targetId: msg.gateway?.id,
                  fromId: clientId,
                  candidate: {
                    candidate: e.candidate.candidate,
                    mid: e.candidate.sdpMid || "",
                  },
                }));
              }
            };

            control.onopen = () => {
              clearTimeout(timeout);
              console.log("[SSH-WebRTC] DataChannel open");
              resolve({ peerConnection: pc!, controlChannel: control });
            };

            // Create and send SDP offer
            const offer = await pc.createOffer();
            await pc.setLocalDescription(offer);
            sigWs.send(JSON.stringify({
              type: "sdp_offer",
              targetId: msg.gateway?.id,
              fromId: clientId,
              sdp: offer.sdp,
              sdpType: "offer",
            }));
            break;
          }

          case "sdp_answer": {
            if (pc && msg.sdp) {
              await pc.setRemoteDescription(new RTCSessionDescription({
                type: msg.sdpType || "answer",
                sdp: msg.sdp,
              }));
              remoteDescSet = true;
              // Flush pending candidates
              for (const c of pendingCandidates) {
                await pc.addIceCandidate(c).catch(() => {});
              }
              pendingCandidates = [];
            }
            break;
          }

          case "candidate": {
            if (pc && msg.candidate) {
              const ice = new RTCIceCandidate({
                candidate: msg.candidate.candidate,
                sdpMid: msg.candidate.mid,
              });
              if (remoteDescSet) {
                await pc.addIceCandidate(ice).catch(() => {});
              } else {
                pendingCandidates.push(ice);
              }
            }
            break;
          }

          case "error": {
            clearTimeout(timeout);
            reject(new Error(msg.message || "Signaling error"));
            break;
          }
        }
      } catch {}
    };

    sigWs.onerror = () => {
      clearTimeout(timeout);
      reject(new Error("Signaling connection failed"));
    };
  });

  // Step 4: Open SSH tunnel through DataChannel
  // Use the control channel to send ws_open, then bridge data
  const wsPath = `/ws/ssh?host=${encodeURIComponent(host)}&port=${port}&token=${encodeURIComponent(token)}&serverId=${encodeURIComponent(host)}`;
  const tunnelId = crypto.randomUUID();

  return new Promise<WebSocket>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("SSH tunnel open timeout"));
    }, 10000);

    // Create a fake WebSocket that bridges through the DataChannel
    const fakeWs = createDCWebSocket(controlChannel, tunnelId, wsPath, token);

    // Wait for the ws_open confirmation
    const origOnOpen = fakeWs.onopen;
    fakeWs.onopen = (event: Event) => {
      clearTimeout(timeout);
      if (origOnOpen) origOnOpen.call(fakeWs, event);
    };

    // Listen for ws_opened / ws_message / ws_close from gateway
    const origHandler = controlChannel.onmessage;
    controlChannel.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.id !== tunnelId) {
          // Not for us — pass to original handler
          if (origHandler) origHandler.call(controlChannel, event);
          return;
        }

        switch (msg.type) {
          case "ws_opened":
            (fakeWs as any).readyState = WebSocket.OPEN;
            fakeWs.dispatchEvent(new Event("open"));
            clearTimeout(timeout);
            resolve(fakeWs);
            break;
          case "ws_message":
            if (msg.binary) {
              // Base64 binary data
              const bytes = Uint8Array.from(atob(msg.data), c => c.charCodeAt(0));
              fakeWs.dispatchEvent(new MessageEvent("message", {
                data: bytes.buffer,
              }));
            } else {
              fakeWs.dispatchEvent(new MessageEvent("message", {
                data: msg.data,
              }));
            }
            break;
          case "ws_close":
            (fakeWs as any).readyState = WebSocket.CLOSED;
            fakeWs.dispatchEvent(new CloseEvent("close", {
              code: msg.code || 1000,
              reason: msg.reason || "",
            }));
            break;
          case "ws_error":
            fakeWs.dispatchEvent(new Event("error"));
            break;
        }
      } catch {
        // Not JSON — might be binary data, pass through
        if (origHandler) origHandler.call(controlChannel, event);
      }
    };

    // The ws_open triggers the gateway to open /ws/ssh
    // Gateway responds with ws_opened, then we resolve
  });
}

function createDCWebSocket(
  controlChannel: RTCDataChannel,
  tunnelId: string,
  wsPath: string,
  token: string,
): WebSocket {
  const ws = Object.create(WebSocket.prototype) as WebSocket;
  const listeners: Record<string, Function[]> = {};

  Object.defineProperties(ws, {
    readyState: { value: WebSocket.CONNECTING, writable: true, configurable: true },
    protocol: { value: "", writable: true },
    extensions: { value: "" },
    bufferedAmount: { value: 0 },
    binaryType: { value: "arraybuffer", writable: true },
    url: { value: `ws://gateway${wsPath}` },
    onopen: { value: null, writable: true },
    onmessage: { value: null, writable: true },
    onclose: { value: null, writable: true },
    onerror: { value: null, writable: true },
  });

  // Send ws_open to gateway through DataChannel
  controlChannel.send(JSON.stringify({
    type: "ws_open",
    id: tunnelId,
    url: wsPath,
    protocols: [],
    headers: token ? { cookie: `gateway_access=${token}` } : {},
  }));

  // Override send
  (ws as any).send = (data: string | ArrayBuffer | ArrayBufferView) => {
    if (typeof data === "string") {
      controlChannel.send(JSON.stringify({
        type: "ws_message",
        id: tunnelId,
        data,
      }));
    } else {
      let bytes: Uint8Array;
      if (data instanceof ArrayBuffer) {
        bytes = new Uint8Array(data);
      } else if (ArrayBuffer.isView(data)) {
        bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
      } else {
        return;
      }
      // Send as base64 over control channel
      let binary = "";
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      controlChannel.send(JSON.stringify({
        type: "ws_message",
        id: tunnelId,
        data: btoa(binary),
        binary: true,
      }));
    }
  };

  // Override close
  (ws as any).close = (code?: number, reason?: string) => {
    (ws as any).readyState = WebSocket.CLOSING;
    controlChannel.send(JSON.stringify({
      type: "ws_close",
      id: tunnelId,
      code: code || 1000,
      reason: reason || "",
    }));
    (ws as any).readyState = WebSocket.CLOSED;
  };

  // Event listener support
  (ws as any).addEventListener = (type: string, fn: Function) => {
    if (!listeners[type]) listeners[type] = [];
    listeners[type].push(fn);
  };

  (ws as any).removeEventListener = (type: string, fn: Function) => {
    if (!listeners[type]) return;
    listeners[type] = listeners[type].filter(f => f !== fn);
  };

  (ws as any).dispatchEvent = (event: Event) => {
    const handler = (ws as any)[`on${event.type}`];
    if (typeof handler === "function") handler.call(ws, event);
    (listeners[event.type] || []).forEach(fn => fn.call(ws, event));
    return true;
  };

  return ws;
}
