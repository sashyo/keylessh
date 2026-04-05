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

  // Step 1: Fetch TURN/STUN config
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

  // Single Promise: register → pair → WebRTC → DataChannel → tunnel open
  return new Promise<WebSocket>((resolve, reject) => {
    const timeout = setTimeout(() => {
      sigWs.close();
      reject(new Error("WebRTC signaling timeout"));
    }, 30000);

    let pc: RTCPeerConnection | null = null;
    let pendingCandidates: RTCIceCandidate[] = [];
    let remoteDescSet = false;
    const tunnelId = crypto.randomUUID();
    const wsPath = `/ws/ssh?host=${encodeURIComponent(host)}&port=${port}&token=${encodeURIComponent(token)}&serverId=${encodeURIComponent(host)}`;

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
        console.log("[SSH-WebRTC] Received:", msg.type, msg.fromId || "");

        switch (msg.type) {
          case "paired": {
            console.log("[SSH-WebRTC] Paired with gateway:", msg.gateway?.id);

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

            pc.onconnectionstatechange = () => {
              console.log("[SSH-WebRTC] Connection state:", pc!.connectionState);
            };

            const control = pc.createDataChannel("http-tunnel", { ordered: true });
            pc.createDataChannel("bulk-data", { ordered: false });

            pc.onicecandidate = (e) => {
              if (e.candidate && sigWs.readyState === WebSocket.OPEN) {
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

            // When DataChannel opens, send ws_open immediately
            control.onopen = () => {
              console.log("[SSH-WebRTC] DataChannel open, sending ws_open");
              control.send(JSON.stringify({
                type: "ws_open",
                id: tunnelId,
                url: wsPath,
                protocols: [],
                headers: token ? { cookie: `gateway_access=${token}` } : {},
              }));
            };

            // Listen for ALL messages on control channel
            control.onmessage = (msgEvent) => {
              try {
                const data = JSON.parse(msgEvent.data);

                // Gateway sends capabilities first — ignore
                if (data.type === "capabilities") return;

                // Only handle messages for our tunnel
                if (data.id !== tunnelId) return;

                switch (data.type) {
                  case "ws_opened": {
                    clearTimeout(timeout);
                    console.log("[SSH-WebRTC] SSH tunnel opened!");

                    // Create fake WebSocket wrapping the DataChannel
                    const fakeWs = createDCWebSocket(control, tunnelId);
                    resolve(fakeWs);
                    break;
                  }
                  case "ws_error": {
                    clearTimeout(timeout);
                    reject(new Error(data.message || "WS tunnel error"));
                    break;
                  }
                }
              } catch {}
            };

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
}

/**
 * Create a fake WebSocket that wraps a DataChannel WS tunnel.
 * After ws_opened, all subsequent messages for this tunnelId
 * are dispatched as WebSocket events.
 */
function createDCWebSocket(
  control: RTCDataChannel,
  tunnelId: string,
): WebSocket {
  const ws = Object.create(WebSocket.prototype) as WebSocket;
  const listeners: Record<string, Function[]> = {};

  Object.defineProperties(ws, {
    readyState: { value: WebSocket.OPEN, writable: true, configurable: true },
    protocol: { value: "", writable: true },
    extensions: { value: "" },
    bufferedAmount: { value: 0 },
    binaryType: { value: "arraybuffer", writable: true },
    url: { value: "dc://gateway/ws/ssh" },
    onopen: { value: null, writable: true },
    onmessage: { value: null, writable: true },
    onclose: { value: null, writable: true },
    onerror: { value: null, writable: true },
  });

  // Override the control channel message handler to dispatch WS events
  const prevHandler = control.onmessage;
  control.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.id !== tunnelId) {
        if (prevHandler) prevHandler.call(control, event);
        return;
      }

      switch (msg.type) {
        case "ws_message":
          if (msg.binary) {
            const bytes = Uint8Array.from(atob(msg.data), c => c.charCodeAt(0));
            dispatch("message", new MessageEvent("message", { data: bytes.buffer }));
          } else {
            dispatch("message", new MessageEvent("message", { data: msg.data }));
          }
          break;
        case "ws_close":
          (ws as any).readyState = WebSocket.CLOSED;
          dispatch("close", new CloseEvent("close", {
            code: msg.code || 1000,
            reason: msg.reason || "",
          }));
          break;
        case "ws_error":
          dispatch("error", new Event("error"));
          break;
      }
    } catch {
      // Not JSON — ignore
    }
  };

  function dispatch(type: string, event: Event) {
    const handler = (ws as any)[`on${type}`];
    if (typeof handler === "function") handler.call(ws, event);
    (listeners[type] || []).forEach(fn => fn.call(ws, event));
  }

  // Override send
  (ws as any).send = (data: string | ArrayBuffer | ArrayBufferView) => {
    if (typeof data === "string") {
      control.send(JSON.stringify({
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
      let binary = "";
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      control.send(JSON.stringify({
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
    control.send(JSON.stringify({
      type: "ws_close",
      id: tunnelId,
      code: code || 1000,
      reason: reason || "",
    }));
    (ws as any).readyState = WebSocket.CLOSED;
  };

  (ws as any).addEventListener = (type: string, fn: Function) => {
    if (!listeners[type]) listeners[type] = [];
    listeners[type].push(fn);
  };

  (ws as any).removeEventListener = (type: string, fn: Function) => {
    if (!listeners[type]) return;
    listeners[type] = listeners[type].filter(f => f !== fn);
  };

  // Fire open immediately
  setTimeout(() => dispatch("open", new Event("open")), 0);

  return ws;
}
