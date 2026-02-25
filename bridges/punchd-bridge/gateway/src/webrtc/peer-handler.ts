/**
 * WebRTC peer connection handler.
 *
 * Manages WebRTC DataChannel connections from browser clients.
 * When a client sends an SDP offer (via the signaling server),
 * the gateway creates a PeerConnection, establishes a DataChannel,
 * and tunnels HTTP requests/responses over it — same format
 * as the WebSocket-based HTTP relay.
 */

import { createHmac } from "crypto";
import { PeerConnection, DataChannel } from "node-datachannel";
import { request as httpRequest } from "http";
import { request as httpsRequest } from "https";
import WebSocket from "ws";

export interface PeerHandlerOptions {
  /** STUN server for ICE, e.g. "stun:relay.example.com:3478" */
  iceServers: string[];
  /** TURN server URL, e.g. "turn:host:3478" */
  turnServer?: string;
  /** Shared secret for TURN REST API ephemeral credentials */
  turnSecret?: string;
  /** Gateway's HTTP port for local requests */
  listenPort: number;
  /** Whether the gateway is using HTTPS (self-signed) */
  useTls?: boolean;
  /** Send signaling messages (SDP answers, ICE candidates) back via WebSocket */
  sendSignaling: (msg: unknown) => void;
  /** Gateway ID — used as fromId in signaling messages */
  gatewayId: string;
}

export interface PeerHandler {
  handleSdpOffer: (clientId: string, sdp: string) => void;
  handleCandidate: (clientId: string, candidate: string, mid: string) => void;
  cleanup: () => void;
}

const MAX_PEERS = 200;
const ALLOWED_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

export function createPeerHandler(options: PeerHandlerOptions): PeerHandler {
  const peers = new Map<string, PeerConnection>();

  function handleSdpOffer(clientId: string, sdp: string): void {
    // Clean up existing peer if reconnecting
    const existing = peers.get(clientId);
    if (existing) {
      existing.close();
      peers.delete(clientId);
    }

    // Reject new peers if at capacity (reconnects already cleaned up above)
    if (peers.size >= MAX_PEERS) {
      console.warn(`[WebRTC] Peer limit reached (${MAX_PEERS}), rejecting ${clientId}`);
      return;
    }

    console.log(`[WebRTC] Creating peer for client: ${clientId}`);

    // Build ICE servers list: STUN + optional TURN with ephemeral credentials
    // node-datachannel format: "stun:host:port" or "turn:user:pass@host:port"
    const iceServers = [...options.iceServers];
    if (options.turnServer && options.turnSecret) {
      const turnHost = options.turnServer.replace(/^turn:/, "");
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      const user = `${expiry}`;
      const pass = createHmac("sha1", options.turnSecret)
        .update(user)
        .digest("base64");
      iceServers.push(`turn:${user}:${pass}@${turnHost}`);
    }
    console.log(`[WebRTC] ICE servers:`, iceServers);

    const pc = new PeerConnection(`gateway-${clientId}`, {
      iceServers,
    });

    pc.onLocalDescription((desc, type) => {
      console.log(`[WebRTC] Sending ${type} to client: ${clientId}`);
      options.sendSignaling({
        type: "sdp_answer",
        fromId: options.gatewayId,
        targetId: clientId,
        sdp: desc,
        sdpType: type,
      });
    });

    pc.onLocalCandidate((candidate, mid) => {
      console.log(`[WebRTC] Local ICE candidate: ${candidate}`);
      options.sendSignaling({
        type: "candidate",
        fromId: options.gatewayId,
        targetId: clientId,
        candidate: { candidate, mid },
      });
    });

    pc.onStateChange((state) => {
      console.log(`[WebRTC] Peer ${clientId} state: ${state}`);
      if (state === "connected") {
        // Report connection type to STUN server
        try {
          const pair = pc.getSelectedCandidatePair();
          const candidateType = pair?.local?.type || "unknown";
          const connectionType = candidateType === "relay" ? "turn" : "p2p";
          console.log(`[WebRTC] Peer ${clientId} connected via ${connectionType} (candidate: ${candidateType})`);
          options.sendSignaling({
            type: "client_status",
            clientId,
            connectionType,
          });
        } catch {
          // Fallback — report as p2p if we can't determine
          options.sendSignaling({
            type: "client_status",
            clientId,
            connectionType: "p2p",
          });
        }
      }
      if (state === "closed" || state === "failed") {
        peers.delete(clientId);
      }
    });

    pc.onDataChannel((dc) => {
      console.log(`[WebRTC] DataChannel opened with client: ${clientId} (label: ${dc.getLabel()})`);
      const wsConnections = new Map<string, WebSocket>();

      dc.onMessage((msg) => {
        try {
          const parsed = JSON.parse(typeof msg === "string" ? msg : msg.toString());
          if (parsed.type === "http_request") {
            handleDataChannelRequest(dc, parsed);
          } else if (parsed.type === "ws_open") {
            handleWsOpen(dc, parsed, wsConnections);
          } else if (parsed.type === "ws_message") {
            const ws = wsConnections.get(parsed.id);
            if (ws && ws.readyState === WebSocket.OPEN) {
              ws.send(parsed.binary ? Buffer.from(parsed.data, "base64") : parsed.data);
            }
          } else if (parsed.type === "ws_close") {
            const ws = wsConnections.get(parsed.id);
            if (ws) ws.close(parsed.code || 1000, parsed.reason || "");
          }
        } catch {
          console.error("[WebRTC] Failed to parse DataChannel message");
        }
      });

      dc.onClosed(() => {
        console.log(`[WebRTC] DataChannel closed with client: ${clientId}`);
        for (const [, ws] of wsConnections) {
          try { ws.close(); } catch {}
        }
        wsConnections.clear();
      });
    });

    pc.setRemoteDescription(sdp, "offer");
    peers.set(clientId, pc);
  }

  function handleCandidate(clientId: string, candidate: string, mid: string): void {
    console.log(`[WebRTC] Remote ICE candidate from ${clientId}: ${candidate}`);
    const pc = peers.get(clientId);
    if (pc) {
      pc.addRemoteCandidate(candidate, mid);
    }
  }

  /** Content types that should be streamed chunk-by-chunk instead of buffered */
  function isStreamingResponse(res: import("http").IncomingMessage): boolean {
    const ct = (res.headers["content-type"] || "").toLowerCase();
    return ct.includes("text/event-stream")
      || ct.includes("application/x-ndjson")
      || (ct.includes("text/plain") && res.headers["transfer-encoding"] === "chunked");
  }

  // Responses smaller than this are sent as a single DC message;
  // larger responses are streamed progressively.
  const MAX_SINGLE_MSG = 200_000;

  /**
   * Handle an HTTP request received over DataChannel.
   * Small responses are buffered and sent as a single message.
   * Large responses (video, downloads) and streaming content (SSE, NDJSON)
   * are forwarded progressively as data arrives from the backend.
   */
  function handleDataChannelRequest(
    dc: DataChannel,
    msg: { id: string; method?: string; url?: string; headers?: Record<string, string | string[]>; body?: string }
  ): void {
    const requestId = msg.id;
    const method = msg.method || "GET";
    const url = msg.url || "/";
    const headers = msg.headers || {};
    const bodyB64 = msg.body || "";

    // Validate URL path — must start with / and contain no CRLF (header injection)
    if (!url.startsWith("/") || /[\r\n]/.test(url)) {
      if (dc.isOpen()) {
        dc.sendMessageBinary(Buffer.from(JSON.stringify({
          type: "http_response",
          id: requestId,
          statusCode: 400,
          headers: { "content-type": "application/json" },
          body: Buffer.from(JSON.stringify({ error: "Invalid URL" })).toString("base64"),
        })));
      }
      return;
    }

    // Validate HTTP method
    if (!ALLOWED_METHODS.has(method.toUpperCase())) {
      if (dc.isOpen()) {
        dc.sendMessageBinary(Buffer.from(JSON.stringify({
          type: "http_response",
          id: requestId,
          statusCode: 405,
          headers: { "content-type": "application/json" },
          body: Buffer.from(JSON.stringify({ error: "Method not allowed" })).toString("base64"),
        })));
      }
      return;
    }

    console.log(`[WebRTC] DC request: ${method} ${url} cookie=${!!(headers as Record<string, unknown>).cookie} headers=${Object.keys(headers).join(',')}`);

    // Limit decoded body size to 10MB to prevent OOM
    const MAX_BODY_SIZE = 10 * 1024 * 1024;
    if (bodyB64 && bodyB64.length > MAX_BODY_SIZE * 1.37) {
      if (dc.isOpen()) {
        dc.sendMessageBinary(Buffer.from(JSON.stringify({
          type: "http_response",
          id: requestId,
          statusCode: 413,
          headers: { "content-type": "application/json" },
          body: Buffer.from(JSON.stringify({ error: "Request body too large" })).toString("base64"),
        })));
      }
      return;
    }
    const bodyBuf = bodyB64 ? Buffer.from(bodyB64, "base64") : undefined;

    // Mark as DataChannel request so the HTTP proxy can use the backend cookie jar
    (headers as Record<string, string>)["x-dc-request"] = "1";
    // Don't forward accept-encoding — we send raw bytes over DC, compression
    // breaks Content-Range offsets and confuses browser media pipelines.
    delete (headers as Record<string, unknown>)["accept-encoding"];

    const makeReq = options.useTls ? httpsRequest : httpRequest;
    const req = makeReq(
      {
        hostname: "127.0.0.1",
        port: options.listenPort,
        path: url,
        method,
        headers: headers as Record<string, string | string[]>,
        rejectUnauthorized: false,
      },
      (res) => {
        // Collect response headers, stripping hop-by-hop headers that are
        // meaningless for SW-constructed Responses and can confuse Chrome
        // (e.g. transfer-encoding: chunked would make Chrome try to
        // chunk-decode an already-decoded body).
        const HOP_BY_HOP = new Set(["transfer-encoding", "connection", "keep-alive", "te", "trailer", "upgrade"]);
        const responseHeaders: Record<string, string | string[]> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (value !== undefined && !HOP_BY_HOP.has(key)) {
            responseHeaders[key] = value as string | string[];
          }
        }

        // Determine response mode:
        // - Small responses (< MAX_SINGLE_MSG): buffer and send as single message
        // - Large or streaming: progressive streaming over DataChannel
        const contentLength = parseInt(res.headers["content-length"] || "0", 10);
        const isLive = isStreamingResponse(res);
        const useStreaming = isLive || contentLength > MAX_SINGLE_MSG / 2;

        if (useStreaming) {
          // Stream response progressively — works for SSE, video, large files
          console.log(`[WebRTC] Streaming DC response: ${res.statusCode} for ${url} (${contentLength || "unknown"} bytes, live=${isLive})`);
          if (!dc.isOpen()) return;

          // Queue-based sending with flow control.
          // All messages sent as binary to avoid SCTP PPID confusion.
          const DC_MAX_BUFFER = 65_536;
          const queue: { binary: Buffer }[] = [];
          let scheduled = false;

          const flush = (): void => {
            scheduled = false;
            while (queue.length > 0) {
              if (!dc.isOpen()) { req.destroy(); return; }
              if (dc.bufferedAmount() > DC_MAX_BUFFER) {
                res.pause();
                scheduled = true;
                setTimeout(flush, 5);
                return;
              }
              try {
                const sent = dc.sendMessageBinary(queue[0].binary);
                if (!sent) {
                  res.pause();
                  scheduled = true;
                  setTimeout(flush, 10);
                  return;
                }
              } catch {
                req.destroy();
                return;
              }
              queue.shift();
            }
            res.resume();
          }

          // All streaming messages are sent as binary to avoid SCTP PPID
          // confusion when interleaving text (PPID 51) and binary (PPID 53).
          // Control messages are JSON in a Buffer; chunk data uses requestId prefix.
          // The browser detects JSON by checking if the first byte is '{'.
          let chunksSent = 0;

          // Start message — JSON as binary
          // live=true for SSE/NDJSON (client uses ReadableStream)
          // live=false for large responses like video (client buffers then delivers complete)
          queue.push({ binary: Buffer.from(JSON.stringify({
            type: "http_response_start",
            id: requestId,
            statusCode: res.statusCode || 200,
            headers: responseHeaders,
            streaming: true,
            live: isLive,
          })) });
          flush();

          res.on("data", (chunk: Buffer) => {
            if (!dc.isOpen()) { req.destroy(); return; }
            // Binary chunk: 36-byte requestId prefix + raw bytes (no base64)
            const idBuf = Buffer.from(requestId, "ascii");
            queue.push({ binary: Buffer.concat([idBuf, chunk]) });
            chunksSent++;
            if (!scheduled) flush();
          });

          res.on("end", () => {
            console.log(`[WebRTC] Streaming complete for ${url}: ${chunksSent} chunks sent`);
            // End message — JSON as binary
            queue.push({ binary: Buffer.from(JSON.stringify({ type: "http_response_end", id: requestId })) });
            if (!scheduled) flush();
          });

          res.on("error", (err) => {
            console.error(`[WebRTC] Streaming response error for ${url}: ${err.message}`);
            queue.push({ binary: Buffer.from(JSON.stringify({ type: "http_response_end", id: requestId })) });
            if (!scheduled) flush();
          });
        } else {
          // Small response: buffer and send as single message (binary to avoid PPID confusion)
          const chunks: Buffer[] = [];
          let totalResponseSize = 0;
          const MAX_BUFFERED = 50 * 1024 * 1024; // 50MB
          let aborted = false;
          res.on("data", (chunk: Buffer) => {
            totalResponseSize += chunk.length;
            if (totalResponseSize > MAX_BUFFERED) {
              if (!aborted) {
                aborted = true;
                req.destroy();
                if (dc.isOpen()) {
                  dc.sendMessageBinary(Buffer.from(JSON.stringify({
                    type: "http_response", id: requestId, statusCode: 502,
                    headers: { "content-type": "application/json" },
                    body: Buffer.from('{"error":"Response too large"}').toString("base64"),
                  })));
                }
              }
              return;
            }
            chunks.push(chunk);
          });
          res.on("end", () => {
            if (aborted || !dc.isOpen()) return;
            const responseBody = Buffer.concat(chunks).toString("base64");
            dc.sendMessageBinary(Buffer.from(JSON.stringify({
              type: "http_response",
              id: requestId,
              statusCode: res.statusCode || 500,
              headers: responseHeaders,
              body: responseBody,
            })));
          });
        }
      }
    );

    req.setTimeout(30000, () => {
      req.destroy();
      if (dc.isOpen()) {
        dc.sendMessageBinary(Buffer.from(JSON.stringify({
          type: "http_response",
          id: requestId,
          statusCode: 504,
          headers: { "content-type": "application/json" },
          body: Buffer.from(JSON.stringify({ error: "Gateway timeout" })).toString("base64"),
        })));
      }
    });

    req.on("error", (err) => {
      console.error(`[WebRTC] Local request failed: ${err.message}`);
      if (dc.isOpen()) {
        dc.sendMessageBinary(Buffer.from(JSON.stringify({
          type: "http_response",
          id: requestId,
          statusCode: 502,
          headers: { "content-type": "application/json" },
          body: Buffer.from(JSON.stringify({ error: "Gateway internal error" })).toString("base64"),
        })));
      }
    });

    if (bodyBuf && bodyBuf.length > 0) {
      req.end(bodyBuf);
    } else {
      req.end();
    }
  }

  const MAX_WS_PER_DC = 50;

  function handleWsOpen(
    dc: DataChannel,
    msg: { id: string; url?: string; protocols?: string[]; headers?: Record<string, string> },
    wsConnections: Map<string, WebSocket>
  ): void {
    if (wsConnections.size >= MAX_WS_PER_DC) {
      if (dc.isOpen()) {
        dc.sendMessageBinary(Buffer.from(JSON.stringify({ type: "ws_error", id: msg.id, message: "Too many WebSocket connections" })));
      }
      return;
    }

    const wsPath = msg.url || "/";
    if (!wsPath.startsWith("/") || /[\r\n]/.test(wsPath)) {
      if (dc.isOpen()) {
        dc.sendMessageBinary(Buffer.from(JSON.stringify({ type: "ws_error", id: msg.id, message: "Invalid URL" })));
      }
      return;
    }

    const protocol = options.useTls ? "wss" : "ws";
    const wsUrl = `${protocol}://127.0.0.1:${options.listenPort}${wsPath}`;
    const headers: Record<string, string> = { ...(msg.headers || {}) };
    headers["x-dc-request"] = "1";

    const ws = new WebSocket(wsUrl, msg.protocols || [], {
      rejectUnauthorized: false,
      headers,
    });

    ws.on("open", () => {
      if (dc.isOpen()) {
        dc.sendMessageBinary(Buffer.from(JSON.stringify({ type: "ws_opened", id: msg.id, protocol: ws.protocol || "" })));
      }
    });

    ws.on("message", (data: Buffer, isBinary: boolean) => {
      if (!dc.isOpen()) { ws.close(); return; }
      dc.sendMessageBinary(Buffer.from(JSON.stringify({
        type: "ws_message",
        id: msg.id,
        data: isBinary ? data.toString("base64") : data.toString("utf-8"),
        binary: isBinary,
      })));
    });

    ws.on("close", (code: number, reason: Buffer) => {
      wsConnections.delete(msg.id);
      if (dc.isOpen()) {
        dc.sendMessageBinary(Buffer.from(JSON.stringify({ type: "ws_close", id: msg.id, code, reason: reason.toString() })));
      }
    });

    ws.on("error", (err: Error) => {
      wsConnections.delete(msg.id);
      if (dc.isOpen()) {
        dc.sendMessageBinary(Buffer.from(JSON.stringify({ type: "ws_error", id: msg.id, message: err.message })));
      }
    });

    wsConnections.set(msg.id, ws);
    console.log(`[WebRTC] WS tunnel opened: ${msg.url} (id: ${msg.id})`);
  }

  function cleanup(): void {
    for (const [id, pc] of peers) {
      pc.close();
    }
    peers.clear();
  }

  return { handleSdpOffer, handleCandidate, cleanup };
}
