/**
 * WebRTC peer connection handler.
 *
 * Manages WebRTC DataChannel connections from browser clients.
 * When a client sends an SDP offer (via the signaling server),
 * the gateway creates a PeerConnection, establishes a DataChannel,
 * and tunnels HTTP requests/responses over it — same format
 * as the WebSocket-based HTTP relay.
 *
 * Supports dual DataChannels for high-throughput scenarios (4K video, gaming):
 *   - "http-tunnel" (control): JSON control messages, small responses
 *   - "bulk-data" (bulk): binary streaming chunks, binary WebSocket frames
 * Falls back to single-channel mode for older clients.
 */

import { createHmac } from "crypto";
import { connect as netConnect, type Socket } from "net";
import { PeerConnection, DataChannel, setSctpSettings } from "node-datachannel";
import { request as httpRequest } from "http";
import { request as httpsRequest } from "https";
import WebSocket from "ws";
import type { JWTPayload } from "jose";
import type { BackendEntry } from "../config.js";
import { createRDCleanPathSession, type RDCleanPathSession } from "../rdcleanpath/rdcleanpath-handler.js";

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
  /** Backend configurations (for TCP tunnel target resolution) */
  backends: BackendEntry[];
  /** JWT verification function (for RDCleanPath auth) */
  verifyToken?: (token: string) => Promise<JWTPayload | null>;
  /** TideCloak client ID for dest: role extraction */
  tcClientId?: string;
}

export interface PeerHandler {
  handleSdpOffer: (clientId: string, sdp: string) => void;
  handleCandidate: (clientId: string, candidate: string, mid: string) => void;
  cleanup: () => void;
}

const MAX_PEERS = 200;
const ALLOWED_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

// Buffer thresholds — separate for control (small JSON) and bulk (streaming data)
const CONTROL_MAX_BUFFER = 512_000;     // 512KB for control channel
const BULK_MAX_BUFFER    = 4_194_304;   // 4MB for bulk channel — keeps pipe full for 4K video

// Chunk coalescing: batch small HTTP response chunks into larger DC messages
const COALESCE_TARGET  = 65_536; // 64KB target coalesced message size
const COALESCE_TIMEOUT = 1;      // 1ms max coalescing delay

// Binary WebSocket fast-path magic byte (avoids JSON+base64 overhead for gaming)
const BINARY_WS_MAGIC = 0x02;
// TCP tunnel binary fast-path magic byte
const TCP_TUNNEL_MAGIC = 0x03;
const MAX_TCP_PER_DC = 5;

// Tune SCTP buffers for high-throughput streaming
let sctpConfigured = false;
function ensureSctpSettings(): void {
  if (sctpConfigured) return;
  sctpConfigured = true;
  try {
    setSctpSettings({
      sendBufferSize: 8 * 1024 * 1024,      // 8MB send buffer
      recvBufferSize: 8 * 1024 * 1024,      // 8MB receive buffer
      maxChunksOnQueue: 65536,               // up from default 8192
      initialCongestionWindow: 32,            // faster ramp-up
    });
  } catch {
    // setSctpSettings may fail if PeerConnections already exist
  }
}

/** Per-peer state shared between control and bulk channels. */
interface PeerState {
  wsConnections: Map<string, WebSocket>;
  tcpConnections: Map<string, Socket>;
  rdcleanpathSessions: Map<string, RDCleanPathSession>;
  capabilities: Set<string>;
  controlDc: DataChannel | null;
  bulkDc: DataChannel | null;
  controlQueue: Buffer[];
  bulkQueue: Buffer[];
  controlPaused: boolean;
  bulkPaused: boolean;
  pausedStreams: Set<import("http").IncomingMessage>;
}

export function createPeerHandler(options: PeerHandlerOptions): PeerHandler {
  ensureSctpSettings();

  const peers = new Map<string, PeerConnection>();
  const peerStates = new Map<string, PeerState>();

  function getPeerState(clientId: string): PeerState {
    let state = peerStates.get(clientId);
    if (!state) {
      state = {
        wsConnections: new Map(),
        tcpConnections: new Map(),
        rdcleanpathSessions: new Map(),
        capabilities: new Set(),
        controlDc: null,
        bulkDc: null,
        controlQueue: [],
        bulkQueue: [],
        controlPaused: false,
        bulkPaused: false,
        pausedStreams: new Set(),
      };
      peerStates.set(clientId, state);
    }
    return state;
  }

  // --- Shared send-queue helpers with event-driven flow control ---

  function setupFlowControl(dc: DataChannel, queue: Buffer[], maxBuffer: number, getPaused: () => boolean, setPaused: (v: boolean) => void, state: PeerState): void {
    dc.setBufferedAmountLowThreshold(maxBuffer / 4);
    dc.onBufferedAmountLow(() => {
      if (getPaused()) {
        setPaused(false);
        drainQueue(dc, queue, maxBuffer, getPaused, setPaused, state);
      }
    });
  }

  function drainQueue(dc: DataChannel, queue: Buffer[], maxBuffer: number, getPaused: () => boolean, setPaused: (v: boolean) => void, state: PeerState): void {
    while (queue.length > 0) {
      if (!dc.isOpen()) return;
      if (dc.bufferedAmount() > maxBuffer) {
        setPaused(true);
        // Pause all in-flight HTTP response streams
        for (const stream of state.pausedStreams) {
          stream.pause();
        }
        return;
      }
      try {
        const sent = dc.sendMessageBinary(queue[0]);
        if (!sent) {
          setPaused(true);
          return;
        }
      } catch {
        return;
      }
      queue.shift();
    }
    // Queue drained — resume any paused streams
    for (const stream of state.pausedStreams) {
      stream.resume();
    }
  }

  function enqueueControl(state: PeerState, buf: Buffer): void {
    const dc = state.controlDc;
    if (!dc || !dc.isOpen()) return;
    state.controlQueue.push(buf);
    if (!state.controlPaused) {
      drainQueue(dc, state.controlQueue, CONTROL_MAX_BUFFER,
        () => state.controlPaused, (v) => { state.controlPaused = v; }, state);
    }
  }

  function enqueueBulk(state: PeerState, buf: Buffer): void {
    // Use bulk channel if available, otherwise fall back to control
    const dc = state.bulkDc && state.bulkDc.isOpen() ? state.bulkDc : state.controlDc;
    if (!dc || !dc.isOpen()) return;

    if (dc === state.bulkDc) {
      state.bulkQueue.push(buf);
      if (!state.bulkPaused) {
        drainQueue(dc, state.bulkQueue, BULK_MAX_BUFFER,
          () => state.bulkPaused, (v) => { state.bulkPaused = v; }, state);
      }
    } else {
      // Fallback to control channel (single-channel mode)
      enqueueControl(state, buf);
    }
  }

  // --- Channel setup ---

  function handleSdpOffer(clientId: string, sdp: string): void {
    // Clean up existing peer if reconnecting
    const existing = peers.get(clientId);
    if (existing) {
      existing.close();
      peers.delete(clientId);
      peerStates.delete(clientId);
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
        peerStates.delete(clientId);
      }
    });

    pc.onDataChannel((dc) => {
      const label = dc.getLabel();
      console.log(`[WebRTC] DataChannel opened with client: ${clientId} (label: ${label})`);

      if (label === "http-tunnel") {
        setupControlChannel(dc, clientId);
      } else if (label === "bulk-data") {
        setupBulkChannel(dc, clientId);
      } else {
        console.warn(`[WebRTC] Unknown DataChannel label: ${label}, treating as control`);
        setupControlChannel(dc, clientId);
      }
    });

    pc.setRemoteDescription(sdp, "offer");
    peers.set(clientId, pc);
  }

  const GATEWAY_FEATURES = ["bulk-channel", "binary-ws", "tcp-tunnel"];

  function sendCapabilities(state: PeerState): void {
    enqueueControl(state, Buffer.from(JSON.stringify({
      type: "capabilities",
      version: 2,
      features: GATEWAY_FEATURES,
    })));
  }

  function setupControlChannel(dc: DataChannel, clientId: string): void {
    const state = getPeerState(clientId);
    state.controlDc = dc;

    setupFlowControl(dc, state.controlQueue, CONTROL_MAX_BUFFER,
      () => state.controlPaused, (v) => { state.controlPaused = v; }, state);

    // Send capabilities proactively as soon as the channel is open —
    // don't wait for the client to ask (message could be lost or delayed).
    if (dc.isOpen()) {
      console.log(`[WebRTC] Sending proactive capabilities to ${clientId}`);
      sendCapabilities(state);
    }
    dc.onOpen(() => {
      console.log(`[WebRTC] Control channel fully open for ${clientId}, sending capabilities`);
      sendCapabilities(state);
    });

    dc.onMessage((msg) => {
      try {
        const parsed = JSON.parse(typeof msg === "string" ? msg : Buffer.from(msg as ArrayBuffer).toString());
        if (parsed.type === "http_request") {
          handleDataChannelRequest(state, parsed);
        } else if (parsed.type === "ws_open") {
          handleWsOpen(state, parsed);
        } else if (parsed.type === "ws_message") {
          const rdcp = state.rdcleanpathSessions.get(parsed.id);
          if (rdcp) {
            rdcp.handleMessage(parsed.binary ? Buffer.from(parsed.data, "base64") : Buffer.from(parsed.data));
          } else {
            const ws = state.wsConnections.get(parsed.id);
            if (ws && ws.readyState === WebSocket.OPEN) {
              ws.send(parsed.binary ? Buffer.from(parsed.data, "base64") : parsed.data);
            }
          }
        } else if (parsed.type === "ws_close") {
          const rdcp = state.rdcleanpathSessions.get(parsed.id);
          if (rdcp) {
            rdcp.close();
            state.rdcleanpathSessions.delete(parsed.id);
          } else {
            const ws = state.wsConnections.get(parsed.id);
            if (ws) ws.close(parsed.code || 1000, parsed.reason || "");
          }
        } else if (parsed.type === "eddsa_response") {
          // Route EdDSA signature response to the correct RDCleanPath session
          const rdcpSession = state.rdcleanpathSessions.get(parsed.sessionId);
          if (rdcpSession?.handleEddsaResponse) {
            rdcpSession.handleEddsaResponse(
              Buffer.from(parsed.signature, "base64"),
              Buffer.from(parsed.publicKey, "base64"),
            );
          } else {
            console.warn(`[WebRTC] eddsa_response for unknown session: ${parsed.sessionId}`);
          }
        } else if (parsed.type === "tcp_open") {
          handleTcpOpen(state, parsed);
        } else if (parsed.type === "tcp_close") {
          handleTcpClose(state, parsed.id);
        } else if (parsed.type === "capabilities") {
          // Client capability handshake — respond with our supported features
          const clientFeatures: string[] = parsed.features || [];
          for (const f of clientFeatures) {
            if (GATEWAY_FEATURES.includes(f)) state.capabilities.add(f);
          }
          console.log(`[WebRTC] Client ${clientId} capabilities: ${[...state.capabilities].join(", ")}`);
          // Reply (client may have missed the proactive announcement)
          sendCapabilities(state);
        }
      } catch (err) {
        console.error("[WebRTC] DataChannel message error:", err instanceof Error ? err.message : err);
      }
    });

    dc.onClosed(() => {
      console.log(`[WebRTC] Control channel closed with client: ${clientId}`);
      for (const [, ws] of state.wsConnections) {
        try { ws.close(); } catch {}
      }
      state.wsConnections.clear();
      for (const [, sock] of state.tcpConnections) {
        try { sock.destroy(); } catch {}
      }
      state.tcpConnections.clear();
      for (const [, session] of state.rdcleanpathSessions) {
        try { session.close(); } catch {}
      }
      state.rdcleanpathSessions.clear();
      state.controlDc = null;
    });
  }

  function setupBulkChannel(dc: DataChannel, clientId: string): void {
    const state = getPeerState(clientId);
    state.bulkDc = dc;

    setupFlowControl(dc, state.bulkQueue, BULK_MAX_BUFFER,
      () => state.bulkPaused, (v) => { state.bulkPaused = v; }, state);

    dc.onMessage((msg) => {
      const buf = Buffer.isBuffer(msg) ? msg : Buffer.from(msg as ArrayBuffer);
      if (buf.length < 1) return;

      // Binary WS fast-path: [0x02][36-byte WS UUID][payload]
      if (buf[0] === BINARY_WS_MAGIC && buf.length >= 37) {
        const wsId = buf.toString("ascii", 1, 37);
        const payload = buf.subarray(37);
        // Check RDCleanPath sessions first (virtual WS)
        const rdcp = state.rdcleanpathSessions.get(wsId);
        if (rdcp) {
          rdcp.handleMessage(payload);
          return;
        }
        const ws = state.wsConnections.get(wsId);
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(payload);
        }
        return;
      }

      // TCP tunnel fast-path: [0x03][36-byte tunnel UUID][payload]
      if (buf[0] === TCP_TUNNEL_MAGIC && buf.length >= 37) {
        const tunnelId = buf.toString("ascii", 1, 37);
        const payload = buf.subarray(37);
        const sock = state.tcpConnections.get(tunnelId);
        if (sock && !sock.destroyed) {
          sock.write(payload);
        }
        return;
      }

      // Other binary messages on bulk channel (shouldn't happen but handle gracefully)
      try {
        const parsed = JSON.parse(buf.toString());
        if (parsed.type === "ws_message") {
          const ws = state.wsConnections.get(parsed.id);
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(parsed.binary ? Buffer.from(parsed.data, "base64") : parsed.data);
          }
        }
      } catch {
        // Not JSON, ignore
      }
    });

    dc.onClosed(() => {
      console.log(`[WebRTC] Bulk channel closed with client: ${clientId}`);
      state.bulkDc = null;
    });
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

  /** Binary content types that should always stream (not buffer + base64) */
  function isBinaryContent(res: import("http").IncomingMessage): boolean {
    const ct = (res.headers["content-type"] || "").toLowerCase();
    return ct.startsWith("image/")
      || ct.startsWith("video/")
      || ct.startsWith("audio/")
      || ct.startsWith("font/")
      || ct.includes("application/octet-stream")
      || ct.includes("application/wasm")
      || ct.includes("application/zip")
      || ct.includes("application/pdf");
  }

  // Responses smaller than this are sent as a single DC message (base64 on control);
  // larger responses are streamed progressively as binary via bulk channel.
  const MAX_SINGLE_MSG = 32_000; // 32KB — API JSON fits; images stream

  /**
   * Handle an HTTP request received over DataChannel.
   * Small responses are buffered and sent as a single message.
   * Large responses (video, downloads) and streaming content (SSE, NDJSON)
   * are forwarded progressively as data arrives from the backend.
   */
  function handleDataChannelRequest(
    state: PeerState,
    msg: { id: string; method?: string; url?: string; headers?: Record<string, string | string[]>; body?: string }
  ): void {
    const requestId = msg.id;
    const method = msg.method || "GET";
    const url = msg.url || "/";
    const headers = msg.headers || {};
    const bodyB64 = msg.body || "";

    // Validate URL path — must start with / and contain no CRLF (header injection)
    if (!url.startsWith("/") || /[\r\n]/.test(url)) {
      enqueueControl(state, Buffer.from(JSON.stringify({
        type: "http_response",
        id: requestId,
        statusCode: 400,
        headers: { "content-type": "application/json" },
        body: Buffer.from(JSON.stringify({ error: "Invalid URL" })).toString("base64"),
      })));
      return;
    }

    // Validate HTTP method
    if (!ALLOWED_METHODS.has(method.toUpperCase())) {
      enqueueControl(state, Buffer.from(JSON.stringify({
        type: "http_response",
        id: requestId,
        statusCode: 405,
        headers: { "content-type": "application/json" },
        body: Buffer.from(JSON.stringify({ error: "Method not allowed" })).toString("base64"),
      })));
      return;
    }

    console.log(`[WebRTC] DC request: ${method} ${url} cookie=${!!(headers as Record<string, unknown>).cookie} headers=${Object.keys(headers).join(',')}`);

    // Limit decoded body size to 10MB to prevent OOM
    const MAX_BODY_SIZE = 10 * 1024 * 1024;
    if (bodyB64 && bodyB64.length > MAX_BODY_SIZE * 1.37) {
      enqueueControl(state, Buffer.from(JSON.stringify({
        type: "http_response",
        id: requestId,
        statusCode: 413,
        headers: { "content-type": "application/json" },
        body: Buffer.from(JSON.stringify({ error: "Request body too large" })).toString("base64"),
      })));
      return;
    }
    const bodyBuf = bodyB64 ? Buffer.from(bodyB64, "base64") : undefined;

    // Mark as DataChannel request so the HTTP proxy can use the backend cookie jar
    (headers as Record<string, string>)["x-dc-request"] = "1";
    // Don't forward accept-encoding — we send raw bytes over DC, compression
    // breaks Content-Range offsets and confuses browser media pipelines.
    delete (headers as Record<string, unknown>)["accept-encoding"];
    // Strip conditional headers — DC responses bypass the browser's HTTP
    // cache, so 304 responses produce null-body Responses in the Service
    // Worker that the browser can't match to a cache entry.
    delete (headers as Record<string, unknown>)["if-none-match"];
    delete (headers as Record<string, unknown>)["if-modified-since"];

    // Cap Range request size for DataChannel responses.
    // Non-live responses (video) are buffered on the client before delivery
    // (Chrome's <video> can't consume ReadableStream 206 from Service Workers).
    // Without capping, a multi-GB video would be buffered entirely in memory.
    // The browser naturally makes follow-up Range requests for remaining data.
    const DC_MAX_RANGE = 5 * 1024 * 1024; // 5MB per range response
    const rangeHeader = (headers as Record<string, string>).range;
    if (typeof rangeHeader === "string") {
      const rangeMatch = rangeHeader.match(/bytes=(\d+)-(\d*)/);
      if (rangeMatch) {
        const rangeStart = parseInt(rangeMatch[1]);
        const rangeEnd = rangeMatch[2] ? parseInt(rangeMatch[2]) : Infinity;
        if (rangeEnd - rangeStart + 1 > DC_MAX_RANGE || rangeEnd === Infinity) {
          const cappedEnd = rangeStart + DC_MAX_RANGE - 1;
          (headers as Record<string, string>).range = `bytes=${rangeStart}-${cappedEnd}`;
        }
      }
    }

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
        // Strip transport-layer headers that are meaningless for DC delivery.
        // content-encoding: DC sends raw bytes, browser must not attempt decompression.
        // content-length: SW constructs Response from actual bytes; a mismatched
        //   header value can confuse the browser or truncate the body.
        const HOP_BY_HOP = new Set([
          "transfer-encoding", "connection", "keep-alive", "te", "trailer", "upgrade",
          "content-encoding", "content-length",
        ]);
        const responseHeaders: Record<string, string | string[]> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (value !== undefined && !HOP_BY_HOP.has(key)) {
            responseHeaders[key] = value as string | string[];
          }
        }

        // Determine response mode:
        // - Small text/JSON responses: buffer and send as single base64 message on control
        // - Large, binary, or streaming: progressive binary streaming via bulk channel
        // Key: binary content (images, video, etc.) ALWAYS streams — even without
        // content-length (chunked transfer). This prevents oversized SCTP messages
        // (256KB limit) and eliminates base64 overhead for binary data.
        const contentLength = parseInt(res.headers["content-length"] || "0", 10);
        const isLive = isStreamingResponse(res);
        const isBinary = isBinaryContent(res);
        const useStreaming = isLive || contentLength > MAX_SINGLE_MSG / 2 || isBinary;

        if (useStreaming) {
          // Stream response progressively — works for SSE, video, large files
          console.log(`[WebRTC] Streaming DC response: ${res.statusCode} for ${url} (${contentLength || "unknown"} bytes, live=${isLive})`);
          const controlDc = state.controlDc;
          if (!controlDc || !controlDc.isOpen()) return;

          // Track this stream for backpressure pause/resume
          state.pausedStreams.add(res);

          let chunksSent = 0;

          // Send a lightweight ack on the CONTROL channel so the client can
          // extend its timeout immediately — the bulk queue may be congested
          // with other streaming data, which could delay http_response_start
          // past the client's 15-second initial timeout.
          enqueueControl(state, Buffer.from(JSON.stringify({
            type: "http_response_ack",
            id: requestId,
          })));

          // Send start on BULK channel so it's ordered with data chunks and end marker.
          // All three (start, data, end) must be on the same channel to prevent
          // cross-channel race conditions. enqueueBulk falls back to control
          // when no bulk channel is available (single-channel mode).
          enqueueBulk(state, Buffer.from(JSON.stringify({
            type: "http_response_start",
            id: requestId,
            statusCode: res.statusCode || 200,
            headers: responseHeaders,
            streaming: true,
            live: isLive,
          })));

          if (isLive) {
            // Live streams (SSE/NDJSON): send chunks immediately, no coalescing
            res.on("data", (chunk: Buffer) => {
              if (!controlDc.isOpen()) { req.destroy(); return; }
              const idBuf = Buffer.from(requestId, "ascii");
              enqueueBulk(state, Buffer.concat([idBuf, chunk]));
              chunksSent++;
            });
          } else {
            // Non-live (video, large files): coalesce small chunks into larger messages
            const idBuf = Buffer.from(requestId, "ascii");
            let coalesceBuffers: Buffer[] = [];
            let coalesceSize = 0;
            let coalesceTimer: ReturnType<typeof setTimeout> | null = null;

            const flushCoalesce = (): void => {
              if (coalesceTimer) { clearTimeout(coalesceTimer); coalesceTimer = null; }
              if (coalesceBuffers.length === 0) return;
              const payload = coalesceBuffers.length === 1
                ? coalesceBuffers[0]
                : Buffer.concat(coalesceBuffers);
              enqueueBulk(state, Buffer.concat([idBuf, payload]));
              coalesceBuffers = [];
              coalesceSize = 0;
              chunksSent++;
            };

            res.on("data", (chunk: Buffer) => {
              if (!controlDc.isOpen()) { req.destroy(); return; }
              coalesceBuffers.push(chunk);
              coalesceSize += chunk.length;
              if (coalesceSize >= COALESCE_TARGET) {
                flushCoalesce();
              } else if (!coalesceTimer) {
                coalesceTimer = setTimeout(flushCoalesce, COALESCE_TIMEOUT);
              }
            });

            res.on("end", () => {
              flushCoalesce();
            });

            res.on("error", () => {
              flushCoalesce();
            });
          }

          res.on("end", () => {
            state.pausedStreams.delete(res);
            console.log(`[WebRTC] Streaming complete for ${url}: ${chunksSent} chunks sent`);
            // Send end marker on BULK channel so it arrives AFTER all data chunks
            // (control and bulk are independent SCTP streams with no cross-ordering).
            // enqueueBulk falls back to control when no bulk channel is available.
            enqueueBulk(state, Buffer.from(JSON.stringify({ type: "http_response_end", id: requestId })));
          });

          res.on("error", (err) => {
            state.pausedStreams.delete(res);
            console.error(`[WebRTC] Streaming response error for ${url}: ${err.message}`);
            enqueueBulk(state, Buffer.from(JSON.stringify({ type: "http_response_end", id: requestId })));
          });
        } else {
          // Small text/JSON response: buffer and send as single base64 message.
          // Binary content always takes the streaming path above, so this
          // branch only handles API responses, HTML fragments, etc.
          const chunks: Buffer[] = [];
          let totalResponseSize = 0;
          const MAX_BUFFERED = 10 * 1024 * 1024; // 10MB safety limit
          let aborted = false;
          res.on("data", (chunk: Buffer) => {
            totalResponseSize += chunk.length;
            if (totalResponseSize > MAX_BUFFERED) {
              if (!aborted) {
                aborted = true;
                req.destroy();
                enqueueControl(state, Buffer.from(JSON.stringify({
                  type: "http_response", id: requestId, statusCode: 502,
                  headers: { "content-type": "application/json" },
                  body: Buffer.from('{"error":"Response too large"}').toString("base64"),
                })));
              }
              return;
            }
            chunks.push(chunk);
          });
          res.on("end", () => {
            if (aborted) return;
            const body = Buffer.concat(chunks);
            enqueueControl(state, Buffer.from(JSON.stringify({
              type: "http_response",
              id: requestId,
              statusCode: res.statusCode || 200,
              headers: responseHeaders,
              body: body.toString("base64"),
            })));
          });
        }
      }
    );

    req.setTimeout(30000, () => {
      req.destroy();
      enqueueControl(state, Buffer.from(JSON.stringify({
        type: "http_response",
        id: requestId,
        statusCode: 504,
        headers: { "content-type": "application/json" },
        body: Buffer.from(JSON.stringify({ error: "Gateway timeout" })).toString("base64"),
      })));
    });

    req.on("error", (err) => {
      console.error(`[WebRTC] Local request failed: ${err.message}`);
      enqueueControl(state, Buffer.from(JSON.stringify({
        type: "http_response",
        id: requestId,
        statusCode: 502,
        headers: { "content-type": "application/json" },
        body: Buffer.from(JSON.stringify({ error: "Gateway internal error" })).toString("base64"),
      })));
    });

    if (bodyBuf && bodyBuf.length > 0) {
      req.end(bodyBuf);
    } else {
      req.end();
    }
  }

  // ── TCP tunnel handlers ────────────────────────────────────────

  function handleTcpOpen(
    state: PeerState,
    msg: { id: string; backend?: string }
  ): void {
    if (state.tcpConnections.size >= MAX_TCP_PER_DC) {
      enqueueControl(state, Buffer.from(JSON.stringify({ type: "tcp_error", id: msg.id, message: "Too many TCP tunnels" })));
      return;
    }

    // Resolve backend name → host:port (only rdp:// backends allowed)
    const backendName = msg.backend || "";
    console.log(`[WebRTC] tcp_open request: backend="${backendName}", available=[${options.backends.map(b => `${b.name}(${b.protocol})`).join(", ")}]`);
    const backend = options.backends.find((b) => b.name === backendName && b.protocol === "rdp");
    if (!backend) {
      console.warn(`[WebRTC] tcp_open rejected: no matching backend for "${backendName}"`);
      enqueueControl(state, Buffer.from(JSON.stringify({ type: "tcp_error", id: msg.id, message: "Unknown or disallowed backend" })));
      return;
    }

    // Parse rdp://host:port
    let host: string;
    let port: number;
    try {
      const url = new URL(backend.url);
      host = url.hostname;
      port = parseInt(url.port || "3389", 10);
    } catch {
      enqueueControl(state, Buffer.from(JSON.stringify({ type: "tcp_error", id: msg.id, message: "Invalid backend URL" })));
      return;
    }

    console.log(`[WebRTC] TCP tunnel opening: ${backendName} → ${host}:${port} (id: ${msg.id})`);

    const sock = netConnect({ host, port, timeout: 10000 });

    sock.on("timeout", () => {
      console.error(`[WebRTC] TCP tunnel connect timeout (${msg.id}): ${host}:${port}`);
      sock.destroy();
      state.tcpConnections.delete(msg.id);
      enqueueControl(state, Buffer.from(JSON.stringify({ type: "tcp_error", id: msg.id, message: "Connection timed out" })));
    });

    sock.on("connect", () => {
      sock.setTimeout(0); // clear timeout once connected
      console.log(`[WebRTC] TCP tunnel connected: ${msg.id} → ${host}:${port}`);
      enqueueControl(state, Buffer.from(JSON.stringify({ type: "tcp_opened", id: msg.id })));
    });

    sock.on("data", (data: Buffer) => {
      if (!state.controlDc?.isOpen()) { sock.destroy(); return; }
      const header = Buffer.alloc(37);
      header[0] = TCP_TUNNEL_MAGIC;
      header.write(msg.id, 1, "ascii");
      enqueueBulk(state, Buffer.concat([header, data]));
    });

    sock.on("close", () => {
      state.tcpConnections.delete(msg.id);
      enqueueControl(state, Buffer.from(JSON.stringify({ type: "tcp_close", id: msg.id })));
    });

    sock.on("error", (err: Error) => {
      console.error(`[WebRTC] TCP tunnel error (${msg.id}): ${err.message}`);
      state.tcpConnections.delete(msg.id);
      enqueueControl(state, Buffer.from(JSON.stringify({ type: "tcp_error", id: msg.id, message: err.message })));
    });

    state.tcpConnections.set(msg.id, sock);
  }

  function handleTcpClose(state: PeerState, tunnelId: string): void {
    const sock = state.tcpConnections.get(tunnelId);
    if (sock) {
      sock.destroy();
      state.tcpConnections.delete(tunnelId);
      console.log(`[WebRTC] TCP tunnel closed: ${tunnelId}`);
    }
  }

  // ── WebSocket tunnel handlers ──────────────────────────────────

  const MAX_WS_PER_DC = 50;

  function handleWsOpen(
    state: PeerState,
    msg: { id: string; url?: string; protocols?: string[]; headers?: Record<string, string> }
  ): void {
    if (state.wsConnections.size + state.rdcleanpathSessions.size >= MAX_WS_PER_DC) {
      enqueueControl(state, Buffer.from(JSON.stringify({ type: "ws_error", id: msg.id, message: "Too many WebSocket connections" })));
      return;
    }

    const wsPath = msg.url || "/";

    // RDCleanPath virtual WebSocket — handle in-process (no real WS)
    if (wsPath === "/ws/rdcleanpath" || wsPath.startsWith("/ws/rdcleanpath?")) {
      handleRDCleanPathWsOpen(state, msg);
      return;
    }

    if (!wsPath.startsWith("/") || /[\r\n]/.test(wsPath)) {
      enqueueControl(state, Buffer.from(JSON.stringify({ type: "ws_error", id: msg.id, message: "Invalid URL" })));
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
      enqueueControl(state, Buffer.from(JSON.stringify({ type: "ws_opened", id: msg.id, protocol: ws.protocol || "" })));
    });

    ws.on("message", (data: Buffer, isBinary: boolean) => {
      if (!state.controlDc?.isOpen()) { ws.close(); return; }

      // Binary WS fast-path: send raw binary on bulk channel (no base64/JSON)
      if (isBinary && state.capabilities.has("binary-ws") && state.bulkDc?.isOpen()) {
        const header = Buffer.alloc(37);
        header[0] = BINARY_WS_MAGIC;
        header.write(msg.id, 1, "ascii");
        enqueueBulk(state, Buffer.concat([header, data]));
      } else {
        // JSON path (text messages, or no bulk channel / binary-ws capability)
        enqueueControl(state, Buffer.from(JSON.stringify({
          type: "ws_message",
          id: msg.id,
          data: isBinary ? data.toString("base64") : data.toString("utf-8"),
          binary: isBinary,
        })));
      }
    });

    ws.on("close", (code: number, reason: Buffer) => {
      state.wsConnections.delete(msg.id);
      enqueueControl(state, Buffer.from(JSON.stringify({ type: "ws_close", id: msg.id, code, reason: reason.toString() })));
    });

    ws.on("error", (err: Error) => {
      state.wsConnections.delete(msg.id);
      enqueueControl(state, Buffer.from(JSON.stringify({ type: "ws_error", id: msg.id, message: err.message })));
    });

    state.wsConnections.set(msg.id, ws);
    console.log(`[WebRTC] WS tunnel opened: ${msg.url} (id: ${msg.id})`);
  }

  // ── RDCleanPath virtual WebSocket handler ─────────────────────

  function handleRDCleanPathWsOpen(
    state: PeerState,
    msg: { id: string; url?: string; headers?: Record<string, string> }
  ): void {
    if (!options.verifyToken) {
      enqueueControl(state, Buffer.from(JSON.stringify({ type: "ws_error", id: msg.id, message: "RDCleanPath not configured (no auth)" })));
      return;
    }

    // Send ws_opened immediately (virtual WS is always "connected")
    enqueueControl(state, Buffer.from(JSON.stringify({
      type: "ws_opened", id: msg.id, protocol: "",
    })));

    const session = createRDCleanPathSession({
      sendBinary: (data: Buffer) => {
        // Use binary WS fast-path via bulk channel when available
        if (state.capabilities.has("binary-ws") && state.bulkDc?.isOpen()) {
          const header = Buffer.alloc(37);
          header[0] = BINARY_WS_MAGIC;
          header.write(msg.id, 1, "ascii");
          enqueueBulk(state, Buffer.concat([header, data]));
        } else {
          enqueueControl(state, Buffer.from(JSON.stringify({
            type: "ws_message", id: msg.id,
            data: data.toString("base64"), binary: true,
          })));
        }
      },
      sendClose: (code: number, reason: string) => {
        state.rdcleanpathSessions.delete(msg.id);
        enqueueControl(state, Buffer.from(JSON.stringify({
          type: "ws_close", id: msg.id, code, reason,
        })));
      },
      sendEddsaChallenge: (sessionId: string, challenge: Buffer) => {
        enqueueControl(state, Buffer.from(JSON.stringify({
          type: "eddsa_challenge",
          sessionId: sessionId || msg.id,
          challenge: challenge.toString("base64"),
        })));
      },
      sessionId: msg.id,
      backends: options.backends,
      verifyToken: options.verifyToken,
      gatewayId: options.gatewayId,
      tcClientId: options.tcClientId,
    });

    state.rdcleanpathSessions.set(msg.id, session);
    console.log(`[WebRTC] RDCleanPath session opened: ${msg.id}`);
  }

  function cleanup(): void {
    for (const [id, pc] of peers) {
      pc.close();
    }
    peers.clear();
    peerStates.clear();
  }

  return { handleSdpOffer, handleCandidate, cleanup };
}
