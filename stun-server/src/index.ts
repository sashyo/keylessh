/**
 * KeyleSSH STUN/TURN Server (public-facing)
 *
 * Two interfaces:
 *   - UDP/TCP on STUN_PORT (3478): Standard STUN/TURN protocol
 *   - HTTP/WebSocket on SIGNAL_PORT (8080): Registration, signaling, health check
 *
 * This is the public entry point. Remote clients connect here for:
 *   1. NAT traversal (STUN Binding)
 *   2. TURN relay (when direct P2P to WAF is not possible)
 *   3. Signaling (registration + pairing with local WAF instances)
 *
 * WAF instances (local-facing) register via WebSocket and are paired
 * with clients. Clients reach WAFs through TURN relay or direct
 * connection after NAT traversal.
 */

import { createServer as createHttpServer } from "http";
import { createServer as createHttpsServer } from "https";
import { readFileSync } from "fs";
import { loadConfig } from "./config.js";
import { createHealthServer } from "./health.js";
import { createUdpServer } from "./transport/udp-server.js";
import { createTcpServer, TcpConnection } from "./transport/tcp-server.js";
import { parseMessage } from "./stun/message.js";
import { METHOD_BINDING } from "./stun/constants.js";
import { handleBindingRequest, TransportInfo } from "./stun/binding.js";
import {
  handleTurnMessage,
  TurnHandlerContext,
} from "./turn/handlers.js";
import {
  createAllocationManager,
  AllocationManager,
} from "./turn/allocation-manager.js";
import { makeFiveTupleKey } from "./turn/types.js";
import {
  handleRelayData,
  parseChannelData,
  handleChannelDataFromClient,
} from "./turn/relay.js";
import { createRegistry } from "./signaling/registry.js";
import { createSignalingServer } from "./signaling/ws-server.js";
import { createHttpRelay } from "./relay/http-relay.js";
import { createApiHandler } from "./api/routes.js";
import { createAdminAuth } from "./auth/jwt.js";

// ── Configuration ────────────────────────────────────────────────

const config = loadConfig();

// ── Allocation Manager ───────────────────────────────────────────

const allocationManager = createAllocationManager(
  config.externalIp,
  config.relayPortMin,
  config.relayPortMax,
  (allocation, peerAddr, peerPort, data) => {
    // Route relay data back to the client
    const transport = allocation.protocol;
    if (transport === "udp") {
      udpServer.send(
        buildRelayResponse(allocation, peerAddr, peerPort, data),
        allocation.clientPort,
        allocation.clientAddress
      );
    }
    // TCP clients are handled via their persistent connection (not yet tracked)
  }
);

function buildRelayResponse(
  allocation: import("./turn/types.js").Allocation,
  peerAddr: string,
  peerPort: number,
  data: Buffer
): Buffer {
  // Use handleRelayData to build the appropriate response
  let response: Buffer = Buffer.alloc(0);
  handleRelayData(allocation, peerAddr, peerPort, data, (buf) => {
    response = buf;
  });
  return response;
}

// ── TURN Handler Context ─────────────────────────────────────────

const turnCtx: TurnHandlerContext = {
  allocationManager,
  defaultLifetime: config.defaultLifetime,
  realm: config.realm,
  turnSecret: config.turnSecret,
};

// ── STUN/TURN message handler ────────────────────────────────────

async function handleStunPacket(
  buf: Buffer,
  transport: TransportInfo,
  respond: (buf: Buffer) => void
): Promise<void> {
  const msg = parseMessage(buf);
  if (!msg) return;

  if (msg.header.method === METHOD_BINDING) {
    // STUN Binding — no auth required
    respond(handleBindingRequest(msg, transport));
    return;
  }

  // TURN methods
  const response = await handleTurnMessage(turnCtx, msg, transport);
  if (response) {
    respond(response);
  }
}

// ── ChannelData handler ──────────────────────────────────────────

function handleChannelDataPacket(
  buf: Buffer,
  protocol: "udp" | "tcp",
  clientAddr: string,
  clientPort: number
): void {
  const cd = parseChannelData(buf);
  if (!cd) return;

  const key = makeFiveTupleKey(protocol, clientAddr, clientPort);
  const alloc = allocationManager.get(key);
  if (alloc) {
    handleChannelDataFromClient(alloc, cd.channelNumber, cd.data);
  }
}

// ── UDP Server ───────────────────────────────────────────────────

// On Fly.io, UDP must bind to "fly-global-services" instead of 0.0.0.0
const isFlyIo = !!process.env.FLY_APP_NAME;

const udpServer = createUdpServer({
  port: config.stunPort,
  bindAddress: isFlyIo ? "fly-global-services" : undefined,
  onStunMessage(buf, rinfo) {
    const transport: TransportInfo = {
      sourceAddress: rinfo.address,
      sourcePort: rinfo.port,
      protocol: "udp",
    };
    handleStunPacket(buf, transport, (resp) => {
      udpServer.send(resp, rinfo.port, rinfo.address);
    });
  },
  onChannelData(buf, rinfo) {
    handleChannelDataPacket(buf, "udp", rinfo.address, rinfo.port);
  },
});

// ── TCP Server ───────────────────────────────────────────────────

const tcpServer = createTcpServer({
  port: config.stunPort,
  onStunMessage(buf, conn) {
    const transport: TransportInfo = {
      sourceAddress: conn.remoteAddress,
      sourcePort: conn.remotePort,
      protocol: "tcp",
    };
    handleStunPacket(buf, transport, (resp) => {
      conn.send(resp);
    });
  },
  onChannelData(buf, conn) {
    handleChannelDataPacket(
      buf,
      "tcp",
      conn.remoteAddress,
      conn.remotePort
    );
  },
});

// ── Signaling + Health HTTP Server ───────────────────────────────

const registry = createRegistry();

const adminAuth = config.tidecloakConfig
  ? createAdminAuth(config.tidecloakConfig)
  : undefined;

const apiHandler = createApiHandler(registry, adminAuth, config.tidecloakConfig);

const useTls = !!(config.tlsCertPath && config.tlsKeyPath);
const relayHandler = createHttpRelay(registry, useTls);

const requestHandler = (req: import("http").IncomingMessage, res: import("http").ServerResponse) => {
  if (req.url === "/health") {
    const allocStats = allocationManager.getStats();
    const signalStats = registry.getStats();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        status: "ok",
        ...allocStats,
        ...signalStats,
      })
    );
    return;
  }

  // Try portal, admin, and API routes first
  if (apiHandler(req, res)) return;

  // Relay all other HTTP requests to a WAF
  relayHandler(req, res);
};

const httpServer = useTls
  ? createHttpsServer(
      {
        key: readFileSync(config.tlsKeyPath!),
        cert: readFileSync(config.tlsCertPath!),
      },
      requestHandler
    )
  : createHttpServer(requestHandler);

const signalingWss = createSignalingServer(httpServer, registry, {
  apiSecret: config.apiSecret,
  adminAuth,
});

const scheme = useTls ? "https" : "http";
const wsScheme = useTls ? "wss" : "ws";

httpServer.listen(config.signalPort, () => {
  console.log(
    `[Signal] WebSocket + health on ${scheme}://localhost:${config.signalPort}`
  );
});

// ── Startup banner ───────────────────────────────────────────────

console.log(`[STUN] KeyleSSH STUN/TURN server (public-facing)`);
console.log(`[STUN] STUN/TURN: UDP+TCP port ${config.stunPort}`);
console.log(
  `[STUN] Signaling: ${wsScheme}://localhost:${config.signalPort}`
);
console.log(
  `[STUN] Health: ${scheme}://localhost:${config.signalPort}/health`
);
if (useTls) {
  console.log(`[STUN] TLS: ${config.tlsCertPath}`);
}
console.log(`[STUN] API Secret: ${config.apiSecret ? "set" : "disabled (open)"}`);
console.log(`[STUN] Admin auth: ${adminAuth ? "TideCloak JWT" : "disabled (open)"}`);
console.log(`[STUN] TURN Secret: ${config.turnSecret ? "set" : "disabled (open)"}`);
console.log(`[STUN] External IP: ${config.externalIp}`);
console.log(
  `[STUN] Relay ports: ${config.relayPortMin}-${config.relayPortMax}`
);

// ── Graceful shutdown ────────────────────────────────────────────

process.on("SIGTERM", () => {
  console.log("[STUN] Shutting down...");
  allocationManager.shutdownAll();
  signalingWss.clients.forEach((client) =>
    client.close(1001, "Server shutting down")
  );
  udpServer.close();
  tcpServer.close();
  httpServer.close(() => {
    console.log("[STUN] Shutdown complete");
    process.exit(0);
  });
});
