/**
 * KeyleSSH Gateway - HTTP/HTTPS Auth Gateway (local-facing)
 *
 * Runs on the internal/private network. Not exposed to the internet.
 * Remote clients reach this gateway through the public STUN/TURN server.
 *
 * 1. Registers with the public STUN server as a gateway instance
 * 2. Receives HTTP traffic from clients (via STUN/TURN relay or direct after NAT traversal)
 * 3. Serves login page for TideCloak authentication (server-side OIDC)
 * 4. Validates TideCloak JWT (cookie or Authorization header)
 * 5. Proxies authorized requests to the local backend
 */

import { hostname } from "os";
import { loadConfig, loadTidecloakConfig } from "./config.js";
import { createTidecloakAuth } from "./auth/tidecloak.js";
import { createProxy } from "./proxy/http-proxy.js";
import { createHealthServer } from "./health.js";
import { registerWithStun } from "./registration/stun-client.js";
import { generateSelfSignedCert } from "./tls/self-signed.js";

async function main() {
  // ── Configuration ────────────────────────────────────────────────

  const config = loadConfig();
  const tcConfig = loadTidecloakConfig();

  const auth = createTidecloakAuth(tcConfig);

  // ── TLS ─────────────────────────────────────────────────────────

  const tls = config.https
    ? await generateSelfSignedCert(config.tlsHostname)
    : undefined;

  // ── HTTP/HTTPS Proxy ────────────────────────────────────────────

  const { server: proxyServer, getStats } = createProxy({
    listenPort: config.listenPort,
    backendUrl: config.backendUrl,
    backends: config.backends,
    auth,
    stripAuthHeader: config.stripAuthHeader,
    tcConfig,
    authServerPublicUrl: config.authServerPublicUrl,
    iceServers: config.iceServers,
    turnServer: config.turnServer,
    turnSecret: config.turnSecret,
    tls,
    tcInternalUrl: config.tcInternalUrl,
    gatewayId: config.gatewayId,
  });

  // ── Health Check ─────────────────────────────────────────────────

  const healthServer = createHealthServer(config.healthPort, () => ({
    gatewayId: config.gatewayId,
    ...getStats(),
  }));

  // ── STUN Registration ────────────────────────────────────────────

  const stunReg = registerWithStun({
    stunServerUrl: config.stunServerUrl,
    gatewayId: config.gatewayId,
    listenPort: config.listenPort,
    useTls: !!tls,
    iceServers: config.iceServers,
    turnServer: config.turnServer,
    turnSecret: config.turnSecret,
    apiSecret: config.apiSecret,
    metadata: {
      displayName: config.displayName,
      description: config.description,
      backends: config.backends.map((b) => ({ name: b.name, protocol: b.protocol || "http", ...(b.auth ? { auth: b.auth } : {}) })),
      realm: tcConfig.realm,
    },
    backends: config.backends,
    verifyToken: (token: string) => auth.verifyToken(token),
    tcClientId: tcConfig.resource,
    addresses: [`${getLocalAddress()}:${config.listenPort}`],
    onPaired(client) {
      console.log(
        `[Gateway] Client ${client.id} paired (reflexive: ${client.reflexiveAddress})`
      );
    },
  });

  function getLocalAddress(): string {
    return process.env.GATEWAY_ADDRESS || hostname();
  }

  // ── Startup banner ───────────────────────────────────────────────

  const scheme = config.https ? "https" : "http";
  console.log(`[Gateway] KeyleSSH Gateway (local-facing)`);
  console.log(`[Gateway] Login: ${scheme}://localhost:${config.listenPort}/login`);
  console.log(`[Gateway] Proxy: ${scheme}://localhost:${config.listenPort}`);
  console.log(`[Gateway] Health: http://localhost:${config.healthPort}/health`);
  if (config.backends.length > 1) {
    for (const b of config.backends) {
      console.log(`[Gateway] Backend: ${b.name} → ${b.url}`);
    }
  } else {
    console.log(`[Gateway] Backend: ${config.backendUrl}`);
  }
  console.log(`[Gateway] STUN Server: ${config.stunServerUrl}`);
  console.log(`[Gateway] Gateway ID: ${config.gatewayId}`);

  // ── Graceful shutdown ────────────────────────────────────────────

  process.on("SIGTERM", () => {
    console.log("[Gateway] Shutting down...");
    stunReg.close();
    proxyServer.close();
    healthServer.close(() => {
      console.log("[Gateway] Shutdown complete");
      process.exit(0);
    });
  });
}

main().catch((err) => {
  console.error("[Gateway] Fatal:", err);
  process.exit(1);
});
