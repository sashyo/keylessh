/**
 * KeyleSSH WAF - HTTP/HTTPS Auth Gateway (local-facing)
 *
 * Runs on the internal/private network. Not exposed to the internet.
 * Remote clients reach this WAF through the public STUN/TURN server.
 *
 * 1. Registers with the public STUN server as a WAF instance
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
    auth,
    stripAuthHeader: config.stripAuthHeader,
    tcConfig,
    authServerPublicUrl: config.authServerPublicUrl,
    iceServers: config.iceServers,
    turnServer: config.turnServer,
    turnSecret: config.turnSecret,
    localAuthUrl: config.localAuthUrl,
    tls,
  });

  // ── Health Check ─────────────────────────────────────────────────

  const healthServer = createHealthServer(config.healthPort, () => ({
    wafId: config.wafId,
    ...getStats(),
  }));

  // ── STUN Registration ────────────────────────────────────────────

  const stunReg = registerWithStun({
    stunServerUrl: config.stunServerUrl,
    wafId: config.wafId,
    listenPort: config.listenPort,
    useTls: !!tls,
    iceServers: config.iceServers,
    turnServer: config.turnServer,
    turnSecret: config.turnSecret,
    apiSecret: config.apiSecret,
    metadata: { displayName: config.displayName, description: config.description },
    addresses: [`${getLocalAddress()}:${config.listenPort}`],
    onPaired(client) {
      console.log(
        `[WAF] Client ${client.id} paired (reflexive: ${client.reflexiveAddress})`
      );
    },
  });

  function getLocalAddress(): string {
    return process.env.WAF_ADDRESS || hostname();
  }

  // ── Startup banner ───────────────────────────────────────────────

  const scheme = config.https ? "https" : "http";
  console.log(`[WAF] KeyleSSH WAF Gateway (local-facing)`);
  console.log(`[WAF] Login: ${scheme}://localhost:${config.listenPort}/login`);
  console.log(`[WAF] Proxy: ${scheme}://localhost:${config.listenPort}`);
  console.log(`[WAF] Health: http://localhost:${config.healthPort}/health`);
  console.log(`[WAF] Backend: ${config.backendUrl}`);
  console.log(`[WAF] STUN Server: ${config.stunServerUrl}`);
  console.log(`[WAF] WAF ID: ${config.wafId}`);

  // ── Graceful shutdown ────────────────────────────────────────────

  process.on("SIGTERM", () => {
    console.log("[WAF] Shutting down...");
    stunReg.close();
    proxyServer.close();
    healthServer.close(() => {
      console.log("[WAF] Shutdown complete");
      process.exit(0);
    });
  });
}

main().catch((err) => {
  console.error("[WAF] Fatal:", err);
  process.exit(1);
});
