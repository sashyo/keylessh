/**
 * WAF configuration loaded from environment variables and TideCloak config.
 *
 * The WAF is local-facing — it runs on the internal/private network.
 * Remote clients reach it through the public STUN/TURN server.
 */

import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { networkInterfaces } from "os";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export interface BackendEntry {
  name: string;
  url: string;
}

export interface ServerConfig {
  listenPort: number;
  healthPort: number;
  backendUrl: string;
  backends: BackendEntry[];
  stunServerUrl: string;
  wafId: string;
  stripAuthHeader: boolean;
  /** Public-facing TideCloak URL for browser redirects (overrides config auth-server-url) */
  authServerPublicUrl?: string;
  /** ICE servers for WebRTC NAT traversal, e.g. ["stun:relay.example.com:3478"] */
  iceServers: string[];
  /** TURN server URL for WebRTC relay fallback, e.g. "turn:relay.example.com:3478" */
  turnServer?: string;
  /** Shared secret for TURN REST API ephemeral credentials (same as TURN server's TURN_SECRET) */
  turnSecret: string;
  /** Shared secret for STUN server API authentication (API_SECRET) */
  apiSecret: string;
  /** Local TideCloak URL for proxying /realms/* and /resources/* (LOCAL_AUTH_URL).
   *  Use when the backend's TideCloak is a different instance from the WAF's auth-server-url. */
  localAuthUrl?: string;
  /** Display name shown in the portal (WAF_DISPLAY_NAME) */
  displayName?: string;
  /** Description shown in the portal (WAF_DESCRIPTION) */
  description?: string;
  /** Enable HTTPS with a self-signed certificate */
  https: boolean;
  /** Hostname for the self-signed certificate */
  tlsHostname: string;
}

export interface TidecloakConfig {
  realm: string;
  "auth-server-url": string;
  resource: string;
  "public-client"?: boolean;
  jwk: {
    keys: Array<{
      kid: string;
      kty: string;
      alg: string;
      use: string;
      crv: string;
      x: string;
    }>;
  };
  [key: string]: unknown; // Allow extra fields (vendorId, homeOrkUrl, etc.)
}

export function loadConfig(): ServerConfig {
  const stunServerUrl = process.env.STUN_SERVER_URL;
  if (!stunServerUrl) {
    console.error("[WAF] STUN_SERVER_URL is required");
    process.exit(1);
  }

  // Parse BACKENDS env var: "Name=http://host:port,Other=http://host2:port2"
  // Falls back to BACKEND_URL for backwards compat
  const backends = parseBackends();
  const backendUrl = backends[0]?.url || "";

  if (!backendUrl) {
    console.error("[WAF] BACKENDS or BACKEND_URL is required");
    process.exit(1);
  }

  return {
    listenPort: parseInt(process.env.LISTEN_PORT || "7891", 10),
    healthPort: parseInt(process.env.HEALTH_PORT || "7892", 10),
    backendUrl,
    backends,
    stunServerUrl,
    wafId: process.env.WAF_ID || `waf-${Math.random().toString(36).slice(2, 8)}`,
    stripAuthHeader: process.env.STRIP_AUTH_HEADER === "true",
    authServerPublicUrl: process.env.AUTH_SERVER_PUBLIC_URL || undefined,
    iceServers: process.env.ICE_SERVERS
      ? process.env.ICE_SERVERS.split(",")
      : deriveIceServers(stunServerUrl),
    turnServer: process.env.TURN_SERVER || undefined,
    turnSecret: process.env.TURN_SECRET || "",
    apiSecret: process.env.API_SECRET || "",
    localAuthUrl: process.env.LOCAL_AUTH_URL || undefined,
    displayName: process.env.WAF_DISPLAY_NAME || undefined,
    description: process.env.WAF_DESCRIPTION || undefined,
    https: process.env.HTTPS !== "false",
    tlsHostname: process.env.TLS_HOSTNAME || "localhost",
  };
}

function parseBackends(): BackendEntry[] {
  const backendsEnv = process.env.BACKENDS;
  if (backendsEnv) {
    return backendsEnv.split(",").map((entry) => {
      const eq = entry.indexOf("=");
      if (eq < 0) return { name: "Default", url: entry.trim() };
      return { name: entry.slice(0, eq).trim(), url: entry.slice(eq + 1).trim() };
    }).filter((b) => b.url);
  }

  const backendUrl = process.env.BACKEND_URL;
  if (backendUrl) {
    const name = process.env.WAF_DISPLAY_NAME || "Default";
    return [{ name, url: backendUrl }];
  }

  return [];
}

/**
 * Load TideCloak config from file or base64 env var.
 */
export function loadTidecloakConfig(): TidecloakConfig {
  const configB64 = process.env.TIDECLOAK_CONFIG_B64;

  let configData: string;

  if (configB64) {
    configData = Buffer.from(configB64, "base64").toString("utf-8");
    console.log("[WAF] Loading JWKS from TIDECLOAK_CONFIG_B64");
  } else {
    const configPath = resolveTidecloakPath();
    configData = readFileSync(configPath, "utf-8");
    console.log(`[WAF] Loading JWKS from ${configPath}`);
  }

  const config = JSON.parse(configData) as TidecloakConfig;

  if (!config.jwk?.keys?.length) {
    console.error("[WAF] No JWKS keys found in config");
    process.exit(1);
  }

  return config;
}

/**
 * Derive STUN ICE server address from the signaling WebSocket URL.
 * ws://host:9090 → stun:host:3478
 * If host is localhost/127.0.0.1, auto-detect LAN IP so browsers on the
 * same network can reach the STUN server.
 */
function deriveIceServers(wsUrl: string): string[] {
  try {
    const url = new URL(wsUrl);
    let host = url.hostname;
    if (host === "localhost" || host === "127.0.0.1") {
      host = detectLanIp();
    }
    return [`stun:${host}:3478`];
  } catch {
    return [];
  }
}

function detectLanIp(): string {
  const ifaces = networkInterfaces();
  for (const addrs of Object.values(ifaces)) {
    if (!addrs) continue;
    for (const addr of addrs) {
      if (addr.family === "IPv4" && !addr.internal) {
        return addr.address;
      }
    }
  }
  return "127.0.0.1";
}

function resolveTidecloakPath(): string {
  if (process.env.TIDECLOAK_CONFIG_PATH) {
    return process.env.TIDECLOAK_CONFIG_PATH;
  }

  // Resolve relative to project root (parent of src/ or dist/)
  const projectRoot = join(__dirname, "..");
  return join(projectRoot, "data", "tidecloak.json");
}
