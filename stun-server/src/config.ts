/**
 * Server configuration loaded from environment variables.
 */

import { networkInterfaces } from "os";

export interface TidecloakConfig {
  realm: string;
  "auth-server-url": string;
  resource: string;
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
  [key: string]: unknown;
}

export interface ServerConfig {
  stunPort: number;
  signalPort: number;
  externalIp: string;
  relayPortMin: number;
  relayPortMax: number;
  defaultLifetime: number;
  realm: string;
  /** Shared secret for TURN REST API ephemeral credentials. If empty, TURN auth is disabled. */
  turnSecret: string;
  /** Shared secret for WAF registration. If empty, WAF auth is disabled. */
  apiSecret: string;
  /** TideCloak config for admin JWT validation. If undefined, admin auth is disabled. */
  tidecloakConfig?: TidecloakConfig;
  /** Path to TLS certificate file. If set with tlsKeyPath, signaling uses HTTPS/WSS. */
  tlsCertPath?: string;
  /** Path to TLS private key file. */
  tlsKeyPath?: string;
}

export function loadConfig(): ServerConfig {
  // EXTERNAL_IP > FLY_PUBLIC_IP (Fly.io dedicated IPv4) > LAN auto-detect
  const externalIp = process.env.EXTERNAL_IP || process.env.FLY_PUBLIC_IP || detectLanIp();
  if (externalIp === "0.0.0.0") {
    console.warn(
      "[Config] Could not detect LAN IP — TURN relay addresses will use 0.0.0.0"
    );
  }

  return {
    stunPort: parseInt(process.env.STUN_PORT || "3478", 10),
    signalPort: parseInt(process.env.SIGNAL_PORT || "9090", 10),
    externalIp,
    relayPortMin: parseInt(process.env.RELAY_PORT_MIN || "49152", 10),
    relayPortMax: parseInt(process.env.RELAY_PORT_MAX || "65535", 10),
    defaultLifetime: parseInt(process.env.DEFAULT_LIFETIME || "600", 10),
    realm: process.env.REALM || "keylessh",
    turnSecret: process.env.TURN_SECRET || "",
    apiSecret: process.env.API_SECRET || "",
    tidecloakConfig: loadTidecloakConfig(),
    tlsCertPath: process.env.TLS_CERT_PATH || undefined,
    tlsKeyPath: process.env.TLS_KEY_PATH || undefined,
  };
}

function loadTidecloakConfig(): TidecloakConfig | undefined {
  const b64 = process.env.TIDECLOAK_CONFIG_B64;
  if (!b64) return undefined;
  try {
    const config = JSON.parse(Buffer.from(b64, "base64").toString("utf-8")) as TidecloakConfig;
    if (!config.jwk?.keys?.length) {
      console.warn("[Config] TIDECLOAK_CONFIG_B64 has no JWKS keys — admin auth disabled");
      return undefined;
    }
    console.log("[Config] TideCloak JWKS loaded for admin auth");
    return config;
  } catch (err) {
    console.warn("[Config] Failed to parse TIDECLOAK_CONFIG_B64:", err);
    return undefined;
  }
}

/**
 * Auto-detect the LAN IP address (first non-internal IPv4 address).
 */
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
  return "0.0.0.0";
}
