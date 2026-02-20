/**
 * Server configuration loaded from environment variables.
 */

import { networkInterfaces } from "os";

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
    tlsCertPath: process.env.TLS_CERT_PATH || undefined,
    tlsKeyPath: process.env.TLS_KEY_PATH || undefined,
  };
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
