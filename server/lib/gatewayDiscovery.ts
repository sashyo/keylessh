import type { GatewayConfig } from "../storage";
import type { SignalServer } from "@shared/schema";

/**
 * Self-registered gateways.
 *
 * A gateway that registers with a signal server is live and usable, but until
 * someone creates a matching config record it cannot be managed from the
 * console. Rather than making an admin retype what the gateway already knows,
 * the console lists live gateways alongside stored ones and adopts a gateway —
 * creating its record — the first time anyone edits it.
 *
 * The gateway reports its own settings at registration, so an adopted record
 * starts out matching reality. Without that, adoption would seed blanks and the
 * first save would push them over a working config.
 */

/** A gateway as the signal server reports it. */
export interface LiveGateway {
  id: string;
  displayName?: string | null;
  description?: string | null;
  online?: boolean;
  issuer?: string | null;
  /** Settings the gateway reports about itself, in gateway.toml key names. */
  config?: Record<string, unknown> | null;
  signalServerId?: string;
  signalServerName?: string;
  signalServerUrl?: string;
}

/** A stored config, or a live gateway that has no record yet. */
export type ListedGateway = (GatewayConfig & { discovered?: false }) | DiscoveredGateway;

export interface DiscoveredGateway {
  /** Synthetic id — no database row exists yet. */
  id: string;
  gatewayId: string;
  displayName: string | null;
  discovered: true;
  online: boolean;
  signalServerName: string | null;
  stunServerUrl: string | null;
  issuer: string | null;
  /** Editable settings as the gateway reports them. */
  backends: string | null;
  listenPort: number | null;
  healthPort: number | null;
  https: boolean | null;
  tlsHostname: string | null;
  serverUrl: string | null;
  iceServers: string | null;
  turnServer: string | null;
}

/** Prefix marking an id as not-yet-adopted, so the UI and API can tell. */
export const DISCOVERED_PREFIX = "discovered:";

export function isDiscoveredId(id: string): boolean {
  return id.startsWith(DISCOVERED_PREFIX);
}

export function gatewayIdFromDiscoveredId(id: string): string {
  return id.slice(DISCOVERED_PREFIX.length);
}

function str(value: unknown): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

function port(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value > 0 && value <= 65535
    ? value
    : null;
}

function bool(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

/** Convert a live gateway into a listable entry using what it reported. */
export function toDiscovered(live: LiveGateway): DiscoveredGateway {
  const c = live.config ?? {};
  return {
    id: `${DISCOVERED_PREFIX}${live.id}`,
    gatewayId: live.id,
    displayName: str(c.display_name) ?? str(live.displayName),
    discovered: true,
    online: live.online !== false,
    signalServerName: live.signalServerName ?? null,
    stunServerUrl: live.signalServerUrl ?? null,
    issuer: live.issuer ?? null,
    backends: str(c.backends),
    listenPort: port(c.listen_port),
    healthPort: port(c.health_port),
    https: bool(c.https),
    tlsHostname: str(c.tls_hostname),
    serverUrl: str(c.server_url),
    iceServers: str(c.ice_servers),
    turnServer: str(c.turn_server),
  };
}

/**
 * List stored configs plus any live gateway without one.
 *
 * Matching is on `gatewayId`, case-insensitively — that is the identity the
 * gateway registers under and the key config pushes are addressed to.
 */
export function mergeDiscovered(
  stored: GatewayConfig[],
  live: LiveGateway[]
): ListedGateway[] {
  const known = new Set(stored.map((c) => c.gatewayId.toLowerCase()));
  const seen = new Set<string>();
  const discovered: DiscoveredGateway[] = [];

  for (const gw of live) {
    const key = gw.id.toLowerCase();
    // A gateway can be registered with more than one signal server; list it once.
    if (known.has(key) || seen.has(key)) continue;
    seen.add(key);
    discovered.push(toDiscovered(gw));
  }

  return [...stored, ...discovered];
}

/**
 * Build the record to create when a discovered gateway is adopted.
 *
 * Only fields the gateway actually reported are set. Anything it did not report
 * is left to the storage layer's defaults rather than guessed, so adoption never
 * invents a value that a later push would write back to the gateway.
 */
export function adoptionRecord(live: LiveGateway): Record<string, unknown> {
  const d = toDiscovered(live);
  const record: Record<string, unknown> = { gatewayId: d.gatewayId };

  const optional: Record<string, unknown> = {
    displayName: d.displayName,
    stunServerUrl: d.stunServerUrl,
    backends: d.backends,
    listenPort: d.listenPort,
    healthPort: d.healthPort,
    https: d.https,
    tlsHostname: d.tlsHostname,
    serverUrl: d.serverUrl,
    iceServers: d.iceServers,
    turnServer: d.turnServer,
  };
  for (const [key, value] of Object.entries(optional)) {
    if (value !== null && value !== undefined) record[key] = value;
  }
  return record;
}

/** Find the signal server a live gateway registered with. */
export function signalServerFor(
  live: LiveGateway,
  signalServers: SignalServer[]
): SignalServer | undefined {
  return signalServers.find((ss) => ss.id === live.signalServerId || ss.url === live.signalServerUrl);
}
