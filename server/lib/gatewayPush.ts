import type { GatewayConfig } from "../storage";
import type { SignalServer } from "@shared/schema";

/**
 * Config push: deliver a gateway's settings to the running gateway instead of
 * making someone copy gateway.toml onto the box.
 *
 * The console POSTs to the signal server, which forwards the payload down the
 * gateway's existing WebSocket; the gateway writes gateway.toml and reloads.
 */

export interface RejectedField {
  field: string;
  reason: string;
}

export interface GatewayPushResult {
  /** The gateway received and acknowledged the push. */
  delivered: boolean;
  /** Gateway was offline — the signal server is holding the config for it. */
  pending: boolean;
  /** Fields whose value actually changed on the gateway. */
  applied: string[];
  /** Fields the gateway refused, with why. */
  rejected: RejectedField[];
  /** False when the gateway was already in the requested state. */
  changed: boolean;
  /** Set when the push could not be completed. */
  error?: string | null;
  /** Human-readable status for the console. */
  message?: string;
}

/**
 * Fields that are never pushed, because the gateway refuses them anyway.
 *
 * `tidecloak*` / `auth_server_public_url` decide which TideCloak the gateway
 * trusts, and `gateway_id` / `stun_server_url` / `api_secret` are its identity
 * and bootstrap. Sending them would only produce rejections — the gateway's own
 * allowlist is the actual enforcement point (see PROTECTED_FIELDS in config.rs).
 */
export const NEVER_PUSHED = [
  "gateway_id",
  "stun_server_url",
  "api_secret",
  "tidecloak_config_b64",
  "tidecloak_config_path",
  "auth_server_public_url",
  "tc_internal_url",
] as const;

/**
 * Map a stored gateway config to the snake_case gateway.toml keys the gateway
 * accepts. ICE/TURN fall back to the signal server's values, matching how
 * `toToml` renders the downloadable file.
 */
export function buildPushPayload(
  config: GatewayConfig,
  signalServer?: SignalServer | null
): Record<string, unknown> {
  const ss = signalServer as (SignalServer & { iceServers?: string; turnServer?: string; turnSecret?: string }) | null | undefined;

  const payload: Record<string, unknown> = {
    backends: config.backends ?? null,
    display_name: config.displayName ?? null,
    ice_servers: config.iceServers || ss?.iceServers || null,
    turn_server: config.turnServer || ss?.turnServer || null,
    turn_secret: config.turnSecret || ss?.turnSecret || null,
    server_url: config.serverUrl ?? null,
    listen_port: config.listenPort,
    health_port: config.healthPort,
    https: config.https,
    tls_hostname: config.tlsHostname,
  };

  // Drop keys with no value rather than pushing nulls that would clear settings
  // the gateway may legitimately hold locally. An explicit empty string still
  // clears a field, which is how the console removes a TURN server.
  for (const [key, value] of Object.entries(payload)) {
    if (value === null || value === undefined) delete payload[key];
  }
  return payload;
}

/** Find the signal server a gateway config points at. */
export function matchSignalServer(
  config: GatewayConfig,
  signalServers: SignalServer[]
): SignalServer | undefined {
  return signalServers.find((ss) => {
    const wsUrl = ss.url.replace(/^http/, "ws");
    return config.stunServerUrl === ss.url || config.stunServerUrl === wsUrl;
  });
}

/**
 * Push a config to its gateway via the signal server.
 *
 * Never throws — a gateway being unreachable is an expected outcome that the
 * console renders, not an error that should fail the surrounding save.
 */
export async function pushGatewayConfig(
  config: GatewayConfig,
  signalServer: SignalServer | undefined | null,
  options: { fetchImpl?: typeof fetch; timeoutMs?: number } = {}
): Promise<GatewayPushResult> {
  const failure = (message: string): GatewayPushResult => ({
    delivered: false,
    pending: false,
    applied: [],
    rejected: [],
    changed: false,
    error: message,
    message,
  });

  if (!signalServer) {
    return failure("No signal server matches this gateway's STUN URL");
  }

  const secret = (signalServer as SignalServer & { apiSecret?: string }).apiSecret || config.apiSecret || "";
  // The signal server derives its HTTP base from the same URL used for signaling.
  const base = signalServer.url.replace(/^ws/, "http").replace(/\/$/, "");
  const url = `${base}/api/gateways/${encodeURIComponent(config.gatewayId)}/config`;

  const doFetch = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 20000);

  try {
    const resp = await doFetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-secret": secret },
      body: JSON.stringify(buildPushPayload(config, signalServer)),
      signal: controller.signal,
    });

    const body = (await resp.json().catch(() => ({}))) as Partial<GatewayPushResult> & { error?: string };

    if (!resp.ok && resp.status !== 202) {
      return failure(body.error || `Signal server returned ${resp.status}`);
    }

    return {
      delivered: body.delivered ?? false,
      pending: body.pending ?? false,
      applied: body.applied ?? [],
      rejected: body.rejected ?? [],
      changed: body.changed ?? false,
      error: body.error ?? null,
      message: body.message,
    };
  } catch (e) {
    const reason = e instanceof Error && e.name === "AbortError"
      ? "Signal server did not respond in time"
      : e instanceof Error
        ? e.message
        : String(e);
    return failure(reason);
  } finally {
    clearTimeout(timeout);
  }
}
