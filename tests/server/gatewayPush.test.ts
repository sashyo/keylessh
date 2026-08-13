/**
 * @fileoverview Tests for pushing gateway config to a running gateway.
 *
 * Covers buildPushPayload() (which fields leave the console), matchSignalServer()
 * and pushGatewayConfig() (delivery, queueing, and failure handling).
 */

import { describe, it, expect, vi } from "vitest";
import {
  buildPushPayload,
  matchSignalServer,
  pushGatewayConfig,
  NEVER_PUSHED,
} from "../../server/lib/gatewayPush";
import type { GatewayConfig } from "../../server/storage";
import type { SignalServer } from "@shared/schema";

function gatewayConfig(overrides: Partial<GatewayConfig> = {}): GatewayConfig {
  return {
    id: "cfg-1",
    gatewayId: "gw-1",
    displayName: "Demo Gateway",
    stunServerUrl: "wss://signal.example.com",
    apiSecret: "gateway-secret",
    iceServers: "stun:1.2.3.4:3478",
    turnServer: "turn:1.2.3.4:3478",
    turnSecret: "turn-secret",
    backends: "App=http://10.0.0.5:8080",
    tidecloakConfigB64: "ZXhpc3Rpbmc=",
    authServerPublicUrl: "https://tc.example.com",
    serverUrl: "https://console.example.com",
    vpnEnabled: false,
    vpnSubnet: "10.66.0.0/24",
    listenPort: 7891,
    healthPort: 7892,
    https: true,
    tlsHostname: "gw.example.com",
    extraConfig: null,
    directUrl: null,
    enabled: true,
    createdAt: 0,
    updatedAt: 0,
    ...overrides,
  };
}

function signalServer(overrides: Partial<SignalServer> = {}): SignalServer {
  return {
    id: "ss-1",
    name: "Shared Signal",
    url: "https://signal.example.com",
    description: null,
    enabled: true,
    createdAt: new Date(0),
    apiSecret: "signal-secret",
    iceServers: null,
    turnServer: null,
    turnSecret: null,
    ...overrides,
  } as SignalServer;
}

describe("buildPushPayload", () => {
  it("maps stored config to gateway.toml keys", () => {
    const payload = buildPushPayload(gatewayConfig());

    expect(payload).toMatchObject({
      backends: "App=http://10.0.0.5:8080",
      display_name: "Demo Gateway",
      ice_servers: "stun:1.2.3.4:3478",
      turn_server: "turn:1.2.3.4:3478",
      listen_port: 7891,
      health_port: 7892,
      https: true,
      tls_hostname: "gw.example.com",
      server_url: "https://console.example.com",
    });
  });

  it("never sends the TideCloak trust anchor or gateway identity", () => {
    const payload = buildPushPayload(gatewayConfig(), signalServer());

    for (const field of NEVER_PUSHED) {
      expect(payload).not.toHaveProperty(field);
    }
    // Nor their camelCase spellings, in case a rename slips through.
    expect(payload).not.toHaveProperty("tidecloakConfigB64");
    expect(payload).not.toHaveProperty("authServerPublicUrl");
    expect(payload).not.toHaveProperty("apiSecret");
    expect(payload).not.toHaveProperty("gatewayId");
  });

  it("falls back to the signal server for ICE/TURN", () => {
    const config = gatewayConfig({ iceServers: null, turnServer: null, turnSecret: null });
    const ss = signalServer({
      iceServers: "stun:9.9.9.9:3478",
      turnServer: "turn:9.9.9.9:3478",
      turnSecret: "inherited",
    } as Partial<SignalServer>);

    const payload = buildPushPayload(config, ss);

    expect(payload.ice_servers).toBe("stun:9.9.9.9:3478");
    expect(payload.turn_server).toBe("turn:9.9.9.9:3478");
    expect(payload.turn_secret).toBe("inherited");
  });

  it("omits unset fields rather than pushing nulls", () => {
    const payload = buildPushPayload(gatewayConfig({ backends: null, serverUrl: null }));

    expect(payload).not.toHaveProperty("backends");
    expect(payload).not.toHaveProperty("server_url");
  });

  it("keeps an explicit empty string so a field can be cleared", () => {
    const payload = buildPushPayload(gatewayConfig({ backends: "" }), signalServer());

    expect(payload.backends).toBe("");
  });
});

describe("matchSignalServer", () => {
  it("matches on the ws form of the signal server URL", () => {
    const config = gatewayConfig({ stunServerUrl: "wss://signal.example.com" });
    expect(matchSignalServer(config, [signalServer()])?.id).toBe("ss-1");
  });

  it("matches on the http form too", () => {
    const config = gatewayConfig({ stunServerUrl: "https://signal.example.com" });
    expect(matchSignalServer(config, [signalServer()])?.id).toBe("ss-1");
  });

  it("returns undefined when nothing matches", () => {
    const config = gatewayConfig({ stunServerUrl: "wss://other.example.com" });
    expect(matchSignalServer(config, [signalServer()])).toBeUndefined();
  });
});

describe("pushGatewayConfig", () => {
  it("posts to the signal server with its API secret", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ delivered: true, applied: ["backends"], rejected: [], changed: true }),
    });

    const result = await pushGatewayConfig(gatewayConfig(), signalServer(), { fetchImpl: fetchImpl as any });

    expect(fetchImpl).toHaveBeenCalledOnce();
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe("https://signal.example.com/api/gateways/gw-1/config");
    expect(init.method).toBe("POST");
    expect(init.headers["x-api-secret"]).toBe("signal-secret");
    expect(result.delivered).toBe(true);
    expect(result.applied).toEqual(["backends"]);
  });

  it("derives an http base from a ws signal server URL", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ delivered: true }) });

    await pushGatewayConfig(gatewayConfig(), signalServer({ url: "wss://signal.example.com/" }), {
      fetchImpl: fetchImpl as any,
    });

    expect(fetchImpl.mock.calls[0][0]).toBe("https://signal.example.com/api/gateways/gw-1/config");
  });

  it("reports a queued push for an offline gateway", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: false,
      status: 202,
      json: async () => ({ delivered: false, pending: true, message: "Gateway offline — config queued" }),
    });

    const result = await pushGatewayConfig(gatewayConfig(), signalServer(), { fetchImpl: fetchImpl as any });

    expect(result.pending).toBe(true);
    expect(result.delivered).toBe(false);
    expect(result.error).toBeNull();
    expect(result.message).toContain("queued");
  });

  it("surfaces fields the gateway refused", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        delivered: true,
        changed: true,
        applied: ["backends"],
        rejected: [{ field: "api_secret", reason: "set locally on the gateway only" }],
      }),
    });

    const result = await pushGatewayConfig(gatewayConfig(), signalServer(), { fetchImpl: fetchImpl as any });

    expect(result.rejected).toEqual([{ field: "api_secret", reason: "set locally on the gateway only" }]);
  });

  it("fails cleanly when no signal server matches", async () => {
    const result = await pushGatewayConfig(gatewayConfig(), undefined);

    expect(result.delivered).toBe(false);
    expect(result.error).toContain("No signal server");
  });

  it("does not throw when the signal server is unreachable", async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));

    const result = await pushGatewayConfig(gatewayConfig(), signalServer(), { fetchImpl: fetchImpl as any });

    expect(result.delivered).toBe(false);
    expect(result.error).toBe("ECONNREFUSED");
  });

  it("reports an error status from the signal server", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ error: "Invalid API secret" }),
    });

    const result = await pushGatewayConfig(gatewayConfig(), signalServer(), { fetchImpl: fetchImpl as any });

    expect(result.delivered).toBe(false);
    expect(result.error).toBe("Invalid API secret");
  });

  it("times out rather than hanging on a silent signal server", async () => {
    const fetchImpl = vi.fn().mockImplementation((_url: string, init: RequestInit) =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => {
          const err = new Error("aborted");
          err.name = "AbortError";
          reject(err);
        });
      })
    );

    const result = await pushGatewayConfig(gatewayConfig(), signalServer(), {
      fetchImpl: fetchImpl as any,
      timeoutMs: 10,
    });

    expect(result.delivered).toBe(false);
    expect(result.error).toContain("did not respond in time");
  });
});
