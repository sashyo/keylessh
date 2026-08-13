/**
 * @fileoverview Tests for listing self-registered gateways and adopting them.
 *
 * The risk this guards against: adopting a gateway must never seed values the
 * gateway did not report, because the first save pushes the record back and
 * would overwrite a working config with blanks.
 */

import { describe, it, expect } from "vitest";
import {
  mergeDiscovered,
  toDiscovered,
  adoptionRecord,
  isDiscoveredId,
  gatewayIdFromDiscoveredId,
  signalServerFor,
  belongsToTenant,
  DISCOVERED_PREFIX,
  type LiveGateway,
} from "../../server/lib/gatewayDiscovery";
import type { GatewayConfig } from "../../server/storage";
import type { SignalServer } from "@shared/schema";

function stored(overrides: Partial<GatewayConfig> = {}): GatewayConfig {
  return {
    id: "cfg-1",
    gatewayId: "Managed-GW",
    displayName: "Managed",
    stunServerUrl: "wss://signal.example.com",
    apiSecret: null,
    iceServers: null,
    turnServer: null,
    turnSecret: null,
    backends: "App=http://10.0.0.5:8080",
    tidecloakConfigB64: null,
    authServerPublicUrl: null,
    serverUrl: null,
    vpnEnabled: false,
    vpnSubnet: "10.66.0.0/24",
    listenPort: 7891,
    healthPort: 7892,
    https: true,
    tlsHostname: "localhost",
    extraConfig: null,
    directUrl: null,
    enabled: true,
    createdAt: 0,
    updatedAt: 0,
    ...overrides,
  };
}

function live(overrides: Partial<LiveGateway> = {}): LiveGateway {
  return {
    id: "Self-GW",
    displayName: "Self Registered",
    online: true,
    issuer: "https://tc.example.com/realms/demo",
    signalServerId: "ss-1",
    signalServerName: "Shared Signal",
    signalServerUrl: "https://signal.example.com",
    config: {
      backends: "Shell=ssh://10.0.0.3:22",
      listen_port: 7891,
      health_port: 7892,
      quic_port: 7893,
      https: true,
      tls_hostname: "gw.internal",
      display_name: "Self Registered",
      server_url: "https://console.example.com",
      ice_servers: "stun:1.2.3.4:3478",
      turn_server: "turn:1.2.3.4:3478",
    },
    ...overrides,
  };
}

describe("mergeDiscovered", () => {
  it("lists stored configs alongside gateways that have no record", () => {
    const listed = mergeDiscovered([stored()], [live()]);

    expect(listed).toHaveLength(2);
    expect(listed[0]).toMatchObject({ gatewayId: "Managed-GW" });
    expect(listed[1]).toMatchObject({ gatewayId: "Self-GW", discovered: true });
  });

  it("does not list a gateway that already has a record", () => {
    const listed = mergeDiscovered([stored({ gatewayId: "Self-GW" })], [live()]);

    expect(listed).toHaveLength(1);
    expect((listed[0] as any).discovered).toBeUndefined();
  });

  it("matches an existing record case-insensitively", () => {
    const listed = mergeDiscovered([stored({ gatewayId: "self-gw" })], [live({ id: "SELF-GW" })]);

    expect(listed).toHaveLength(1);
  });

  it("lists a gateway once even when two signal servers report it", () => {
    const listed = mergeDiscovered([], [live(), live({ signalServerId: "ss-2" })]);

    expect(listed).toHaveLength(1);
  });

  it("marks a stored gateway online when it is registered", () => {
    // A record means configured; whether it is connected is a separate fact,
    // and previously the two were conflated in the UI.
    const listed = mergeDiscovered([stored({ gatewayId: "Self-GW" })], [live()]);

    expect((listed[0] as any).online).toBe(true);
  });

  it("marks a stored gateway offline when it is not registered", () => {
    const listed = mergeDiscovered([stored({ gatewayId: "Absent-GW" })], [live()]);

    expect((listed[0] as any).online).toBe(false);
  });

  it("treats an explicitly offline live gateway as not registered", () => {
    const listed = mergeDiscovered([stored({ gatewayId: "Self-GW" })], [live({ online: false })]);

    expect((listed[0] as any).online).toBe(false);
  });

  it("returns stored configs when nothing is live, marked offline", () => {
    expect(mergeDiscovered([stored()], [])).toEqual([{ ...stored(), online: false }]);
  });

  it("returns nothing when there is neither", () => {
    expect(mergeDiscovered([], [])).toEqual([]);
  });
});

describe("toDiscovered", () => {
  it("surfaces the settings the gateway reported", () => {
    const d = toDiscovered(live());

    expect(d).toMatchObject({
      id: `${DISCOVERED_PREFIX}Self-GW`,
      gatewayId: "Self-GW",
      discovered: true,
      online: true,
      backends: "Shell=ssh://10.0.0.3:22",
      listenPort: 7891,
      https: true,
      tlsHostname: "gw.internal",
      serverUrl: "https://console.example.com",
      stunServerUrl: "https://signal.example.com",
    });
  });

  it("leaves settings null when the gateway reported nothing", () => {
    const d = toDiscovered(live({ config: null }));

    expect(d.backends).toBeNull();
    expect(d.listenPort).toBeNull();
    expect(d.https).toBeNull();
    expect(d.gatewayId).toBe("Self-GW");
  });

  it("ignores values of the wrong type rather than trusting them", () => {
    const d = toDiscovered(live({
      config: { listen_port: "7891", https: "yes", backends: 42, tls_hostname: "" },
    }));

    expect(d.listenPort).toBeNull();
    expect(d.https).toBeNull();
    expect(d.backends).toBeNull();
    expect(d.tlsHostname).toBeNull();
  });

  it("rejects out-of-range ports", () => {
    expect(toDiscovered(live({ config: { listen_port: 0 } })).listenPort).toBeNull();
    expect(toDiscovered(live({ config: { listen_port: 70000 } })).listenPort).toBeNull();
    expect(toDiscovered(live({ config: { listen_port: 1.5 } })).listenPort).toBeNull();
  });

  it("prefers the reported display name over the registration one", () => {
    const d = toDiscovered(live({ displayName: "Registration", config: { display_name: "Reported" } }));
    expect(d.displayName).toBe("Reported");
  });

  it("treats an explicitly offline gateway as offline", () => {
    expect(toDiscovered(live({ online: false })).online).toBe(false);
  });
});

describe("adoptionRecord", () => {
  it("seeds a record from what the gateway reported", () => {
    const record = adoptionRecord(live());

    expect(record).toMatchObject({
      gatewayId: "Self-GW",
      backends: "Shell=ssh://10.0.0.3:22",
      listenPort: 7891,
      healthPort: 7892,
      https: true,
      tlsHostname: "gw.internal",
      serverUrl: "https://console.example.com",
      stunServerUrl: "https://signal.example.com",
    });
  });

  it("omits anything the gateway did not report, rather than seeding blanks", () => {
    // The important one: a seeded blank would be pushed back on first save and
    // wipe the setting on a working gateway.
    const record = adoptionRecord(live({ config: { backends: "App=http://h:80" } }));

    expect(record.backends).toBe("App=http://h:80");
    for (const field of ["listenPort", "healthPort", "https", "tlsHostname", "serverUrl", "iceServers", "turnServer"]) {
      expect(record).not.toHaveProperty(field);
    }
  });

  it("never carries secrets or the trust anchor", () => {
    // Those are not reported by the gateway; assert the record can't grow them.
    const record = adoptionRecord(live({
      config: {
        backends: "App=http://h:80",
        api_secret: "leaked",
        turn_secret: "leaked",
        tidecloak_config_b64: "leaked",
      } as Record<string, unknown>,
    }));

    expect(JSON.stringify(record)).not.toContain("leaked");
    for (const field of ["apiSecret", "turnSecret", "tidecloakConfigB64", "authServerPublicUrl"]) {
      expect(record).not.toHaveProperty(field);
    }
  });

  it("always sets the gateway id, since that is what pushes are addressed to", () => {
    expect(adoptionRecord(live({ config: null })).gatewayId).toBe("Self-GW");
  });
});

describe("discovered ids", () => {
  it("round-trips a gateway id", () => {
    const id = toDiscovered(live()).id;
    expect(isDiscoveredId(id)).toBe(true);
    expect(gatewayIdFromDiscoveredId(id)).toBe("Self-GW");
  });

  it("does not mistake a stored record id for a discovered one", () => {
    expect(isDiscoveredId("cfg-1")).toBe(false);
    expect(isDiscoveredId("a7f3-discovered:x")).toBe(false);
  });
});

describe("signalServerFor", () => {
  const ss = { id: "ss-1", name: "Shared", url: "https://signal.example.com" } as SignalServer;

  it("matches by id", () => {
    expect(signalServerFor(live(), [ss])?.id).toBe("ss-1");
  });

  it("falls back to matching by url", () => {
    expect(signalServerFor(live({ signalServerId: undefined }), [ss])?.id).toBe("ss-1");
  });

  it("returns undefined when nothing matches", () => {
    expect(signalServerFor(live({ signalServerId: "other", signalServerUrl: "https://other" }), [ss])).toBeUndefined();
  });
});

describe("belongsToTenant", () => {
  const own = "https://login.dauth.me/realms/keylessh-devops";

  it("accepts an exact match", () => {
    expect(belongsToTenant(own, own)).toBe(true);
  });

  it("rejects another realm on the same host", () => {
    expect(belongsToTenant("https://login.dauth.me/realms/keylessh-demo", own)).toBe(false);
  });

  it("rejects the same realm name on another host", () => {
    expect(belongsToTenant("https://staging.dauth.me/realms/keylessh-devops", own)).toBe(false);
  });

  it("ignores a trailing slash and case", () => {
    expect(belongsToTenant(own + "/", own)).toBe(true);
    expect(belongsToTenant("https://LOGIN.dauth.me/realms/keylessh-devops", own)).toBe(true);
  });

  it("rejects a gateway that reports no issuer", () => {
    // Strict: reporting nothing used to mean "show everywhere", which is the
    // cross-tenant leakage the issuer exists to prevent.
    expect(belongsToTenant(null, own)).toBe(false);
    expect(belongsToTenant(undefined, own)).toBe(false);
    expect(belongsToTenant("", own)).toBe(false);
  });
});
