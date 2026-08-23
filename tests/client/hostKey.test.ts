/**
 * @fileoverview Tests for SSH host key verification.
 *
 * The gap these close: the client accepted any host key presented, so anything
 * in the relay path could impersonate a target host.
 */

import { describe, it, expect } from "vitest";
import {
  sshFingerprint,
  verifyHostKey,
  hostKeyTarget,
  knownHostsLine,
  type PinnedHostKey,
} from "../../client/src/lib/hostKey";

const KEY_A = "AAAAC3NzaC1lZDI1NTE5AAAAIB1cUxK8vB1TWpPXKuHVGvNqIRnMAY0hZ4EwZQfKZ1aB";
const KEY_B = "AAAAC3NzaC1lZDI1NTE5AAAAIDifferentKeyBytesHereForTestingPurposes00000";

const pinned = (over: Partial<PinnedHostKey> = {}): PinnedHostKey => ({
  algorithm: "ssh-ed25519",
  publicKey: KEY_A,
  fingerprint: "SHA256:whatever",
  ...over,
});

describe("sshFingerprint", () => {
  it("formats as OpenSSH does", async () => {
    const fp = await sshFingerprint(new Uint8Array([1, 2, 3]));

    expect(fp).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);
    expect(fp).not.toContain("="); // OpenSSH strips padding
  });

  it("is stable for the same key", async () => {
    const bytes = new Uint8Array([9, 8, 7, 6]);
    expect(await sshFingerprint(bytes)).toBe(await sshFingerprint(bytes));
  });

  it("differs for different keys", async () => {
    const a = await sshFingerprint(new Uint8Array([1, 2, 3]));
    const b = await sshFingerprint(new Uint8Array([1, 2, 4]));
    expect(a).not.toBe(b);
  });

  it("matches a known OpenSSH fingerprint", async () => {
    // sha256 of the empty input is a fixed, checkable value; OpenSSH prints it
    // base64 with padding removed.
    const fp = await sshFingerprint(new Uint8Array([]));
    expect(fp).toBe("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU");
  });
});

describe("verifyHostKey", () => {
  it("matches an identical key", () => {
    expect(verifyHostKey({ algorithm: "ssh-ed25519", publicKey: KEY_A }, pinned())).toBe("match");
  });

  it("flags a changed key", () => {
    expect(verifyHostKey({ algorithm: "ssh-ed25519", publicKey: KEY_B }, pinned())).toBe("mismatch");
  });

  it("flags a changed algorithm even with the same bytes", () => {
    expect(verifyHostKey({ algorithm: "ssh-rsa", publicKey: KEY_A }, pinned())).toBe("mismatch");
  });

  it("reports unknown when nothing is pinned", () => {
    expect(verifyHostKey({ algorithm: "ssh-ed25519", publicKey: KEY_A }, null)).toBe("unknown");
    expect(verifyHostKey({ algorithm: "ssh-ed25519", publicKey: KEY_A }, undefined)).toBe("unknown");
  });

  it("does not treat a truncated key as a match", () => {
    // Guards against a prefix comparison creeping in.
    const truncated = { algorithm: "ssh-ed25519", publicKey: KEY_A.slice(0, 20) };
    expect(verifyHostKey(truncated, pinned())).toBe("mismatch");
  });

  it("is case sensitive on the key, since base64 is", () => {
    const flipped = { algorithm: "ssh-ed25519", publicKey: KEY_A.toLowerCase() };
    expect(verifyHostKey(flipped, pinned())).toBe("mismatch");
  });
});

describe("hostKeyTarget", () => {
  it("prefers the server record, so a pin survives an address change", () => {
    expect(hostKeyTarget({ serverId: "srv-1", host: "10.0.0.5", port: 22 })).toBe("server:srv-1");
    expect(hostKeyTarget({ serverId: "srv-1", host: "10.0.0.9", port: 22 })).toBe("server:srv-1");
  });

  it("falls back to address for ad-hoc connections", () => {
    expect(hostKeyTarget({ host: "10.0.0.5", port: 22 })).toBe("addr:10.0.0.5:22");
    expect(hostKeyTarget({ serverId: null, host: "10.0.0.5", port: 2222 })).toBe("addr:10.0.0.5:2222");
  });

  it("normalises host case but keeps ports distinct", () => {
    expect(hostKeyTarget({ host: "Host.Example.COM", port: 22 })).toBe("addr:host.example.com:22");
    expect(hostKeyTarget({ host: "h", port: 22 })).not.toBe(hostKeyTarget({ host: "h", port: 2222 }));
  });
});

describe("knownHostsLine", () => {
  it("renders a line comparable with the host's own key", () => {
    expect(knownHostsLine("10.0.0.5", { algorithm: "ssh-ed25519", publicKey: KEY_A }))
      .toBe(`10.0.0.5 ssh-ed25519 ${KEY_A}`);
  });
});
