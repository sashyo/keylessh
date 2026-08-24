/**
 * @fileoverview Tests for OpenSSH host certificate parsing and verification.
 *
 * Certificates are built here in real wire format and signed with real Ed25519
 * keys, so the parser is exercised against bytes an sshd would actually send
 * rather than against a fixture shaped to match the parser.
 */

import { describe, it, expect, beforeAll } from "vitest";
import {
  parseCertificate,
  verifyCertificate,
  readEd25519PublicKey,
  ED25519_CERT_ALGORITHM,
  CERT_TYPE_HOST,
  CERT_TYPE_USER,
} from "../../client/src/lib/sshCert";

// ── Wire format helpers, the mirror of the parser ──────────────────

function u32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}
function u64(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, false);
  return b;
}
function str(v: string | Uint8Array): Uint8Array {
  const bytes = typeof v === "string" ? new TextEncoder().encode(v) : v;
  return concat(u32(bytes.length), bytes);
}
function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
function stringList(items: string[]): Uint8Array {
  return str(concat(...items.map((i) => str(i))));
}
function ed25519KeyBlob(raw: Uint8Array): Uint8Array {
  return concat(str("ssh-ed25519"), str(raw));
}

interface CertFields {
  publicKey: Uint8Array;
  type?: number;
  keyId?: string;
  principals?: string[];
  validAfter?: bigint;
  validBefore?: bigint;
  caPublicKey: Uint8Array;
  algorithm?: string;
  signatureAlgorithm?: string;
}

/** Build a certificate and sign it with the CA private key. */
async function buildCert(fields: CertFields, caPrivate: CryptoKey, tamper?: (signed: Uint8Array) => Uint8Array) {
  const body = concat(
    str(fields.algorithm ?? ED25519_CERT_ALGORITHM),
    str(new Uint8Array([1, 2, 3, 4])), // nonce
    str(fields.publicKey),
    u64(42n), // serial
    u32(fields.type ?? CERT_TYPE_HOST),
    str(fields.keyId ?? "host-cert"),
    stringList(fields.principals ?? []),
    u64(fields.validAfter ?? 0n),
    u64(fields.validBefore ?? 0xffffffffffffffffn),
    str(new Uint8Array()), // critical options
    str(new Uint8Array()), // extensions
    str(new Uint8Array()), // reserved
    str(ed25519KeyBlob(fields.caPublicKey)),
  );

  const signedBytes = tamper ? tamper(body) : body;
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, caPrivate, signedBytes as BufferSource),
  );
  return concat(signedBytes, str(concat(str(fields.signatureAlgorithm ?? "ssh-ed25519"), str(sig))));
}

// ── Fixtures ───────────────────────────────────────────────────────

let ca: CryptoKeyPair, caRaw: Uint8Array;
let host: CryptoKeyPair, hostRaw: Uint8Array;
let other: CryptoKeyPair, otherRaw: Uint8Array;

async function rawPublic(pair: CryptoKeyPair): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
}

beforeAll(async () => {
  const gen = () => crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;
  [ca, host, other] = await Promise.all([gen(), gen(), gen()]);
  [caRaw, hostRaw, otherRaw] = await Promise.all([rawPublic(ca), rawPublic(host), rawPublic(other)]);
});

const policy = (over: Partial<{ caPublicKey: Uint8Array; host: string; now: number }> = {}) => ({
  caPublicKey: caRaw,
  host: "10.0.0.5",
  now: 1_800_000_000,
  ...over,
});

describe("parseCertificate", () => {
  it("reads every field of a real certificate", async () => {
    const blob = await buildCert(
      { publicKey: hostRaw, caPublicKey: caRaw, keyId: "web-01", principals: ["10.0.0.5", "web-01"] },
      ca.privateKey,
    );
    const cert = parseCertificate(blob);

    expect(cert.algorithm).toBe(ED25519_CERT_ALGORITHM);
    expect(cert.publicKey).toEqual(hostRaw);
    expect(cert.type).toBe(CERT_TYPE_HOST);
    expect(cert.keyId).toBe("web-01");
    expect(cert.principals).toEqual(["10.0.0.5", "web-01"]);
    expect(cert.serial).toBe(42n);
    expect(cert.signatureAlgorithm).toBe("ssh-ed25519");
    expect(cert.signature).toHaveLength(64);
    expect(readEd25519PublicKey(cert.signatureKey)).toEqual(caRaw);
  });

  it("handles an empty principal list", async () => {
    const blob = await buildCert({ publicKey: hostRaw, caPublicKey: caRaw, principals: [] }, ca.privateKey);
    expect(parseCertificate(blob).principals).toEqual([]);
  });

  it("rejects a different algorithm", async () => {
    const blob = await buildCert(
      { publicKey: hostRaw, caPublicKey: caRaw, algorithm: "ssh-rsa-cert-v01@openssh.com" },
      ca.privateKey,
    );
    expect(() => parseCertificate(blob)).toThrow(/Unsupported certificate algorithm/);
  });

  it("rejects a truncated blob rather than reading past the end", async () => {
    const blob = await buildCert({ publicKey: hostRaw, caPublicKey: caRaw }, ca.privateKey);
    expect(() => parseCertificate(blob.subarray(0, blob.length - 10))).toThrow(/Malformed certificate/);
    expect(() => parseCertificate(new Uint8Array([0, 0, 0, 5]))).toThrow(/Malformed certificate/);
    expect(() => parseCertificate(new Uint8Array())).toThrow(/Malformed certificate/);
  });

  it("rejects a length prefix that overruns the buffer", () => {
    // A hostile length field must not be trusted.
    const evil = concat(str(ED25519_CERT_ALGORITHM), u32(0xfffffff0));
    expect(() => parseCertificate(evil)).toThrow(/Malformed certificate/);
  });
});

describe("verifyCertificate", () => {
  it("accepts a well-formed certificate from the trusted CA", async () => {
    const blob = await buildCert(
      { publicKey: hostRaw, caPublicKey: caRaw, principals: ["10.0.0.5"] },
      ca.privateKey,
    );
    const verdict = await verifyCertificate(parseCertificate(blob), policy());

    expect(verdict.valid).toBe(true);
  });

  it("rejects one signed by a different authority", async () => {
    // Signed by `other`, and claiming to be — the check that matters most.
    const blob = await buildCert({ publicKey: hostRaw, caPublicKey: otherRaw }, other.privateKey);
    const verdict = await verifyCertificate(parseCertificate(blob), policy());

    expect(verdict).toMatchObject({ valid: false, reason: expect.stringMatching(/unknown authority/i) });
  });

  it("rejects one claiming our CA but signed by another key", async () => {
    // Names the real CA, signed by an impostor. Catching this is the whole point.
    const blob = await buildCert({ publicKey: hostRaw, caPublicKey: caRaw }, other.privateKey);
    const verdict = await verifyCertificate(parseCertificate(blob), policy());

    expect(verdict).toMatchObject({ valid: false, reason: expect.stringMatching(/signature is invalid/i) });
  });

  it("rejects a certificate edited after signing", async () => {
    const blob = await buildCert(
      { publicKey: hostRaw, caPublicKey: caRaw, keyId: "web-01" },
      ca.privateKey,
    );
    // Flip a byte inside the signed region.
    const tampered = new Uint8Array(blob);
    tampered[40] ^= 0xff;
    const verdict = await verifyCertificate(parseCertificate(tampered), policy());

    expect(verdict).toMatchObject({ valid: false, reason: expect.stringMatching(/signature is invalid/i) });
  });

  it("rejects a user certificate presented as a host key", async () => {
    const blob = await buildCert(
      { publicKey: hostRaw, caPublicKey: caRaw, type: CERT_TYPE_USER },
      ca.privateKey,
    );
    const verdict = await verifyCertificate(parseCertificate(blob), policy());

    expect(verdict).toMatchObject({ valid: false, reason: expect.stringMatching(/Not a host certificate/i) });
  });

  it("rejects one that is not valid yet", async () => {
    const blob = await buildCert(
      { publicKey: hostRaw, caPublicKey: caRaw, validAfter: 2_000_000_000n },
      ca.privateKey,
    );
    const verdict = await verifyCertificate(parseCertificate(blob), policy({ now: 1_800_000_000 }));

    expect(verdict).toMatchObject({ valid: false, reason: expect.stringMatching(/not valid until/i) });
  });

  it("rejects an expired one", async () => {
    const blob = await buildCert(
      { publicKey: hostRaw, caPublicKey: caRaw, validBefore: 1_700_000_000n },
      ca.privateKey,
    );
    const verdict = await verifyCertificate(parseCertificate(blob), policy({ now: 1_800_000_000 }));

    expect(verdict).toMatchObject({ valid: false, reason: expect.stringMatching(/expired/i) });
  });

  it("treats validBefore as exclusive, as OpenSSH does", async () => {
    const blob = await buildCert(
      { publicKey: hostRaw, caPublicKey: caRaw, validBefore: 1_800_000_000n },
      ca.privateKey,
    );
    const atBoundary = await verifyCertificate(parseCertificate(blob), policy({ now: 1_800_000_000 }));
    const justBefore = await verifyCertificate(parseCertificate(blob), policy({ now: 1_799_999_999 }));

    expect(atBoundary.valid).toBe(false);
    expect(justBefore.valid).toBe(true);
  });

  it("rejects a host it was not issued for", async () => {
    const blob = await buildCert(
      { publicKey: hostRaw, caPublicKey: caRaw, principals: ["10.0.0.9", "db-01"] },
      ca.privateKey,
    );
    const verdict = await verifyCertificate(parseCertificate(blob), policy({ host: "10.0.0.5" }));

    expect(verdict).toMatchObject({ valid: false, reason: expect.stringMatching(/not valid for 10\.0\.0\.5/) });
  });

  it("matches principals case-insensitively", async () => {
    const blob = await buildCert(
      { publicKey: hostRaw, caPublicKey: caRaw, principals: ["Web-01.Example.COM"] },
      ca.privateKey,
    );
    const verdict = await verifyCertificate(parseCertificate(blob), policy({ host: "web-01.example.com" }));

    expect(verdict.valid).toBe(true);
  });

  it("accepts an empty principal list as valid for any host", async () => {
    // OpenSSH's own semantics: empty means unrestricted, and that is the
    // signer's deliberate choice rather than a parse failure.
    const blob = await buildCert({ publicKey: hostRaw, caPublicKey: caRaw, principals: [] }, ca.privateKey);
    const verdict = await verifyCertificate(parseCertificate(blob), policy({ host: "anything" }));

    expect(verdict.valid).toBe(true);
  });

  it("rejects an unsupported CA signature algorithm", async () => {
    const blob = await buildCert(
      { publicKey: hostRaw, caPublicKey: caRaw, signatureAlgorithm: "ssh-rsa" },
      ca.privateKey,
    );
    const verdict = await verifyCertificate(parseCertificate(blob), policy());

    expect(verdict).toMatchObject({ valid: false, reason: expect.stringMatching(/Unsupported CA signature/i) });
  });
});
