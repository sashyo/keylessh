/**
 * OpenSSH host certificates.
 *
 * A host certificate lets a server prove its identity against a certificate
 * authority instead of against a key the client has seen before. For KeyleSSH
 * the CA is the VVK, which the client already trusts — so there is no
 * known_hosts to distribute and no first-use prompt to train people to click
 * through.
 *
 * Two independent checks are required and neither is sufficient alone:
 *
 *   1. The key exchange signature proves the server holds the private key for
 *      the public key *inside* the certificate. The SSH library does this.
 *   2. The CA signature proves the VVK vouched for that public key. Nothing in
 *      the library does this — verify it here, or any self-signed certificate
 *      is accepted.
 *
 * Format per PROTOCOL.certkeys:
 *   string  "ssh-ed25519-cert-v01@openssh.com"
 *   string  nonce
 *   string  pk            (raw 32-byte ed25519 public key)
 *   uint64  serial
 *   uint32  type          (1 = user, 2 = host)
 *   string  key id
 *   string  valid principals   (a list of strings, itself length-prefixed)
 *   uint64  valid after
 *   uint64  valid before
 *   string  critical options
 *   string  extensions
 *   string  reserved
 *   string  signature key (the CA's public key blob)
 *   string  signature     (covers everything preceding it)
 */

export const ED25519_CERT_ALGORITHM = "ssh-ed25519-cert-v01@openssh.com";

/** Certificate types from PROTOCOL.certkeys. A host key must not be a user cert. */
export const CERT_TYPE_USER = 1;
export const CERT_TYPE_HOST = 2;

export interface SshCertificate {
  algorithm: string;
  /** Raw 32-byte ed25519 key the certificate vouches for. */
  publicKey: Uint8Array;
  serial: bigint;
  type: number;
  keyId: string;
  principals: string[];
  validAfter: bigint;
  validBefore: bigint;
  criticalOptions: Uint8Array;
  extensions: Uint8Array;
  /** The CA's public key blob, as it appears in the certificate. */
  signatureKey: Uint8Array;
  /** Signature algorithm name from inside the signature blob. */
  signatureAlgorithm: string;
  /** Raw 64-byte ed25519 signature. */
  signature: Uint8Array;
  /** Exactly the bytes the signature covers. */
  signedBytes: Uint8Array;
}

/** Reader for the SSH wire format, which is length-prefixed big-endian. */
export class SshBlobReader {
  private offset = 0;
  constructor(private readonly buf: Uint8Array) {}

  get position(): number {
    return this.offset;
  }

  private require(n: number): void {
    // Every read is bounds-checked: this parses attacker-supplied bytes, and a
    // truncated field must be an error rather than a silent short read.
    if (this.offset + n > this.buf.length) {
      throw new Error(`Malformed certificate: wanted ${n} bytes at ${this.offset}, have ${this.buf.length}`);
    }
  }

  readUint32(): number {
    this.require(4);
    const v = new DataView(this.buf.buffer, this.buf.byteOffset + this.offset, 4).getUint32(0, false);
    this.offset += 4;
    return v;
  }

  readUint64(): bigint {
    this.require(8);
    const v = new DataView(this.buf.buffer, this.buf.byteOffset + this.offset, 8).getBigUint64(0, false);
    this.offset += 8;
    return v;
  }

  readBytes(): Uint8Array {
    const len = this.readUint32();
    this.require(len);
    const out = this.buf.subarray(this.offset, this.offset + len);
    this.offset += len;
    return out;
  }

  readString(): string {
    return new TextDecoder().decode(this.readBytes());
  }

  /** A list of strings, itself wrapped in a length-prefixed field. */
  readStringList(): string[] {
    const inner = new SshBlobReader(this.readBytes());
    const out: string[] = [];
    while (inner.remaining() > 0) out.push(inner.readString());
    return out;
  }

  remaining(): number {
    return this.buf.length - this.offset;
  }
}

/** Parse a host certificate blob. Throws on anything malformed. */
export function parseCertificate(blob: Uint8Array): SshCertificate {
  const r = new SshBlobReader(blob);

  const algorithm = r.readString();
  if (algorithm !== ED25519_CERT_ALGORITHM) {
    throw new Error(`Unsupported certificate algorithm: ${algorithm}`);
  }

  r.readBytes(); // nonce, not used in validation
  const publicKey = r.readBytes();
  const serial = r.readUint64();
  const type = r.readUint32();
  const keyId = r.readString();
  const principals = r.readStringList();
  const validAfter = r.readUint64();
  const validBefore = r.readUint64();
  const criticalOptions = r.readBytes();
  const extensions = r.readBytes();
  r.readBytes(); // reserved
  const signatureKey = r.readBytes();

  // The signature covers everything before its own length prefix.
  const signedBytes = blob.subarray(0, r.position);

  const signatureBlob = r.readBytes();
  const sr = new SshBlobReader(signatureBlob);
  const signatureAlgorithm = sr.readString();
  const signature = sr.readBytes();

  if (publicKey.length !== 32) {
    throw new Error(`Expected a 32-byte ed25519 key, got ${publicKey.length}`);
  }

  return {
    algorithm,
    publicKey,
    serial,
    type,
    keyId,
    principals,
    validAfter,
    validBefore,
    criticalOptions,
    extensions,
    signatureKey,
    signatureAlgorithm,
    signature,
    signedBytes,
  };
}

/** Extract the raw ed25519 key from an `ssh-ed25519` public key blob. */
export function readEd25519PublicKey(blob: Uint8Array): Uint8Array {
  const r = new SshBlobReader(blob);
  const alg = r.readString();
  if (alg !== "ssh-ed25519") throw new Error(`Expected an ssh-ed25519 key, got ${alg}`);
  const key = r.readBytes();
  if (key.length !== 32) throw new Error(`Expected a 32-byte ed25519 key, got ${key.length}`);
  return key;
}

async function verifyEd25519(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", publicKey as BufferSource, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, signature as BufferSource, message as BufferSource);
}

export interface CertificatePolicy {
  /** The CA whose signature is required — for KeyleSSH, the VVK. Raw 32 bytes. */
  caPublicKey: Uint8Array;
  /** The host being connected to, matched against the certificate's principals. */
  host: string;
  /** Seconds since the epoch. Injected so validity is testable. */
  now: number;
  /** Serials to refuse regardless of validity. */
  revokedSerials?: Set<bigint>;
}

export type CertificateVerdict =
  | { valid: true; certificate: SshCertificate }
  | { valid: false; reason: string };

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Check a host certificate against a policy.
 *
 * Order matters only for the quality of the error: every check must pass. The
 * CA signature is verified over the certificate's own signed bytes, so a
 * certificate cannot be edited after signing without invalidating it.
 */
export async function verifyCertificate(
  cert: SshCertificate,
  policy: CertificatePolicy,
): Promise<CertificateVerdict> {
  if (cert.type !== CERT_TYPE_HOST) {
    // A user certificate presented as a host key would otherwise let anyone
    // holding one impersonate a server.
    return { valid: false, reason: `Not a host certificate (type ${cert.type})` };
  }

  let caKey: Uint8Array;
  try {
    caKey = readEd25519PublicKey(cert.signatureKey);
  } catch (e) {
    return { valid: false, reason: `Unreadable CA key: ${e instanceof Error ? e.message : String(e)}` };
  }

  if (!equalBytes(caKey, policy.caPublicKey)) {
    return { valid: false, reason: "Certificate was signed by an unknown authority" };
  }

  if (cert.signatureAlgorithm !== "ssh-ed25519") {
    return { valid: false, reason: `Unsupported CA signature algorithm: ${cert.signatureAlgorithm}` };
  }

  const now = BigInt(Math.floor(policy.now));
  if (now < cert.validAfter) {
    return { valid: false, reason: `Certificate is not valid until ${cert.validAfter}` };
  }
  // validBefore is exclusive, matching OpenSSH.
  if (now >= cert.validBefore) {
    return { valid: false, reason: `Certificate expired at ${cert.validBefore}` };
  }

  // OpenSSH treats an empty principal list as "valid for any host". That is too
  // permissive here: a certificate issued for one server would authenticate
  // every other, so every certificate must name what it is for.
  if (cert.principals.length === 0) {
    return { valid: false, reason: "Certificate names no principals, so it is valid for nothing" };
  }

  const host = policy.host.toLowerCase();
  if (!cert.principals.some((p) => p.toLowerCase() === host)) {
    return {
      valid: false,
      reason: `Certificate is not valid for ${policy.host} (valid for: ${cert.principals.join(", ")})`,
    };
  }

  // Critical options must be understood or the certificate refused — that is
  // what makes them critical. None are supported for host certificates, so any
  // at all is a refusal rather than something to ignore.
  if (cert.criticalOptions.length > 0) {
    return { valid: false, reason: "Certificate carries critical options this client does not implement" };
  }

  if (policy.revokedSerials?.has(cert.serial)) {
    return { valid: false, reason: `Certificate serial ${cert.serial} is revoked` };
  }

  let signatureOk: boolean;
  try {
    signatureOk = await verifyEd25519(caKey, cert.signature, cert.signedBytes);
  } catch (e) {
    return { valid: false, reason: `CA signature could not be checked: ${e instanceof Error ? e.message : String(e)}` };
  }
  if (!signatureOk) {
    return { valid: false, reason: "CA signature is invalid" };
  }

  return { valid: true, certificate: cert };
}
