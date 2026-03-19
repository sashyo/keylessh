/**
 * DPoP Proof Verification (RFC 9449) for the gateway.
 *
 * Checks: typ, alg, signature, htm, htu, iat freshness, jti replay, cnf.jkt binding.
 */

import { createPublicKey, createHash, verify } from "crypto";

function base64UrlEncode(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(str: string): Buffer {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}

/** Compute JWK Thumbprint (RFC 7638) — SHA-256 of the canonical JWK */
function computeJwkThumbprint(jwk: any): string {
  let canonical: string;
  if (jwk.kty === "EC") {
    canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  } else if (jwk.kty === "OKP") {
    canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`;
  } else if (jwk.kty === "RSA") {
    canonical = `{"e":"${jwk.e}","kty":"${jwk.kty}","n":"${jwk.n}"}`;
  } else {
    throw new Error(`Unsupported key type: ${jwk.kty}`);
  }
  const hash = createHash("sha256").update(canonical).digest();
  return base64UrlEncode(hash);
}

// JTI replay protection — track seen JTIs with TTL
const seenJtis = new Map<string, number>();
const JTI_TTL_MS = 120_000; // 2 minutes

function checkAndStoreJti(jti: string): boolean {
  const now = Date.now();
  // Purge expired entries periodically
  if (seenJtis.size > 1000) {
    seenJtis.forEach((exp, k) => {
      if (exp < now) seenJtis.delete(k);
    });
  }
  if (seenJtis.has(jti)) return false;
  seenJtis.set(jti, now + JTI_TTL_MS);
  return true;
}

export interface DPoPVerifyResult {
  valid: boolean;
  error?: string;
}

/**
 * Verify a DPoP proof JWT (RFC 9449).
 */
export function verifyDPoPProof(
  proofJwt: string,
  httpMethod: string,
  httpUrl: string,
  expectedJkt?: string,
): DPoPVerifyResult {
  try {
    const parts = proofJwt.split(".");
    if (parts.length !== 3) return { valid: false, error: "Invalid JWT structure" };

    const header = JSON.parse(base64UrlDecode(parts[0]).toString());
    const payload = JSON.parse(base64UrlDecode(parts[1]).toString());

    // Check typ
    if (header.typ !== "dpop+jwt") return { valid: false, error: "Invalid typ" };

    // Check alg — support EdDSA and ES256/384/512
    const supportedAlgs = ["EdDSA", "ES256", "ES384", "ES512"];
    if (!supportedAlgs.includes(header.alg)) return { valid: false, error: `Unsupported alg: ${header.alg}` };

    // Must have jwk in header
    if (!header.jwk) return { valid: false, error: "Missing jwk in header" };

    // Import the public key and verify signature
    const publicKey = createPublicKey({ key: header.jwk, format: "jwk" });
    const signInput = `${parts[0]}.${parts[1]}`;
    const signature = base64UrlDecode(parts[2]);

    const alg = header.alg === "EdDSA" ? null : header.alg.toLowerCase().replace("es", "sha");
    const valid = verify(alg, Buffer.from(signInput), publicKey, signature);
    if (!valid) return { valid: false, error: "Invalid signature" };

    // Check htm (HTTP method)
    if (payload.htm !== httpMethod) return { valid: false, error: `htm mismatch: ${payload.htm} != ${httpMethod}` };

    // Check htu (HTTP URL, without query string)
    const expectedHtu = httpUrl.split("?")[0];
    if (payload.htu !== expectedHtu) return { valid: false, error: "htu mismatch" };

    // Check iat freshness (allow 2 minute skew)
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - payload.iat) > 120) return { valid: false, error: "iat too far from current time" };

    // Check jti replay
    if (!payload.jti || !checkAndStoreJti(payload.jti)) return { valid: false, error: "jti missing or replayed" };

    // Check cnf.jkt binding if provided
    if (expectedJkt) {
      const thumbprint = computeJwkThumbprint(header.jwk);
      if (thumbprint !== expectedJkt) return { valid: false, error: "JWK thumbprint does not match cnf.jkt" };
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, error: `DPoP verification error: ${err}` };
  }
}

/**
 * Extract cnf.jkt from a JWT payload (without full verification — the JWT
 * should already be verified by the JWKS verifier).
 */
export function extractCnfJkt(token: string): string | undefined {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return undefined;
    const payload = JSON.parse(base64UrlDecode(parts[1]).toString());
    return payload?.cnf?.jkt;
  } catch {
    return undefined;
  }
}
