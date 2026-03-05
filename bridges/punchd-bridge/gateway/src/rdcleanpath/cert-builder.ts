/**
 * X.509 certificate builder for browser-based smart card emulation.
 *
 * Builds a self-signed X.509 v3 certificate from the browser's RSA public key
 * (SPKI DER). The certificate has Smart Card Logon + Client Auth EKUs so
 * Windows accepts it for smart card logon.
 *
 * The TBSCertificate is sent to the browser for signing (the private key
 * never leaves the browser), then assembled into a full Certificate here.
 */

import { randomBytes } from "crypto";
import { encodeTlv, encodeSequence } from "./der-codec.js";

// ── ASN.1 tags ──────────────────────────────────────────────────

const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OCTET_STRING = 0x04;
const TAG_NULL = 0x05;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
const TAG_SET = 0x31;
const TAG_PRINTABLE_STRING = 0x13;
const TAG_UTC_TIME = 0x17;

// ── OID constants (DER-encoded, without tag+length) ─────────────

// sha256WithRSAEncryption: 1.2.840.113549.1.1.11
const OID_SHA256_RSA = Buffer.from([
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
]);

// id-at-commonName: 2.5.4.3
const OID_COMMON_NAME = Buffer.from([0x55, 0x04, 0x03]);

// id-ce-keyUsage: 2.5.29.15
const OID_KEY_USAGE = Buffer.from([0x55, 0x1d, 0x0f]);

// id-ce-extKeyUsage: 2.5.29.37
const OID_EXT_KEY_USAGE = Buffer.from([0x55, 0x1d, 0x25]);

// id-kp-clientAuth: 1.3.6.1.5.5.7.3.2
const OID_CLIENT_AUTH = Buffer.from([
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
]);

// id-kp-smartCardLogon: 1.3.6.1.4.1.311.20.2.2
const OID_SMART_CARD_LOGON = Buffer.from([
  0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x02,
]);

// ── Helpers ─────────────────────────────────────────────────────

function derOid(oid: Buffer): Buffer {
  return encodeTlv(TAG_OID, oid);
}

function derInteger(value: Buffer): Buffer {
  // Ensure positive (prepend 0x00 if high bit set)
  if (value[0] & 0x80) {
    value = Buffer.concat([Buffer.from([0x00]), value]);
  }
  return encodeTlv(TAG_INTEGER, value);
}

function derSmallInt(n: number): Buffer {
  const bytes: number[] = [];
  if (n === 0) {
    bytes.push(0);
  } else {
    let v = n;
    while (v > 0) {
      bytes.unshift(v & 0xff);
      v = v >>> 8;
    }
    if (bytes[0] & 0x80) bytes.unshift(0);
  }
  return encodeTlv(TAG_INTEGER, Buffer.from(bytes));
}

function derBitString(data: Buffer): Buffer {
  // Prefix with 0x00 (unused bits count)
  const content = Buffer.concat([Buffer.from([0x00]), data]);
  return encodeTlv(TAG_BIT_STRING, content);
}

function derExplicit(tagNum: number, inner: Buffer): Buffer {
  return encodeTlv(0xa0 | tagNum, inner);
}

function derUtcTime(date: Date): Buffer {
  const y = date.getUTCFullYear() % 100;
  const s =
    String(y).padStart(2, "0") +
    String(date.getUTCMonth() + 1).padStart(2, "0") +
    String(date.getUTCDate()).padStart(2, "0") +
    String(date.getUTCHours()).padStart(2, "0") +
    String(date.getUTCMinutes()).padStart(2, "0") +
    String(date.getUTCSeconds()).padStart(2, "0") +
    "Z";
  return encodeTlv(TAG_UTC_TIME, Buffer.from(s, "ascii"));
}

function derPrintableString(str: string): Buffer {
  return encodeTlv(TAG_PRINTABLE_STRING, Buffer.from(str, "ascii"));
}

// ── Certificate building ────────────────────────────────────────

/**
 * Build the TBSCertificate DER for a smart card logon certificate.
 *
 * @param username - CN value (Windows username)
 * @param spkiPublicKey - SubjectPublicKeyInfo in DER (browser's SPKI export)
 * @returns DER-encoded TBSCertificate
 */
export function buildTbsCertificate(
  username: string,
  spkiPublicKey: Buffer,
): Buffer {
  // version [0] EXPLICIT INTEGER (v3 = 2)
  const version = derExplicit(0, derSmallInt(2));

  // serialNumber — random 16 bytes
  const serial = derInteger(randomBytes(16));

  // signature AlgorithmIdentifier: sha256WithRSAEncryption + NULL
  const sigAlg = encodeSequence([derOid(OID_SHA256_RSA), encodeTlv(TAG_NULL, Buffer.alloc(0))]);

  // issuer/subject: Name { CN=<username> }
  const cn = encodeSequence([derOid(OID_COMMON_NAME), derPrintableString(username)]);
  const rdn = encodeTlv(TAG_SET, cn);
  const name = encodeSequence([rdn]);

  // validity: now → now + 1 hour
  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + 3600 * 1000);
  const validity = encodeSequence([derUtcTime(notBefore), derUtcTime(notAfter)]);

  // subjectPublicKeyInfo — pass through browser's SPKI DER directly
  const spki = spkiPublicKey;

  // extensions [3] EXPLICIT SEQUENCE OF Extension
  const extensions = buildExtensions();
  const extensionsWrapper = derExplicit(3, encodeSequence(extensions));

  const tbs = encodeSequence([
    version,
    serial,
    sigAlg,
    name,       // issuer
    validity,
    name,       // subject (self-signed, same as issuer)
    spki,
    extensionsWrapper,
  ]);

  return tbs;
}

/**
 * Assemble a full X.509 Certificate from TBSCertificate + signature.
 *
 * @param tbsCert - DER-encoded TBSCertificate
 * @param signature - RSA signature over tbsCert
 * @returns DER-encoded Certificate
 */
export function assembleCertificate(
  tbsCert: Buffer,
  signature: Buffer,
): Buffer {
  const sigAlg = encodeSequence([derOid(OID_SHA256_RSA), encodeTlv(TAG_NULL, Buffer.alloc(0))]);
  const sigBits = derBitString(signature);
  return encodeSequence([tbsCert, sigAlg, sigBits]);
}

// ── Extensions ──────────────────────────────────────────────────

function buildExtensions(): Buffer[] {
  const exts: Buffer[] = [];

  // KeyUsage: digitalSignature (bit 0)
  // BIT STRING: 0x03 (3 unused bits) 0x80 (digitalSignature = bit 0)
  // Wait — DER BIT STRING for KeyUsage: value is a named bit string.
  // digitalSignature is bit 0 → byte 0x80, with 7 unused bits → padding byte = 0x07
  const kuValue = encodeTlv(TAG_BIT_STRING, Buffer.from([0x07, 0x80]));
  exts.push(
    encodeSequence([
      derOid(OID_KEY_USAGE),
      encodeTlv(0x01, Buffer.from([0xff])), // critical = TRUE
      encodeTlv(TAG_OCTET_STRING, kuValue),
    ]),
  );

  // ExtKeyUsage: smartCardLogon + clientAuth
  const ekuSeq = encodeSequence([
    derOid(OID_SMART_CARD_LOGON),
    derOid(OID_CLIENT_AUTH),
  ]);
  exts.push(
    encodeSequence([
      derOid(OID_EXT_KEY_USAGE),
      encodeTlv(TAG_OCTET_STRING, ekuSeq),
    ]),
  );

  return exts;
}
