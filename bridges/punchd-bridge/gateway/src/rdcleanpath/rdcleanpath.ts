/**
 * RDCleanPath PDU types and serialization.
 *
 * Implements the RDCleanPath protocol PDU used by IronRDP WASM to
 * negotiate RDP connections through a WebSocket proxy. The gateway
 * handles the TLS handshake with the RDP server and returns the
 * server's certificate chain so IronRDP can perform NLA/CredSSP.
 *
 * Wire format: ASN.1 DER SEQUENCE with EXPLICIT context-specific tags.
 * Version constant: 3390 (BASE_VERSION 3389 + 1).
 */

import {
  DerReader,
  encodeSequence,
  encodeExplicit,
  encodeInteger,
  encodeOctetString,
  encodeUtf8String,
  encodeTlv,
  TAG_SEQUENCE,
} from "./der-codec.js";

export const RDCLEANPATH_VERSION = 3390;

// ── Request (client → gateway) ───────────────────────────────────

export interface RDCleanPathRequest {
  version: number;
  destination: string;
  proxyAuth: string;
  preconnectionBlob?: string;
  x224ConnectionPdu: Buffer;
}

/**
 * Parse a binary buffer as an RDCleanPath Request PDU.
 */
export function parseRDCleanPathRequest(data: Buffer): RDCleanPathRequest {
  const outer = new DerReader(data);
  const seq = outer.readSequence();

  // [0] version
  const versionCtx = seq.readExplicit(0);
  if (!versionCtx) throw new Error("RDCleanPath: missing version field");
  const version = versionCtx.readInteger();
  if (version !== RDCLEANPATH_VERSION) {
    throw new Error(`RDCleanPath: unexpected version ${version}, expected ${RDCLEANPATH_VERSION}`);
  }

  // Skip [1] error (not present in requests)
  seq.readExplicit(1);

  // [2] destination
  const destCtx = seq.readExplicit(2);
  if (!destCtx) throw new Error("RDCleanPath: missing destination field");
  const destination = destCtx.readUtf8String();

  // [3] proxy_auth
  const authCtx = seq.readExplicit(3);
  if (!authCtx) throw new Error("RDCleanPath: missing proxy_auth field");
  const proxyAuth = authCtx.readUtf8String();

  // [4] server_auth (unused, skip)
  seq.readExplicit(4);

  // [5] preconnection_blob (optional)
  const pcbCtx = seq.readExplicit(5);
  const preconnectionBlob = pcbCtx ? pcbCtx.readUtf8String() : undefined;

  // [6] x224_connection_pdu
  const x224Ctx = seq.readExplicit(6);
  if (!x224Ctx) throw new Error("RDCleanPath: missing x224_connection_pdu field");
  const x224ConnectionPdu = x224Ctx.readOctetString();

  return { version, destination, proxyAuth, preconnectionBlob, x224ConnectionPdu };
}

// ── Response (gateway → client) ──────────────────────────────────

export interface RDCleanPathResponse {
  x224ConnectionPdu: Buffer;
  serverCertChain: Buffer[];
  serverAddr: string;
}

/**
 * Build a successful RDCleanPath Response PDU.
 */
export function buildRDCleanPathResponse(resp: RDCleanPathResponse): Buffer {
  const fields: Buffer[] = [];

  // [0] version
  fields.push(encodeExplicit(0, encodeInteger(RDCLEANPATH_VERSION)));

  // [6] x224_connection_pdu
  fields.push(encodeExplicit(6, encodeOctetString(resp.x224ConnectionPdu)));

  // [7] server_cert_chain — SEQUENCE OF OCTET STRING
  const certElements = resp.serverCertChain.map((cert) => encodeOctetString(cert));
  const certSeq = encodeSequence(certElements);
  fields.push(encodeExplicit(7, certSeq));

  // [9] server_addr
  fields.push(encodeExplicit(9, encodeUtf8String(resp.serverAddr)));

  return encodeSequence(fields);
}

// ── Error (gateway → client) ─────────────────────────────────────

export interface RDCleanPathError {
  errorCode: number;
  httpStatusCode?: number;
  wsaLastError?: number;
  tlsAlertCode?: number;
}

/**
 * Build an RDCleanPath Error PDU.
 */
export function buildRDCleanPathError(err: RDCleanPathError): Buffer {
  const fields: Buffer[] = [];

  // [0] version
  fields.push(encodeExplicit(0, encodeInteger(RDCLEANPATH_VERSION)));

  // [1] error — SEQUENCE { [0] errorCode, [1] httpStatus?, [2] wsaError?, [3] tlsAlert? }
  const errFields: Buffer[] = [];
  errFields.push(encodeExplicit(0, encodeInteger(err.errorCode)));
  if (err.httpStatusCode !== undefined) {
    errFields.push(encodeExplicit(1, encodeInteger(err.httpStatusCode)));
  }
  if (err.wsaLastError !== undefined) {
    errFields.push(encodeExplicit(2, encodeInteger(err.wsaLastError)));
  }
  if (err.tlsAlertCode !== undefined) {
    errFields.push(encodeExplicit(3, encodeInteger(err.tlsAlertCode)));
  }
  fields.push(encodeExplicit(1, encodeSequence(errFields)));

  return encodeSequence(fields);
}

// ── Error codes ──────────────────────────────────────────────────

export const RDCLEANPATH_ERROR_GENERAL = 1;
export const RDCLEANPATH_ERROR_NEGOTIATION = 2;
