/**
 * @fileoverview Tests for RDCleanPath PDU serialization/deserialization.
 *
 * Tests the RDCleanPath protocol PDU types used by IronRDP WASM to
 * negotiate RDP connections through a WebSocket proxy. Covers request
 * parsing, response building, and error PDU construction.
 */

import { describe, it, expect } from "vitest";
import {
  parseRDCleanPathRequest,
  buildRDCleanPathResponse,
  buildRDCleanPathError,
  RDCLEANPATH_VERSION,
  RDCLEANPATH_ERROR_GENERAL,
  RDCLEANPATH_ERROR_NEGOTIATION,
} from "../../bridges/punchd-bridge/gateway/src/rdcleanpath/rdcleanpath";
import {
  DerReader,
  encodeSequence,
  encodeExplicit,
  encodeInteger,
  encodeOctetString,
  encodeUtf8String,
  contextTag,
} from "../../bridges/punchd-bridge/gateway/src/rdcleanpath/der-codec";

describe("RDCLEANPATH_VERSION", () => {
  it("should be 3390 (3389 + 1)", () => {
    expect(RDCLEANPATH_VERSION).toBe(3390);
  });
});

describe("parseRDCleanPathRequest", () => {
  function buildRequest(opts: {
    version?: number;
    destination?: string;
    proxyAuth?: string;
    preconnectionBlob?: string;
    x224?: Buffer;
  }) {
    const fields: Buffer[] = [];

    // [0] version
    fields.push(encodeExplicit(0, encodeInteger(opts.version ?? RDCLEANPATH_VERSION)));
    // [1] error (not present in requests, but include empty explicit for format)
    fields.push(encodeExplicit(1, encodeSequence([])));
    // [2] destination
    fields.push(encodeExplicit(2, encodeUtf8String(opts.destination ?? "My PC")));
    // [3] proxy_auth
    fields.push(encodeExplicit(3, encodeUtf8String(opts.proxyAuth ?? "jwt-token-here")));
    // [4] server_auth (unused)
    fields.push(encodeExplicit(4, encodeUtf8String("")));
    // [5] preconnection_blob (optional)
    if (opts.preconnectionBlob !== undefined) {
      fields.push(encodeExplicit(5, encodeUtf8String(opts.preconnectionBlob)));
    }
    // [6] x224_connection_pdu
    fields.push(encodeExplicit(6, encodeOctetString(opts.x224 ?? Buffer.from([0x03, 0x00]))));

    return encodeSequence(fields);
  }

  it("should parse a valid request", () => {
    const x224 = Buffer.from([0x03, 0x00, 0x00, 0x13]);
    const buf = buildRequest({
      destination: "My PC",
      proxyAuth: "my-jwt-token",
      x224,
    });

    const req = parseRDCleanPathRequest(buf);
    expect(req.version).toBe(RDCLEANPATH_VERSION);
    expect(req.destination).toBe("My PC");
    expect(req.proxyAuth).toBe("my-jwt-token");
    expect(req.x224ConnectionPdu).toEqual(x224);
    expect(req.preconnectionBlob).toBeUndefined();
  });

  it("should parse request with preconnection blob", () => {
    const buf = buildRequest({
      preconnectionBlob: "vm-guid-123",
    });

    const req = parseRDCleanPathRequest(buf);
    expect(req.preconnectionBlob).toBe("vm-guid-123");
  });

  it("should reject wrong version", () => {
    const buf = buildRequest({ version: 9999 });
    expect(() => parseRDCleanPathRequest(buf)).toThrow("unexpected version 9999");
  });
});

describe("buildRDCleanPathResponse", () => {
  it("should build a valid response PDU", () => {
    const x224Confirm = Buffer.from([0x03, 0x00, 0x00, 0x0B]);
    const cert1 = Buffer.from([0x30, 0x82, 0x01, 0x00]); // mock DER cert
    const cert2 = Buffer.from([0x30, 0x82, 0x02, 0x00]);

    const buf = buildRDCleanPathResponse({
      x224ConnectionPdu: x224Confirm,
      serverCertChain: [cert1, cert2],
      serverAddr: "192.168.1.100:3389",
    });

    // Parse it back
    const outer = new DerReader(buf);
    const seq = outer.readSequence();

    // [0] version
    const vCtx = seq.readExplicit(0);
    expect(vCtx).not.toBeNull();
    expect(vCtx!.readInteger()).toBe(RDCLEANPATH_VERSION);

    // [6] x224_connection_pdu
    const x224Ctx = seq.readExplicit(6);
    expect(x224Ctx).not.toBeNull();
    expect(x224Ctx!.readOctetString()).toEqual(x224Confirm);

    // [7] server_cert_chain (SEQUENCE OF OCTET STRING)
    const certCtx = seq.readExplicit(7);
    expect(certCtx).not.toBeNull();
    const certs = certCtx!.readSequenceOfOctetStrings();
    expect(certs).toHaveLength(2);
    expect(certs[0]).toEqual(cert1);
    expect(certs[1]).toEqual(cert2);

    // [9] server_addr
    const addrCtx = seq.readExplicit(9);
    expect(addrCtx).not.toBeNull();
    expect(addrCtx!.readUtf8String()).toBe("192.168.1.100:3389");
  });

  it("should handle single certificate", () => {
    const cert = Buffer.from([0x30, 0x00]);
    const buf = buildRDCleanPathResponse({
      x224ConnectionPdu: Buffer.from([0x03]),
      serverCertChain: [cert],
      serverAddr: "10.0.0.1:3389",
    });

    const outer = new DerReader(buf);
    const seq = outer.readSequence();
    seq.readExplicit(0); // version
    seq.readExplicit(6); // x224
    const certCtx = seq.readExplicit(7);
    const certs = certCtx!.readSequenceOfOctetStrings();
    expect(certs).toHaveLength(1);
  });
});

describe("buildRDCleanPathError", () => {
  it("should build error PDU with only error code", () => {
    const buf = buildRDCleanPathError({
      errorCode: RDCLEANPATH_ERROR_GENERAL,
    });

    const outer = new DerReader(buf);
    const seq = outer.readSequence();

    // [0] version
    const vCtx = seq.readExplicit(0);
    expect(vCtx!.readInteger()).toBe(RDCLEANPATH_VERSION);

    // [1] error SEQUENCE
    const errCtx = seq.readExplicit(1);
    expect(errCtx).not.toBeNull();
    const errSeq = errCtx!.readSequence();

    // [0] errorCode
    const codeCtx = errSeq.readExplicit(0);
    expect(codeCtx!.readInteger()).toBe(RDCLEANPATH_ERROR_GENERAL);
  });

  it("should build error PDU with HTTP status", () => {
    const buf = buildRDCleanPathError({
      errorCode: RDCLEANPATH_ERROR_GENERAL,
      httpStatusCode: 401,
    });

    const outer = new DerReader(buf);
    const seq = outer.readSequence();
    seq.readExplicit(0); // version
    const errCtx = seq.readExplicit(1);
    const errSeq = errCtx!.readSequence();
    errSeq.readExplicit(0); // errorCode
    const httpCtx = errSeq.readExplicit(1);
    expect(httpCtx!.readInteger()).toBe(401);
  });

  it("should build error PDU with all fields", () => {
    const buf = buildRDCleanPathError({
      errorCode: RDCLEANPATH_ERROR_NEGOTIATION,
      httpStatusCode: 403,
      wsaLastError: 10061,
      tlsAlertCode: 48,
    });

    const outer = new DerReader(buf);
    const seq = outer.readSequence();
    seq.readExplicit(0); // version
    const errCtx = seq.readExplicit(1);
    const errSeq = errCtx!.readSequence();

    expect(errSeq.readExplicit(0)!.readInteger()).toBe(RDCLEANPATH_ERROR_NEGOTIATION);
    expect(errSeq.readExplicit(1)!.readInteger()).toBe(403);
    expect(errSeq.readExplicit(2)!.readInteger()).toBe(10061);
    expect(errSeq.readExplicit(3)!.readInteger()).toBe(48);
  });
});

describe("error constants", () => {
  it("should have correct error codes", () => {
    expect(RDCLEANPATH_ERROR_GENERAL).toBe(1);
    expect(RDCLEANPATH_ERROR_NEGOTIATION).toBe(2);
  });
});
