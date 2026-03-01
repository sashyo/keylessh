/**
 * @fileoverview Tests for ASN.1 DER encoder/decoder.
 *
 * Tests the minimal DER codec used by the RDCleanPath protocol,
 * covering encoding/decoding of INTEGER, OCTET STRING, UTF8String,
 * SEQUENCE, and context-specific EXPLICIT tags.
 */

import { describe, it, expect } from "vitest";
import {
  DerReader,
  encodeInteger,
  encodeOctetString,
  encodeUtf8String,
  encodeSequence,
  encodeExplicit,
  encodeTlv,
  contextTag,
  TAG_INTEGER,
  TAG_OCTET_STRING,
  TAG_UTF8_STRING,
  TAG_SEQUENCE,
} from "../../bridges/punchd-bridge/gateway/src/rdcleanpath/der-codec";

describe("DER Tag Constants", () => {
  it("should have correct tag values", () => {
    expect(TAG_INTEGER).toBe(0x02);
    expect(TAG_OCTET_STRING).toBe(0x04);
    expect(TAG_UTF8_STRING).toBe(0x0c);
    expect(TAG_SEQUENCE).toBe(0x30);
  });
});

describe("contextTag", () => {
  it("should produce context-specific constructed tags", () => {
    expect(contextTag(0)).toBe(0xa0);
    expect(contextTag(1)).toBe(0xa1);
    expect(contextTag(7)).toBe(0xa7);
    expect(contextTag(9)).toBe(0xa9);
  });
});

describe("encodeInteger", () => {
  it("should encode zero", () => {
    const buf = encodeInteger(0);
    // TAG(02) LEN(01) VALUE(00)
    expect(buf).toEqual(Buffer.from([0x02, 0x01, 0x00]));
  });

  it("should encode small positive integer", () => {
    const buf = encodeInteger(42);
    // TAG(02) LEN(01) VALUE(2a)
    expect(buf).toEqual(Buffer.from([0x02, 0x01, 0x2a]));
  });

  it("should encode 127 (largest single-byte positive)", () => {
    const buf = encodeInteger(127);
    expect(buf).toEqual(Buffer.from([0x02, 0x01, 0x7f]));
  });

  it("should prepend 0x00 when high bit is set (128)", () => {
    const buf = encodeInteger(128);
    // Value 0x80 has high bit set, so needs 0x00 prefix
    expect(buf).toEqual(Buffer.from([0x02, 0x02, 0x00, 0x80]));
  });

  it("should encode 256", () => {
    const buf = encodeInteger(256);
    // 256 = 0x0100
    expect(buf).toEqual(Buffer.from([0x02, 0x02, 0x01, 0x00]));
  });

  it("should encode RDCLEANPATH_VERSION (3390)", () => {
    const buf = encodeInteger(3390);
    // 3390 = 0x0D3E
    expect(buf).toEqual(Buffer.from([0x02, 0x02, 0x0d, 0x3e]));
  });
});

describe("encodeOctetString", () => {
  it("should encode empty buffer", () => {
    const buf = encodeOctetString(Buffer.alloc(0));
    expect(buf).toEqual(Buffer.from([0x04, 0x00]));
  });

  it("should encode binary data", () => {
    const data = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]);
    const buf = encodeOctetString(data);
    expect(buf).toEqual(Buffer.from([0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]));
  });
});

describe("encodeUtf8String", () => {
  it("should encode empty string", () => {
    const buf = encodeUtf8String("");
    expect(buf).toEqual(Buffer.from([0x0c, 0x00]));
  });

  it("should encode ASCII string", () => {
    const buf = encodeUtf8String("hello");
    expect(buf[0]).toBe(0x0c); // TAG
    expect(buf[1]).toBe(5);    // LEN
    expect(buf.subarray(2).toString("utf-8")).toBe("hello");
  });

  it("should encode UTF-8 string with multibyte chars", () => {
    const buf = encodeUtf8String("héllo");
    expect(buf[0]).toBe(0x0c);
    expect(buf.subarray(2).toString("utf-8")).toBe("héllo");
  });
});

describe("encodeSequence", () => {
  it("should encode empty sequence", () => {
    const buf = encodeSequence([]);
    expect(buf).toEqual(Buffer.from([0x30, 0x00]));
  });

  it("should encode sequence with one element", () => {
    const inner = encodeInteger(42);
    const buf = encodeSequence([inner]);
    expect(buf[0]).toBe(0x30); // SEQUENCE tag
    expect(buf[1]).toBe(inner.length); // length
    expect(buf.subarray(2)).toEqual(inner);
  });

  it("should encode sequence with multiple elements", () => {
    const int1 = encodeInteger(1);
    const int2 = encodeInteger(2);
    const buf = encodeSequence([int1, int2]);
    expect(buf[0]).toBe(0x30);
    expect(buf[1]).toBe(int1.length + int2.length);
  });
});

describe("encodeExplicit", () => {
  it("should wrap content in context-specific tag [0]", () => {
    const inner = encodeInteger(3390);
    const buf = encodeExplicit(0, inner);
    expect(buf[0]).toBe(0xa0); // context [0]
    expect(buf[1]).toBe(inner.length);
    expect(buf.subarray(2)).toEqual(inner);
  });

  it("should wrap content in context-specific tag [7]", () => {
    const inner = encodeOctetString(Buffer.from([0x01]));
    const buf = encodeExplicit(7, inner);
    expect(buf[0]).toBe(0xa7);
  });
});

describe("long-form length encoding", () => {
  it("should use long-form for lengths >= 128", () => {
    const data = Buffer.alloc(200, 0x42);
    const buf = encodeOctetString(data);
    // TAG(04) LEN(81 C8) VALUE(200 bytes)
    expect(buf[0]).toBe(0x04);
    expect(buf[1]).toBe(0x81); // long form, 1 byte length
    expect(buf[2]).toBe(200);
    expect(buf.length).toBe(1 + 2 + 200);
  });

  it("should use 2-byte long-form for lengths > 255", () => {
    const data = Buffer.alloc(300, 0x42);
    const buf = encodeOctetString(data);
    expect(buf[0]).toBe(0x04);
    expect(buf[1]).toBe(0x82); // long form, 2 byte length
    expect(buf.readUInt16BE(2)).toBe(300);
    expect(buf.length).toBe(1 + 3 + 300);
  });
});

// ── DerReader ───────────────────────────────────────────────────

describe("DerReader", () => {
  describe("readInteger", () => {
    it("should read encoded integer", () => {
      const buf = encodeInteger(3390);
      const reader = new DerReader(buf);
      expect(reader.readInteger()).toBe(3390);
    });

    it("should read zero", () => {
      const buf = encodeInteger(0);
      const reader = new DerReader(buf);
      expect(reader.readInteger()).toBe(0);
    });

    it("should throw on wrong tag", () => {
      const buf = encodeUtf8String("hello");
      const reader = new DerReader(buf);
      expect(() => reader.readInteger()).toThrow("expected INTEGER");
    });
  });

  describe("readOctetString", () => {
    it("should read encoded octet string", () => {
      const data = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]);
      const buf = encodeOctetString(data);
      const reader = new DerReader(buf);
      expect(reader.readOctetString()).toEqual(data);
    });

    it("should read empty octet string", () => {
      const buf = encodeOctetString(Buffer.alloc(0));
      const reader = new DerReader(buf);
      expect(reader.readOctetString()).toEqual(Buffer.alloc(0));
    });
  });

  describe("readUtf8String", () => {
    it("should read encoded UTF-8 string", () => {
      const buf = encodeUtf8String("hello world");
      const reader = new DerReader(buf);
      expect(reader.readUtf8String()).toBe("hello world");
    });
  });

  describe("readSequence", () => {
    it("should read sequence and return inner reader", () => {
      const inner = encodeInteger(42);
      const buf = encodeSequence([inner]);
      const reader = new DerReader(buf);
      const seqReader = reader.readSequence();
      expect(seqReader.readInteger()).toBe(42);
      expect(seqReader.hasMore()).toBe(false);
    });

    it("should read sequence with multiple elements", () => {
      const buf = encodeSequence([encodeInteger(1), encodeInteger(2), encodeInteger(3)]);
      const reader = new DerReader(buf);
      const seqReader = reader.readSequence();
      expect(seqReader.readInteger()).toBe(1);
      expect(seqReader.readInteger()).toBe(2);
      expect(seqReader.readInteger()).toBe(3);
      expect(seqReader.hasMore()).toBe(false);
    });
  });

  describe("readExplicit", () => {
    it("should read matching explicit tag", () => {
      const inner = encodeInteger(42);
      const buf = encodeExplicit(0, inner);
      const reader = new DerReader(buf);
      const ctx = reader.readExplicit(0);
      expect(ctx).not.toBeNull();
      expect(ctx!.readInteger()).toBe(42);
    });

    it("should return null for non-matching tag", () => {
      const inner = encodeInteger(42);
      const buf = encodeExplicit(0, inner);
      const reader = new DerReader(buf);
      expect(reader.readExplicit(1)).toBeNull();
    });
  });

  describe("readSequenceOfOctetStrings", () => {
    it("should read sequence of octet strings", () => {
      const cert1 = Buffer.from([0x01, 0x02]);
      const cert2 = Buffer.from([0x03, 0x04]);
      const buf = encodeSequence([encodeOctetString(cert1), encodeOctetString(cert2)]);
      const reader = new DerReader(buf);
      const result = reader.readSequenceOfOctetStrings();
      expect(result).toHaveLength(2);
      expect(result[0]).toEqual(cert1);
      expect(result[1]).toEqual(cert2);
    });
  });

  describe("hasMore", () => {
    it("should return false for empty reader", () => {
      const reader = new DerReader(Buffer.alloc(0));
      expect(reader.hasMore()).toBe(false);
    });

    it("should return false after reading all data", () => {
      const buf = encodeInteger(42);
      const reader = new DerReader(buf);
      reader.readInteger();
      expect(reader.hasMore()).toBe(false);
    });
  });

  describe("skip", () => {
    it("should skip a TLV element", () => {
      const buf = Buffer.concat([encodeInteger(1), encodeInteger(2)]);
      const reader = new DerReader(buf);
      reader.skip(); // skip first integer
      expect(reader.readInteger()).toBe(2);
    });
  });

  describe("peekTag", () => {
    it("should peek at next tag without advancing", () => {
      const buf = encodeInteger(42);
      const reader = new DerReader(buf);
      expect(reader.peekTag()).toBe(TAG_INTEGER);
      // Still at same position
      expect(reader.readInteger()).toBe(42);
    });

    it("should return -1 at end of buffer", () => {
      const reader = new DerReader(Buffer.alloc(0));
      expect(reader.peekTag()).toBe(-1);
    });
  });

  describe("error handling", () => {
    it("should throw on unexpected end of data for readTag", () => {
      const reader = new DerReader(Buffer.alloc(0));
      expect(() => reader.readTag()).toThrow("unexpected end of data");
    });

    it("should throw when value overflows buffer", () => {
      // Craft a TLV that claims length 100 but buffer is only 3 bytes
      const bad = Buffer.from([0x04, 0x64, 0x00]); // OCTET STRING, length 100, 1 byte
      const reader = new DerReader(bad);
      expect(() => reader.readOctetString()).toThrow("overflows buffer");
    });
  });

  describe("roundtrip", () => {
    it("should roundtrip a complex nested structure", () => {
      // Build: SEQUENCE { [0] INTEGER(3390), [2] UTF8("hello"), [6] OCTET(deadbeef) }
      const original = encodeSequence([
        encodeExplicit(0, encodeInteger(3390)),
        encodeExplicit(2, encodeUtf8String("hello")),
        encodeExplicit(6, encodeOctetString(Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]))),
      ]);

      const outer = new DerReader(original);
      const seq = outer.readSequence();

      const ctx0 = seq.readExplicit(0);
      expect(ctx0!.readInteger()).toBe(3390);

      const ctx2 = seq.readExplicit(2);
      expect(ctx2!.readUtf8String()).toBe("hello");

      const ctx6 = seq.readExplicit(6);
      expect(ctx6!.readOctetString()).toEqual(Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]));

      expect(seq.hasMore()).toBe(false);
    });
  });
});
