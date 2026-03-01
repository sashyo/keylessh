/**
 * Minimal ASN.1 DER encoder/decoder for RDCleanPath PDUs.
 *
 * Only implements the primitives used by the RDCleanPath protocol:
 * SEQUENCE, INTEGER, OCTET STRING, UTF8String, and context-specific
 * EXPLICIT tags [0]–[9].
 */

// ── Tag constants ────────────────────────────────────────────────

export const TAG_INTEGER = 0x02;
export const TAG_OCTET_STRING = 0x04;
export const TAG_UTF8_STRING = 0x0c;
export const TAG_SEQUENCE = 0x30;

/** Context-specific EXPLICIT constructed tag for [n] */
export function contextTag(n: number): number {
  return 0xa0 | n;
}

// ── Length encoding ──────────────────────────────────────────────

function encodeLength(len: number): Buffer {
  if (len < 0x80) {
    return Buffer.from([len]);
  }
  if (len <= 0xff) {
    return Buffer.from([0x81, len]);
  }
  if (len <= 0xffff) {
    const buf = Buffer.alloc(3);
    buf[0] = 0x82;
    buf.writeUInt16BE(len, 1);
    return buf;
  }
  // 3-byte length (up to 16MB)
  const buf = Buffer.alloc(4);
  buf[0] = 0x83;
  buf[1] = (len >> 16) & 0xff;
  buf[2] = (len >> 8) & 0xff;
  buf[3] = len & 0xff;
  return buf;
}

// ── TLV encoding ─────────────────────────────────────────────────

export function encodeTlv(tag: number, content: Buffer): Buffer {
  const lenBuf = encodeLength(content.length);
  const out = Buffer.alloc(1 + lenBuf.length + content.length);
  out[0] = tag;
  lenBuf.copy(out, 1);
  content.copy(out, 1 + lenBuf.length);
  return out;
}

export function encodeInteger(value: number): Buffer {
  // Encode as signed big-endian with minimal bytes
  const bytes: number[] = [];
  if (value === 0) {
    bytes.push(0);
  } else {
    let v = value;
    while (v > 0) {
      bytes.unshift(v & 0xff);
      v = v >>> 8;
    }
    // Prepend 0x00 if high bit set (DER signed integer)
    if (bytes[0] & 0x80) {
      bytes.unshift(0);
    }
  }
  return encodeTlv(TAG_INTEGER, Buffer.from(bytes));
}

export function encodeOctetString(data: Buffer): Buffer {
  return encodeTlv(TAG_OCTET_STRING, data);
}

export function encodeUtf8String(str: string): Buffer {
  return encodeTlv(TAG_UTF8_STRING, Buffer.from(str, "utf-8"));
}

export function encodeSequence(elements: Buffer[]): Buffer {
  const content = Buffer.concat(elements);
  return encodeTlv(TAG_SEQUENCE, content);
}

/** Wrap inner content in a context-specific EXPLICIT [tagNum] */
export function encodeExplicit(tagNum: number, inner: Buffer): Buffer {
  return encodeTlv(contextTag(tagNum), inner);
}

// ── DER Reader ───────────────────────────────────────────────────

export class DerReader {
  private buf: Buffer;
  private pos: number;
  private end: number;

  constructor(buf: Buffer, offset = 0, length?: number) {
    this.buf = buf;
    this.pos = offset;
    this.end = offset + (length ?? buf.length - offset);
  }

  hasMore(): boolean {
    return this.pos < this.end;
  }

  /** Peek at the next tag without advancing */
  peekTag(): number {
    if (this.pos >= this.end) return -1;
    return this.buf[this.pos];
  }

  /** Read a tag byte */
  readTag(): number {
    if (this.pos >= this.end) throw new Error("DER: unexpected end of data");
    return this.buf[this.pos++];
  }

  /** Read a DER length */
  readLength(): number {
    if (this.pos >= this.end) throw new Error("DER: unexpected end of data");
    const first = this.buf[this.pos++];
    if (first < 0x80) return first;

    const numBytes = first & 0x7f;
    if (numBytes === 0 || numBytes > 3) throw new Error(`DER: unsupported length form: ${numBytes} bytes`);
    if (this.pos + numBytes > this.end) throw new Error("DER: length overflows buffer");

    let len = 0;
    for (let i = 0; i < numBytes; i++) {
      len = (len << 8) | this.buf[this.pos++];
    }
    return len;
  }

  /** Read a full TLV, return tag and value buffer */
  readTlv(): { tag: number; value: Buffer } {
    const tag = this.readTag();
    const len = this.readLength();
    if (this.pos + len > this.end) throw new Error("DER: value overflows buffer");
    const value = this.buf.subarray(this.pos, this.pos + len);
    this.pos += len;
    return { tag, value };
  }

  /** Read a SEQUENCE and return a DerReader over its contents */
  readSequence(): DerReader {
    const { tag, value } = this.readTlv();
    if (tag !== TAG_SEQUENCE) throw new Error(`DER: expected SEQUENCE (0x30), got 0x${tag.toString(16)}`);
    return new DerReader(value, 0, value.length);
  }

  /**
   * If the next tag matches EXPLICIT [tagNum], consume it and return
   * a DerReader over the inner content. Otherwise return null.
   */
  readExplicit(tagNum: number): DerReader | null {
    if (this.peekTag() !== contextTag(tagNum)) return null;
    const { value } = this.readTlv();
    return new DerReader(value, 0, value.length);
  }

  /** Read an INTEGER and return as a JS number (up to 48-bit safe) */
  readInteger(): number {
    const { tag, value } = this.readTlv();
    if (tag !== TAG_INTEGER) throw new Error(`DER: expected INTEGER (0x02), got 0x${tag.toString(16)}`);
    let result = 0;
    for (let i = 0; i < value.length; i++) {
      result = result * 256 + value[i];
    }
    return result;
  }

  /** Read an OCTET STRING */
  readOctetString(): Buffer {
    const { tag, value } = this.readTlv();
    if (tag !== TAG_OCTET_STRING) throw new Error(`DER: expected OCTET STRING (0x04), got 0x${tag.toString(16)}`);
    return value;
  }

  /** Read a UTF8String */
  readUtf8String(): string {
    const { tag, value } = this.readTlv();
    if (tag !== TAG_UTF8_STRING) throw new Error(`DER: expected UTF8String (0x0C), got 0x${tag.toString(16)}`);
    return value.toString("utf-8");
  }

  /** Skip the current TLV (consume without returning) */
  skip(): void {
    this.readTlv();
  }

  /** Read a SEQUENCE OF OCTET STRING (returns array of buffers) */
  readSequenceOfOctetStrings(): Buffer[] {
    const inner = this.readSequence();
    const result: Buffer[] = [];
    while (inner.hasMore()) {
      result.push(inner.readOctetString());
    }
    return result;
  }
}
