/**
 * SFTP Binary Buffer Utilities
 * Handles reading and writing SFTP protocol binary data
 */

import {
  SSH_FILEXFER_ATTR,
  type SftpAttrs,
  type SftpFileEntry,
} from "./protocol";

/**
 * Buffer writer for constructing SFTP packets
 */
export class SftpBufferWriter {
  private chunks: Uint8Array[] = [];
  private totalLength = 0;

  /**
   * Write an unsigned 8-bit integer
   */
  writeUInt8(value: number): this {
    const buf = new Uint8Array(1);
    buf[0] = value & 0xff;
    this.chunks.push(buf);
    this.totalLength += 1;
    return this;
  }

  /**
   * Write an unsigned 32-bit integer (big-endian)
   */
  writeUInt32(value: number): this {
    const buf = new Uint8Array(4);
    const view = new DataView(buf.buffer);
    view.setUint32(0, value, false); // big-endian
    this.chunks.push(buf);
    this.totalLength += 4;
    return this;
  }

  /**
   * Write an unsigned 64-bit integer (big-endian)
   */
  writeUInt64(value: bigint): this {
    const buf = new Uint8Array(8);
    const view = new DataView(buf.buffer);
    view.setBigUint64(0, value, false); // big-endian
    this.chunks.push(buf);
    this.totalLength += 8;
    return this;
  }

  /**
   * Write a string (length-prefixed)
   */
  writeString(value: string | Uint8Array): this {
    const data =
      typeof value === "string" ? new TextEncoder().encode(value) : value;
    this.writeUInt32(data.length);
    this.chunks.push(data);
    this.totalLength += data.length;
    return this;
  }

  /**
   * Write raw bytes without length prefix
   */
  writeBytes(data: Uint8Array): this {
    this.chunks.push(data);
    this.totalLength += data.length;
    return this;
  }

  /**
   * Write SFTP attributes
   */
  writeAttrs(attrs: Partial<SftpAttrs>): this {
    let flags = 0;

    if (attrs.size !== undefined) flags |= SSH_FILEXFER_ATTR.SIZE;
    if (attrs.uid !== undefined && attrs.gid !== undefined)
      flags |= SSH_FILEXFER_ATTR.UIDGID;
    if (attrs.permissions !== undefined) flags |= SSH_FILEXFER_ATTR.PERMISSIONS;
    if (attrs.atime !== undefined && attrs.mtime !== undefined)
      flags |= SSH_FILEXFER_ATTR.ACMODTIME;

    this.writeUInt32(flags);

    if (flags & SSH_FILEXFER_ATTR.SIZE) {
      this.writeUInt64(attrs.size!);
    }
    if (flags & SSH_FILEXFER_ATTR.UIDGID) {
      this.writeUInt32(attrs.uid!);
      this.writeUInt32(attrs.gid!);
    }
    if (flags & SSH_FILEXFER_ATTR.PERMISSIONS) {
      this.writeUInt32(attrs.permissions!);
    }
    if (flags & SSH_FILEXFER_ATTR.ACMODTIME) {
      this.writeUInt32(attrs.atime!);
      this.writeUInt32(attrs.mtime!);
    }

    return this;
  }

  /**
   * Get the current length of the buffer
   */
  get length(): number {
    return this.totalLength;
  }

  /**
   * Build the final buffer
   */
  toBuffer(): Uint8Array {
    const result = new Uint8Array(this.totalLength);
    let offset = 0;
    for (const chunk of this.chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }

  /**
   * Build an SFTP packet with length prefix
   */
  toPacket(): Uint8Array {
    const payload = this.toBuffer();
    const packet = new Uint8Array(4 + payload.length);
    const view = new DataView(packet.buffer);
    view.setUint32(0, payload.length, false);
    packet.set(payload, 4);
    return packet;
  }
}

/**
 * Buffer reader for parsing SFTP packets
 */
export class SftpBufferReader {
  private view: DataView;
  private offset = 0;

  constructor(private data: Uint8Array) {
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  }

  /**
   * Get remaining bytes
   */
  get remaining(): number {
    return this.data.length - this.offset;
  }

  /**
   * Check if there are more bytes to read
   */
  get hasMore(): boolean {
    return this.offset < this.data.length;
  }

  /**
   * Read an unsigned 8-bit integer
   */
  readUInt8(): number {
    if (this.offset + 1 > this.data.length) {
      throw new Error("Buffer underflow reading uint8");
    }
    return this.data[this.offset++];
  }

  /**
   * Read an unsigned 32-bit integer (big-endian)
   */
  readUInt32(): number {
    if (this.offset + 4 > this.data.length) {
      throw new Error("Buffer underflow reading uint32");
    }
    const value = this.view.getUint32(this.offset, false);
    this.offset += 4;
    return value;
  }

  /**
   * Read an unsigned 64-bit integer (big-endian)
   */
  readUInt64(): bigint {
    if (this.offset + 8 > this.data.length) {
      throw new Error("Buffer underflow reading uint64");
    }
    const value = this.view.getBigUint64(this.offset, false);
    this.offset += 8;
    return value;
  }

  /**
   * Read a length-prefixed string as bytes
   */
  readString(): Uint8Array {
    const length = this.readUInt32();
    if (this.offset + length > this.data.length) {
      throw new Error(`Buffer underflow reading string of length ${length}`);
    }
    const result = this.data.slice(this.offset, this.offset + length);
    this.offset += length;
    return result;
  }

  /**
   * Read a length-prefixed string as text
   */
  readStringAsText(): string {
    return new TextDecoder().decode(this.readString());
  }

  /**
   * Read raw bytes
   */
  readBytes(length: number): Uint8Array {
    if (this.offset + length > this.data.length) {
      throw new Error(`Buffer underflow reading ${length} bytes`);
    }
    const result = this.data.slice(this.offset, this.offset + length);
    this.offset += length;
    return result;
  }

  /**
   * Read remaining bytes
   */
  readRemaining(): Uint8Array {
    const result = this.data.slice(this.offset);
    this.offset = this.data.length;
    return result;
  }

  /**
   * Read SFTP attributes
   */
  readAttrs(): SftpAttrs {
    const flags = this.readUInt32();
    const attrs: SftpAttrs = { flags };

    if (flags & SSH_FILEXFER_ATTR.SIZE) {
      attrs.size = this.readUInt64();
    }
    if (flags & SSH_FILEXFER_ATTR.UIDGID) {
      attrs.uid = this.readUInt32();
      attrs.gid = this.readUInt32();
    }
    if (flags & SSH_FILEXFER_ATTR.PERMISSIONS) {
      attrs.permissions = this.readUInt32();
    }
    if (flags & SSH_FILEXFER_ATTR.ACMODTIME) {
      attrs.atime = this.readUInt32();
      attrs.mtime = this.readUInt32();
    }
    if (flags & SSH_FILEXFER_ATTR.EXTENDED) {
      const count = this.readUInt32();
      attrs.extended = [];
      for (let i = 0; i < count; i++) {
        attrs.extended.push({
          type: this.readStringAsText(),
          data: this.readStringAsText(),
        });
      }
    }

    return attrs;
  }

  /**
   * Read a file entry (filename, longname, attrs)
   */
  readFileEntry(): SftpFileEntry {
    return {
      filename: this.readStringAsText(),
      longname: this.readStringAsText(),
      attrs: this.readAttrs(),
    };
  }

  /**
   * Skip bytes
   */
  skip(length: number): this {
    if (this.offset + length > this.data.length) {
      throw new Error(`Cannot skip ${length} bytes`);
    }
    this.offset += length;
    return this;
  }
}

/**
 * Concatenate multiple Uint8Arrays
 */
export function concatBuffers(...buffers: Uint8Array[]): Uint8Array {
  const totalLength = buffers.reduce((sum, buf) => sum + buf.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const buf of buffers) {
    result.set(buf, offset);
    offset += buf.length;
  }
  return result;
}

/**
 * Compare two Uint8Arrays for equality
 */
export function buffersEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
