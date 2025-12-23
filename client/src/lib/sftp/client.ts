/**
 * SFTP Client Implementation
 * Provides high-level file operations over an SSH SFTP channel
 */

import type { SshChannel } from "@microsoft/dev-tunnels-ssh";
import { SftpBufferReader, SftpBufferWriter, concatBuffers } from "./buffer";
import {
  SSH_FXP,
  SSH_FXF,
  SSH_FX,
  SFTP_VERSION,
  DEFAULT_CHUNK_SIZE,
  SftpError,
  type SftpAttrs,
  type SftpFileEntry,
  type SftpStatusCode,
} from "./protocol";

/**
 * Progress callback for file transfers
 */
export type TransferProgressCallback = (
  bytesTransferred: number,
  totalBytes: number
) => void;

/**
 * Pending request tracking
 */
interface PendingRequest {
  resolve: (data: Uint8Array) => void;
  reject: (error: Error) => void;
}

/**
 * SFTP Client
 */
export class SftpClient {
  private requestId = 0;
  private pendingRequests = new Map<number, PendingRequest>();
  private receiveBuffer = new Uint8Array(0);
  private serverVersion = 0;
  private disposed = false;
  private dataHandler: ((data: Buffer) => void) | null = null;

  constructor(private channel: SshChannel) {
    // Set up data reception
    this.dataHandler = (data: Buffer) => {
      this.onData(new Uint8Array(data));
    };
    this.channel.onDataReceived(this.dataHandler);
  }

  /**
   * Initialize SFTP session
   */
  async init(): Promise<number> {
    const writer = new SftpBufferWriter();
    writer.writeUInt8(SSH_FXP.INIT);
    writer.writeUInt32(SFTP_VERSION);

    await this.sendRaw(writer.toPacket());
    const response = await this.receivePacket();
    const reader = new SftpBufferReader(response);

    const type = reader.readUInt8();
    if (type !== SSH_FXP.VERSION) {
      throw new Error(`Expected VERSION packet, got ${type}`);
    }

    this.serverVersion = reader.readUInt32();
    // Skip any extensions
    return this.serverVersion;
  }

  /**
   * Get real path (resolve symlinks, normalize)
   */
  async realpath(path: string): Promise<string> {
    const id = this.nextRequestId();
    const writer = new SftpBufferWriter();
    writer.writeUInt8(SSH_FXP.REALPATH);
    writer.writeUInt32(id);
    writer.writeString(path);

    const response = await this.sendRequest(id, writer.toPacket());
    const reader = new SftpBufferReader(response);

    const type = reader.readUInt8();
    reader.skip(4); // request id

    if (type === SSH_FXP.STATUS) {
      this.throwStatus(reader);
    }

    if (type !== SSH_FXP.NAME) {
      throw new Error(`Expected NAME packet, got ${type}`);
    }

    const count = reader.readUInt32();
    if (count < 1) {
      throw new Error("No path in REALPATH response");
    }

    return reader.readStringAsText();
  }

  /**
   * Get file/directory stats (follows symlinks)
   */
  async stat(path: string): Promise<SftpAttrs> {
    const id = this.nextRequestId();
    const writer = new SftpBufferWriter();
    writer.writeUInt8(SSH_FXP.STAT);
    writer.writeUInt32(id);
    writer.writeString(path);

    const response = await this.sendRequest(id, writer.toPacket());
    return this.parseAttrsResponse(response);
  }

  /**
   * Get file/directory stats (does not follow symlinks)
   */
  async lstat(path: string): Promise<SftpAttrs> {
    const id = this.nextRequestId();
    const writer = new SftpBufferWriter();
    writer.writeUInt8(SSH_FXP.LSTAT);
    writer.writeUInt32(id);
    writer.writeString(path);

    const response = await this.sendRequest(id, writer.toPacket());
    return this.parseAttrsResponse(response);
  }

  /**
   * Set file/directory attributes
   */
  async setstat(path: string, attrs: Partial<SftpAttrs>): Promise<void> {
    const id = this.nextRequestId();
    const writer = new SftpBufferWriter();
    writer.writeUInt8(SSH_FXP.SETSTAT);
    writer.writeUInt32(id);
    writer.writeString(path);
    writer.writeAttrs(attrs);

    const response = await this.sendRequest(id, writer.toPacket());
    this.expectStatus(response, SSH_FX.OK);
  }

  /**
   * Open a directory for reading
   */
  async opendir(path: string): Promise<Uint8Array> {
    const id = this.nextRequestId();
    const writer = new SftpBufferWriter();
    writer.writeUInt8(SSH_FXP.OPENDIR);
    writer.writeUInt32(id);
    writer.writeString(path);

    const response = await this.sendRequest(id, writer.toPacket());
    return this.parseHandleResponse(response);
  }

  /**
   * Read directory entries
   */
  async readdir(handle: Uint8Array): Promise<SftpFileEntry[]> {
    const id = this.nextRequestId();
    const writer = new SftpBufferWriter();
    writer.writeUInt8(SSH_FXP.READDIR);
    writer.writeUInt32(id);
    writer.writeString(handle);

    const response = await this.sendRequest(id, writer.toPacket());
    const reader = new SftpBufferReader(response);

    const type = reader.readUInt8();
    reader.skip(4); // request id

    if (type === SSH_FXP.STATUS) {
      const code = reader.readUInt32() as SftpStatusCode;
      if (code === SSH_FX.EOF) {
        return []; // End of directory
      }
      throw new SftpError(code, reader.readStringAsText());
    }

    if (type !== SSH_FXP.NAME) {
      throw new Error(`Expected NAME packet, got ${type}`);
    }

    const count = reader.readUInt32();
    const entries: SftpFileEntry[] = [];

    for (let i = 0; i < count; i++) {
      entries.push(reader.readFileEntry());
    }

    return entries;
  }

  /**
   * List all entries in a directory
   */
  async listDirectory(path: string): Promise<SftpFileEntry[]> {
    const handle = await this.opendir(path);
    const allEntries: SftpFileEntry[] = [];

    try {
      while (true) {
        const entries = await this.readdir(handle);
        if (entries.length === 0) break;
        allEntries.push(...entries);
      }
    } finally {
      await this.close(handle);
    }

    // Filter out . and ..
    return allEntries.filter(
      (e) => e.filename !== "." && e.filename !== ".."
    );
  }

  /**
   * Open a file
   */
  async open(
    path: string,
    flags: number,
    attrs: Partial<SftpAttrs> = {}
  ): Promise<Uint8Array> {
    const id = this.nextRequestId();
    const writer = new SftpBufferWriter();
    writer.writeUInt8(SSH_FXP.OPEN);
    writer.writeUInt32(id);
    writer.writeString(path);
    writer.writeUInt32(flags);
    writer.writeAttrs(attrs);

    const response = await this.sendRequest(id, writer.toPacket());
    return this.parseHandleResponse(response);
  }

  /**
   * Close a file or directory handle
   */
  async close(handle: Uint8Array): Promise<void> {
    const id = this.nextRequestId();
    const writer = new SftpBufferWriter();
    writer.writeUInt8(SSH_FXP.CLOSE);
    writer.writeUInt32(id);
    writer.writeString(handle);

    const response = await this.sendRequest(id, writer.toPacket());
    this.expectStatus(response, SSH_FX.OK);
  }

  /**
   * Read from a file
   */
  async read(
    handle: Uint8Array,
    offset: bigint,
    length: number
  ): Promise<Uint8Array> {
    const id = this.nextRequestId();
    const writer = new SftpBufferWriter();
    writer.writeUInt8(SSH_FXP.READ);
    writer.writeUInt32(id);
    writer.writeString(handle);
    writer.writeUInt64(offset);
    writer.writeUInt32(length);

    const response = await this.sendRequest(id, writer.toPacket());
    const reader = new SftpBufferReader(response);

    const type = reader.readUInt8();
    reader.skip(4); // request id

    if (type === SSH_FXP.STATUS) {
      const code = reader.readUInt32() as SftpStatusCode;
      if (code === SSH_FX.EOF) {
        return new Uint8Array(0); // End of file
      }
      throw new SftpError(code, reader.readStringAsText());
    }

    if (type !== SSH_FXP.DATA) {
      throw new Error(`Expected DATA packet, got ${type}`);
    }

    return reader.readString();
  }

  /**
   * Write to a file
   */
  async write(
    handle: Uint8Array,
    offset: bigint,
    data: Uint8Array
  ): Promise<void> {
    const id = this.nextRequestId();
    const writer = new SftpBufferWriter();
    writer.writeUInt8(SSH_FXP.WRITE);
    writer.writeUInt32(id);
    writer.writeString(handle);
    writer.writeUInt64(offset);
    writer.writeString(data);

    const response = await this.sendRequest(id, writer.toPacket());
    this.expectStatus(response, SSH_FX.OK);
  }

  /**
   * Remove a file
   */
  async remove(path: string): Promise<void> {
    const id = this.nextRequestId();
    const writer = new SftpBufferWriter();
    writer.writeUInt8(SSH_FXP.REMOVE);
    writer.writeUInt32(id);
    writer.writeString(path);

    const response = await this.sendRequest(id, writer.toPacket());
    this.expectStatus(response, SSH_FX.OK);
  }

  /**
   * Rename a file or directory
   */
  async rename(oldPath: string, newPath: string): Promise<void> {
    const id = this.nextRequestId();
    const writer = new SftpBufferWriter();
    writer.writeUInt8(SSH_FXP.RENAME);
    writer.writeUInt32(id);
    writer.writeString(oldPath);
    writer.writeString(newPath);

    const response = await this.sendRequest(id, writer.toPacket());
    this.expectStatus(response, SSH_FX.OK);
  }

  /**
   * Create a directory
   */
  async mkdir(path: string, attrs: Partial<SftpAttrs> = {}): Promise<void> {
    const id = this.nextRequestId();
    const writer = new SftpBufferWriter();
    writer.writeUInt8(SSH_FXP.MKDIR);
    writer.writeUInt32(id);
    writer.writeString(path);
    writer.writeAttrs(attrs);

    const response = await this.sendRequest(id, writer.toPacket());
    this.expectStatus(response, SSH_FX.OK);
  }

  /**
   * Remove a directory
   */
  async rmdir(path: string): Promise<void> {
    const id = this.nextRequestId();
    const writer = new SftpBufferWriter();
    writer.writeUInt8(SSH_FXP.RMDIR);
    writer.writeUInt32(id);
    writer.writeString(path);

    const response = await this.sendRequest(id, writer.toPacket());
    this.expectStatus(response, SSH_FX.OK);
  }

  /**
   * Download a file with progress
   */
  async downloadFile(
    remotePath: string,
    onProgress?: TransferProgressCallback
  ): Promise<Uint8Array> {
    // Get file size first
    const attrs = await this.stat(remotePath);
    const totalSize = Number(attrs.size ?? BigInt(0));

    // Open file for reading
    const handle = await this.open(remotePath, SSH_FXF.READ);
    const chunks: Uint8Array[] = [];
    let offset = BigInt(0);
    let bytesRead = 0;

    try {
      while (true) {
        const chunk = await this.read(handle, offset, DEFAULT_CHUNK_SIZE);
        if (chunk.length === 0) break;

        chunks.push(chunk);
        offset += BigInt(chunk.length);
        bytesRead += chunk.length;

        if (onProgress) {
          onProgress(bytesRead, totalSize);
        }
      }
    } finally {
      await this.close(handle);
    }

    return concatBuffers(...chunks);
  }

  /**
   * Upload a file with progress
   */
  async uploadFile(
    data: Uint8Array,
    remotePath: string,
    onProgress?: TransferProgressCallback
  ): Promise<void> {
    const totalSize = data.length;

    // Open file for writing (create/truncate)
    const handle = await this.open(
      remotePath,
      SSH_FXF.WRITE | SSH_FXF.CREAT | SSH_FXF.TRUNC
    );

    let offset = BigInt(0);
    let bytesWritten = 0;

    try {
      while (bytesWritten < totalSize) {
        const chunkSize = Math.min(DEFAULT_CHUNK_SIZE, totalSize - bytesWritten);
        const chunk = data.slice(bytesWritten, bytesWritten + chunkSize);

        await this.write(handle, offset, chunk);

        offset += BigInt(chunkSize);
        bytesWritten += chunkSize;

        if (onProgress) {
          onProgress(bytesWritten, totalSize);
        }
      }
    } finally {
      await this.close(handle);
    }
  }

  /**
   * Check if a path exists
   */
  async exists(path: string): Promise<boolean> {
    try {
      await this.stat(path);
      return true;
    } catch (err) {
      if (err instanceof SftpError && err.code === SSH_FX.NO_SUCH_FILE) {
        return false;
      }
      throw err;
    }
  }

  /**
   * Dispose the client
   */
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;

    // Reject all pending requests
    this.pendingRequests.forEach((pending) => {
      pending.reject(new Error("SFTP client disposed"));
    });
    this.pendingRequests.clear();
  }

  // ─── Private Methods ────────────────────────────────────────

  private nextRequestId(): number {
    return ++this.requestId;
  }

  private async sendRaw(data: Uint8Array): Promise<void> {
    if (this.disposed) {
      throw new Error("SFTP client disposed");
    }
    await this.channel.send(Buffer.from(data));
  }

  private async sendRequest(id: number, packet: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, { resolve, reject });
      this.sendRaw(packet).catch(reject);
    });
  }

  private async receivePacket(): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      // Use request id 0 for init/version
      this.pendingRequests.set(0, { resolve, reject });
    });
  }

  private onData(data: Uint8Array): void {
    // Append to receive buffer
    this.receiveBuffer = concatBuffers(this.receiveBuffer, data);

    // Process complete packets
    while (this.receiveBuffer.length >= 4) {
      const view = new DataView(
        this.receiveBuffer.buffer,
        this.receiveBuffer.byteOffset
      );
      const packetLength = view.getUint32(0, false);

      if (this.receiveBuffer.length < 4 + packetLength) {
        break; // Wait for more data
      }

      // Extract packet
      const packet = this.receiveBuffer.slice(4, 4 + packetLength);
      this.receiveBuffer = this.receiveBuffer.slice(4 + packetLength);

      // Route to pending request
      this.handlePacket(packet);
    }

    // Acknowledge received data for flow control
    this.channel.adjustWindow(data.length);
  }

  private handlePacket(packet: Uint8Array): void {
    if (packet.length < 1) return;

    const type = packet[0];

    // VERSION packet (response to INIT)
    if (type === SSH_FXP.VERSION) {
      const pending = this.pendingRequests.get(0);
      if (pending) {
        this.pendingRequests.delete(0);
        pending.resolve(packet);
      }
      return;
    }

    // All other packets have request id at offset 1
    if (packet.length < 5) return;

    const view = new DataView(packet.buffer, packet.byteOffset);
    const requestId = view.getUint32(1, false);

    const pending = this.pendingRequests.get(requestId);
    if (pending) {
      this.pendingRequests.delete(requestId);
      pending.resolve(packet);
    }
  }

  private parseHandleResponse(response: Uint8Array): Uint8Array {
    const reader = new SftpBufferReader(response);
    const type = reader.readUInt8();
    reader.skip(4); // request id

    if (type === SSH_FXP.STATUS) {
      this.throwStatus(reader);
    }

    if (type !== SSH_FXP.HANDLE) {
      throw new Error(`Expected HANDLE packet, got ${type}`);
    }

    return reader.readString();
  }

  private parseAttrsResponse(response: Uint8Array): SftpAttrs {
    const reader = new SftpBufferReader(response);
    const type = reader.readUInt8();
    reader.skip(4); // request id

    if (type === SSH_FXP.STATUS) {
      this.throwStatus(reader);
    }

    if (type !== SSH_FXP.ATTRS) {
      throw new Error(`Expected ATTRS packet, got ${type}`);
    }

    return reader.readAttrs();
  }

  private expectStatus(response: Uint8Array, expected: SftpStatusCode): void {
    const reader = new SftpBufferReader(response);
    const type = reader.readUInt8();
    reader.skip(4); // request id

    if (type !== SSH_FXP.STATUS) {
      throw new Error(`Expected STATUS packet, got ${type}`);
    }

    const code = reader.readUInt32() as SftpStatusCode;
    if (code !== expected) {
      const message = reader.readStringAsText();
      throw new SftpError(code, message);
    }
  }

  private throwStatus(reader: SftpBufferReader): never {
    const code = reader.readUInt32() as SftpStatusCode;
    const message = reader.readStringAsText();
    throw new SftpError(code, message);
  }
}
