/**
 * SCP Client Implementation
 * Provides file upload/download over SSH exec channels
 * Fallback for servers that don't support SFTP subsystem
 */

import type { SshChannel, SshClientSession, SshDataWriter } from "@microsoft/dev-tunnels-ssh";

// Dynamic import of the actual message classes from CommonJS module
let ChannelRequestMessageCtor: any = null;

async function getChannelRequestMessageClass(): Promise<any> {
  if (ChannelRequestMessageCtor) return ChannelRequestMessageCtor;
  const mod = await import("@microsoft/dev-tunnels-ssh");
  ChannelRequestMessageCtor = mod.ChannelRequestMessage;
  return ChannelRequestMessageCtor;
}

/**
 * Create an exec request message for running a command
 */
async function createExecRequest(command: string): Promise<any> {
  const ChannelRequestMessage = await getChannelRequestMessageClass();
  const msg = new ChannelRequestMessage("exec", true);

  const originalOnWrite = Object.getPrototypeOf(msg).onWrite;

  msg.onWrite = function (writer: SshDataWriter) {
    originalOnWrite.call(this, writer);
    writer.writeString(command, "utf-8");
  };

  return msg;
}

/**
 * Progress callback for file transfers
 */
export type ScpTransferProgressCallback = (
  bytesTransferred: number,
  totalBytes: number
) => void;

/**
 * SCP response codes
 */
const SCP_OK = 0;
const SCP_WARNING = 1;
const SCP_ERROR = 2;

/**
 * SCP Client
 * Uses exec channels to run scp commands on remote server
 */
export class ScpClient {
  private disposed = false;

  constructor(private session: SshClientSession) {}

  /**
   * Download a file from the remote server
   */
  async downloadFile(
    remotePath: string,
    onProgress?: ScpTransferProgressCallback
  ): Promise<Uint8Array> {
    if (this.disposed) {
      throw new Error("SCP client disposed");
    }

    // Open exec channel for scp -f (from/download)
    const channel = await this.session.openChannel("session");

    try {
      const execRequest = await createExecRequest(`scp -f "${remotePath}"`);
      const result = await channel.request(execRequest);

      if (!result) {
        throw new Error("SCP exec request denied by server");
      }

      return await this.receiveFile(channel, onProgress);
    } finally {
      try {
        channel.dispose();
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  /**
   * Upload a file to the remote server
   */
  async uploadFile(
    data: Uint8Array,
    remotePath: string,
    permissions: string = "0644",
    onProgress?: ScpTransferProgressCallback
  ): Promise<void> {
    if (this.disposed) {
      throw new Error("SCP client disposed");
    }

    // Open exec channel for scp -t (to/upload)
    const channel = await this.session.openChannel("session");

    try {
      const execRequest = await createExecRequest(`scp -t "${remotePath}"`);
      const result = await channel.request(execRequest);

      if (!result) {
        throw new Error("SCP exec request denied by server");
      }

      await this.sendFile(channel, data, remotePath, permissions, onProgress);
    } finally {
      try {
        channel.dispose();
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  /**
   * Dispose the client
   */
  dispose(): void {
    this.disposed = true;
  }

  // ─── Private Methods ────────────────────────────────────────

  /**
   * Receive a file via SCP protocol
   */
  private async receiveFile(
    channel: SshChannel,
    onProgress?: ScpTransferProgressCallback
  ): Promise<Uint8Array> {
    const reader = new ScpChannelReader(channel);

    // Send initial acknowledgment (ready to receive)
    await this.sendByte(channel, SCP_OK);

    // Read file header: C<mode> <size> <filename>\n
    const header = await reader.readLine();

    if (header.startsWith("T")) {
      // Time message - skip it and read the file header
      await this.sendByte(channel, SCP_OK);
      const fileHeader = await reader.readLine();
      return this.parseAndReceiveFile(channel, reader, fileHeader, onProgress);
    }

    return this.parseAndReceiveFile(channel, reader, header, onProgress);
  }

  private async parseAndReceiveFile(
    channel: SshChannel,
    reader: ScpChannelReader,
    header: string,
    onProgress?: ScpTransferProgressCallback
  ): Promise<Uint8Array> {
    if (!header.startsWith("C")) {
      if (header.charCodeAt(0) === SCP_ERROR || header.charCodeAt(0) === SCP_WARNING) {
        throw new Error(`SCP error: ${header.substring(1)}`);
      }
      throw new Error(`Invalid SCP header: ${header}`);
    }

    // Parse: C<mode> <size> <filename>
    const parts = header.substring(1).split(" ");
    if (parts.length < 3) {
      throw new Error(`Invalid SCP file header: ${header}`);
    }

    const size = parseInt(parts[1], 10);
    if (isNaN(size)) {
      throw new Error(`Invalid file size in SCP header: ${parts[1]}`);
    }

    // Acknowledge header
    await this.sendByte(channel, SCP_OK);

    // Read file data
    const data = await reader.readBytes(size, (bytesRead) => {
      if (onProgress) {
        onProgress(bytesRead, size);
      }
    });

    // Read trailing null byte
    await reader.readByte();

    // Send final acknowledgment
    await this.sendByte(channel, SCP_OK);

    return data;
  }

  /**
   * Send a file via SCP protocol
   */
  private async sendFile(
    channel: SshChannel,
    data: Uint8Array,
    remotePath: string,
    permissions: string,
    onProgress?: ScpTransferProgressCallback
  ): Promise<void> {
    const reader = new ScpChannelReader(channel);

    // Wait for server ready
    const response = await reader.readByte();
    if (response !== SCP_OK) {
      const error = await reader.readLine();
      throw new Error(`SCP not ready: ${error}`);
    }

    // Extract filename from path
    const filename = remotePath.split("/").pop() || "file";

    // Send file header: C<mode> <size> <filename>\n
    const header = `C${permissions} ${data.length} ${filename}\n`;
    await channel.send(Buffer.from(header, "utf-8"));

    // Wait for acknowledgment
    const headerResponse = await reader.readByte();
    if (headerResponse !== SCP_OK) {
      const error = await reader.readLine();
      throw new Error(`SCP header rejected: ${error}`);
    }

    // Send file data in chunks
    const chunkSize = 32768;
    let offset = 0;

    while (offset < data.length) {
      const end = Math.min(offset + chunkSize, data.length);
      const chunk = data.slice(offset, end);
      await channel.send(Buffer.from(chunk));
      offset = end;

      if (onProgress) {
        onProgress(offset, data.length);
      }
    }

    // Send trailing null byte to indicate end of file
    await this.sendByte(channel, 0);

    // Wait for final acknowledgment
    const finalResponse = await reader.readByte();
    if (finalResponse !== SCP_OK) {
      const error = await reader.readLine();
      throw new Error(`SCP transfer failed: ${error}`);
    }
  }

  private async sendByte(channel: SshChannel, byte: number): Promise<void> {
    await channel.send(Buffer.from([byte]));
  }
}

/**
 * Helper class for reading from SCP channel
 */
class ScpChannelReader {
  private buffer: Uint8Array = new Uint8Array(0);
  private resolveData: ((data: Buffer) => void) | null = null;

  constructor(channel: SshChannel) {
    channel.onDataReceived((data: Buffer) => {
      // Append to buffer
      const newBuffer = new Uint8Array(this.buffer.length + data.length);
      newBuffer.set(this.buffer);
      newBuffer.set(new Uint8Array(data), this.buffer.length);
      this.buffer = newBuffer;

      // Notify waiter
      if (this.resolveData) {
        const resolve = this.resolveData;
        this.resolveData = null;
        resolve(data);
      }

      // Acknowledge received data for flow control
      channel.adjustWindow(data.length);
    });
  }

  /**
   * Read a single byte
   */
  async readByte(): Promise<number> {
    while (this.buffer.length < 1) {
      await this.waitForData();
    }

    const byte = this.buffer[0];
    this.buffer = this.buffer.slice(1);
    return byte;
  }

  /**
   * Read until newline
   */
  async readLine(): Promise<string> {
    let line = "";

    while (true) {
      const byte = await this.readByte();
      if (byte === 0x0a) { // newline
        break;
      }
      line += String.fromCharCode(byte);
    }

    return line;
  }

  /**
   * Read exact number of bytes
   */
  async readBytes(
    count: number,
    onProgress?: (bytesRead: number) => void
  ): Promise<Uint8Array> {
    const result = new Uint8Array(count);
    let offset = 0;

    while (offset < count) {
      if (this.buffer.length === 0) {
        await this.waitForData();
      }

      const available = Math.min(this.buffer.length, count - offset);
      result.set(this.buffer.slice(0, available), offset);
      this.buffer = this.buffer.slice(available);
      offset += available;

      if (onProgress) {
        onProgress(offset);
      }
    }

    return result;
  }

  private waitForData(): Promise<Buffer> {
    return new Promise((resolve) => {
      this.resolveData = resolve;
    });
  }
}
