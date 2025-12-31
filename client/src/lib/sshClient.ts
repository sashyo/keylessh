import {
  SshClientSession,
  SshSessionConfiguration,
  SshChannel,
  WebSocketStream,
  SshAuthenticatingEventArgs,
  SshDataWriter,
  PublicKeyAlgorithm,
} from "@microsoft/dev-tunnels-ssh";
import type { Session } from "@shared/schema";
import type { KeyPair } from "@microsoft/dev-tunnels-ssh";
import type { Signer } from "@microsoft/dev-tunnels-ssh";
import type { Verifier } from "@microsoft/dev-tunnels-ssh";
import { SftpClient } from "./sftp";
import { ScpClient } from "./scp";

function sshWriteString(value: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(value.length, 0);
  return Buffer.concat([len, value]);
}

export function base64UrlToBytes(value: string): Uint8Array {
  let normalized = value.trim().replace(/-/g, "+").replace(/_/g, "/");
  while (normalized.length % 4) normalized += "=";
  const bin = atob(normalized);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function sshEd25519PublicKeyBytes(rawPublicKey: Uint8Array): Buffer {
  if (rawPublicKey.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${rawPublicKey.length}`);
  }
  const alg = Buffer.from("ssh-ed25519", "ascii");
  const key = Buffer.from(rawPublicKey);
  return Buffer.concat([sshWriteString(alg), sshWriteString(key)]);
}

export function formatOpenSshEd25519PublicKey(rawPublicKey: Uint8Array, comment?: string): string {
  const blob = sshEd25519PublicKeyBytes(rawPublicKey);
  return `ssh-ed25519 ${blob.toString("base64")}${comment ? ` ${comment}` : ""}`;
}

export function parseTideUserKeyHex(hex: string): Uint8Array {
  const normalized = hex.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]+$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new Error("Invalid tideuserkey hex string");
  }

  const bytes = Buffer.from(normalized, "hex");

  // Observed format: 3-byte prefix `0x20 0x00 0x00` + 32-byte public key.
  if (bytes.length === 35 && bytes[0] === 0x20 && bytes[1] === 0x00 && bytes[2] === 0x00) {
    return new Uint8Array(bytes.subarray(3));
  }

  if (bytes.length === 32) {
    return new Uint8Array(bytes);
  }

  throw new Error(`Unexpected tideuserkey length: ${bytes.length} bytes`);
}

export async function createEd25519KeyPairFromRawPublicKey(rawPublicKey: Uint8Array): Promise<KeyPair> {
  const kp = new Ed25519KeyPair();
  await kp.setPublicKeyBytes(sshEd25519PublicKeyBytes(rawPublicKey));
  return kp;
}

class Ed25519KeyPair implements KeyPair {
  public readonly keyAlgorithmName = "ssh-ed25519";
  public comment: string | null = null;
  private publicKeyBytes: Buffer | null = null;

  get hasPublicKey(): boolean {
    return !!this.publicKeyBytes;
  }

  // We "have" a private key as long as the signing is delegated externally (e.g. Tide enclave).
  // This prevents dev-tunnels-ssh from requiring a privateKeyProvider.
  get hasPrivateKey(): boolean {
    return true;
  }

  async setPublicKeyBytes(keyBytes: Buffer): Promise<void> {
    this.publicKeyBytes = Buffer.from(keyBytes);
  }

  async getPublicKeyBytes(_algorithmName?: string): Promise<Buffer | null> {
    return this.publicKeyBytes;
  }

  async generate(): Promise<void> {
    throw new Error("Ed25519 key generation is not supported in-browser for this client.");
  }

  async importParameters(_parameters: any): Promise<void> {
    throw new Error("Ed25519 parameter import is not supported by this client.");
  }

  async exportParameters(): Promise<any> {
    throw new Error("Ed25519 parameter export is not supported by this client.");
  }

  dispose(): void {
    // no-op
  }
}

class Ed25519PublicKeyAlgorithm extends PublicKeyAlgorithm {
  constructor() {
    super("ssh-ed25519", "ssh-ed25519", "none");
  }

  createKeyPair(): KeyPair {
    return new Ed25519KeyPair();
  }

  async generateKeyPair(_keySizeInBits?: number): Promise<KeyPair> {
    const kp = new Ed25519KeyPair();
    await kp.generate();
    return kp;
  }

  createSigner(_keyPair: KeyPair): Signer {
    throw new Error(
      "Ed25519 signing must be delegated via BrowserSSHClient options.signer (no local private key available).",
    );
  }

  createVerifier(_keyPair: KeyPair): Verifier {
    throw new Error("Ed25519 verification is not implemented by this client.");
  }
}

export type SSHSignatureRequest = {
  /**
   * SSH signature algorithm name used in the auth request (example: `rsa-sha2-256`).
   */
  algorithmName: string;
  /**
   * Key algorithm for the key being used (example: `ssh-rsa`).
   */
  keyAlgorithmName: string;
  /**
   * Raw payload to sign for SSH publickey authentication.
   */
  data: Uint8Array;
  /**
   * Public key bytes included in the SSH auth request.
   */
  publicKey?: Uint8Array;
  username: string;
  serverId: string;
};

export type SSHSigner = (req: SSHSignatureRequest) => Promise<Uint8Array>;

class CallbackSigner implements Signer {
  public readonly digestLength = 0;
  private disposed = false;

  constructor(private readonly signFn: (data: Buffer) => Promise<Buffer>) {}

  async sign(data: Buffer): Promise<Buffer> {
    if (this.disposed) {
      throw new Error("Signer disposed");
    }
    return await this.signFn(data);
  }

  dispose(): void {
    this.disposed = true;
  }
}

class DelegatingPublicKeyAlgorithm extends PublicKeyAlgorithm {
  constructor(
    private readonly inner: PublicKeyAlgorithm,
    private readonly signerFactory: (keyPair: KeyPair, algorithm: PublicKeyAlgorithm) => Signer,
  ) {
    super(inner.name, inner.keyAlgorithmName, inner.hashAlgorithmName);
  }

  createKeyPair(): KeyPair {
    return this.inner.createKeyPair();
  }

  generateKeyPair(keySizeInBits?: number): Promise<KeyPair> {
    return this.inner.generateKeyPair(keySizeInBits);
  }

  createSigner(keyPair: KeyPair): Signer {
    return this.signerFactory(keyPair, this.inner);
  }

  createVerifier(keyPair: KeyPair) {
    return this.inner.createVerifier(keyPair);
  }

  readSignatureData(signatureData: Buffer): Buffer {
    return this.inner.readSignatureData(signatureData);
  }

  createSignatureData(signature: Buffer): Buffer {
    return this.inner.createSignatureData(signature);
  }
}

// Dynamic import of the actual message classes from CommonJS module
// This ensures we use the exact same prototype chain as the library
let ChannelRequestMessageCtor: any = null;

async function getChannelRequestMessageClass(): Promise<any> {
  if (ChannelRequestMessageCtor) return ChannelRequestMessageCtor;

  // Import the module dynamically
  const mod = await import("@microsoft/dev-tunnels-ssh");
  ChannelRequestMessageCtor = mod.ChannelRequestMessage;
  return ChannelRequestMessageCtor;
}

/**
 * Create a PTY request message by instantiating from the library
 * and monkey-patching the onWrite method.
 */
async function createPtyRequest(cols: number, rows: number): Promise<any> {
  const ChannelRequestMessage = await getChannelRequestMessageClass();
  const msg = new ChannelRequestMessage("pty-req", true);

  // Get the original onWrite from the prototype
  const originalOnWrite = Object.getPrototypeOf(msg).onWrite;

  // Override onWrite to add PTY-specific data
  msg.onWrite = function (writer: SshDataWriter) {
    // Call the original to write requestType and wantReply
    originalOnWrite.call(this, writer);
    // Write PTY-specific fields per RFC 4254
    writer.writeString("xterm-256color", "ascii");
    writer.writeUInt32(cols);
    writer.writeUInt32(rows);
    writer.writeUInt32(0); // width pixels
    writer.writeUInt32(0); // height pixels
    writer.writeBinary(Buffer.alloc(1)); // TTY_OP_END
  };

  return msg;
}

/**
 * Create a shell request message.
 */
async function createShellRequest(): Promise<any> {
  const ChannelRequestMessage = await getChannelRequestMessageClass();
  return new ChannelRequestMessage("shell", true);
}

/**
 * Create a subsystem request message (e.g., for SFTP).
 */
async function createSubsystemRequest(subsystem: string): Promise<any> {
  const ChannelRequestMessage = await getChannelRequestMessageClass();
  const msg = new ChannelRequestMessage("subsystem", true);

  const originalOnWrite = Object.getPrototypeOf(msg).onWrite;

  msg.onWrite = function (writer: SshDataWriter) {
    originalOnWrite.call(this, writer);
    writer.writeString(subsystem, "ascii");
  };

  return msg;
}

/**
 * Create a window change request message.
 */
async function createWindowChangeRequest(
  cols: number,
  rows: number
): Promise<any> {
  const ChannelRequestMessage = await getChannelRequestMessageClass();
  const msg = new ChannelRequestMessage("window-change", false);

  const originalOnWrite = Object.getPrototypeOf(msg).onWrite;

  msg.onWrite = function (writer: SshDataWriter) {
    originalOnWrite.call(this, writer);
    writer.writeUInt32(cols);
    writer.writeUInt32(rows);
    writer.writeUInt32(0); // width pixels
    writer.writeUInt32(0); // height pixels
  };

  return msg;
}

export type SSHConnectionStatus =
  | "disconnected"
  | "connecting"
  | "authenticating"
  | "connected"
  | "error";

export type SSHAuth = { type: "keypair"; keyPair: KeyPair };

export interface SSHClientOptions {
  host: string;
  port: number;
  serverId: string;
  username: string;
  onData: (data: Uint8Array) => void;
  onStatusChange: (status: SSHConnectionStatus) => void;
  onError: (error: string) => void;
  onClose: () => void;
  /**
   * Optional hook to override SSH public-key signing.
   *
   * If provided, KeyleSSH will still use the library for protocol framing,
   * but will call this callback whenever an SSH auth signature is needed.
   *
   * The callback must return the raw signature bytes for the requested SSH
   * signature algorithm (the library will wrap it in SSH "signature data").
   */
  signer?: SSHSigner;
}

/**
 * Browser-based SSH client using Microsoft's dev-tunnels-ssh library.
 * Connects through a WebSocket-TCP bridge to reach SSH servers.
 * SSH signing is delegated to Tide's distributed enclave network via Policy:1 authorization.
 */
export class BrowserSSHClient {
  private session: SshClientSession | null = null;
  private channel: SshChannel | null = null;
  private sftpChannel: SshChannel | null = null;
  private sftpClient: SftpClient | null = null;
  private scpClient: ScpClient | null = null;
  private websocket: WebSocket | null = null;
  private options: SSHClientOptions;
  private cols: number = 80;
  private rows: number = 24;
  private sessionId: string | null = null;
  private sessionEnded = false;
  private isCleaningUp = false;
  private recordingStartTime: number | null = null;

  constructor(options: SSHClientOptions) {
    this.options = options;
  }

  /**
   * Send a recording event through the WebSocket to the server.
   * This sends decrypted terminal I/O for server-side recording.
   */
  private sendRecordingEvent(eventType: "i" | "o", data: string): void {
    if (!this.websocket || this.websocket.readyState !== WebSocket.OPEN) {
      return;
    }
    if (!this.recordingStartTime) {
      return;
    }
    try {
      const relativeTime = (Date.now() - this.recordingStartTime) / 1000;
      this.websocket.send(JSON.stringify({
        type: "record",
        eventType,
        time: relativeTime,
        data,
      }));
    } catch {
      // Ignore recording errors - don't break the connection
    }
  }

  /**
   * Send a file operation event through the WebSocket to the server.
   * This logs SFTP/SCP file operations for audit purposes.
   */
  sendFileOpEvent(event: {
    operation: "upload" | "download" | "delete" | "mkdir" | "rename" | "chmod";
    path: string;
    targetPath?: string;
    fileSize?: number;
    mode: "sftp" | "scp";
    status: "success" | "error";
    errorMessage?: string;
  }): void {
    if (!this.websocket || this.websocket.readyState !== WebSocket.OPEN) {
      return;
    }
    try {
      this.websocket.send(JSON.stringify({
        type: "file_op",
        ...event,
      }));
    } catch {
      // Ignore logging errors - don't break the connection
    }
  }

  async connect(auth: SSHAuth): Promise<void> {
    try {
      // Validate required parameters
      if (!this.options.host) {
        throw new Error("Server host is not configured");
      }
      if (!this.options.serverId) {
        throw new Error("Server ID is not configured");
      }

      this.options.onStatusChange("connecting");

      // Create session record first so the WS bridge can be associated with a session.
      this.sessionId = await this.createSessionRecord();
      this.sessionEnded = false;

      const keyPair = auth.keyPair;

      // Get the WebSocket URL for the TCP bridge
      const wsUrl = this.buildWebSocketUrl();

      // Create WebSocket connection to the TCP bridge
      this.websocket = new WebSocket(wsUrl);
      this.websocket.binaryType = "arraybuffer";

      // Wait for WebSocket to connect
      await this.waitForWebSocketOpen();

      // Handle socket closure (e.g. admin termination, network drop)
      this.websocket.addEventListener("close", (event) => {
        if (this.isCleaningUp) return;
        if (event.reason) {
          this.options.onError(event.reason);
        }
        this.options.onClose();
        this.cleanup();
      });

      // Wait for TCP bridge to confirm connection
      await this.waitForTcpConnection();

      // Create SSH session configuration
      const config = new SshSessionConfiguration(true);
      // dev-tunnels-ssh v3.12.x doesn't include ssh-ed25519 in SshAlgorithms.publicKey,
      // but we can register it so a caller-provided KeyPair with keyAlgorithmName `ssh-ed25519`
      // can be used (signing is delegated via options.signer).
      if (!config.publicKeyAlgorithms.some((a) => a?.keyAlgorithmName === "ssh-ed25519")) {
        // Important: This list is also used for *server host key* algorithm negotiation during key exchange.
        // Put ed25519 at the end so we don't select it for server host key verification unless it's the only option.
        // (We currently delegate ed25519 signing, but we don't implement host-key verification for ed25519 here.)
        config.publicKeyAlgorithms.push(new Ed25519PublicKeyAlgorithm());
      }

      // Optional: intercept/override the SSH public-key auth signature step.
      // dev-tunnels-ssh calls `algorithm.createSigner(keyPair).sign(payload)` internally.
      if (this.options.signer) {
        const signerCallback = this.options.signer;
        for (let i = 0; i < config.publicKeyAlgorithms.length; i++) {
          const alg = config.publicKeyAlgorithms[i];
          if (!alg) continue;

          config.publicKeyAlgorithms[i] = new DelegatingPublicKeyAlgorithm(
            alg,
            (keyPair, algorithm) =>
              new CallbackSigner(async (payload) => {
                const publicKey =
                  keyPair.keyAlgorithmName === "ssh-ed25519"
                    ? await keyPair.getPublicKeyBytes()
                    : await keyPair.getPublicKeyBytes(algorithm.name);
                const sig = await signerCallback({
                  algorithmName: algorithm.name,
                  keyAlgorithmName: keyPair.keyAlgorithmName,
                  data: new Uint8Array(payload),
                  publicKey: publicKey ? new Uint8Array(publicKey) : undefined,
                  username: this.options.username,
                  serverId: this.options.serverId,
                });
                return Buffer.from(sig);
              }),
          );
        }
      }

      // Create client session
      this.session = new SshClientSession(config);

      // Handle server authentication (accept any server for now)
      this.session.onAuthenticating((e: SshAuthenticatingEventArgs) => {
        // For server authentication, just accept
        // In production, you'd verify the host key
        e.authenticationPromise = Promise.resolve({});
      });

      // Wrap WebSocket in SSH stream
      const stream = new WebSocketStream(this.websocket);

      // Connect the SSH session
      await this.session.connect(stream);

      this.options.onStatusChange("authenticating");

      // Authenticate with private key
      const authenticated = await this.session.authenticate({
        username: this.options.username,
        publicKeys: [keyPair],
      });

      if (!authenticated) {
        throw new Error("Authentication failed");
      }

      this.options.onStatusChange("connected");

      // Open a shell channel
      await this.openShell();
    } catch (error) {
      this.options.onStatusChange("error");
      const message = error instanceof Error ? error.message : String(error);
      this.options.onError(message);
      await this.endSessionRecordOnce();
      this.cleanup();
      throw error;
    }
  }

  private buildWebSocketUrl(): string {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host;
    const token = localStorage.getItem("access_token") || "";

    const params = new URLSearchParams({
      host: this.options.host,
      port: this.options.port.toString(),
      serverId: this.options.serverId,
      token,
      sessionId: this.sessionId || "",
    });

    return `${protocol}//${host}/ws/tcp?${params.toString()}`;
  }

  private async createSessionRecord(): Promise<string> {
    const token = localStorage.getItem("access_token");
    if (!token) {
      throw new Error("Not authenticated");
    }

    const res = await fetch("/api/sessions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        serverId: this.options.serverId,
        sshUser: this.options.username,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ message: "Failed to create session" }));
      throw new Error(err.message || `HTTP ${res.status}`);
    }

    const session = (await res.json()) as Session;
    return session.id;
  }

  private async endSessionRecordOnce(): Promise<void> {
    if (!this.sessionId || this.sessionEnded) return;
    this.sessionEnded = true;

    const token = localStorage.getItem("access_token");
    if (!token) return;

    try {
      await fetch(`/api/sessions/${this.sessionId}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
    } catch {
      // ignore
    }
  }

  private waitForWebSocketOpen(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.websocket) {
        reject(new Error("WebSocket not initialized"));
        return;
      }

      if (this.websocket.readyState === WebSocket.OPEN) {
        resolve();
        return;
      }

      const onOpen = () => {
        cleanup();
        resolve();
      };

      const onError = () => {
        cleanup();
        reject(new Error("WebSocket connection failed"));
      };

      const onClose = (event: CloseEvent) => {
        cleanup();
        reject(new Error(event.reason || "WebSocket closed"));
      };

      const cleanup = () => {
        this.websocket?.removeEventListener("open", onOpen);
        this.websocket?.removeEventListener("error", onError);
        this.websocket?.removeEventListener("close", onClose);
      };

      this.websocket.addEventListener("open", onOpen);
      this.websocket.addEventListener("error", onError);
      this.websocket.addEventListener("close", onClose);
    });
  }

  private waitForTcpConnection(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.websocket) {
        reject(new Error("WebSocket not initialized"));
        return;
      }

      const timeout = setTimeout(() => {
        cleanup();
        reject(new Error("TCP connection timeout"));
      }, 10000);

      const onMessage = (event: MessageEvent) => {
        // Check for JSON control message
        if (typeof event.data === "string") {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === "connected") {
              cleanup();
              resolve();
              return;
            }
            if (msg.type === "error") {
              cleanup();
              reject(new Error(msg.message || "Connection failed"));
              return;
            }
          } catch {
            // Not JSON, ignore
          }
        }
      };

      const onClose = (event: CloseEvent) => {
        cleanup();
        reject(new Error(event.reason || "Connection closed"));
      };

      const cleanup = () => {
        clearTimeout(timeout);
        this.websocket?.removeEventListener("message", onMessage);
        this.websocket?.removeEventListener("close", onClose);
      };

      this.websocket.addEventListener("message", onMessage);
      this.websocket.addEventListener("close", onClose);
    });
  }

  private async openShell(): Promise<void> {
    if (!this.session) {
      throw new Error("Session not connected");
    }

    console.log("[SSH] Opening session channel...");
    // Open a session channel
    this.channel = await this.session.openChannel("session");
    console.log("[SSH] Channel opened, id:", this.channel.channelId);

    // Request a PTY
    console.log("[SSH] Requesting PTY...", { cols: this.cols, rows: this.rows });
    const ptyRequest = await createPtyRequest(this.cols, this.rows);
    const ptyResult = await this.channel.request(ptyRequest);
    console.log("[SSH] PTY result:", ptyResult);

    if (!ptyResult) {
      throw new Error("PTY request denied by server");
    }

    // Request shell
    console.log("[SSH] Requesting shell...");
    const shellRequest = await createShellRequest();
    const shellResult = await this.channel.request(shellRequest);
    console.log("[SSH] Shell result:", shellResult);

    if (!shellResult) {
      throw new Error("Shell request denied by server");
    }

    console.log("[SSH] Shell opened successfully, setting up data handler");

    // Start recording timer - server will decide if recording is enabled
    this.recordingStartTime = Date.now();

    // Handle incoming data
    this.channel.onDataReceived((data: Buffer) => {
      console.log("[SSH] Data received:", data.length, "bytes");
      this.options.onData(new Uint8Array(data));
      // Adjust window to allow more data
      this.channel?.adjustWindow(data.length);
      // Send decrypted output to server for recording
      this.sendRecordingEvent("o", data.toString("utf-8"));
    });

    // Handle channel close
    this.channel.onClosed(() => {
      console.log("[SSH] Channel closed");
      this.options.onClose();
      this.cleanup();
    });
  }

  /**
   * Send data to the SSH server (user input)
   */
  send(data: string): void {
    if (this.channel && !this.channel.isClosed) {
      const buffer = Buffer.from(data, "utf-8");
      this.channel.send(buffer).catch((err) => {
        console.error("Failed to send data:", err);
      });
      // Send decrypted input to server for recording
      this.sendRecordingEvent("i", data);
    }
  }

  /**
   * Resize the terminal
   */
  async resize(cols: number, rows: number): Promise<void> {
    this.cols = cols;
    this.rows = rows;

    if (this.channel && !this.channel.isClosed) {
      try {
        const resizeRequest = await createWindowChangeRequest(cols, rows);
        await this.channel.request(resizeRequest);
      } catch (err) {
        console.error("Failed to resize:", err);
      }
    }
  }

  /**
   * Set initial terminal dimensions
   */
  setDimensions(cols: number, rows: number): void {
    this.cols = cols;
    this.rows = rows;
  }

  /**
   * Open an SFTP session on this SSH connection.
   * Returns an SftpClient for file operations.
   */
  async openSftp(): Promise<SftpClient> {
    if (!this.session) {
      throw new Error("SSH session not connected");
    }

    if (this.sftpClient) {
      return this.sftpClient;
    }

    console.log("[SSH] Opening SFTP channel...");

    // Open a new session channel for SFTP
    this.sftpChannel = await this.session.openChannel("session");
    console.log("[SSH] SFTP channel opened, id:", this.sftpChannel.channelId);

    // Request the sftp subsystem
    const subsystemRequest = await createSubsystemRequest("sftp");
    const result = await this.sftpChannel.request(subsystemRequest);

    if (!result) {
      this.sftpChannel.dispose();
      this.sftpChannel = null;
      throw new Error("SFTP subsystem request denied by server");
    }

    console.log("[SSH] SFTP subsystem opened");

    // Create SFTP client
    this.sftpClient = new SftpClient(this.sftpChannel);
    await this.sftpClient.init();

    console.log("[SSH] SFTP client initialized");

    return this.sftpClient;
  }

  /**
   * Close the SFTP session (keeps SSH connection open)
   */
  closeSftp(): void {
    if (this.sftpClient) {
      this.sftpClient.dispose();
      this.sftpClient = null;
    }

    if (this.sftpChannel) {
      try {
        this.sftpChannel.dispose();
      } catch {
        // Ignore
      }
      this.sftpChannel = null;
    }
  }

  /**
   * Check if SFTP is currently open
   */
  get hasSftp(): boolean {
    return this.sftpClient !== null;
  }

  /**
   * Open an SCP client for file transfers.
   * This is a fallback for servers that don't support SFTP.
   * Unlike SFTP, SCP uses exec channels for each transfer operation.
   */
  openScp(): ScpClient {
    if (!this.session) {
      throw new Error("SSH session not connected");
    }

    if (this.scpClient) {
      return this.scpClient;
    }

    console.log("[SSH] Creating SCP client");
    this.scpClient = new ScpClient(this.session);
    return this.scpClient;
  }

  /**
   * Close the SCP client
   */
  closeScp(): void {
    if (this.scpClient) {
      this.scpClient.dispose();
      this.scpClient = null;
    }
  }

  /**
   * Check if SCP client exists
   */
  get hasScp(): boolean {
    return this.scpClient !== null;
  }

  /**
   * Get the raw SSH session for advanced operations.
   * Use with caution - prefer openSftp() or openScp() for file operations.
   */
  getSession(): SshClientSession | null {
    return this.session;
  }

  /**
   * Disconnect from the SSH server
   */
  disconnect(): void {
    this.cleanup();
    this.options.onStatusChange("disconnected");
  }

  private cleanup(): void {
    if (this.isCleaningUp) return;
    this.isCleaningUp = true;

    void this.endSessionRecordOnce();

    // Close SFTP and SCP first
    this.closeSftp();
    this.closeScp();

    if (this.channel) {
      try {
        this.channel.dispose();
      } catch {
        // Ignore
      }
      this.channel = null;
    }

    if (this.session) {
      try {
        this.session.dispose();
      } catch {
        // Ignore
      }
      this.session = null;
    }

    if (this.websocket) {
      try {
        this.websocket.close();
      } catch {
        // Ignore
      }
      this.websocket = null;
    }

    this.isCleaningUp = false;
  }
}
