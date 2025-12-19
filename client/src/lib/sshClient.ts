import {
  SshClientSession,
  SshSessionConfiguration,
  SshChannel,
  WebSocketStream,
  SshAuthenticatingEventArgs,
  SshDataWriter,
} from "@microsoft/dev-tunnels-ssh";
import { importKey } from "@microsoft/dev-tunnels-ssh-keys";
import type { Session } from "@shared/schema";

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

export interface SSHClientOptions {
  host: string;
  port: number;
  serverId: string;
  username: string;
  onData: (data: Uint8Array) => void;
  onStatusChange: (status: SSHConnectionStatus) => void;
  onError: (error: string) => void;
  onClose: () => void;
}

/**
 * Browser-based SSH client using Microsoft's dev-tunnels-ssh library.
 * Connects through a WebSocket-TCP bridge to reach SSH servers.
 * Private key never leaves the browser - all crypto happens client-side.
 */
export class BrowserSSHClient {
  private session: SshClientSession | null = null;
  private channel: SshChannel | null = null;
  private websocket: WebSocket | null = null;
  private options: SSHClientOptions;
  private cols: number = 80;
  private rows: number = 24;
  private sessionId: string | null = null;
  private sessionEnded = false;
  private isCleaningUp = false;

  constructor(options: SSHClientOptions) {
    this.options = options;
  }

  /**
   * Connect to the SSH server using the provided private key.
   * @param privateKeyPem PEM-encoded private key
   * @param passphrase Optional passphrase for encrypted keys
   */
  async connect(privateKeyPem: string, passphrase?: string): Promise<void> {
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

      // Import the private key
      const keyPair = await importKey(privateKeyPem, passphrase);

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

    // Handle incoming data
    this.channel.onDataReceived((data: Buffer) => {
      console.log("[SSH] Data received:", data.length, "bytes");
      this.options.onData(new Uint8Array(data));
      // Adjust window to allow more data
      this.channel?.adjustWindow(data.length);
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
