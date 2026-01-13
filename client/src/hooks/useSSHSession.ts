import { useState, useCallback, useRef, useEffect } from "react";
import { BrowserSSHClient, SSHConnectionStatus, type SSHSigner, type SSHAuth } from "@/lib/sshClient";
import type { SftpClient } from "@/lib/sftp";
import type { ScpClient } from "@/lib/scp";
import type { SshClientSession } from "@microsoft/dev-tunnels-ssh";

interface UseSSHSessionOptions {
  host: string;
  port: number;
  serverId: string;
  username: string;
  onData: (data: Uint8Array) => void;
  signer?: SSHSigner;
}

export type FileOpEvent = {
  operation: "upload" | "download" | "delete" | "mkdir" | "rename" | "chmod";
  path: string;
  targetPath?: string;
  fileSize?: number;
  mode: "sftp" | "scp";
  status: "success" | "error";
  errorMessage?: string;
};

interface UseSSHSessionReturn {
  connect: (auth: SSHAuth, signerOverride?: SSHSigner) => Promise<void>;
  disconnect: () => void;
  send: (data: string) => void;
  resize: (cols: number, rows: number) => void;
  setDimensions: (cols: number, rows: number) => void;
  status: SSHConnectionStatus;
  error: string | null;
  // SFTP
  openSftp: () => Promise<SftpClient>;
  closeSftp: () => void;
  sftpClient: SftpClient | null;
  // SCP (fallback for servers without SFTP)
  openScp: () => ScpClient;
  closeScp: () => void;
  scpClient: ScpClient | null;
  // Raw session for exec commands
  getSession: () => SshClientSession | null;
  // File operation logging
  sendFileOpEvent: (event: FileOpEvent) => void;
}

export function useSSHSession({
  host,
  port,
  serverId,
  username,
  onData,
  signer,
}: UseSSHSessionOptions): UseSSHSessionReturn {
  const [status, setStatus] = useState<SSHConnectionStatus>("disconnected");
  const [error, setError] = useState<string | null>(null);
  const [sftpClient, setSftpClient] = useState<SftpClient | null>(null);
  const [scpClient, setScpClient] = useState<ScpClient | null>(null);
  const clientRef = useRef<BrowserSSHClient | null>(null);
  // Minimum terminal dimensions for consistent recordings
  const MIN_COLS = 80;
  const MIN_ROWS = 24;
  const initialColsRef = useRef<number>(MIN_COLS);
  const initialRowsRef = useRef<number>(MIN_ROWS);

  // Store current values in refs so connect always has access to latest values
  const hostRef = useRef(host);
  const portRef = useRef(port);
  const serverIdRef = useRef(serverId);
  const usernameRef = useRef(username);
  const onDataRef = useRef(onData);
  const signerRef = useRef(signer);

  // Keep refs in sync with props
  useEffect(() => {
    hostRef.current = host;
    portRef.current = port;
    serverIdRef.current = serverId;
    usernameRef.current = username;
    onDataRef.current = onData;
    signerRef.current = signer;
  }, [host, port, serverId, username, onData, signer]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (clientRef.current) {
        clientRef.current.disconnect();
        clientRef.current = null;
      }
    };
  }, []);

  const connect = useCallback(
    async (auth: SSHAuth, signerOverride?: SSHSigner) => {
      // Cleanup any existing connection
      if (clientRef.current) {
        clientRef.current.disconnect();
        clientRef.current = null;
      }

      setError(null);

      // Use refs to get the latest values at call time
      const currentHost = hostRef.current;
      const currentPort = portRef.current;
      const currentServerId = serverIdRef.current;
      const currentUsername = usernameRef.current;
      const currentOnData = onDataRef.current;
      const currentSigner = signerOverride ?? signerRef.current;

      // Create new client with current values
      const client = new BrowserSSHClient({
        host: currentHost,
        port: currentPort,
        serverId: currentServerId,
        username: currentUsername,
        onData: currentOnData,
        signer: currentSigner,
        onStatusChange: (newStatus) => {
          setStatus(newStatus);
        },
        onError: (errorMessage) => {
          setError(errorMessage);
        },
        onClose: () => {
          setStatus("disconnected");
        },
      });

      clientRef.current = client;
      client.setDimensions(initialColsRef.current, initialRowsRef.current);

      // Connect
      await client.connect(auth);
    },
    [] // No deps needed since we use refs
  );

  const disconnect = useCallback(() => {
    if (clientRef.current) {
      clientRef.current.disconnect();
      clientRef.current = null;
    }
    setStatus("disconnected");
    setError(null);
  }, []);

  const send = useCallback((data: string) => {
    if (clientRef.current) {
      clientRef.current.send(data);
    }
  }, []);

  const resize = useCallback((cols: number, rows: number) => {
    // Enforce minimum dimensions for consistent recordings
    const safeCols = Math.max(cols, MIN_COLS);
    const safeRows = Math.max(rows, MIN_ROWS);
    if (clientRef.current) {
      clientRef.current.resize(safeCols, safeRows);
    }
  }, []);

  const setDimensions = useCallback((cols: number, rows: number) => {
    // Enforce minimum dimensions for consistent recordings
    const safeCols = Math.max(cols, MIN_COLS);
    const safeRows = Math.max(rows, MIN_ROWS);
    initialColsRef.current = safeCols;
    initialRowsRef.current = safeRows;
    if (clientRef.current) {
      clientRef.current.setDimensions(safeCols, safeRows);
    }
  }, []);

  const openSftp = useCallback(async (): Promise<SftpClient> => {
    if (!clientRef.current) {
      throw new Error("SSH not connected");
    }
    const client = await clientRef.current.openSftp();
    setSftpClient(client);
    return client;
  }, []);

  const closeSftp = useCallback(() => {
    if (clientRef.current) {
      clientRef.current.closeSftp();
    }
    setSftpClient(null);
  }, []);

  const openScp = useCallback((): ScpClient => {
    if (!clientRef.current) {
      throw new Error("SSH not connected");
    }
    const client = clientRef.current.openScp();
    setScpClient(client);
    return client;
  }, []);

  const closeScp = useCallback(() => {
    if (clientRef.current) {
      clientRef.current.closeScp();
    }
    setScpClient(null);
  }, []);

  const getSession = useCallback((): SshClientSession | null => {
    return clientRef.current?.getSession() ?? null;
  }, []);

  const sendFileOpEvent = useCallback((event: FileOpEvent) => {
    if (clientRef.current) {
      clientRef.current.sendFileOpEvent(event);
    }
  }, []);

  return {
    connect,
    disconnect,
    send,
    resize,
    setDimensions,
    status,
    error,
    openSftp,
    closeSftp,
    sftpClient,
    openScp,
    closeScp,
    scpClient,
    getSession,
    sendFileOpEvent,
  };
}
