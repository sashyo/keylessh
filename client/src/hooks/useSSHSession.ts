import { useState, useCallback, useRef, useEffect } from "react";
import { BrowserSSHClient, SSHConnectionStatus, type SSHSigner, type SSHAuth } from "@/lib/sshClient";

interface UseSSHSessionOptions {
  host: string;
  port: number;
  serverId: string;
  username: string;
  onData: (data: Uint8Array) => void;
  signer?: SSHSigner;
}

interface UseSSHSessionReturn {
  connect: (auth: SSHAuth, signerOverride?: SSHSigner) => Promise<void>;
  disconnect: () => void;
  send: (data: string) => void;
  resize: (cols: number, rows: number) => void;
  setDimensions: (cols: number, rows: number) => void;
  status: SSHConnectionStatus;
  error: string | null;
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
  const clientRef = useRef<BrowserSSHClient | null>(null);
  const initialColsRef = useRef<number>(80);
  const initialRowsRef = useRef<number>(24);

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
    if (clientRef.current) {
      clientRef.current.resize(cols, rows);
    }
  }, []);

  const setDimensions = useCallback((cols: number, rows: number) => {
    initialColsRef.current = cols;
    initialRowsRef.current = rows;
    if (clientRef.current) {
      clientRef.current.setDimensions(cols, rows);
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
  };
}
