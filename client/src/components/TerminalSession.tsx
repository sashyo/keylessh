import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "@xterm/xterm/css/xterm.css";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/hooks/use-toast";
import { PrivateKeyInput } from "@/components/PrivateKeyInput";
import { useSSHSession } from "@/hooks/useSSHSession";
import {
  base64UrlToBytes,
  createEd25519KeyPairFromRawPublicKey,
  formatOpenSshEd25519PublicKey,
} from "@/lib/sshClient";
import { createTideSshSigner } from "@/lib/tideSsh";
import { useAuthConfig } from "@/contexts/AuthContext";
import {
  RefreshCw,
  Power,
  Copy,
  Maximize,
  Minimize,
  Wifi,
  WifiOff,
  Loader2,
  Key,
  X,
  FolderOpen,
  PanelLeftClose,
  Terminal,
  ChevronDown,
} from "lucide-react";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { FileBrowser } from "@/components/sftp";
import type { ServerWithAccess } from "@shared/schema";
import type { SSHConnectionStatus } from "@/lib/sshClient";

const statusConfig: Record<
  SSHConnectionStatus,
  { label: string; color: string; icon: typeof Wifi }
> = {
  connecting: { label: "Connecting...", color: "bg-chart-4", icon: Loader2 },
  authenticating: {
    label: "Authenticating...",
    color: "bg-chart-4",
    icon: Key,
  },
  connected: { label: "Connected", color: "bg-chart-2", icon: Wifi },
  disconnected: {
    label: "Disconnected",
    color: "bg-muted-foreground",
    icon: WifiOff,
  },
  error: { label: "Connection Error", color: "bg-destructive", icon: WifiOff },
};

export function TerminalSession({
  serverId,
  sshUser,
  isActive = true,
  onCloseTab,
}: {
  serverId: string;
  sshUser: string;
  isActive?: boolean;
  onCloseTab?: () => void;
}) {
  const { toast } = useToast();
  const authConfig = useAuthConfig();

  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<XTerm | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const pendingOutputRef = useRef<Uint8Array[]>([]);

  const writeToTerminal = useCallback((data: Uint8Array) => {
    if (!xtermRef.current) {
      pendingOutputRef.current.push(data);
      return;
    }
    xtermRef.current.write(data);
  }, []);

  const [showKeyDialog, setShowKeyDialog] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);

  const { data: server, isLoading: serverLoading } = useQuery<ServerWithAccess>({
    queryKey: ["/api/servers", serverId],
  });

  const serverIsDisabled = server ? !server.enabled : false;
  const serverIsOffline = server ? server.status === "offline" : false;

  const { connect, disconnect, send, resize, setDimensions, status, error, openSftp, closeSftp, sftpClient, openScp, closeScp, scpClient, getSession, sendFileOpEvent } = useSSHSession({
    host: server?.host || "",
    port: server?.port || 22,
    serverId,
    username: sshUser,
    onData: writeToTerminal,
  });

  const [showFileBrowser, setShowFileBrowser] = useState(false);
  const [sftpLoading, setSftpLoading] = useState(false);
  const [fileTransferMode, setFileTransferMode] = useState<"sftp" | "scp" | null>(null);

  const prevStatusRef = useRef<SSHConnectionStatus>("disconnected");
  const disconnectedWithReason = status === "disconnected" && !!error;
  const userInitiatedDisconnectRef = useRef(false);

  const tideSshPublicKey = useMemo(() => {
    try {
      const jwkX = authConfig?.jwk?.keys?.[0]?.x;
      if (typeof jwkX !== "string") return null;
      const rawPublicKey = base64UrlToBytes(jwkX);
      return formatOpenSshEd25519PublicKey(rawPublicKey, `${sshUser}@keylessh`);
    } catch {
      return null;
    }
  }, [sshUser, authConfig]);

  const handleConnect = useCallback(async () => {
    try {
      if (serverLoading || !server) {
        toast({ title: "Loading server info", description: "Please try again in a moment." });
        return;
      }
      if (serverIsDisabled) {
        toast({ title: "Server disabled", description: "This server is disabled and cannot be connected to.", variant: "destructive" });
        return;
      }

      if (xtermRef.current) {
        xtermRef.current.clear();
        xtermRef.current.reset();
      }
      pendingOutputRef.current = [];

      const dims = fitAddonRef.current?.proposeDimensions();
      if (dims?.cols && dims?.rows) {
        setDimensions(dims.cols, dims.rows);
      } else {
        setDimensions(80, 24);
      }

      const jwkX = authConfig?.jwk?.keys?.[0]?.x;
      if (typeof jwkX !== "string") {
        throw new Error("Missing JWKS Ed25519 public key (authConfig.jwk.keys[0].x)");
      }
      const rawPublicKey = base64UrlToBytes(jwkX);
      const keyPair = await createEd25519KeyPairFromRawPublicKey(rawPublicKey);

      await connect({ type: "keypair", keyPair }, createTideSshSigner());
      setShowKeyDialog(false);

      // Fit terminal and send resize to SSH server to trigger prompt display
      if (fitAddonRef.current) {
        fitAddonRef.current.fit();
        const dims = fitAddonRef.current.proposeDimensions();
        if (dims?.cols && dims?.rows) {
          resize(dims.cols, dims.rows);
        }
      }
      xtermRef.current?.focus();
    } catch (err) {
      console.error("Connection failed:", err);
    }
  }, [authConfig, connect, resize, server, serverIsDisabled, serverLoading, setDimensions, toast]);

  const handleReconnect = useCallback(() => {
    setShowKeyDialog(true);
  }, []);

  const handleDisconnect = useCallback(() => {
    userInitiatedDisconnectRef.current = true;
    setShowFileBrowser(false);
    setFileTransferMode(null);
    closeSftp();
    closeScp();
    disconnect();
  }, [closeSftp, closeScp, disconnect]);

  const toggleFileBrowser = useCallback(async () => {
    if (showFileBrowser) {
      setShowFileBrowser(false);
      return;
    }

    // If we already have a file transfer mode, just show the browser
    if (fileTransferMode) {
      setShowFileBrowser(true);
      return;
    }

    setSftpLoading(true);

    // Try SFTP first
    try {
      await openSftp();
      setFileTransferMode("sftp");
      setSftpLoading(false);
      setShowFileBrowser(true);
      return;
    } catch (sftpErr) {
      console.warn("SFTP not available, trying SCP fallback:", sftpErr);
    }

    // Fallback to SCP + exec
    try {
      openScp();
      setFileTransferMode("scp");
      setSftpLoading(false);
      setShowFileBrowser(true);
      toast({
        title: "Using SCP mode",
        description: "SFTP not available, using SCP for file transfers",
      });
    } catch (scpErr) {
      console.error("Failed to open SCP:", scpErr);
      toast({
        title: "File Browser Error",
        description: "Neither SFTP nor SCP is available on this server",
        variant: "destructive",
      });
      setSftpLoading(false);
    }
  }, [showFileBrowser, fileTransferMode, openSftp, openScp, toast]);

  const forceScpMode = useCallback(() => {
    // Close any existing file transfer sessions
    if (sftpClient) {
      closeSftp();
    }
    if (scpClient) {
      closeScp();
    }
    setFileTransferMode(null);

    // Open SCP directly
    setSftpLoading(true);
    try {
      openScp();
      setFileTransferMode("scp");
      setSftpLoading(false);
      setShowFileBrowser(true);
      toast({
        title: "SCP Mode (Forced)",
        description: "Using SCP for file transfers",
      });
    } catch (err) {
      console.error("Failed to open SCP:", err);
      toast({
        title: "SCP Error",
        description: err instanceof Error ? err.message : "Failed to open SCP",
        variant: "destructive",
      });
      setSftpLoading(false);
    }
  }, [sftpClient, scpClient, closeSftp, closeScp, openScp, toast]);

  const handleCopy = useCallback(() => {
    const selection = xtermRef.current?.getSelection();
    if (selection) {
      navigator.clipboard.writeText(selection);
      toast({ title: "Copied to clipboard" });
    }
  }, [toast]);

  const handleCloseTabClick = useCallback(() => {
    userInitiatedDisconnectRef.current = true;
    disconnect();
    onCloseTab?.();
  }, [disconnect, onCloseTab]);

  const toggleFullscreen = useCallback(() => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen();
      setIsFullscreen(true);
    } else {
      document.exitFullscreen();
      setIsFullscreen(false);
    }
  }, []);

  useEffect(() => {
    if (!terminalRef.current || xtermRef.current) return;

    const term = new XTerm({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      theme: {
        background: "#0c0c0c",
        foreground: "#d4d4d4",
        cursor: "#d4d4d4",
        cursorAccent: "#0c0c0c",
        selectionBackground: "#264f78",
        black: "#0c0c0c",
        red: "#cd3131",
        green: "#0dbc79",
        yellow: "#e5e510",
        blue: "#2472c8",
        magenta: "#bc3fbc",
        cyan: "#11a8cd",
        white: "#e5e5e5",
        brightBlack: "#666666",
        brightRed: "#f14c4c",
        brightGreen: "#23d18b",
        brightYellow: "#f5f543",
        brightBlue: "#3b8eea",
        brightMagenta: "#d670d6",
        brightCyan: "#29b8db",
        brightWhite: "#e5e5e5",
      },
      allowProposedApi: true,
    });

    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();

    term.loadAddon(fitAddon);
    term.loadAddon(webLinksAddon);

    term.open(terminalRef.current);
    const fitNow = () => {
      fitAddon.fit();
      const dims = fitAddon.proposeDimensions();
      if (dims?.cols && dims?.rows) {
        setDimensions(dims.cols, dims.rows);
        resize(dims.cols, dims.rows);
      }
    };

    fitNow();
    window.requestAnimationFrame(fitNow);
    window.setTimeout(fitNow, 50);
    if ("fonts" in document) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (document as any).fonts?.ready?.then(() => fitNow()).catch(() => undefined);
    }

    xtermRef.current = term;
    fitAddonRef.current = fitAddon;

    if (pendingOutputRef.current.length > 0) {
      for (const chunk of pendingOutputRef.current) {
        term.write(chunk);
      }
      pendingOutputRef.current = [];
    }

    term.onData((data) => {
      send(data);
    });

    // Ctrl+C: copy selection to clipboard when text is selected, otherwise send SIGINT
    // Ctrl+V paste is handled natively by the browser
    term.attachCustomKeyEventHandler((e: KeyboardEvent) => {
      if (e.type !== 'keydown') return true;

      if ((e.ctrlKey || e.metaKey) && e.key === 'c') {
        const selection = term.getSelection();
        if (selection) {
          navigator.clipboard.writeText(selection);
          term.clearSelection();
          return false;
        }
      }

      return true;
    });

    const handleResize = () => {
      fitNow();
    };

    const resizeObserver = new ResizeObserver(handleResize);
    resizeObserver.observe(terminalRef.current);
    window.addEventListener("resize", handleResize);

    return () => {
      window.removeEventListener("resize", handleResize);
      resizeObserver.disconnect();
      try {
        term.dispose();
      } catch {
        // ignore
      }
      xtermRef.current = null;
      fitAddonRef.current = null;
    };
  }, [resize, send, setDimensions]);

  // When a tab becomes active, refit and resize so xterm renders correctly.
  useEffect(() => {
    if (!isActive) return;
    if (status !== "connected") return;
    const fit = () => {
      const fitAddon = fitAddonRef.current;
      const term = xtermRef.current;
      if (!fitAddon || !term) return;
      fitAddon.fit();
      const dims = fitAddon.proposeDimensions();
      if (dims?.cols && dims?.rows) {
        setDimensions(dims.cols, dims.rows);
        resize(dims.cols, dims.rows);
      }
      term.refresh(0, term.rows - 1);
      term.focus();
    };
    fit();
    window.requestAnimationFrame(fit);
    window.setTimeout(fit, 50);
    window.setTimeout(fit, 150);
  }, [isActive, resize, setDimensions, status]);

  useEffect(() => {
    const prev = prevStatusRef.current;
    if (prev !== status) {
      if (status === "connected") {
        userInitiatedDisconnectRef.current = false;
        toast({ title: "Connected", description: `Connected to ${sshUser}@${server?.name || "server"}` });
      }

      // Only show a toast for unexpected disconnects (not user-triggered).
      if (prev === "connected" && status === "disconnected" && error && !userInitiatedDisconnectRef.current) {
        toast({
          title: "Disconnected",
          description: error,
          variant: "destructive",
        });
      }

      prevStatusRef.current = status;
    }
  }, [server?.name, sshUser, status, toast]);

  // Important UX: never auto-open the Tide connect modal.
  // Users should explicitly click Connect/Reconnect to open it.

  const StatusIcon = statusConfig[status].icon;

  return (
    <div className="flex flex-col gap-2 sm:gap-4 h-full">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0 flex-1">
          <Badge variant="outline" className="gap-1.5 shrink-0">
            <span className={`h-2 w-2 rounded-full ${statusConfig[status].color}`} />
            <StatusIcon className={`h-3.5 w-3.5 ${status === "connecting" || status === "authenticating" ? "animate-spin" : ""}`} />
            <span className="hidden sm:inline">{statusConfig[status].label}</span>
          </Badge>
          <div className="text-sm text-muted-foreground truncate min-w-0">
            {server?.name ? (
              <span className="font-medium text-foreground">{server.name}</span>
            ) : (
              <Skeleton className="h-4 w-24 sm:w-40 inline-block" />
            )}
            <span className="ml-2 font-mono text-xs hidden sm:inline">{sshUser}@{server?.host || "…"}</span>
          </div>
        </div>

        <div className="flex items-center gap-1 sm:gap-2 shrink-0">
          {onCloseTab && (
            <Button variant="outline" size="sm" onClick={handleCloseTabClick} title="Close tab" className="h-8 w-8 sm:w-auto sm:px-3">
              <X className="h-4 w-4 sm:mr-2" />
              <span className="hidden sm:inline">Close</span>
            </Button>
          )}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant={showFileBrowser ? "secondary" : "outline"}
                size="sm"
                disabled={status !== "connected" || sftpLoading}
                title="Files"
                className="h-8 w-8 sm:w-auto sm:px-3"
              >
                {sftpLoading ? (
                  <Loader2 className="h-4 w-4 sm:mr-2 animate-spin" />
                ) : showFileBrowser ? (
                  <PanelLeftClose className="h-4 w-4 sm:mr-2" />
                ) : (
                  <FolderOpen className="h-4 w-4 sm:mr-2" />
                )}
                <span className="hidden sm:inline">{showFileBrowser ? `Files (${fileTransferMode?.toUpperCase() || "..."})` : "Files"}</span>
                <ChevronDown className="h-3 w-3 ml-1 hidden sm:inline" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {showFileBrowser ? (
                <DropdownMenuItem onClick={() => setShowFileBrowser(false)}>
                  <PanelLeftClose className="h-4 w-4 mr-2" />
                  Hide Files
                </DropdownMenuItem>
              ) : (
                <>
                  <DropdownMenuItem onClick={toggleFileBrowser}>
                    <FolderOpen className="h-4 w-4 mr-2" />
                    Open Files (SFTP)
                  </DropdownMenuItem>
                  {import.meta.env.VITE_ENABLE_SCP_DEBUG === "true" && (
                    <DropdownMenuItem onClick={forceScpMode}>
                      <Terminal className="h-4 w-4 mr-2" />
                      Force SCP Mode
                    </DropdownMenuItem>
                  )}
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
          <Button variant="outline" size="sm" onClick={handleCopy} disabled={status !== "connected"} title="Copy" className="h-8 w-8 sm:w-auto sm:px-3">
            <Copy className="h-4 w-4 sm:mr-2" />
            <span className="hidden sm:inline">Copy</span>
          </Button>
          <Button variant="outline" size="sm" onClick={toggleFullscreen} title={isFullscreen ? "Exit Fullscreen" : "Fullscreen"} className="hidden sm:flex h-8 w-8 sm:w-auto sm:px-3">
            {isFullscreen ? <Minimize className="h-4 w-4 sm:mr-2" /> : <Maximize className="h-4 w-4 sm:mr-2" />}
            <span className="hidden md:inline">{isFullscreen ? "Exit" : "Fullscreen"}</span>
          </Button>
          {status === "connected" ? (
            <Button variant="destructive" size="sm" onClick={handleDisconnect} title="Disconnect" className="h-8 w-8 sm:w-auto sm:px-3">
              <Power className="h-4 w-4 sm:mr-2" />
              <span className="hidden sm:inline">Disconnect</span>
            </Button>
          ) : (
            <Button size="sm" onClick={() => setShowKeyDialog(true)} disabled={serverLoading || serverIsDisabled} title="Connect" className="h-8 w-8 sm:w-auto sm:px-3">
              <RefreshCw className="h-4 w-4 sm:mr-2" />
              <span className="hidden sm:inline">Connect</span>
            </Button>
          )}
        </div>
      </div>

      <ResizablePanelGroup direction="horizontal" className="flex-1 min-h-[420px] w-full rounded-xl overflow-hidden">
        {showFileBrowser && (sftpClient || (scpClient && getSession())) && (
          <>
            <ResizablePanel defaultSize={25} minSize={15} maxSize={50} className="border rounded-l-xl bg-background">
              <FileBrowser
                client={sftpClient}
                scpClient={scpClient}
                session={getSession()}
                initialPath="~"
                onFileOp={sendFileOpEvent}
              />
            </ResizablePanel>
            <ResizableHandle withHandle />
          </>
        )}
        <ResizablePanel defaultSize={showFileBrowser ? 75 : 100}>
          <div className="terminal-surface h-full w-full overflow-hidden relative">
            <div ref={terminalRef} className="absolute inset-3" data-testid="terminal-container" />

            {status !== "connected" && (
              <div className="absolute inset-0 flex items-center justify-center bg-background/70 backdrop-blur-[1px]">
                <div className="text-center space-y-3 max-w-md px-4">
                  {(serverIsDisabled || serverIsOffline) && (
                    <div className="text-sm font-medium">
                      {serverIsDisabled ? "Server disabled" : "Server appears offline"}
                    </div>
                  )}
                  {(status === "connecting" || status === "authenticating") && (
                    <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
                  )}
                  <div className="text-sm font-medium">
                    {status === "connecting" || status === "authenticating"
                      ? "Connecting…"
                      : status === "error"
                        ? "Connection failed"
                        : disconnectedWithReason
                          ? "Session disconnected"
                          : "Not connected"}
                  </div>
                  {(status === "error" || disconnectedWithReason) && (
                    <div className="text-sm text-muted-foreground">
                      {error}
                    </div>
                  )}
                  <div className="flex items-center justify-center gap-2">
                    {(status === "connecting" || status === "authenticating") ? (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={handleDisconnect}
                      >
                        <X className="h-4 w-4 mr-2" />
                        Cancel
                      </Button>
                    ) : (
                      <>
                        <Button
                          size="sm"
                          onClick={() => setShowKeyDialog(true)}
                          disabled={serverLoading || serverIsDisabled || serverIsOffline}
                        >
                          <RefreshCw className="h-4 w-4 mr-2" />
                          {status === "error" || disconnectedWithReason ? "Reconnect" : "Connect"}
                        </Button>
                        {serverIsOffline && !serverIsDisabled && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => setShowKeyDialog(true)}
                            disabled={serverLoading}
                            title="Status checks can be wrong; try connecting anyway."
                          >
                            Try anyway
                          </Button>
                        )}
                      </>
                    )}
                    {onCloseTab && (
                      <Button size="sm" variant="outline" onClick={handleCloseTabClick}>
                        <X className="h-4 w-4 mr-2" />
                        Close
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </ResizablePanel>
      </ResizablePanelGroup>

      <PrivateKeyInput
        open={showKeyDialog}
        onOpenChange={(open) => {
          setShowKeyDialog(open);
        }}
        onSubmit={() => void handleConnect()}
        serverName={server?.name || "Server"}
        username={sshUser}
        tidePublicKey={tideSshPublicKey}
        isConnecting={status === "connecting" || status === "authenticating"}
        error={status === "error" || disconnectedWithReason ? error : null}
      />
    </div>
  );
}
