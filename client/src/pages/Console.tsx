import { useEffect, useRef, useState, useCallback } from "react";
import { useParams, useSearch } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "@xterm/xterm/css/xterm.css";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { PrivateKeyInput } from "@/components/PrivateKeyInput";
import { useSSHSession } from "@/hooks/useSSHSession";
import {
  ArrowLeft,
  RefreshCw,
  Power,
  Copy,
  Maximize,
  Minimize,
  Wifi,
  WifiOff,
  Loader2,
  Key,
} from "lucide-react";
import { Link } from "wouter";
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

export default function Console() {
  const params = useParams<{ serverId: string }>();
  const search = useSearch();
  const searchParams = new URLSearchParams(search);
  const sshUser = searchParams.get("user") || "root";

  const { toast } = useToast();

  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<XTerm | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);

  const [showKeyDialog, setShowKeyDialog] = useState(false);
  const [userDismissedDialog, setUserDismissedDialog] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);

  const { data: server, isLoading: serverLoading } = useQuery<ServerWithAccess>(
    {
      queryKey: ["/api/servers", params.serverId],
    }
  );

  // SSH session hook
  const { connect, disconnect, send, resize, setDimensions, status, error } =
    useSSHSession({
      host: server?.host || "",
      port: server?.port || 22,
      serverId: params.serverId || "",
      username: sshUser,
      onData: useCallback((data: Uint8Array) => {
        if (xtermRef.current) {
          xtermRef.current.write(data);
        }
      }, []),
    });

  const prevStatusRef = useRef<SSHConnectionStatus>("disconnected");
  const disconnectedWithReason = status === "disconnected" && !!error;

  // Handle connection with private key
  const handleConnect = useCallback(
    async (privateKey: string, passphrase?: string) => {
      try {
        // Set initial terminal dimensions before connecting
        const dims = fitAddonRef.current?.proposeDimensions();
        if (dims) {
          setDimensions(dims.cols, dims.rows);
        }

        await connect(privateKey, passphrase);
        setShowKeyDialog(false);
        xtermRef.current?.focus();
      } catch (err) {
        // Error is handled by the hook and displayed in the dialog
        console.error("Connection failed:", err);
      }
    },
    [connect, setDimensions]
  );

  const handleReconnect = useCallback(() => {
    setUserDismissedDialog(false);
    setShowKeyDialog(true);
  }, []);

  const handleDisconnect = useCallback(() => {
    disconnect();
  }, [disconnect]);

  const handleCopy = useCallback(() => {
    const selection = xtermRef.current?.getSelection();
    if (selection) {
      navigator.clipboard.writeText(selection);
      toast({ title: "Copied to clipboard" });
    }
  }, [toast]);

  const toggleFullscreen = useCallback(() => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen();
      setIsFullscreen(true);
    } else {
      document.exitFullscreen();
      setIsFullscreen(false);
    }
  }, []);

  // Initialize terminal
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
    fitAddon.fit();

    xtermRef.current = term;
    fitAddonRef.current = fitAddon;

    // Send terminal input to SSH
    term.onData((data) => {
      send(data);
    });

    // Handle terminal resize
    const handleResize = () => {
      fitAddon.fit();
      const dims = fitAddon.proposeDimensions();
      if (dims) {
        resize(dims.cols, dims.rows);
      }
    };

    const resizeObserver = new ResizeObserver(handleResize);
    resizeObserver.observe(terminalRef.current);
    window.addEventListener("resize", handleResize);

    return () => {
      resizeObserver.disconnect();
      window.removeEventListener("resize", handleResize);
      term.dispose();
      xtermRef.current = null;
    };
  }, [send, resize]);

  // Show key dialog when server data is loaded and we're disconnected
  // Only auto-show if user hasn't manually dismissed it
  useEffect(() => {
    if (
      server &&
      status === "disconnected" &&
      !error &&
      !showKeyDialog &&
      !userDismissedDialog
    ) {
      setShowKeyDialog(true);
    }
    // Auto-close dialog when connected
    if (status === "connected" && showKeyDialog) {
      setShowKeyDialog(false);
      setUserDismissedDialog(false); // Reset so it can auto-show on next disconnect
      xtermRef.current?.focus();
    }
  }, [server, status, error, showKeyDialog, userDismissedDialog]);

  // Handle dialog close (user manually closing)
  const handleDialogOpenChange = useCallback((open: boolean) => {
    setShowKeyDialog(open);
    if (!open) {
      setUserDismissedDialog(true);
    }
  }, []);

  // Show error toast when connection fails
  useEffect(() => {
    if (error && status === "error") {
      toast({
        title: "Connection Error",
        description: error,
        variant: "destructive",
      });
    }
  }, [error, status, toast]);

  // Show a clearer message when an established session is disconnected (e.g. admin termination)
  useEffect(() => {
    const prev = prevStatusRef.current;
    prevStatusRef.current = status;

    if (prev !== "disconnected" && status === "disconnected" && error) {
      toast({
        title: "Disconnected",
        description: error,
        variant: "destructive",
      });
      setUserDismissedDialog(true);
      setShowKeyDialog(false);
    }
  }, [status, error, toast]);

  const StatusIcon = statusConfig[status].icon;

  if (serverLoading) {
    return (
      <div className="h-full flex flex-col">
        <div className="h-12 px-4 flex items-center justify-between border-b border-border">
          <div className="flex items-center gap-4">
            <Skeleton className="h-8 w-8" />
            <Skeleton className="h-4 w-48" />
          </div>
          <Skeleton className="h-6 w-24" />
        </div>
        <div className="flex-1 bg-[#0c0c0c] flex items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="h-12 px-4 flex items-center justify-between border-b border-border bg-background shrink-0">
        <div className="flex items-center gap-4">
          <Link href="/app">
            <Button size="icon" variant="ghost" data-testid="back-button">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div className="flex items-center gap-2">
            <span className="font-medium">{server?.name}</span>
            <span className="text-muted-foreground font-mono text-sm">
              {sshUser}@{server?.host}:{server?.port}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Badge
            variant={status === "connected" ? "default" : "secondary"}
            className="gap-1.5"
            data-testid="connection-status"
          >
            <StatusIcon
              className={`h-3 w-3 ${
                status === "connecting" || status === "authenticating"
                  ? "animate-spin"
                  : ""
              }`}
            />
            {statusConfig[status].label}
          </Badge>

          <div className="flex items-center gap-1 ml-2">
            <Button
              size="icon"
              variant="ghost"
              onClick={handleCopy}
              title="Copy selection"
              data-testid="copy-button"
            >
              <Copy className="h-4 w-4" />
            </Button>
            <Button
              size="icon"
              variant="ghost"
              onClick={toggleFullscreen}
              title={isFullscreen ? "Exit fullscreen" : "Fullscreen"}
              data-testid="fullscreen-button"
            >
              {isFullscreen ? (
                <Minimize className="h-4 w-4" />
              ) : (
                <Maximize className="h-4 w-4" />
              )}
            </Button>
            {status !== "connected" && (
              <Button
                size="icon"
                variant="ghost"
                onClick={handleReconnect}
                disabled={
                  status === "connecting" || status === "authenticating"
                }
                title="Connect"
                data-testid="reconnect-button"
              >
                <RefreshCw
                  className={`h-4 w-4 ${
                    status === "connecting" || status === "authenticating"
                      ? "animate-spin"
                      : ""
                  }`}
                />
              </Button>
            )}
            {status === "connected" && (
              <Button
                size="icon"
                variant="ghost"
                onClick={handleDisconnect}
                title="Disconnect"
                data-testid="disconnect-button"
              >
                <Power className="h-4 w-4" />
              </Button>
            )}
          </div>
        </div>
      </div>

      <div className="flex-1 bg-[#0c0c0c] overflow-hidden relative">
        <div
          ref={terminalRef}
          className="absolute inset-0"
          data-testid="terminal-container"
        />

        {disconnectedWithReason && !showKeyDialog && (
          <div className="absolute inset-0 flex items-center justify-center bg-background/80">
            <div className="text-center space-y-4 max-w-md px-4">
              <WifiOff className="h-12 w-12 text-destructive mx-auto" />
              <div>
                <h3 className="font-medium">Session Disconnected</h3>
                <p className="text-sm text-muted-foreground mt-1">{error}</p>
              </div>
              <Button onClick={handleReconnect} data-testid="reconnect-after-disconnect-button">
                <RefreshCw className="h-4 w-4 mr-2" />
                Reconnect
              </Button>
            </div>
          </div>
        )}

        {status === "error" && !showKeyDialog && (
          <div className="absolute inset-0 flex items-center justify-center bg-background/80">
            <div className="text-center space-y-4">
              <WifiOff className="h-12 w-12 text-destructive mx-auto" />
              <div>
                <h3 className="font-medium">Connection Failed</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  {error || `Unable to connect to ${server?.name}`}
                </p>
              </div>
              <Button onClick={handleReconnect} data-testid="retry-button">
                <RefreshCw className="h-4 w-4 mr-2" />
                Try Again
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Private Key Input Dialog */}
      <PrivateKeyInput
        open={showKeyDialog}
        onOpenChange={handleDialogOpenChange}
        onSubmit={handleConnect}
        serverName={server?.name || ""}
        username={sshUser}
        isConnecting={status === "connecting" || status === "authenticating"}
        error={status === "error" || disconnectedWithReason ? error : null}
      />
    </div>
  );
}
