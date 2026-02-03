import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { useParams, useSearch } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Terminal as XTerm } from "@xterm/xterm";
import { api } from "@/lib/api";
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
  base64UrlToBytes,
  createEd25519KeyPairFromRawPublicKey,
  formatOpenSshEd25519PublicKey,
} from "@/lib/sshClient";
import { createTideSshSigner } from "@/lib/tideSsh";
import { useAuthConfig } from "@/contexts/AuthContext";
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
  const [userDismissedDialog, setUserDismissedDialog] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);

  const { data: server, isLoading: serverLoading } = useQuery<ServerWithAccess>(
    {
      queryKey: ["/api/servers", params.serverId],
    }
  );

  const { data: sshAccessStatus } = useQuery({
    queryKey: ["/api/ssh/access-status"],
    queryFn: api.ssh.getAccessStatus,
  });

  const isSshBlocked = sshAccessStatus?.blocked === true;

  // SSH session hook
  const { connect, disconnect, send, resize, setDimensions, status, error } =
    useSSHSession({
      host: server?.host || "",
      port: server?.port || 22,
      serverId: params.serverId || "",
      username: sshUser,
      onData: writeToTerminal,
    });

  const prevStatusRef = useRef<SSHConnectionStatus>("disconnected");
  const disconnectedWithReason = status === "disconnected" && !!error;

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
      // Clear terminal and pending output for fresh connection
      if (xtermRef.current) {
        xtermRef.current.clear();
        xtermRef.current.reset();
      }
      pendingOutputRef.current = [];

      // Set initial terminal dimensions before connecting (persisted in hook)
      const dims = fitAddonRef.current?.proposeDimensions();
      if (dims?.cols && dims?.rows) {
        setDimensions(dims.cols, dims.rows);
      } else {
        setDimensions(80, 24);
      }

      // Use Tide for SSH signing
      const jwkX = authConfig?.jwk?.keys?.[0]?.x;
      if (typeof jwkX !== "string") {
        throw new Error("Missing JWKS Ed25519 public key (authConfig.jwk.keys[0].x)");
      }
      const rawPublicKey = base64UrlToBytes(jwkX);
      const keyPair = await createEd25519KeyPairFromRawPublicKey(rawPublicKey);

      await connect({ type: "keypair", keyPair }, createTideSshSigner());
      setShowKeyDialog(false);

      // Re-fit and focus terminal after connection
      if (fitAddonRef.current) {
        fitAddonRef.current.fit();
      }
      xtermRef.current?.focus();
    } catch (err) {
      // Error is handled by the hook and displayed in the dialog
      console.error("Connection failed:", err);
    }
  }, [authConfig, connect, setDimensions]);

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

    // Flush any output that arrived before xterm was initialized
    if (pendingOutputRef.current.length > 0) {
      for (const chunk of pendingOutputRef.current) {
        term.write(chunk);
      }
      pendingOutputRef.current = [];
    }

    // Send terminal input to SSH
    term.onData((data) => {
      send(data);
    });

    // Ctrl+C (copy when selection exists) and Ctrl+V (paste)
    term.attachCustomKeyEventHandler((e: KeyboardEvent) => {
      if (e.type !== 'keydown') return true;

      // Ctrl+C: copy selection to clipboard, or pass through as SIGINT
      if ((e.ctrlKey || e.metaKey) && e.key === 'c') {
        const selection = term.getSelection();
        if (selection) {
          navigator.clipboard.writeText(selection);
          term.clearSelection();
          return false;
        }
        return true;
      }

      // Ctrl+V: paste from clipboard
      if ((e.ctrlKey || e.metaKey) && e.key === 'v') {
        navigator.clipboard.readText().then((text) => {
          if (text) term.paste(text);
        }).catch(() => {});
        return false;
      }

      return true;
    });

    // Handle terminal resize
    const handleResize = () => {
      fitNow();
    };

    const resizeObserver = new ResizeObserver(handleResize);
    resizeObserver.observe(terminalRef.current);
    window.addEventListener("resize", handleResize);

    return () => {
      resizeObserver.disconnect();
      window.removeEventListener("resize", handleResize);
      term.dispose();
      xtermRef.current = null;
      fitAddonRef.current = null;
    };
  }, [send, resize, setDimensions, serverLoading]);

  // After connecting / closing dialog, re-fit multiple times (helps when first fit ran before fonts/layout were ready)
  useEffect(() => {
    if (status !== "connected") return;
    const fit = () => {
      if (fitAddonRef.current && xtermRef.current) {
        fitAddonRef.current.fit();
        // Also refresh the terminal to ensure proper rendering
        xtermRef.current.refresh(0, xtermRef.current.rows - 1);
      }
    };
    fit();
    window.requestAnimationFrame(fit);
    window.setTimeout(fit, 50);
    window.setTimeout(fit, 150);
  }, [status]);

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
        <div className="flex-1 terminal-surface flex items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  if (isSshBlocked) {
    return (
      <div className="h-full flex flex-col">
        <div className="h-12 px-4 flex items-center justify-between border-b border-border bg-background">
          <div className="flex items-center gap-4">
            <Link href="/app">
              <Button size="icon" variant="ghost">
                <ArrowLeft className="h-4 w-4" />
              </Button>
            </Link>
            <span className="font-medium">{server?.name}</span>
          </div>
        </div>
        <div className="flex-1 terminal-surface flex items-center justify-center">
          <div className="text-center max-w-md p-6 space-y-4">
            <WifiOff className="h-12 w-12 mx-auto text-destructive" />
            <h2 className="text-xl font-semibold">SSH Access Disabled</h2>
            <p className="text-muted-foreground">
              {sshAccessStatus?.reason || "Your organization has exceeded the user limit for the current plan. Please contact an administrator to enable SSH access."}
            </p>
            <Link href="/app">
              <Button variant="outline">
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to Dashboard
              </Button>
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="min-h-[56px] px-2 sm:px-4 py-2 flex flex-wrap items-center justify-between gap-2 border-b border-border bg-background shrink-0">
        <div className="flex items-center gap-2 sm:gap-4 min-w-0">
          <Link href="/app">
            <Button size="icon" variant="ghost" className="h-10 w-10 shrink-0" data-testid="back-button">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div className="flex flex-col sm:flex-row sm:items-center gap-0.5 sm:gap-2 min-w-0">
            <span className="font-medium text-sm sm:text-base truncate">{server?.name}</span>
            <span className="text-muted-foreground font-mono text-xs sm:text-sm truncate hidden sm:inline">
              {sshUser}@{server?.host}:{server?.port}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-1 sm:gap-2">
          <Badge
            variant={status === "connected" ? "default" : "secondary"}
            className="gap-1.5 text-xs shrink-0"
            data-testid="connection-status"
          >
            <StatusIcon
              className={`h-3 w-3 ${
                status === "connecting" || status === "authenticating"
                  ? "animate-spin"
                  : ""
              }`}
            />
            <span className="hidden sm:inline">{statusConfig[status].label}</span>
          </Badge>

          <div className="flex items-center">
            <Button
              size="icon"
              variant="ghost"
              onClick={handleCopy}
              title="Copy selection"
              className="h-10 w-10"
              data-testid="copy-button"
            >
              <Copy className="h-4 w-4" />
            </Button>
            <Button
              size="icon"
              variant="ghost"
              onClick={toggleFullscreen}
              title={isFullscreen ? "Exit fullscreen" : "Fullscreen"}
              className="h-10 w-10 hidden sm:inline-flex"
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
                className="h-10 w-10"
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
                className="h-10 w-10"
                data-testid="disconnect-button"
              >
                <Power className="h-4 w-4" />
              </Button>
            )}
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-hidden relative p-2 sm:p-4">
        <div className="terminal-surface h-full w-full rounded-lg sm:rounded-xl overflow-hidden relative">
          <div
            ref={terminalRef}
            className="absolute inset-2 sm:inset-3"
            data-testid="terminal-container"
          />
        </div>

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
        tidePublicKey={tideSshPublicKey}
        isConnecting={status === "connecting" || status === "authenticating"}
        error={status === "error" || disconnectedWithReason ? error : null}
      />
    </div>
  );
}
