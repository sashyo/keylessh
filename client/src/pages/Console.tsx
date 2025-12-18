import { useEffect, useRef, useState, useCallback } from "react";
import { useParams, useLocation, useSearch } from "wouter";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "@xterm/xterm/css/xterm.css";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { getWebSocketUrl } from "@/lib/api";
import { queryClient, apiRequest } from "@/lib/queryClient";
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
} from "lucide-react";
import { Link } from "wouter";
import type { ServerWithAccess, Session, ConnectionStatus } from "@shared/schema";

const statusConfig: Record<ConnectionStatus, { label: string; color: string; icon: typeof Wifi }> = {
  connecting: { label: "Connecting...", color: "bg-chart-4", icon: Loader2 },
  connected: { label: "Connected", color: "bg-chart-2", icon: Wifi },
  disconnected: { label: "Disconnected", color: "bg-muted-foreground", icon: WifiOff },
  error: { label: "Connection Error", color: "bg-destructive", icon: WifiOff },
};

export default function Console() {
  const params = useParams<{ serverId: string }>();
  const search = useSearch();
  const searchParams = new URLSearchParams(search);
  const sshUser = searchParams.get("user") || "root";
  const existingSessionId = searchParams.get("session");
  
  const [, setLocation] = useLocation();
  const { toast } = useToast();

  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<XTerm | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const sessionIdRef = useRef<string | null>(existingSessionId);

  const [status, setStatus] = useState<ConnectionStatus>("disconnected");
  const [isFullscreen, setIsFullscreen] = useState(false);

  const { data: server, isLoading: serverLoading } = useQuery<ServerWithAccess>({
    queryKey: ["/api/servers", params.serverId],
  });

  const createSessionMutation = useMutation({
    mutationFn: async (data: { serverId: string; sshUser: string }) => {
      const result = await apiRequest("POST", "/api/sessions", data);
      return result as Session;
    },
    onSuccess: (session) => {
      sessionIdRef.current = session.id;
      connectWebSocket(session.id);
    },
    onError: (error) => {
      toast({
        title: "Failed to create session",
        description: error.message,
        variant: "destructive",
      });
      setStatus("error");
    },
  });

  const connectWebSocket = useCallback((sessionId: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.close();
    }

    setStatus("connecting");
    const wsUrl = getWebSocketUrl(sessionId);
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus("connected");
      xtermRef.current?.focus();
    };

    ws.onmessage = (event) => {
      xtermRef.current?.write(event.data);
    };

    ws.onerror = () => {
      setStatus("error");
      toast({
        title: "Connection error",
        description: "Failed to connect to the server",
        variant: "destructive",
      });
    };

    ws.onclose = () => {
      if (status === "connected") {
        setStatus("disconnected");
      }
    };
  }, [status, toast]);

  const handleReconnect = useCallback(() => {
    if (sessionIdRef.current) {
      connectWebSocket(sessionIdRef.current);
    } else if (params.serverId) {
      createSessionMutation.mutate({ serverId: params.serverId, sshUser });
    }
  }, [params.serverId, sshUser, createSessionMutation, connectWebSocket]);

  const handleDisconnect = useCallback(() => {
    wsRef.current?.close();
    setStatus("disconnected");
    queryClient.invalidateQueries({ queryKey: ["/api/sessions"] });
  }, []);

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

    term.onData((data) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(data);
      }
    });

    const handleResize = () => {
      fitAddon.fit();
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        const dims = fitAddon.proposeDimensions();
        if (dims) {
          wsRef.current.send(JSON.stringify({ type: "resize", cols: dims.cols, rows: dims.rows }));
        }
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
      wsRef.current?.close();
    };
  }, []);

  useEffect(() => {
    if (server && !sessionIdRef.current && status === "disconnected") {
      createSessionMutation.mutate({ serverId: params.serverId!, sshUser });
    } else if (existingSessionId && status === "disconnected") {
      connectWebSocket(existingSessionId);
    }
  }, [server, params.serverId, sshUser, existingSessionId]);

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
            <StatusIcon className={`h-3 w-3 ${status === "connecting" ? "animate-spin" : ""}`} />
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
              {isFullscreen ? <Minimize className="h-4 w-4" /> : <Maximize className="h-4 w-4" />}
            </Button>
            {status !== "connected" && (
              <Button
                size="icon"
                variant="ghost"
                onClick={handleReconnect}
                disabled={createSessionMutation.isPending || status === "connecting"}
                title="Reconnect"
                data-testid="reconnect-button"
              >
                <RefreshCw className={`h-4 w-4 ${createSessionMutation.isPending ? "animate-spin" : ""}`} />
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
        <div ref={terminalRef} className="absolute inset-0" data-testid="terminal-container" />
        
        {status === "error" && (
          <div className="absolute inset-0 flex items-center justify-center bg-background/80">
            <div className="text-center space-y-4">
              <WifiOff className="h-12 w-12 text-destructive mx-auto" />
              <div>
                <h3 className="font-medium">Connection Failed</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Unable to connect to {server?.name}
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
    </div>
  );
}
