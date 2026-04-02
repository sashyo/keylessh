import { useState, useEffect, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Wifi, WifiOff, Download, Loader2, RefreshCw, X } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api, type GatewayEndpoint } from "@/lib/api";
import { useAuth, useAuthConfig } from "@/contexts/AuthContext";

const AGENT_URL = "http://127.0.0.1:19877";

interface AgentConnection {
  gatewayId: string;
  info: {
    gatewayId: string;
    tunName?: string;
    status?: string;
    clientIp?: string;
    serverIp?: string;
  };
}

interface AgentStatus {
  running: boolean;
  connected: boolean;
  connections: AgentConnection[];
}

export function VpnPanel() {
  const { getToken } = useAuth();
  const authConfig = useAuthConfig();
  const [agentRunning, setAgentRunning] = useState(false);
  const [connections, setConnections] = useState<AgentConnection[]>([]);
  const [selectedGateway, setSelectedGateway] = useState<string>("");
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data: gateways } = useQuery({
    queryKey: ["/api/gateway-endpoints"],
    queryFn: api.gatewayEndpoints.list,
  });

  const checkAgent = useCallback(async () => {
    try {
      const resp = await fetch(`${AGENT_URL}/status`, { signal: AbortSignal.timeout(2000) });
      if (resp.ok) {
        const data: AgentStatus = await resp.json();
        setAgentRunning(data.running);
        setConnections(data.connections || []);
        return;
      }
    } catch {}
    setAgentRunning(false);
    setConnections([]);
  }, []);

  useEffect(() => {
    checkAgent();
  }, [checkAgent]);

  const connectedGatewayIds = new Set(connections.map((c) => c.gatewayId));

  const handleConnect = async () => {
    const token = getToken();
    if (!selectedGateway || !token) return;

    setConnecting(true);
    setError(null);

    const gw = (gateways || []).find((g) => g.id === selectedGateway);
    if (!gw) {
      setError("Gateway not found");
      setConnecting(false);
      return;
    }

    // Get a token for the stun server client via silent OIDC auth
    // The user is already SSO'd from the main app login, so TideCloak
    // returns a token without re-prompting.
    const stunClientId = authConfig?.["stun-server-client-id"];
    let vpnToken = token;

    if (stunClientId && stunClientId !== authConfig?.resource) {
      try {
        const authUrl = authConfig?.["auth-server-url"]?.replace(/\/+$/, "");
        const realm = authConfig?.realm;
        if (authUrl && realm) {
          const tokenUrl = `${authUrl}/realms/${realm}/protocol/openid-connect/token`;
          const tokenResp = await fetch(tokenUrl, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
              client_id: stunClientId,
              subject_token: token!,
              requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
              audience: stunClientId,
            }),
          });
          if (tokenResp.ok) {
            const tokenData = await tokenResp.json();
            vpnToken = tokenData.access_token;
          }
        }
      } catch {
        // Token exchange failed — fall back to original token
      }
    }

    try {
      const resp = await fetch(`${AGENT_URL}/connect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          stunServer: gw.signalServerUrl.replace(/^http/, "ws"),
          gatewayId: gw.id,
          token: vpnToken,
        }),
      });

      const data = await resp.json();
      if (!resp.ok) {
        setError(data.error || "Failed to connect");
      } else {
        setSelectedGateway("");
      }
    } catch {
      setError("Cannot reach VPN agent. Is it running?");
    }

    setConnecting(false);
    setTimeout(checkAgent, 2000);
    setTimeout(checkAgent, 5000);
  };

  const handleDisconnect = async (gatewayId: string) => {
    try {
      await fetch(`${AGENT_URL}/disconnect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ gatewayId }),
      });
    } catch {}
    setTimeout(checkAgent, 1000);
  };

  const handleDisconnectAll = async () => {
    try {
      await fetch(`${AGENT_URL}/disconnect`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    } catch {}
    setTimeout(checkAgent, 1000);
  };

  // Agent not detected
  if (!agentRunning) {
    return (
      <Card>
        <CardContent className="p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-muted-foreground">
              <WifiOff className="h-4 w-4" />
              <span className="text-sm font-medium">VPN Agent Not Detected</span>
            </div>
            <Button size="sm" variant="ghost" className="h-7 w-7 p-0" onClick={checkAgent} title="Check again">
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            Install and run the VPN agent to connect to gateway networks. Already running? Click refresh.
          </p>
          <p className="text-[10px] text-muted-foreground">
            Run with: <code className="bg-muted px-1 rounded">punchd-vpn --agent</code>
          </p>
        </CardContent>
      </Card>
    );
  }

  // Available gateways (not already connected)
  const availableGateways = (gateways || []).filter((g) => g.online && !connectedGatewayIds.has(g.id));

  return (
    <Card>
      <CardContent className="p-4 space-y-3">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="gap-1 bg-green-50 text-green-700 border-green-200 dark:bg-green-950/30 dark:text-green-400">
              <Wifi className="h-3 w-3" />
              VPN Agent
            </Badge>
            {connections.length > 0 && (
              <Badge variant="secondary" className="text-[10px]">
                {connections.length} active
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-1">
            <Button size="sm" variant="ghost" className="h-7 w-7 p-0" onClick={checkAgent} title="Refresh">
              <RefreshCw className="h-3 w-3" />
            </Button>
            {connections.length > 1 && (
              <Button size="sm" variant="ghost" className="h-7 text-xs text-destructive" onClick={handleDisconnectAll}>
                Disconnect All
              </Button>
            )}
          </div>
        </div>

        {/* Active connections */}
        {connections.map((conn) => (
          <div key={conn.gatewayId} className="flex items-center justify-between p-2 rounded-md bg-blue-50/50 dark:bg-blue-950/20 border border-blue-200/50 dark:border-blue-800/50">
            <div className="text-xs space-y-0.5">
              <p className="font-medium text-foreground flex items-center gap-1.5">
                <Wifi className="h-3 w-3 text-blue-600" />
                {conn.gatewayId}
              </p>
              {conn.info.tunName && (
                <p className="text-muted-foreground font-mono">{conn.info.tunName}</p>
              )}
            </div>
            <Button
              size="sm"
              variant="ghost"
              className="h-6 w-6 p-0 text-muted-foreground hover:text-destructive"
              onClick={() => handleDisconnect(conn.gatewayId)}
              title="Disconnect"
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          </div>
        ))}

        {/* Connect to another gateway */}
        {availableGateways.length > 0 && (
          <div className="flex items-center gap-2">
            <Select value={selectedGateway} onValueChange={setSelectedGateway}>
              <SelectTrigger className="h-8 text-xs flex-1">
                <SelectValue placeholder="Connect to gateway..." />
              </SelectTrigger>
              <SelectContent>
                {availableGateways.map((gw) => (
                  <SelectItem key={gw.id} value={gw.id}>
                    {gw.displayName || gw.id}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button
              size="sm"
              className="h-8 gap-1 shrink-0"
              onClick={handleConnect}
              disabled={!selectedGateway || connecting}
            >
              {connecting ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <Wifi className="h-3 w-3" />
              )}
              Connect
            </Button>
          </div>
        )}

        {error && (
          <p className="text-xs text-destructive">{error}</p>
        )}
      </CardContent>
    </Card>
  );
}
