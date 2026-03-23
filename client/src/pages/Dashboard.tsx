import { useAuth } from "@/contexts/AuthContext";
import { useIsFetching, useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Server, Terminal, Clock, Activity, ArrowRight, HelpCircle, AlertCircle, X, Globe, ExternalLink, Search, LayoutGrid, List, Monitor } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { Input } from "@/components/ui/input";
import type { ServerWithAccess, ActiveSession } from "@shared/schema";
import { useAutoRefresh } from "@/hooks/useAutoRefresh";
import { RefreshButton } from "@/components/RefreshButton";
import { IAMService } from "@tidecloak/js";
import { appFetch } from "@/lib/appFetch";
import { api, type GatewayEndpoint } from "@/lib/api";

type ServiceItem =
  | { kind: "ssh"; server: ServerWithAccess }
  | { kind: "web"; endpoint: GatewayEndpoint; backend: { name: string; protocol?: string; accessible?: boolean } }
  | { kind: "rdp"; endpoint: GatewayEndpoint; backend: { name: string; protocol?: string; accessible?: boolean } };

function ServerCard({ server, sshBlocked }: { server: ServerWithAccess; sshBlocked?: boolean }) {
  const [selectedUser, setSelectedUser] = useState<string>(server.allowedSshUsers[0] || "");
  const hasAnySshUser = server.allowedSshUsers.length > 0;
  const isDisabled = !server.enabled || server.status === "offline" || !selectedUser || sshBlocked;

  return (
    <Card className="group cyber-card hover-neon-glow" data-testid={`server-card-${server.id}`}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[hsl(var(--neon-cyan)/0.15)] border border-[hsl(var(--neon-cyan)/0.3)] group-hover:border-[hsl(var(--neon-cyan)/0.5)] transition-colors">
              <Server className="h-5 w-5 text-[hsl(var(--neon-cyan))]" />
            </div>
            <div>
              <CardTitle className="text-base">{server.name}</CardTitle>
              <CardDescription className="font-mono text-xs">
                {server.host}:{server.port}
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {server.status === "online" ? (
              <Badge variant="outline" className="gap-1.5 label-success">
                <span className="h-2 w-2 rounded-full bg-[hsl(var(--neon-green))] animate-pulse" />
                Online
              </Badge>
            ) : server.status === "offline" ? (
              <Badge variant="outline" className="gap-1.5 label-danger">
                <span className="h-2 w-2 rounded-full bg-[hsl(var(--neon-red))]" />
                Offline
              </Badge>
            ) : (
              <Badge variant="outline" className="gap-1.5">
                <HelpCircle className="h-3 w-3" />
                Unknown
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-1.5">
          <Badge variant="secondary" className="text-xs">
            {server.environment}
          </Badge>
          {server.tags?.map((tag) => (
            <Badge key={tag} variant="outline" className="text-xs">
              {tag}
            </Badge>
          ))}
        </div>

        <div className="space-y-2">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            SSH User
          </label>
          <Select value={selectedUser} onValueChange={setSelectedUser} disabled={!hasAnySshUser}>
            <SelectTrigger className="w-full" data-testid={`select-ssh-user-${server.id}`}>
              <SelectValue placeholder="Select SSH user" />
            </SelectTrigger>
            <SelectContent>
              {server.allowedSshUsers.map((user) => (
                <SelectItem key={user} value={user}>
                  {user}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {!hasAnySshUser && (
            <p className="text-xs text-muted-foreground">
              No SSH usernames are permitted for your account on this server. Ask an admin to grant a role like{" "}
              <span className="font-mono">ssh:{server.sshUsers?.[0] || "root"}</span>.
            </p>
          )}
        </div>

        {isDisabled ? (
          <Button
            className="w-full gap-2"
            disabled
            data-testid={`connect-button-${server.id}`}
          >
            <Terminal className="h-4 w-4" />
            {sshBlocked ? "SSH Disabled" : "Connect"}
            <ArrowRight className="h-4 w-4" />
          </Button>
        ) : (
          <Link href={`/app/console?serverId=${encodeURIComponent(server.id)}&user=${encodeURIComponent(selectedUser)}`}>
            <Button
              className="w-full gap-2 btn-primary-glow"
              data-testid={`connect-button-${server.id}`}
            >
              <Terminal className="h-4 w-4" />
              Connect
              <ArrowRight className="h-4 w-4" />
            </Button>
          </Link>
        )}
      </CardContent>
    </Card>
  );
}

function ServerCardSkeleton() {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <Skeleton className="h-10 w-10 rounded-lg" />
            <div className="space-y-2">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-3 w-24" />
            </div>
          </div>
          <Skeleton className="h-6 w-16" />
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-1.5">
          <Skeleton className="h-5 w-20" />
          <Skeleton className="h-5 w-16" />
        </div>
        <div className="space-y-2">
          <Skeleton className="h-3 w-16" />
          <Skeleton className="h-9 w-full" />
        </div>
        <Skeleton className="h-9 w-full" />
      </CardContent>
    </Card>
  );
}

function GatewayEndpointCard({ endpoint, backend }: { endpoint: GatewayEndpoint; backend: { name: string; accessible?: boolean } }) {
  const accessible = backend.accessible !== false;
  const isDisabled = !accessible || !endpoint.online;
  const handleConnect = () => {
    const url = endpoint.signalServerUrl.replace(/\/$/, "");
    const token = localStorage.getItem("access_token") || "";
    const params = new URLSearchParams({
      gateway: endpoint.id,
      backend: backend.name,
    });
    if (token) params.set("token", token);
    window.open(`${url}/api/select?${params.toString()}`, "_blank");
  };

  return (
    <Card className="group cyber-card hover-neon-glow">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[hsl(var(--neon-purple)/0.15)] border border-[hsl(var(--neon-purple)/0.3)] group-hover:border-[hsl(var(--neon-purple)/0.5)] transition-colors">
              <Globe className="h-5 w-5 text-[hsl(var(--neon-purple))]" />
            </div>
            <div>
              <CardTitle className="text-base">{backend.name}</CardTitle>
              <CardDescription className="text-xs">
                {endpoint.displayName}
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {endpoint.online ? (
              <Badge variant="outline" className="gap-1.5 label-success">
                <span className="h-2 w-2 rounded-full bg-[hsl(var(--neon-green))] animate-pulse" />
                Online
              </Badge>
            ) : (
              <Badge variant="outline" className="gap-1.5 label-danger">
                <span className="h-2 w-2 rounded-full bg-[hsl(var(--neon-red))]" />
                Offline
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {endpoint.description && (
          <p className="text-sm text-muted-foreground">{endpoint.description}</p>
        )}

        {!accessible && (
          <p className="text-xs text-muted-foreground">
            No access to this endpoint. Ask an admin to grant a role like{" "}
            <span className="font-mono">dest:{endpoint.id}:{backend.name}</span>.
          </p>
        )}

        {isDisabled ? (
          <Button className="w-full gap-2" disabled>
            <ExternalLink className="h-4 w-4" />
            Connect
            <ArrowRight className="h-4 w-4" />
          </Button>
        ) : (
          <Button
            className="w-full gap-2 btn-primary-glow"
            onClick={handleConnect}
          >
            <ExternalLink className="h-4 w-4" />
            Connect
            <ArrowRight className="h-4 w-4" />
          </Button>
        )}
      </CardContent>
    </Card>
  );
}

function RdpEndpointCard({ endpoint, backend }: { endpoint: GatewayEndpoint; backend: { name: string; accessible?: boolean } }) {
  const accessible = backend.accessible !== false;
  const isDisabled = !accessible || !endpoint.online;
  const handleConnect = () => {
    // Navigate to the gateway's RDP page via signal server redirect
    const url = endpoint.signalServerUrl.replace(/\/$/, "");
    const token = localStorage.getItem("access_token") || "";
    // Select gateway first, then redirect to /rdp page
    const params = new URLSearchParams({
      gateway: endpoint.id,
      backend: backend.name,
    });
    if (token) params.set("token", token);
    window.open(`${url}/api/select?${params.toString()}&redirect=${encodeURIComponent(`/rdp?backend=${encodeURIComponent(backend.name)}`)}`, "_blank");
  };

  return (
    <Card className="group cyber-card hover-neon-glow">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[hsl(var(--neon-blue,210_100%_60%)/0.15)] border border-[hsl(var(--neon-blue,210_100%_60%)/0.3)] group-hover:border-[hsl(var(--neon-blue,210_100%_60%)/0.5)] transition-colors">
              <Monitor className="h-5 w-5 text-[hsl(var(--neon-blue,210_100%_60%))]" />
            </div>
            <div>
              <CardTitle className="text-base">{backend.name}</CardTitle>
              <CardDescription className="text-xs">
                {endpoint.displayName} &middot; Remote Desktop
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-xs">RDP</Badge>
            {endpoint.online ? (
              <Badge variant="outline" className="gap-1.5 label-success">
                <span className="h-2 w-2 rounded-full bg-[hsl(var(--neon-green))] animate-pulse" />
                Online
              </Badge>
            ) : (
              <Badge variant="outline" className="gap-1.5 label-danger">
                <span className="h-2 w-2 rounded-full bg-[hsl(var(--neon-red))]" />
                Offline
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {endpoint.description && (
          <p className="text-sm text-muted-foreground">{endpoint.description}</p>
        )}

        {!accessible && (
          <p className="text-xs text-muted-foreground">
            No access to this endpoint. Ask an admin to grant a role like{" "}
            <span className="font-mono">dest:{endpoint.id}:{backend.name}</span>.
          </p>
        )}

        {isDisabled ? (
          <Button className="w-full gap-2" disabled>
            <Monitor className="h-4 w-4" />
            Connect RDP
            <ArrowRight className="h-4 w-4" />
          </Button>
        ) : (
          <Button
            className="w-full gap-2 btn-primary-glow"
            onClick={handleConnect}
          >
            <Monitor className="h-4 w-4" />
            Connect RDP
            <ArrowRight className="h-4 w-4" />
          </Button>
        )}
      </CardContent>
    </Card>
  );
}

function ServiceListItem({ item, sshBlocked }: { item: ServiceItem; sshBlocked?: boolean }) {
  const [selectedUser, setSelectedUser] = useState<string>(
    item.kind === "ssh" ? item.server.allowedSshUsers[0] || "" : ""
  );

  if (item.kind === "ssh") {
    const { server } = item;
    const hasAnySshUser = server.allowedSshUsers.length > 0;
    const isDisabled = !server.enabled || server.status === "offline" || !selectedUser || sshBlocked;

    return (
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 py-3 px-4 hover-elevate rounded-md group">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[hsl(var(--neon-cyan)/0.15)] border border-[hsl(var(--neon-cyan)/0.3)]">
            <Server className="h-5 w-5 text-[hsl(var(--neon-cyan))]" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-medium truncate">{server.name}</p>
            <p className="text-xs text-muted-foreground font-mono truncate">
              {server.host}:{server.port}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 pl-13 sm:pl-0">
          {server.status === "online" ? (
            <Badge variant="outline" className="gap-1.5 label-success shrink-0">
              <span className="h-2 w-2 rounded-full bg-[hsl(var(--neon-green))] animate-pulse" />
              Online
            </Badge>
          ) : server.status === "offline" ? (
            <Badge variant="outline" className="gap-1.5 label-danger shrink-0">
              <span className="h-2 w-2 rounded-full bg-[hsl(var(--neon-red))]" />
              Offline
            </Badge>
          ) : (
            <Badge variant="outline" className="gap-1.5 shrink-0">
              <HelpCircle className="h-3 w-3" />
              Unknown
            </Badge>
          )}
          {hasAnySshUser && (
            <Select value={selectedUser} onValueChange={setSelectedUser}>
              <SelectTrigger className="w-[120px] h-9">
                <SelectValue placeholder="User" />
              </SelectTrigger>
              <SelectContent>
                {server.allowedSshUsers.map((user) => (
                  <SelectItem key={user} value={user}>{user}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          {isDisabled ? (
            <Button size="sm" disabled className="gap-1.5 min-h-[36px]">
              <Terminal className="h-4 w-4" />
              {sshBlocked ? "Disabled" : "Connect"}
            </Button>
          ) : (
            <Link href={`/app/console?serverId=${encodeURIComponent(server.id)}&user=${encodeURIComponent(selectedUser)}`}>
              <Button size="sm" className="gap-1.5 btn-primary-glow min-h-[36px]">
                <Terminal className="h-4 w-4" />
                Connect
              </Button>
            </Link>
          )}
        </div>
      </div>
    );
  }

  // Web or RDP endpoint
  const { endpoint, backend } = item;
  const isRdp = item.kind === "rdp";
  const accessible = backend.accessible !== false;
  const isDisabled = !accessible || !endpoint.online;
  const handleConnect = () => {
    const url = endpoint.signalServerUrl.replace(/\/$/, "");
    const token = localStorage.getItem("access_token") || "";
    const params = new URLSearchParams({ gateway: endpoint.id, backend: backend.name });
    if (token) params.set("token", token);
    if (isRdp) {
      params.set("redirect", `/rdp?backend=${encodeURIComponent(backend.name)}`);
    }
    window.open(`${url}/api/select?${params.toString()}`, "_blank");
  };

  const Icon = isRdp ? Monitor : Globe;
  const colorVar = isRdp ? "--neon-blue,210_100%_60%" : "--neon-purple";
  const connectLabel = isRdp ? "Connect RDP" : "Connect";

  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 py-3 px-4 hover-elevate rounded-md group">
      <div className="flex items-center gap-3 min-w-0">
        <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[hsl(var(${colorVar})/0.15)] border border-[hsl(var(${colorVar})/0.3)]`}>
          <Icon className={`h-5 w-5 text-[hsl(var(${colorVar}))]`} />
        </div>
        <div className="min-w-0">
          <p className="text-sm font-medium truncate">{backend.name}</p>
          <p className="text-xs text-muted-foreground truncate">
            {endpoint.displayName}{isRdp && " \u00b7 Remote Desktop"}
          </p>
        </div>
      </div>
      <div className="flex items-center gap-3 pl-13 sm:pl-0">
        {isRdp && <Badge variant="outline" className="text-xs shrink-0">RDP</Badge>}
        {endpoint.online ? (
          <Badge variant="outline" className="gap-1.5 label-success shrink-0">
            <span className="h-2 w-2 rounded-full bg-[hsl(var(--neon-green))] animate-pulse" />
            Online
          </Badge>
        ) : (
          <Badge variant="outline" className="gap-1.5 label-danger shrink-0">
            <span className="h-2 w-2 rounded-full bg-[hsl(var(--neon-red))]" />
            Offline
          </Badge>
        )}
        {isDisabled ? (
          <Button size="sm" disabled className="gap-1.5 min-h-[36px]">
            <Icon className="h-4 w-4" />
            {connectLabel}
          </Button>
        ) : (
          <Button size="sm" className="gap-1.5 btn-primary-glow min-h-[36px]" onClick={handleConnect}>
            <Icon className="h-4 w-4" />
            {connectLabel}
          </Button>
        )}
      </div>
    </div>
  );
}

function SessionItem({ session, onTerminate }: { session: ActiveSession; onTerminate: (id: string) => void }) {
  const [terminating, setTerminating] = useState(false);

  const handleTerminate = async () => {
    setTerminating(true);
    try {
      await onTerminate(session.id);
    } finally {
      setTerminating(false);
    }
  };

  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 py-3 px-4 hover-elevate rounded-md group" data-testid={`session-${session.id}`}>
      <div className="flex items-center gap-3 min-w-0">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-[hsl(var(--neon-green)/0.15)] border border-[hsl(var(--neon-green)/0.3)]">
          <Activity className="h-5 w-5 text-[hsl(var(--neon-green))]" />
        </div>
        <div className="min-w-0">
          <p className="text-sm font-medium truncate">{session.serverName}</p>
          <p className="text-xs text-muted-foreground font-mono truncate">
            {session.sshUser}@{session.serverHost}
          </p>
        </div>
      </div>
      <div className="flex items-center justify-between sm:justify-end gap-3 pl-13 sm:pl-0">
        <Badge variant="outline" className="text-xs gap-1 label-success shrink-0">
          <span className="h-1.5 w-1.5 rounded-full bg-[hsl(var(--neon-green))] animate-pulse" />
          Active
        </Badge>
        <div className="flex items-center gap-1">
          <Link href={`/app/console?serverId=${encodeURIComponent(session.serverId)}&user=${encodeURIComponent(session.sshUser)}`}>
            <Button size="sm" variant="ghost" className="group-hover:text-[hsl(var(--neon-cyan))] min-h-[44px] min-w-[44px]" data-testid={`reconnect-session-${session.id}`}>
              Reconnect
            </Button>
          </Link>
          <Button
            size="sm"
            variant="ghost"
            className="text-muted-foreground hover:text-destructive min-h-[44px] min-w-[44px]"
            onClick={handleTerminate}
            disabled={terminating}
            data-testid={`terminate-session-${session.id}`}
            title="Terminate session"
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { user } = useAuth();

  const { data: servers, isLoading: serversLoading, refetch: refetchServers } = useQuery<ServerWithAccess[]>({
    queryKey: ["/api/servers"],
    staleTime: 30_000,
  });

  const { data: sessions, isLoading: sessionsLoading, refetch: refetchSessions } = useQuery<ActiveSession[]>({
    queryKey: ["/api/sessions"],
    staleTime: 15_000,
  });

  const { data: gatewayEndpoints, refetch: refetchGatewayEndpoints } = useQuery<GatewayEndpoint[]>({
    queryKey: ["/api/gateway-endpoints"],
    queryFn: api.gatewayEndpoints.list,
    staleTime: 30_000,
  });

  const { data: sshAccessStatus } = useQuery({
    queryKey: ["/api/ssh/access-status"],
    queryFn: api.ssh.getAccessStatus,
    staleTime: 60_000,
  });

  const isSshBlocked = sshAccessStatus?.blocked === true;

  const isFetchingServers = useIsFetching({ queryKey: ["/api/servers"] }) > 0;
  const isFetchingSessions = useIsFetching({ queryKey: ["/api/sessions"] }) > 0;
  const isFetching = isFetchingServers || isFetchingSessions;

  const refreshAll = useCallback(async () => {
    await Promise.all([refetchServers(), refetchSessions(), refetchGatewayEndpoints()]);
  }, [refetchServers, refetchSessions, refetchGatewayEndpoints]);

  const terminateSession = useCallback(async (sessionId: string) => {
    const token = await IAMService.getToken();
    if (!token) return;

    await appFetch(`${window.location.origin}/api/sessions/${sessionId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    await refetchSessions();
  }, [refetchSessions]);

  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 15,
    refresh: refreshAll,
    isBlocked: isFetching,
  });

  const activeSessions = sessions?.filter((s) => s.status === "active") || [];
  const recentSessions = sessions?.filter((s) => s.status !== "active").slice(0, 5) || [];

  const [search, setSearch] = useState("");
  const [viewMode, setViewMode] = useState<"grid" | "list">("grid");
  const [typeFilter, setTypeFilter] = useState<"all" | "ssh" | "web" | "rdp">("all");

  const allServices: ServiceItem[] = useMemo(() => {
    const items: ServiceItem[] = [];
    for (const server of servers ?? []) {
      items.push({ kind: "ssh", server });
    }
    for (const endpoint of gatewayEndpoints ?? []) {
      const backends = endpoint.backends?.length > 0 ? endpoint.backends : [{ name: "Default", accessible: true }];
      for (const backend of backends) {
        const kind = backend.protocol === "rdp" ? "rdp" : "web";
        items.push(kind === "rdp"
          ? { kind: "rdp", endpoint, backend }
          : { kind: "web", endpoint, backend });
      }
    }
    // Sort: accessible/connectable items first
    items.sort((a, b) => {
      const aOk = a.kind === "ssh"
        ? (a.server.allowedSshUsers.length > 0 && a.server.status === "online") ? 0 : 1
        : (a.backend.accessible !== false ? 0 : 1);
      const bOk = b.kind === "ssh"
        ? (b.server.allowedSshUsers.length > 0 && b.server.status === "online") ? 0 : 1
        : (b.backend.accessible !== false ? 0 : 1);
      return aOk - bOk;
    });
    return items;
  }, [servers, gatewayEndpoints]);

  const sshCount = useMemo(() => allServices.filter((i) => i.kind === "ssh").length, [allServices]);
  const webCount = useMemo(() => allServices.filter((i) => i.kind === "web").length, [allServices]);
  const rdpCount = useMemo(() => allServices.filter((i) => i.kind === "rdp").length, [allServices]);

  const filteredServices = useMemo(() => {
    let list = allServices;
    if (typeFilter !== "all") {
      list = list.filter((item) => item.kind === typeFilter);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter((item) => {
        if (item.kind === "ssh") {
          const s = item.server;
          return s.name.toLowerCase().includes(q)
            || s.host.toLowerCase().includes(q)
            || s.environment.toLowerCase().includes(q)
            || s.tags?.some((t) => t.toLowerCase().includes(q));
        }
        const { endpoint, backend } = item;
        return endpoint.displayName.toLowerCase().includes(q)
          || backend.name.toLowerCase().includes(q)
          || endpoint.description?.toLowerCase().includes(q)
          || endpoint.signalServerName.toLowerCase().includes(q);
      });
    }
    return list;
  }, [allServices, search, typeFilter]);

  return (
    <div className="p-4 sm:p-6 space-y-6 sm:space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-xl sm:text-2xl font-semibold tracking-tight text-foreground" data-testid="dashboard-title">
            Welcome back, {user?.username}
          </h1>
          <p className="text-sm sm:text-base text-muted-foreground">
            Connect to your servers and manage your SSH sessions
          </p>
        </div>
        <RefreshButton
          onClick={() => void refreshNow()}
          isRefreshing={isFetching}
          secondsRemaining={secondsRemaining}
          data-testid="refresh-dashboard"
          title="Refresh now"
          className="self-end sm:self-auto"
        />
      </div>

      {isSshBlocked && (
        <Alert className="bg-red-50 border-red-200 dark:bg-red-950/20 dark:border-red-800">
          <AlertCircle className="h-4 w-4 text-red-600 dark:text-red-400" />
          <AlertDescription className="text-red-800 dark:text-red-200">
            <strong>SSH access disabled.</strong>{" "}
            {sshAccessStatus?.reason || "Your organization has exceeded the user limit. Please contact an administrator."}
          </AlertDescription>
        </Alert>
      )}

      {activeSessions.length > 0 && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base sm:text-lg font-medium flex items-center gap-2 text-foreground">
              <Activity className="h-5 w-5 text-[hsl(var(--neon-green))]" />
              Active Sessions
            </h2>
            <Badge variant="secondary" className="label-info">{activeSessions.length}</Badge>
          </div>
          <Card>
            <CardContent className="p-0 divide-y divide-border">
              {activeSessions.map((session) => (
                <SessionItem key={session.id} session={session} onTerminate={terminateSession} />
              ))}
            </CardContent>
          </Card>
        </div>
      )}

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base sm:text-lg font-medium flex items-center gap-2 text-foreground">
            <Server className="h-5 w-5 text-[hsl(var(--neon-cyan))]" />
            Available Services
          </h2>
          <Badge variant="secondary" className="label-info">
            {filteredServices.length !== allServices.length
              ? `${filteredServices.length} / ${allServices.length}`
              : allServices.length}
          </Badge>
        </div>

        {!serversLoading && allServices.length > 0 && (
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search services..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
              />
            </div>
            <div className="flex items-center gap-2">
              <div className="flex items-center border border-border rounded-md">
                <Button
                  variant="ghost"
                  size="sm"
                  className={`h-9 px-3 rounded-r-none text-xs ${typeFilter === "all" ? "bg-accent" : ""}`}
                  onClick={() => setTypeFilter("all")}
                >
                  All
                </Button>
                {sshCount > 0 && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className={`h-9 px-3 rounded-none border-x border-border text-xs gap-1.5 ${typeFilter === "ssh" ? "bg-accent" : ""}`}
                    onClick={() => setTypeFilter("ssh")}
                  >
                    <Terminal className="h-3.5 w-3.5" />
                    SSH
                  </Button>
                )}
                {webCount > 0 && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className={`h-9 px-3 ${rdpCount > 0 ? "rounded-none border-r border-border" : "rounded-l-none"} text-xs gap-1.5 ${typeFilter === "web" ? "bg-accent" : ""}`}
                    onClick={() => setTypeFilter("web")}
                  >
                    <Globe className="h-3.5 w-3.5" />
                    Endpoints
                  </Button>
                )}
                {rdpCount > 0 && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className={`h-9 px-3 rounded-l-none text-xs gap-1.5 ${typeFilter === "rdp" ? "bg-accent" : ""}`}
                    onClick={() => setTypeFilter("rdp")}
                  >
                    <Monitor className="h-3.5 w-3.5" />
                    RDP
                  </Button>
                )}
              </div>
              <div className="flex items-center border border-border rounded-md">
                <Button
                  variant="ghost"
                  size="sm"
                  className={`h-9 px-2.5 rounded-r-none ${viewMode === "grid" ? "bg-accent" : ""}`}
                  onClick={() => setViewMode("grid")}
                  title="Grid view"
                >
                  <LayoutGrid className="h-4 w-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className={`h-9 px-2.5 rounded-l-none ${viewMode === "list" ? "bg-accent" : ""}`}
                  onClick={() => setViewMode("list")}
                  title="List view"
                >
                  <List className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        )}

        {serversLoading ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {[1, 2, 3].map((i) => (
              <ServerCardSkeleton key={i} />
            ))}
          </div>
        ) : filteredServices.length > 0 ? (
          viewMode === "grid" ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredServices.map((item) =>
                item.kind === "ssh" ? (
                  <ServerCard key={item.server.id} server={item.server} sshBlocked={isSshBlocked} />
                ) : item.kind === "rdp" ? (
                  <RdpEndpointCard key={`${item.endpoint.signalServerId}-${item.endpoint.id}-${item.backend.name}`} endpoint={item.endpoint} backend={item.backend} />
                ) : (
                  <GatewayEndpointCard key={`${item.endpoint.signalServerId}-${item.endpoint.id}-${item.backend.name}`} endpoint={item.endpoint} backend={item.backend} />
                )
              )}
            </div>
          ) : (
            <Card>
              <CardContent className="p-0 divide-y divide-border">
                {filteredServices.map((item) => (
                  <ServiceListItem key={item.kind === "ssh" ? item.server.id : `${item.endpoint.signalServerId}-${item.endpoint.id}-${item.backend.name}`} item={item} sshBlocked={isSshBlocked} />
                ))}
              </CardContent>
            </Card>
          )
        ) : allServices.length > 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-12">
              <Search className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="font-medium text-foreground">No matches</h3>
              <p className="text-sm text-muted-foreground mt-1">
                Try a different search term
              </p>
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-12">
              <Server className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="font-medium text-foreground">No servers available</h3>
              <p className="text-sm text-muted-foreground mt-1">
                Contact your administrator to get server access
              </p>
            </CardContent>
          </Card>
        )}
      </div>

      {recentSessions.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-base sm:text-lg font-medium flex items-center gap-2 text-foreground">
            <Clock className="h-5 w-5 text-[hsl(var(--neon-purple))]" />
            Recent Connections
          </h2>
          <Card>
            <CardContent className="p-0 divide-y divide-border">
              {recentSessions.map((session) => (
                <div key={session.id} className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 py-3 px-4">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-muted">
                      <Terminal className="h-5 w-5 text-muted-foreground" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-medium truncate">{session.serverName}</p>
                      <p className="text-xs text-muted-foreground font-mono truncate">
                        {session.sshUser}@{session.serverHost}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center justify-between sm:justify-end gap-3 pl-13 sm:pl-0">
                    <div className="text-xs text-muted-foreground">
                      {session.endedAt ? new Date(session.endedAt).toLocaleDateString() : ""}
                    </div>
                    <Link href={`/app/console?serverId=${encodeURIComponent(session.serverId)}&user=${encodeURIComponent(session.sshUser)}`}>
                      <Button size="sm" variant="ghost" className="min-h-[44px] min-w-[44px]" data-testid={`reconnect-recent-session-${session.id}`}>
                        Reconnect
                      </Button>
                    </Link>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
