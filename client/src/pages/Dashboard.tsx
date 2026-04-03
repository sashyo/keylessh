import { useAuth } from "@/contexts/AuthContext";
import { useIsFetching, useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Server, Terminal, Clock, Activity, ArrowRight, HelpCircle, AlertCircle, X, Globe, ExternalLink, Search, LayoutGrid, List, Monitor, Network } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { Input } from "@/components/ui/input";
import type { ServerWithAccess, ActiveSession } from "@shared/schema";
import { useAutoRefresh } from "@/hooks/useAutoRefresh";
import { RefreshButton } from "@/components/RefreshButton";
import { VpnPanel } from "@/components/VpnPanel";
import { IAMService } from "@tidecloak/js";
import { appFetch } from "@/lib/appFetch";
import { api, type GatewayEndpoint } from "@/lib/api";

type ServiceItem =
  | { kind: "ssh"; endpoint: GatewayEndpoint; backend: { name: string; protocol?: string; auth?: string; accessible?: boolean } }
  | { kind: "web"; endpoint: GatewayEndpoint; backend: { name: string; protocol?: string; auth?: string; rdpUsernames?: string[]; accessible?: boolean } }
  | { kind: "rdp"; endpoint: GatewayEndpoint; backend: { name: string; protocol?: string; auth?: string; rdpUsernames?: string[]; accessible?: boolean } }
  | { kind: "custom"; endpoint: GatewayEndpoint };

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

function RdpEndpointCard({ endpoint, backend }: { endpoint: GatewayEndpoint; backend: { name: string; auth?: string; rdpUsernames?: string[]; accessible?: boolean } }) {
  const accessible = backend.accessible !== false;
  const isDisabled = !accessible || !endpoint.online;
  const isEddsa = backend.auth === "eddsa";
  const usernames = backend.rdpUsernames || [];
  const [selectedUser, setSelectedUser] = useState<string>(usernames[0] || "");
  const handleConnect = () => {
    const signalUrl = endpoint.signalServerUrl.replace(/\/$/, "");
    const params = new URLSearchParams({
      signalUrl,
      gateway: endpoint.id,
      backend: backend.name,
    });
    window.open(`/gateway/rdp.html?${params.toString()}`, "_blank");
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
            {isEddsa && <Badge variant="outline" className="text-xs label-success">Passwordless</Badge>}
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
            <span className="font-mono">dest:{endpoint.id}:{backend.name}:{isEddsa ? "username" : ""}</span>.
          </p>
        )}

        {isEddsa && usernames.length > 0 && (
          <Select value={selectedUser} onValueChange={setSelectedUser}>
            <SelectTrigger className="h-8 text-sm">
              <SelectValue placeholder="Select user..." />
            </SelectTrigger>
            <SelectContent>
              {usernames.map((u) => (
                <SelectItem key={u} value={u}>{u}</SelectItem>
              ))}
            </SelectContent>
          </Select>
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

function CustomConnectionCard({ endpoint }: { endpoint: GatewayEndpoint }) {
  const [open, setOpen] = useState(false);
  const [protocol, setProtocol] = useState<"rdp" | "web">("rdp");
  const [host, setHost] = useState("");
  const [port, setPort] = useState(protocol === "rdp" ? "3389" : "443");
  const [noAuth, setNoAuth] = useState(false);
  const [eddsa, setEddsa] = useState(false);
  const [stripAuth, setStripAuth] = useState(false);

  const handleConnect = () => {
    if (!host.trim()) return;
    const url = endpoint.signalServerUrl.replace(/\/$/, "");
    const token = localStorage.getItem("access_token") || "";
    const target = `${host.trim()}:${port || (protocol === "rdp" ? "3389" : "443")}`;
    const flags = [
      noAuth ? "noauth" : "",
      eddsa ? "eddsa" : "",
      stripAuth ? "stripauth" : "",
    ].filter(Boolean).join(";");

    const params = new URLSearchParams({
      gateway: endpoint.id,
      backend: "__custom__",
      customTarget: target,
      customProtocol: protocol,
    });
    if (flags) params.set("customFlags", flags);
    if (token) params.set("token", token);

    if (protocol === "rdp") {
      const rdpParams = new URLSearchParams({
        signalUrl: url,
        gateway: endpoint.id,
        backend: "__custom__",
        host: target,
      });
      if (flags) rdpParams.set("customFlags", flags);
      window.open(`/gateway/rdp.html?${rdpParams.toString()}`, "_blank");
    } else {
      window.open(`${url}/api/select?${params.toString()}`, "_blank");
    }
    setOpen(false);
  };

  return (
    <>
      <Card className="group cyber-card hover-neon-glow border-dashed">
        <CardHeader className="pb-3">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-muted/50 border border-dashed border-muted-foreground/30 group-hover:border-muted-foreground/50 transition-colors">
                <Network className="h-5 w-5 text-muted-foreground" />
              </div>
              <div>
                <CardTitle className="text-base">Custom Connection</CardTitle>
                <CardDescription className="text-xs">
                  {endpoint.displayName} &middot; Connect to any IP
                </CardDescription>
              </div>
            </div>
            {endpoint.online && (
              <Badge variant="outline" className="gap-1.5 label-success">
                <span className="h-2 w-2 rounded-full bg-[hsl(var(--neon-green))] animate-pulse" />
                Online
              </Badge>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <Button
            className="w-full gap-2"
            variant="outline"
            disabled={!endpoint.online}
            onClick={() => setOpen(true)}
          >
            <Network className="h-4 w-4" />
            Connect to IP
            <ArrowRight className="h-4 w-4" />
          </Button>
        </CardContent>
      </Card>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Custom Connection</DialogTitle>
            <DialogDescription>
              Connect to a device on {endpoint.displayName}'s network
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Protocol</Label>
              <Select value={protocol} onValueChange={(v) => {
                const p = v as "rdp" | "web";
                setProtocol(p);
                setPort(p === "rdp" ? "3389" : "443");
              }}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="rdp">
                    <div className="flex items-center gap-2">
                      <Monitor className="h-3.5 w-3.5" /> Remote Desktop (RDP)
                    </div>
                  </SelectItem>
                  <SelectItem value="web">
                    <div className="flex items-center gap-2">
                      <Globe className="h-3.5 w-3.5" /> Web / HTTP
                    </div>
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2 space-y-2">
                <Label>Host / IP Address</Label>
                <Input
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  placeholder="192.168.0.5"
                  autoFocus
                  onKeyDown={(e) => e.key === "Enter" && handleConnect()}
                />
              </div>
              <div className="space-y-2">
                <Label>Port</Label>
                <Input
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  placeholder={protocol === "rdp" ? "3389" : "443"}
                />
              </div>
            </div>
          </div>

          {protocol === "rdp" && (
            <div className="space-y-2">
              <Label className="text-xs text-muted-foreground">Connection Options</Label>
              <div className="flex flex-wrap gap-4">
                <label className="flex items-center gap-2 text-sm cursor-pointer">
                  <input type="checkbox" checked={eddsa} onChange={(e) => setEddsa(e.target.checked)} className="rounded" />
                  Passwordless (EdDSA)
                </label>
                <label className="flex items-center gap-2 text-sm cursor-pointer">
                  <input type="checkbox" checked={noAuth} onChange={(e) => setNoAuth(e.target.checked)} className="rounded" />
                  No Auth
                </label>
                <label className="flex items-center gap-2 text-sm cursor-pointer">
                  <input type="checkbox" checked={stripAuth} onChange={(e) => setStripAuth(e.target.checked)} className="rounded" />
                  Strip Auth
                </label>
              </div>
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={handleConnect} disabled={!host.trim()}>
              {protocol === "rdp" ? (
                <><Monitor className="h-4 w-4 mr-2" /> Connect RDP</>
              ) : (
                <><Globe className="h-4 w-4 mr-2" /> Connect</>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function ServiceListItem({ item, sshBlocked }: { item: ServiceItem; sshBlocked?: boolean }) {
  const [selectedUser, setSelectedUser] = useState<string>("");

  if (item.kind === "ssh") {
    const { endpoint, backend } = item;
    const accessible = backend.accessible !== false;
    const isDisabled = !accessible || !endpoint.online;

    const handleSshConnect = () => {
      // Route through gateway's direct URL or signal server
      const baseUrl = endpoint.directUrl || endpoint.signalServerUrl.replace(/\/$/, "");
      const token = localStorage.getItem("access_token") || "";
      const params = new URLSearchParams({
        gateway: endpoint.id,
        backend: backend.name,
        token,
      });
      // Open SSH terminal pointing to the gateway's /ws/ssh endpoint
      window.open(`/app/console?gatewayUrl=${encodeURIComponent(baseUrl)}&backend=${encodeURIComponent(backend.name)}&gateway=${encodeURIComponent(endpoint.id)}`, "_blank");
    };

    return (
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 py-3 px-4 hover-elevate rounded-md group">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[hsl(var(--neon-cyan)/0.15)] border border-[hsl(var(--neon-cyan)/0.3)]">
            <Terminal className="h-5 w-5 text-[hsl(var(--neon-cyan))]" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-medium truncate">{backend.name}</p>
            <p className="text-xs text-muted-foreground truncate">
              {endpoint.displayName} &middot; SSH
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 pl-13 sm:pl-0">
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
          <Button size="sm" disabled={isDisabled} onClick={handleSshConnect} className={isDisabled ? "gap-1.5 min-h-[36px]" : "gap-1.5 btn-primary-glow min-h-[36px]"}>
            <Terminal className="h-4 w-4" />
            Connect
          </Button>
        </div>
      </div>
    );
  }

  // Custom connection — render inline with just gateway name
  if (item.kind === "custom") {
    return (
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 py-3 px-4 hover-elevate rounded-md group">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-muted/50 border border-dashed border-muted-foreground/30">
            <Network className="h-5 w-5 text-muted-foreground" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-medium truncate">Custom Connection</p>
            <p className="text-xs text-muted-foreground truncate">{item.endpoint.displayName} &middot; Connect to any IP</p>
          </div>
        </div>
        <CustomConnectionCard endpoint={item.endpoint} />
      </div>
    );
  }

  // Web or RDP endpoint
  const { endpoint, backend } = item;
  const isRdp = item.kind === "rdp";
  const accessible = backend.accessible !== false;
  const isDisabled = !accessible || !endpoint.online;
  const handleConnect = () => {
    const signalUrl = endpoint.signalServerUrl.replace(/\/$/, "");
    if (isRdp) {
      const rdpParams = new URLSearchParams({
        signalUrl,
        gateway: endpoint.id,
        backend: backend.name,
      });
      window.open(`/gateway/rdp.html?${rdpParams.toString()}`, "_blank");
    } else {
      const token = localStorage.getItem("access_token") || "";
      const params = new URLSearchParams({ gateway: endpoint.id, backend: backend.name });
      if (token) params.set("token", token);
      window.open(`${signalUrl}/api/select?${params.toString()}`, "_blank");
    }
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
        {isRdp && backend.auth === "eddsa" && <Badge variant="outline" className="text-xs shrink-0 label-success">Passwordless</Badge>}
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
    for (const endpoint of gatewayEndpoints ?? []) {
      const backends = endpoint.backends?.length > 0 ? endpoint.backends : [{ name: "Default", accessible: true }];
      for (const backend of backends) {
        if (backend.protocol === "ssh") {
          items.push({ kind: "ssh", endpoint, backend });
        } else {
          const kind = backend.protocol === "rdp" ? "rdp" : "web";
          items.push(kind === "rdp"
            ? { kind: "rdp", endpoint, backend }
            : { kind: "web", endpoint, backend });
        }
      }
      // Add a "Custom Connection" card for each online gateway
      if (endpoint.online) {
        items.push({ kind: "custom", endpoint });
      }
    }
    // Sort: accessible/connectable items first, custom cards last
    items.sort((a, b) => {
      const rank = (item: ServiceItem) => {
        if (item.kind === "custom") return 2; // custom cards at end
        if (item.kind === "ssh") return (item.backend.accessible !== false && item.endpoint.online) ? 0 : 1;
        return item.backend.accessible !== false ? 0 : 1;
      };
      return rank(a) - rank(b);
    });
    return items;
  }, [gatewayEndpoints]);

  const sshCount = useMemo(() => allServices.filter((i) => i.kind === "ssh").length, [allServices]);
  const webCount = useMemo(() => allServices.filter((i) => i.kind === "web").length, [allServices]);
  const rdpCount = useMemo(() => allServices.filter((i) => i.kind === "rdp").length, [allServices]);

  const filteredServices = useMemo(() => {
    let list = allServices;
    if (typeFilter !== "all") {
      list = list.filter((item) => item.kind === typeFilter || item.kind === "custom");
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter((item) => {
        if (item.kind === "ssh") {
          return item.backend.name.toLowerCase().includes(q)
            || item.endpoint.displayName.toLowerCase().includes(q);
        }
        if (item.kind === "custom") {
          return "custom".includes(q)
            || item.endpoint.displayName.toLowerCase().includes(q)
            || item.endpoint.signalServerName.toLowerCase().includes(q);
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

      {/* VPN Control Panel */}
      <VpnPanel />

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
                  <GatewayEndpointCard key={`ssh-${item.endpoint.id}-${item.backend.name}`} endpoint={item.endpoint} backend={item.backend} />
                ) : item.kind === "rdp" ? (
                  <RdpEndpointCard key={`${item.endpoint.signalServerId}-${item.endpoint.id}-${item.backend.name}`} endpoint={item.endpoint} backend={item.backend} />
                ) : item.kind === "custom" ? (
                  <CustomConnectionCard key={`custom-${item.endpoint.id}`} endpoint={item.endpoint} />
                ) : (
                  <GatewayEndpointCard key={`${item.endpoint.signalServerId}-${item.endpoint.id}-${item.backend.name}`} endpoint={item.endpoint} backend={item.backend} />
                )
              )}
            </div>
          ) : (
            <Card>
              <CardContent className="p-0 divide-y divide-border">
                {filteredServices.map((item) => (
                  <ServiceListItem key={item.kind === "ssh" ? `ssh-${item.endpoint.id}-${item.backend.name}` : item.kind === "custom" ? `custom-${item.endpoint.id}` : `${item.endpoint.signalServerId}-${item.endpoint.id}-${item.backend.name}`} item={item} sshBlocked={isSshBlocked} />
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
