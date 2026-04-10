import { useAuth } from "@/contexts/AuthContext";
import { useIsFetching, useQuery } from "@tanstack/react-query";
import { Link, useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Server, Terminal, Clock, Activity, ArrowRight, HelpCircle, AlertCircle, X, Globe, ExternalLink, Search, LayoutGrid, List, Monitor, Network, Plus, Trash2, Router, Wifi, WifiOff, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Input } from "@/components/ui/input";
import type { ServerWithAccess, ActiveSession } from "@shared/schema";
import { useAutoRefresh } from "@/hooks/useAutoRefresh";
import { RefreshButton } from "@/components/RefreshButton";
import { VpnPanel } from "@/components/VpnPanel";
import { IAMService } from "@tidecloak/js";
import { appFetch } from "@/lib/appFetch";
import { api, type GatewayEndpoint } from "@/lib/api";
import { lazy, Suspense } from "react";
const AdminServers = lazy(() => import("@/pages/AdminServers"));

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

function GatewayEndpointCard({ endpoint, backend }: { endpoint: GatewayEndpoint; backend: { name: string; protocol?: string; sshUsernames?: string[]; accessible?: boolean } }) {
  const accessible = backend.accessible !== false;
  const isSsh = backend.protocol === "ssh";
  const sshUsernames = (backend as any).sshUsernames || [];
  const [selectedSshUser, setSelectedSshUser] = useState<string>(sshUsernames[0] || "");
  const isDisabled = !accessible || !endpoint.online || (isSsh && !selectedSshUser);
  const [, setLocation] = useLocation();
  const handleConnect = () => {
    if (isSsh) {
      // SSH: open console with gateway routing + selected username
      const baseUrl = endpoint.directUrl || endpoint.signalServerUrl.replace(/\/$/, "");
      setLocation(`/app/console?gatewayUrl=${encodeURIComponent(baseUrl)}&backend=${encodeURIComponent(backend.name)}&gateway=${encodeURIComponent(endpoint.id)}&user=${encodeURIComponent(selectedSshUser)}`);
    } else {
      // Web endpoint: open via signal server relay
      const url = endpoint.signalServerUrl.replace(/\/$/, "");
      const token = localStorage.getItem("access_token") || "";
      const params = new URLSearchParams({
        gateway: endpoint.id,
        backend: backend.name,
      });
      if (token) params.set("token", token);
      window.open(`${url}/api/select?${params.toString()}`, "_blank");
    }
  };

  const IconComponent = isSsh ? Terminal : Globe;
  const colorVar = isSsh ? "--neon-cyan" : "--neon-purple";

  return (
    <Card className="group cyber-card hover-neon-glow">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[hsl(var(${colorVar})/0.15)] border border-[hsl(var(${colorVar})/0.3)] group-hover:border-[hsl(var(${colorVar})/0.5)] transition-colors`}>
              <IconComponent className={`h-5 w-5 text-[hsl(var(${colorVar}))]`} />
            </div>
            <div>
              <CardTitle className="text-base">{backend.name}</CardTitle>
              <CardDescription className="text-xs">
                {endpoint.displayName} {isSsh && <Badge variant="outline" className="ml-1 text-[10px] px-1 py-0">SSH</Badge>}
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
            <span className="font-mono">{backend.protocol === "ssh" ? "ssh" : "dest"}:{endpoint.id}:{backend.name}{backend.protocol === "ssh" ? ":username" : ""}</span>.
          </p>
        )}

        {isSsh && sshUsernames.length > 0 && (
          <Select value={selectedSshUser} onValueChange={setSelectedSshUser}>
            <SelectTrigger className="w-full">
              <SelectValue placeholder="Select user" />
            </SelectTrigger>
            <SelectContent>
              {sshUsernames.map((u: string) => (
                <SelectItem key={u} value={u}>{u}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        {isDisabled ? (
          <Button className="w-full gap-2" disabled>
            {isSsh ? <Terminal className="h-4 w-4" /> : <ExternalLink className="h-4 w-4" />}
            {isSsh ? (selectedSshUser ? `SSH as ${selectedSshUser}` : "SSH") : "Connect"}
          </Button>
        ) : (
          <Button
            className="w-full gap-2 btn-primary-glow"
            onClick={handleConnect}
          >
            {isSsh ? <Terminal className="h-4 w-4" /> : <ExternalLink className="h-4 w-4" />}
            {isSsh ? `SSH as ${selectedSshUser}` : "Connect"}
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
  const [, setLocation] = useLocation();
  const [open, setOpen] = useState(false);
  const [protocol, setProtocol] = useState<"rdp" | "ssh" | "web">("rdp");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("3389");
  const [sshUser, setSshUser] = useState("");
  const [noAuth, setNoAuth] = useState(false);
  const [eddsa, setEddsa] = useState(false);
  const [stripAuth, setStripAuth] = useState(false);

  const defaultPort = protocol === "rdp" ? "3389" : protocol === "ssh" ? "22" : "443";

  const handleConnect = () => {
    if (!host.trim()) return;
    const url = endpoint.directUrl || endpoint.signalServerUrl.replace(/\/$/, "");
    const token = localStorage.getItem("access_token") || "";
    const target = `${host.trim()}:${port || defaultPort}`;
    const flags = [
      noAuth ? "noauth" : "",
      eddsa ? "eddsa" : "",
      stripAuth ? "stripauth" : "",
    ].filter(Boolean).join(";");

    if (protocol === "ssh") {
      const user = sshUser.trim() || "root";
      const backendName = `ssh://${target}`;
      setLocation(`/app/console?gatewayUrl=${encodeURIComponent(url)}&backend=${encodeURIComponent(backendName)}&gateway=${encodeURIComponent(endpoint.id)}&user=${encodeURIComponent(user)}`);
      setOpen(false);
      return;
    }

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
                <CardTitle className="text-base">{endpoint.displayName || endpoint.id}</CardTitle>
                <CardDescription className="text-xs">
                  Custom Connection &middot; Connect to any IP
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
                const p = v as "rdp" | "ssh" | "web";
                setProtocol(p);
                setPort(p === "rdp" ? "3389" : p === "ssh" ? "22" : "443");
              }}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ssh">
                    <div className="flex items-center gap-2">
                      <Terminal className="h-3.5 w-3.5" /> SSH
                    </div>
                  </SelectItem>
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

          {(protocol === "ssh" || (protocol === "rdp" && eddsa)) && (
            <div className="space-y-2">
              <Label>{protocol === "ssh" ? "SSH Username" : "RDP Username"}</Label>
              <Input
                value={sshUser}
                onChange={(e) => setSshUser(e.target.value)}
                placeholder={protocol === "ssh" ? "root" : "Administrator"}
                onKeyDown={(e) => e.key === "Enter" && handleConnect()}
              />
            </div>
          )}

          {(protocol === "rdp" || protocol === "web") && (
            <div className="space-y-2">
              <Label className="text-xs text-muted-foreground">Connection Options</Label>
              <div className="flex flex-wrap gap-4">
                {protocol === "rdp" && (
                  <label className="flex items-center gap-2 text-sm cursor-pointer">
                    <input type="checkbox" checked={eddsa} onChange={(e) => setEddsa(e.target.checked)} className="rounded" />
                    Passwordless (EdDSA)
                  </label>
                )}
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
            <Button onClick={handleConnect} disabled={!host.trim() || (protocol === "ssh" && !sshUser.trim())}>
              {protocol === "rdp" ? (
                <><Monitor className="h-4 w-4 mr-2" /> Connect RDP</>
              ) : protocol === "ssh" ? (
                <><Terminal className="h-4 w-4 mr-2" /> SSH as {sshUser || "..."}</>
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
      window.location.href = `/app/console?gatewayUrl=${encodeURIComponent(baseUrl)}&backend=${encodeURIComponent(backend.name)}&gateway=${encodeURIComponent(endpoint.id)}`;
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
            <p className="text-sm font-medium truncate">{item.endpoint.displayName || item.endpoint.id}</p>
            <p className="text-xs text-muted-foreground truncate">Custom Connection &middot; Connect to any IP</p>
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
      const params = new URLSearchParams({ gateway: endpoint.id, backend: backend.name });
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

// ── Local Gateways (offline/LAN mode) ─────────────────────────────

const LOCAL_GW_STORAGE_KEY = "keylessh.localGateways.v1";

interface LocalGateway {
  id: string;
  name: string;
  url: string;  // e.g. http://192.168.0.10:7891
  online?: boolean;
  certError?: boolean;
  backends?: { name: string; protocol?: string; sshUsernames?: string[]; rdpUsernames?: string[] }[];
  lastChecked?: number;
}

function loadLocalGateways(): LocalGateway[] {
  try {
    const raw = localStorage.getItem(LOCAL_GW_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch { return []; }
}

function saveLocalGateways(gateways: LocalGateway[]) {
  localStorage.setItem(LOCAL_GW_STORAGE_KEY, JSON.stringify(gateways));
}

async function probeGateway(url: string): Promise<{ online: boolean; backends: LocalGateway["backends"]; id?: string; name?: string; certError?: boolean }> {
  try {
    const base = url.replace(/\/$/, "");
    const resp = await fetch(`${base}/api/info`, { signal: AbortSignal.timeout(5000) });
    if (!resp.ok) return { online: false, backends: [] };
    const info = await resp.json();
    const backends = info.backends || [];
    return { online: true, backends, id: info.gatewayId, name: info.displayName };
  } catch {
    // If HTTPS URL fails, likely a self-signed cert issue
    const certError = url.startsWith("https://");
    return { online: false, backends: [], certError };
  }
}

function GatewaysTab() {
  const [, setLocation] = useLocation();
  const [gateways, setGateways] = useState<LocalGateway[]>(loadLocalGateways);
  const [addOpen, setAddOpen] = useState(false);
  const [addUrl, setAddUrl] = useState("");
  const [addName, setAddName] = useState("");
  const [adding, setAdding] = useState(false);
  const [probing, setProbing] = useState<string | null>(null);

  // Persist on change
  useEffect(() => { saveLocalGateways(gateways); }, [gateways]);

  // Probe all gateways on mount
  useEffect(() => {
    gateways.forEach((gw) => {
      probeGateway(gw.url).then((result) => {
        setGateways((prev) => prev.map((g) =>
          g.id === gw.id ? { ...g, online: result.online, certError: result.certError, backends: result.backends, lastChecked: Date.now() } : g
        ));
      });
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleAdd = async () => {
    if (!addUrl.trim()) return;
    setAdding(true);
    const result = await probeGateway(addUrl.trim());
    const id = result.id || `local-${Date.now()}`;
    const name = addName.trim() || result.name || new URL(addUrl.trim()).hostname;
    setGateways((prev) => [...prev, {
      id,
      name,
      url: addUrl.trim().replace(/\/$/, ""),
      online: result.online,
      backends: result.backends,
      lastChecked: Date.now(),
    }]);
    setAddUrl("");
    setAddName("");
    setAdding(false);
    setAddOpen(false);
  };

  const handleRemove = (id: string) => {
    setGateways((prev) => prev.filter((g) => g.id !== id));
  };

  const handleProbe = async (id: string) => {
    const gw = gateways.find((g) => g.id === id);
    if (!gw) return;
    setProbing(id);
    const result = await probeGateway(gw.url);
    setGateways((prev) => prev.map((g) =>
      g.id === id ? { ...g, online: result.online, backends: result.backends, lastChecked: Date.now() } : g
    ));
    setProbing(null);
  };

  const handleConnect = (gw: LocalGateway, backend: { name: string; protocol?: string; sshUsernames?: string[] }, sshUser?: string) => {
    if (backend.protocol === "ssh" && sshUser) {
      setLocation(`/app/console?gatewayUrl=${encodeURIComponent(gw.url)}&backend=${encodeURIComponent(backend.name)}&gateway=${encodeURIComponent(gw.id)}&user=${encodeURIComponent(sshUser)}`);
    } else if (backend.protocol === "rdp") {
      window.open(`${gw.url}/rdp/${encodeURIComponent(backend.name)}`, "_blank");
    } else {
      const params = new URLSearchParams({ gateway: gw.id, backend: backend.name });
      window.open(`${gw.url}/api/select?${params.toString()}`, "_blank");
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-base sm:text-lg font-medium flex items-center gap-2 text-foreground">
          <Router className="h-5 w-5 text-[hsl(var(--neon-purple))]" />
          Local Gateways
        </h2>
        <Button size="sm" onClick={() => setAddOpen(true)} className="gap-1.5">
          <Plus className="h-4 w-4" />
          Add Gateway
        </Button>
      </div>

      <p className="text-sm text-muted-foreground">
        Connect to gateways on your local network or offline gateways that aren't registered with a signal server.
      </p>

      {gateways.length === 0 && (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground">
            <Router className="h-10 w-10 mx-auto mb-3 opacity-30" />
            <p className="text-sm">No local gateways added yet.</p>
            <p className="text-xs mt-1">Add a gateway URL to connect directly without a signal server.</p>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {gateways.map((gw) => (
          <Card key={gw.id} className="cyber-card">
            <CardHeader className="pb-3">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-3 min-w-0">
                  <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border ${gw.online ? "bg-[hsl(var(--neon-green)/0.15)] border-[hsl(var(--neon-green)/0.3)]" : "bg-muted border-border"}`}>
                    {gw.online ? <Wifi className="h-5 w-5 text-[hsl(var(--neon-green))]" /> : <WifiOff className="h-5 w-5 text-muted-foreground" />}
                  </div>
                  <div className="min-w-0">
                    <CardTitle className="text-base truncate">{gw.name}</CardTitle>
                    <CardDescription className="font-mono text-xs truncate">{gw.url}</CardDescription>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => handleProbe(gw.id)} disabled={probing === gw.id} title="Refresh">
                    <RefreshCw className={`h-4 w-4 ${probing === gw.id ? "animate-spin" : ""}`} />
                  </Button>
                  <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive" onClick={() => handleRemove(gw.id)} title="Remove">
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-2">
              {!gw.online && gw.certError && (
                <div className="space-y-1">
                  <Badge variant="destructive" className="text-xs">Certificate Error</Badge>
                  <p className="text-xs text-muted-foreground">
                    Self-signed certificate not accepted.{" "}
                    <a href={gw.url} target="_blank" rel="noopener" className="text-[hsl(var(--neon-cyan))] underline">
                      Accept certificate
                    </a>
                    {" "}then refresh, or use <code className="bg-muted px-1 rounded">https = false</code> in gateway.toml.
                  </p>
                </div>
              )}
              {!gw.online && !gw.certError && (
                <Badge variant="secondary" className="text-xs">Offline</Badge>
              )}
              {gw.online && gw.backends && gw.backends.length > 0 && (
                <div className="space-y-2">
                  {gw.backends.map((backend) => (
                    <LocalBackendItem key={backend.name} gw={gw} backend={backend} onConnect={handleConnect} />
                  ))}
                </div>
              )}
              {gw.online && (!gw.backends || gw.backends.length === 0) && (
                <p className="text-xs text-muted-foreground">No backends configured on this gateway.</p>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Add Gateway Dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Local Gateway</DialogTitle>
            <DialogDescription>
              Enter the URL of a gateway on your local network.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="gw-url">Gateway URL</Label>
              <Input
                id="gw-url"
                placeholder="https://192.168.0.10:7891"
                value={addUrl}
                onChange={(e) => setAddUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleAdd()}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="gw-name">Display Name (optional)</Label>
              <Input
                id="gw-name"
                placeholder="Office Gateway"
                value={addName}
                onChange={(e) => setAddName(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button onClick={handleAdd} disabled={adding || !addUrl.trim()}>
              {adding ? "Connecting..." : "Add Gateway"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function LocalBackendItem({ gw, backend, onConnect }: {
  gw: LocalGateway;
  backend: NonNullable<LocalGateway["backends"]>[number];
  onConnect: (gw: LocalGateway, backend: any, sshUser?: string) => void;
}) {
  const isSsh = backend.protocol === "ssh";
  const sshUsernames = backend.sshUsernames || [];
  const [selectedUser, setSelectedUser] = useState(sshUsernames[0] || "");

  return (
    <div className="flex items-center gap-2 p-2 rounded-md bg-muted/50">
      {isSsh ? <Terminal className="h-4 w-4 text-[hsl(var(--neon-cyan))] shrink-0" /> : <Globe className="h-4 w-4 text-[hsl(var(--neon-purple))] shrink-0" />}
      <span className="text-sm flex-1 truncate">{backend.name}</span>
      <Badge variant="outline" className="text-xs">{backend.protocol || "http"}</Badge>
      {isSsh && sshUsernames.length > 0 && (
        <Select value={selectedUser} onValueChange={setSelectedUser}>
          <SelectTrigger className="w-[100px] h-7 text-xs">
            <SelectValue placeholder="User" />
          </SelectTrigger>
          <SelectContent>
            {sshUsernames.map((u) => (
              <SelectItem key={u} value={u}>{u}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
      <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => onConnect(gw, backend, selectedUser)} disabled={isSsh && !selectedUser}>
        Connect
      </Button>
    </div>
  );
}

export default function Dashboard() {
  const { user, hasRole } = useAuth();
  const isAdmin = hasRole("admin");
  const canAccessGateways = isAdmin || (() => {
    try {
      const token = localStorage.getItem("access_token");
      if (!token) return false;
      const payload = JSON.parse(atob(token.split(".")[1]));
      const clientId = payload.azp;
      const clientRoles = payload.resource_access?.[clientId]?.roles || [];
      return clientRoles.includes("allowConfigDownload");
    } catch { return false; }
  })();

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
      const backends = endpoint.backends?.length > 0 ? endpoint.backends : [];
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

      <Tabs defaultValue="services" className="space-y-4">
        <TabsList>
          <TabsTrigger value="services" className="gap-1.5">
            <Server className="h-4 w-4" />
            Services
            {(allServices.length + (servers?.length || 0)) > 0 && <Badge variant="secondary" className="ml-1 text-xs">{allServices.length + (servers?.length || 0)}</Badge>}
          </TabsTrigger>
          {canAccessGateways && (
            <TabsTrigger value="gateways" className="gap-1.5">
              <Router className="h-4 w-4" />
              Local Gateways
            </TabsTrigger>
          )}
          {canAccessGateways && (
            <TabsTrigger value="servers" className="gap-1.5">
              <Monitor className="h-4 w-4" />
              Servers
            </TabsTrigger>
          )}
        </TabsList>

        <TabsContent value="services">
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
        ) : (filteredServices.length > 0 || (servers && servers.length > 0)) ? (
          viewMode === "grid" ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {(servers || []).map((server) => (
                <ServerCard key={`local-${server.id}`} server={server} sshBlocked={isSshBlocked} />
              ))}
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
        </TabsContent>

        {canAccessGateways && (
          <TabsContent value="gateways">
            <GatewaysTab />
          </TabsContent>
        )}
        {canAccessGateways && (
          <TabsContent value="servers">
            <Suspense fallback={<div className="py-8 text-center text-muted-foreground">Loading...</div>}>
              <AdminServers />
            </Suspense>
          </TabsContent>
        )}
      </Tabs>

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
