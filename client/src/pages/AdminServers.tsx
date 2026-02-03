import { useState, useEffect, useCallback, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useIsFetching } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useAutoRefresh } from "@/hooks/useAutoRefresh";
import { Plus, Pencil, Trash2, Server, Search, AlertCircle, Video, Loader2, CheckCircle, XCircle, Wifi, KeyRound, Copy, Check } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import type { Server as ServerType, ServerStatus, Bridge } from "@shared/schema";
import { api, testBridgeConnection, getBridgeWebSocketUrl } from "@/lib/api";
import { base64UrlToBytes, formatOpenSshEd25519PublicKey } from "@/lib/sshClient";
import { useAuth, useAuthConfig } from "@/contexts/AuthContext";
import { UpgradeBanner } from "@/components/UpgradeBanner";
import { RefreshButton } from "@/components/RefreshButton";

function SshPublicKeyBanner() {
  const { user } = useAuth();
  const authConfig = useAuthConfig();
  const [copied, setCopied] = useState(false);
  const username = user?.username || "user";

  const publicKey = useMemo(() => {
    try {
      const jwkX = authConfig?.jwk?.keys?.[0]?.x;
      if (typeof jwkX !== "string") return null;
      const rawPublicKey = base64UrlToBytes(jwkX);
      return formatOpenSshEd25519PublicKey(rawPublicKey, `${username}@keylessh`);
    } catch {
      return null;
    }
  }, [username, authConfig]);

  if (!publicKey) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(publicKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 px-4 py-3">
        <KeyRound className="h-4 w-4 text-[hsl(var(--neon-cyan))] shrink-0" />
        <span className="text-sm font-medium flex-1">SSH Public Key</span>
        <Badge variant="outline" className="text-xs font-mono">ed25519</Badge>
      </div>
      <div className="px-4 pb-3 space-y-2">
        <p className="text-xs text-muted-foreground">
          Add this key to <code className="text-xs bg-muted px-1 py-0.5 rounded">~/.ssh/authorized_keys</code> on your servers to enable keyless SSH authentication.
        </p>
        <div className="flex gap-2">
          <code className="flex-1 text-xs font-mono bg-muted px-3 py-2 rounded-md break-all select-all leading-relaxed">
            {publicKey}
          </code>
          <Button variant="outline" size="sm" onClick={handleCopy} className="shrink-0 h-auto">
            {copied ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
          </Button>
        </div>
      </div>
    </div>
  );
}

interface ServerFormData {
  name: string;
  host: string;
  port: number;
  environment: string;
  tags: string;
  sshUsers: string;
  enabled: boolean;
  recordingEnabled: boolean;
  recordedUsers: string;
  bridgeId: string;
}

const defaultFormData: ServerFormData = {
  name: "",
  host: "",
  port: 22,
  environment: "production",
  tags: "",
  sshUsers: "root",
  enabled: true,
  recordingEnabled: false,
  recordedUsers: "",
  bridgeId: "",
};

function ServerForm({
  initialData,
  onSubmit,
  onCancel,
  isLoading,
  bridges,
}: {
  initialData?: ServerFormData;
  onSubmit: (data: ServerFormData) => void;
  onCancel: () => void;
  isLoading: boolean;
  bridges?: Bridge[];
}) {
  const [formData, setFormData] = useState<ServerFormData>(initialData || defaultFormData);
  const [testStatus, setTestStatus] = useState<"idle" | "testing" | "success" | "error">("idle");
  const [testMessage, setTestMessage] = useState<string>("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  const handleTestConnection = async () => {
    if (!formData.host) {
      setTestStatus("error");
      setTestMessage("Please enter a host address first");
      return;
    }

    setTestStatus("testing");
    setTestMessage("");

    // Determine which bridge URL to use
    let bridgeUrl: string;
    if (formData.bridgeId && bridges) {
      const selectedBridge = bridges.find(b => b.id === formData.bridgeId);
      bridgeUrl = selectedBridge?.url || getBridgeWebSocketUrl();
    } else {
      // Use default bridge if available
      const defaultBridge = bridges?.find(b => b.isDefault && b.enabled);
      bridgeUrl = defaultBridge?.url || getBridgeWebSocketUrl();
    }

    try {
      const result = await testBridgeConnection(bridgeUrl, formData.host, formData.port || 22);
      setTestStatus(result.success ? "success" : "error");
      setTestMessage(result.message);
    } catch (err) {
      setTestStatus("error");
      setTestMessage(err instanceof Error ? err.message : "Test failed");
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label htmlFor="name">Server Name</Label>
          <Input
            id="name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            placeholder="Production Web Server"
            required
            data-testid="input-server-name"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="host">Host</Label>
          <Input
            id="host"
            value={formData.host}
            onChange={(e) => setFormData({ ...formData, host: e.target.value })}
            placeholder="192.168.1.100"
            required
            data-testid="input-server-host"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label htmlFor="port">Port</Label>
          <Input
            id="port"
            type="number"
            value={formData.port}
            onChange={(e) => setFormData({ ...formData, port: parseInt(e.target.value) || 22 })}
            placeholder="22"
            data-testid="input-server-port"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="environment">Environment</Label>
          <Select
            value={formData.environment}
            onValueChange={(value) => setFormData({ ...formData, environment: value })}
          >
            <SelectTrigger data-testid="select-server-environment">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="production">Production</SelectItem>
              <SelectItem value="staging">Staging</SelectItem>
              <SelectItem value="development">Development</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-2">
        <Label htmlFor="tags">Tags (comma-separated)</Label>
        <Input
          id="tags"
          value={formData.tags}
          onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
          placeholder="web, api, database"
          data-testid="input-server-tags"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="sshUsers">SSH Users (comma-separated)</Label>
        <Input
          id="sshUsers"
          value={formData.sshUsers}
          onChange={(e) => setFormData({ ...formData, sshUsers: e.target.value })}
          placeholder="root, debian, docker"
          data-testid="input-server-ssh-users"
        />
      </div>

      {bridges && bridges.length > 0 && (
        <div className="space-y-2">
          <Label htmlFor="bridgeId">SSH Bridge</Label>
          <Select
            value={formData.bridgeId || "_default"}
            onValueChange={(value) => setFormData({ ...formData, bridgeId: value === "_default" ? "" : value })}
          >
            <SelectTrigger data-testid="select-server-bridge">
              <SelectValue placeholder="Use default bridge" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="_default">Use default bridge</SelectItem>
              {bridges.filter(b => b.enabled).map((bridge) => (
                <SelectItem key={bridge.id} value={bridge.id}>
                  {bridge.name} {bridge.isDefault && "(default)"}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            Select a specific bridge for this server or use the default
          </p>
        </div>
      )}

      {/* Test Connection Button */}
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleTestConnection}
            disabled={testStatus === "testing" || !formData.host}
            className="gap-2"
          >
            {testStatus === "testing" ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Wifi className="h-4 w-4" />
            )}
            Test Connection
          </Button>
          {testStatus === "success" && (
            <div className="flex items-center gap-1 text-sm text-green-600">
              <CheckCircle className="h-4 w-4" />
              {testMessage}
            </div>
          )}
          {testStatus === "error" && (
            <div className="flex items-center gap-1 text-sm text-red-600">
              <XCircle className="h-4 w-4" />
              {testMessage}
            </div>
          )}
        </div>
        <p className="text-xs text-muted-foreground">
          Test SSH connectivity through the selected bridge
        </p>
      </div>

      <div className="flex items-center justify-between">
        <Label htmlFor="enabled">Enabled</Label>
        <Switch
          id="enabled"
          checked={formData.enabled}
          onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
          data-testid="switch-server-enabled"
        />
      </div>

      <div className="border-t pt-4 mt-4 space-y-4">
        <div className="flex items-center gap-2">
          <Video className="h-4 w-4 text-muted-foreground" />
          <h4 className="font-medium">Session Recording</h4>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <Label htmlFor="recordingEnabled">Enable Recording</Label>
            <p className="text-xs text-muted-foreground">Record SSH sessions for compliance audits</p>
          </div>
          <Switch
            id="recordingEnabled"
            checked={formData.recordingEnabled}
            onCheckedChange={(checked) => setFormData({ ...formData, recordingEnabled: checked })}
            data-testid="switch-recording-enabled"
          />
        </div>

        {formData.recordingEnabled && (
          <div className="space-y-2">
            <Label htmlFor="recordedUsers">Recorded Users (comma-separated)</Label>
            <Input
              id="recordedUsers"
              value={formData.recordedUsers}
              onChange={(e) => setFormData({ ...formData, recordedUsers: e.target.value })}
              placeholder="Leave empty to record all users"
              data-testid="input-recorded-users"
            />
            <p className="text-xs text-muted-foreground">
              Specify which SSH users to record. Leave empty to record all sessions.
            </p>
          </div>
        )}
      </div>

      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={isLoading} data-testid="submit-server-form">
          {isLoading ? "Saving..." : initialData ? "Update Server" : "Add Server"}
        </Button>
      </DialogFooter>
    </form>
  );
}

export default function AdminServers() {
  const { toast } = useToast();
  const [search, setSearch] = useState("");
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingServer, setEditingServer] = useState<ServerType | null>(null);
  // Client-side status checks for servers using external bridges
  const [clientSideStatus, setClientSideStatus] = useState<Record<string, ServerStatus>>({});
  const [checkingStatus, setCheckingStatus] = useState<Set<string>>(new Set());

  const { data: servers, isLoading, refetch } = useQuery<ServerType[]>({
    queryKey: ["/api/admin/servers"],
  });

  const { data: serverStatusData, refetch: refetchServerStatus } = useQuery<{
    statuses: Record<string, ServerStatus>;
  }>({
    queryKey: ["/api/admin/servers/status"],
  });

  const { data: serverLimit, refetch: refetchServerLimit } = useQuery({
    queryKey: ["/api/admin/license/check/server"],
    queryFn: () => api.admin.license.checkLimit("server"),
  });

  const { data: licenseInfo, refetch: refetchLicense } = useQuery({
    queryKey: ["/api/admin/license"],
    queryFn: api.admin.license.get,
  });

  const { data: bridges } = useQuery<Bridge[]>({
    queryKey: ["/api/admin/bridges"],
    queryFn: api.admin.bridges.list,
  });

  // Check server status through bridge (client-side for external bridges)
  const checkServerViaClient = useCallback(async (server: ServerType) => {
    if (!bridges) return;

    // Determine which bridge to use
    let bridgeUrl: string;
    if (server.bridgeId) {
      const bridge = bridges.find(b => b.id === server.bridgeId && b.enabled);
      if (!bridge) return;
      bridgeUrl = bridge.url;
    } else {
      // Use default bridge
      const defaultBridge = bridges.find(b => b.isDefault && b.enabled);
      bridgeUrl = defaultBridge?.url || getBridgeWebSocketUrl();
    }

    setCheckingStatus(prev => new Set(prev).add(server.id));

    try {
      const result = await testBridgeConnection(bridgeUrl, server.host, server.port || 22, 5000);
      setClientSideStatus(prev => ({
        ...prev,
        [server.id]: result.success ? "online" : "offline"
      }));
    } catch {
      setClientSideStatus(prev => ({
        ...prev,
        [server.id]: "offline"
      }));
    } finally {
      setCheckingStatus(prev => {
        const next = new Set(prev);
        next.delete(server.id);
        return next;
      });
    }
  }, [bridges]);

  // Check servers with "unknown" status through client
  useEffect(() => {
    if (!servers || !serverStatusData || !bridges) return;

    const serverStatuses = serverStatusData.statuses || {};

    // Find servers with "unknown" status that haven't been checked yet
    const unknownServers = servers.filter(server =>
      server.enabled &&
      serverStatuses[server.id] === "unknown" &&
      !clientSideStatus[server.id] &&
      !checkingStatus.has(server.id)
    );

    // Check up to 3 servers at a time to avoid overwhelming
    unknownServers.slice(0, 3).forEach(server => {
      checkServerViaClient(server);
    });
  }, [servers, serverStatusData, bridges, clientSideStatus, checkingStatus, checkServerViaClient]);

  const isFetching = useIsFetching({ queryKey: ["/api/admin/servers"] }) > 0;
  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 15,
    refresh: () => {
      // Clear client-side status on refresh to re-check
      setClientSideStatus({});
      return Promise.all([refetch(), refetchServerStatus(), refetchServerLimit(), refetchLicense()]);
    },
    isBlocked: isFetching,
  });

  const createMutation = useMutation({
    mutationFn: async (data: ServerFormData) => {
      const serverData = {
        name: data.name,
        host: data.host,
        port: data.port,
        environment: data.environment,
        tags: data.tags.split(",").map((t) => t.trim()).filter(Boolean),
        sshUsers: data.sshUsers.split(",").map((u) => u.trim()).filter(Boolean),
        enabled: data.enabled,
        recordingEnabled: data.recordingEnabled,
        recordedUsers: data.recordedUsers.split(",").map((u) => u.trim()).filter(Boolean),
        bridgeId: data.bridgeId || null,
      };
      return apiRequest("POST", "/api/admin/servers", serverData);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/servers"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/servers/status"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/license/check/server"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/servers"] });
      setIsDialogOpen(false);
      toast({ title: "Server created successfully" });
    },
    onError: (error) => {
      toast({ title: "Failed to create server", description: error.message, variant: "destructive" });
    },
  });

  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: ServerFormData }) => {
      const serverData = {
        name: data.name,
        host: data.host,
        port: data.port,
        environment: data.environment,
        tags: data.tags.split(",").map((t) => t.trim()).filter(Boolean),
        sshUsers: data.sshUsers.split(",").map((u) => u.trim()).filter(Boolean),
        enabled: data.enabled,
        recordingEnabled: data.recordingEnabled,
        recordedUsers: data.recordedUsers.split(",").map((u) => u.trim()).filter(Boolean),
        bridgeId: data.bridgeId || null,
      };
      return apiRequest("PATCH", `/api/admin/servers/${id}`, serverData);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/servers"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/servers/status"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/servers"] });
      setEditingServer(null);
      setIsDialogOpen(false);
      toast({ title: "Server updated successfully" });
    },
    onError: (error) => {
      toast({ title: "Failed to update server", description: error.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      return apiRequest("DELETE", `/api/admin/servers/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/servers"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/servers/status"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/license/check/server"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/servers"] });
      toast({ title: "Server deleted successfully" });
    },
    onError: (error) => {
      toast({ title: "Failed to delete server", description: error.message, variant: "destructive" });
    },
  });

  const toggleEnabledMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      return apiRequest("PATCH", `/api/admin/servers/${id}`, { enabled });
    },
    onSuccess: (_, { enabled }) => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/servers"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/license"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/servers"] });
      toast({ title: enabled ? "Server enabled" : "Server disabled" });
    },
    onError: (error) => {
      toast({ title: "Failed to update server", description: error.message, variant: "destructive" });
    },
  });

  const handleSubmit = (data: ServerFormData) => {
    if (editingServer) {
      updateMutation.mutate({ id: editingServer.id, data });
    } else {
      createMutation.mutate(data);
    }
  };

  const handleEdit = (server: ServerType) => {
    setEditingServer(server);
    setIsDialogOpen(true);
  };

  const handleCloseDialog = () => {
    setIsDialogOpen(false);
    setEditingServer(null);
  };

  const filteredServers = servers?.filter(
    (server) =>
      server.name.toLowerCase().includes(search.toLowerCase()) ||
      server.host.toLowerCase().includes(search.toLowerCase())
  );

  const statusById = serverStatusData?.statuses || {};

  return (
    <div className="p-4 sm:p-6 space-y-4 sm:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-xl sm:text-2xl font-semibold tracking-tight flex items-center gap-2" data-testid="admin-servers-title">
            <Server className="h-5 w-5 sm:h-6 sm:w-6" />
            Manage Servers
          </h1>
          <p className="text-sm text-muted-foreground">
            Add, edit, and remove SSH servers
          </p>
        </div>

        <div className="flex items-center gap-2">
          <RefreshButton
            onClick={() => void refreshNow()}
            isRefreshing={isFetching}
            secondsRemaining={secondsRemaining}
            data-testid="refresh-servers"
            title="Refresh now"
          />

          <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
            <DialogTrigger asChild>
              <Button
                onClick={() => setEditingServer(null)}
                disabled={serverLimit ? !serverLimit.allowed : false}
                title={
                  serverLimit && !serverLimit.allowed
                    ? `Server limit reached (${serverLimit.current}/${serverLimit.limit}). Upgrade your plan to add more.`
                    : "Add Server"
                }
                data-testid="add-server-button"
                className="shrink-0"
              >
                <Plus className="h-4 w-4 sm:mr-2" />
                <span className="hidden sm:inline">Add Server</span>
              </Button>
            </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>{editingServer ? "Edit Server" : "Add New Server"}</DialogTitle>
              <DialogDescription>
                {editingServer ? "Update the server configuration" : "Configure a new SSH server"}
              </DialogDescription>
            </DialogHeader>
            <ServerForm
              initialData={
                editingServer
                  ? {
                      name: editingServer.name,
                      host: editingServer.host,
                      port: editingServer.port,
                      environment: editingServer.environment,
                      tags: editingServer.tags?.join(", ") || "",
                      sshUsers: editingServer.sshUsers?.join(", ") || "",
                      enabled: editingServer.enabled,
                      recordingEnabled: editingServer.recordingEnabled || false,
                      recordedUsers: editingServer.recordedUsers?.join(", ") || "",
                      bridgeId: editingServer.bridgeId || "",
                    }
                  : undefined
              }
              bridges={bridges}
              onSubmit={handleSubmit}
              onCancel={handleCloseDialog}
              isLoading={createMutation.isPending || updateMutation.isPending}
            />
          </DialogContent>
        </Dialog>
        </div>
      </div>

      {serverLimit && !serverLimit.allowed && (
        <UpgradeBanner
          message={`Server limit reached (${serverLimit.current}/${serverLimit.limit}) on the ${serverLimit.tierName} plan. Upgrade to add more servers.`}
          current={serverLimit.current}
          limit={serverLimit.limit}
          tierName={serverLimit.tierName}
        />
      )}

      {licenseInfo?.overLimit?.servers.isOverLimit && (
        <Alert className="bg-red-50 border-red-200 dark:bg-red-950/20 dark:border-red-800">
          <AlertCircle className="h-4 w-4 text-red-600 dark:text-red-400" />
          <AlertDescription className="text-red-800 dark:text-red-200">
            <strong>Server limit exceeded.</strong> You have {licenseInfo.overLimit.servers.enabled} enabled servers but your plan allows {licenseInfo.overLimit.servers.limit}.
            Please disable {licenseInfo.overLimit.servers.overBy} server(s) or upgrade your plan.
          </AlertDescription>
        </Alert>
      )}

      <SshPublicKeyBanner />

      <Card>
        <CardHeader className="pb-4">
          <div className="flex items-center gap-4">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search servers..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
                data-testid="search-servers"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4 space-y-3">
              {[1, 2, 3].map((i) => (
                <div key={i} className="flex items-center gap-4">
                  <Skeleton className="h-10 w-10" />
                  <div className="flex-1 space-y-2">
                    <Skeleton className="h-4 w-32" />
                    <Skeleton className="h-3 w-48" />
                  </div>
                  <Skeleton className="h-6 w-16" />
                </div>
              ))}
            </div>
          ) : filteredServers && filteredServers.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Server</TableHead>
                  <TableHead className="hidden sm:table-cell">Environment</TableHead>
                  <TableHead className="hidden lg:table-cell">SSH Users</TableHead>
                  <TableHead className="hidden md:table-cell">Recording</TableHead>
                  <TableHead className="hidden sm:table-cell">Enabled</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredServers.map((server) => (
                  <TableRow key={server.id} data-testid={`server-row-${server.id}`}>
                    <TableCell>
                      <div>
                        <p className="font-medium">{server.name}</p>
                        <p className="text-xs text-muted-foreground font-mono">
                          {server.host}:{server.port}
                        </p>
                      </div>
                    </TableCell>
                    <TableCell className="hidden sm:table-cell">
                      <Badge variant="secondary" className="text-xs">
                        {server.environment}
                      </Badge>
                    </TableCell>
                    <TableCell className="hidden lg:table-cell">
                      <div className="flex flex-wrap gap-1">
                        {server.sshUsers?.slice(0, 3).map((user) => (
                          <Badge key={user} variant="outline" className="text-xs font-mono">
                            {user}
                          </Badge>
                        ))}
                        {server.sshUsers && server.sshUsers.length > 3 && (
                          <Badge variant="outline" className="text-xs">
                            +{server.sshUsers.length - 3}
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      {server.recordingEnabled ? (
                        <Badge variant="default" className="gap-1 text-xs">
                          <Video className="h-3 w-3" />
                          {server.recordedUsers && server.recordedUsers.length > 0
                            ? `${server.recordedUsers.length} user${server.recordedUsers.length > 1 ? "s" : ""}`
                            : "All"}
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-xs text-muted-foreground">
                          Off
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="hidden sm:table-cell">
                      <Switch
                        checked={server.enabled}
                        onCheckedChange={(enabled) =>
                          toggleEnabledMutation.mutate({ id: server.id, enabled })
                        }
                        disabled={toggleEnabledMutation.isPending}
                      />
                    </TableCell>
                    <TableCell>
                      {server.enabled ? (
                        (() => {
                          // Use client-side status for servers with external bridges, fall back to server status
                          const effectiveStatus = clientSideStatus[server.id] || statusById[server.id];
                          const isChecking = checkingStatus.has(server.id);

                          if (isChecking) {
                            return (
                              <Badge variant="secondary" className="gap-1">
                                <Loader2 className="h-3 w-3 animate-spin" />
                                Checking
                              </Badge>
                            );
                          }

                          return (
                            <Badge
                              variant={
                                effectiveStatus === "online"
                                  ? "default"
                                  : effectiveStatus === "offline"
                                    ? "destructive"
                                    : "secondary"
                              }
                            >
                              {effectiveStatus === "online"
                                ? "Online"
                                : effectiveStatus === "offline"
                                  ? "Offline"
                                  : "Unknown"}
                            </Badge>
                          );
                        })()
                      ) : (
                        <Badge variant="secondary">Disabled</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => handleEdit(server)}
                          data-testid={`edit-server-${server.id}`}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => deleteMutation.mutate(server.id)}
                          disabled={deleteMutation.isPending}
                          data-testid={`delete-server-${server.id}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <Server className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="font-medium">No servers found</h3>
              <p className="text-sm text-muted-foreground mt-1">
                {search ? "Try a different search term" : "Add your first server to get started"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
