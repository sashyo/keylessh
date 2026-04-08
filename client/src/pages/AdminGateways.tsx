import { useState } from "react";
import { useQuery, useMutation, useIsFetching } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { queryClient } from "@/lib/queryClient";
import { api, type GatewayConfigSummary } from "@/lib/api";
import { useAutoRefresh } from "@/hooks/useAutoRefresh";
import { RefreshButton } from "@/components/RefreshButton";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Router, Plus, Pencil, Trash2, Download, Wifi, Copy, Check, KeyRound, FileDown, Shield, Settings } from "lucide-react";
import type { SignalServer } from "@shared/schema";
import { useAuth, useAuthConfig } from "@/contexts/AuthContext";
import { useMemo } from "react";
import { base64UrlToBytes, formatOpenSshEd25519PublicKey } from "@/lib/sshClient";

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

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-3 px-4 py-3">
        <KeyRound className="h-4 w-4 text-[hsl(var(--neon-cyan))] shrink-0" />
        <span className="text-sm font-medium flex-1">SSH Public Key</span>
        <Badge variant="outline" className="text-xs font-mono">ed25519</Badge>
      </div>
      <div className="px-4 pb-3 space-y-2">
        <p className="text-xs text-muted-foreground">
          Add this key to <code className="text-xs bg-muted px-1 py-0.5 rounded">~/.ssh/authorized_keys</code> on your SSH servers to enable passwordless authentication.
        </p>
        <div className="flex gap-2">
          <code className="flex-1 text-xs font-mono bg-muted px-3 py-2 rounded-md break-all select-all leading-relaxed">
            {publicKey}
          </code>
          <Button variant="outline" size="sm" onClick={() => { navigator.clipboard.writeText(publicKey); setCopied(true); setTimeout(() => setCopied(false), 2000); }} className="shrink-0 h-auto">
            {copied ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
          </Button>
        </div>
      </div>
    </div>
  );
}

const defaultForm: Partial<GatewayConfigSummary> = {
  gatewayId: "",
  displayName: "",
  stunServerUrl: "",
  apiSecret: "",
  iceServers: "",
  turnServer: "",
  turnSecret: "",
  backends: "",
  tidecloakConfigB64: "",
  authServerPublicUrl: "",
  serverUrl: "",
  vpnEnabled: false,
  vpnSubnet: "10.66.0.0/24",
  listenPort: 7891,
  healthPort: 7892,
  https: true,
  tlsHostname: "localhost",
};

export default function AdminGateways() {
  const { toast } = useToast();
  const authConfig = useAuthConfig();
  const [editing, setEditing] = useState<GatewayConfigSummary | null>(null);
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<GatewayConfigSummary | null>(null);
  const [form, setForm] = useState<Partial<GatewayConfigSummary>>(defaultForm);
  const [copied, setCopied] = useState<string | null>(null);

  const { data: signalServers } = useQuery<SignalServer[]>({
    queryKey: ["/api/admin/signal-servers"],
  });

  const { data: configs, isLoading, refetch } = useQuery({
    queryKey: ["/api/admin/gateway-configs"],
    queryFn: api.admin.gatewayConfigs.list,
  });
  const isFetching = useIsFetching({ queryKey: ["/api/admin/gateway-configs"] }) > 0;
  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 30,
    refresh: () => refetch(),
    isBlocked: isFetching,
  });

  const createMutation = useMutation({
    mutationFn: (data: any) => api.admin.gatewayConfigs.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/gateway-configs"] });
      setCreating(false);
      setForm(defaultForm);
      toast({ title: "Gateway config created" });
    },
    onError: (e: Error) => toast({ title: "Failed to create", description: e.message, variant: "destructive" }),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => api.admin.gatewayConfigs.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/gateway-configs"] });
      setEditing(null);
      toast({ title: "Gateway config updated" });
    },
    onError: (e: Error) => toast({ title: "Failed to update", description: e.message, variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.admin.gatewayConfigs.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/gateway-configs"] });
      setDeleting(null);
      toast({ title: "Gateway config deleted" });
    },
  });

  const handleCreate = () => {
    // Auto-generate gateway ID and pre-fill from current config
    const randomSuffix = Math.random().toString(36).substring(2, 8);
    setForm({
      ...defaultForm,
      gatewayId: `gateway-${randomSuffix}`,
      authServerPublicUrl: authConfig?.["auth-server-url"] || "",
      serverUrl: window.location.origin,
    });
    setCreating(true);
  };

  const handleEdit = (config: GatewayConfigSummary) => {
    setForm({ ...config });
    setEditing(config);
  };

  const handleCopyId = (id: string) => {
    navigator.clipboard.writeText(id);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleDownload = (config: GatewayConfigSummary) => {
    const token = localStorage.getItem("access_token");
    window.open(`${api.admin.gatewayConfigs.downloadUrl(config.id)}?token=${encodeURIComponent(token || "")}`, "_blank");
  };

  const handleDownloadVpn = (config: GatewayConfigSummary) => {
    const token = localStorage.getItem("access_token");
    window.open(`${api.admin.gatewayConfigs.vpnConfigUrl(config.id)}?token=${encodeURIComponent(token || "")}`, "_blank");
  };

  const handleDownloadTidecloak = (config: GatewayConfigSummary) => {
    const token = localStorage.getItem("access_token");
    window.open(`${api.admin.gatewayConfigs.tidecloakConfigUrl(config.id)}?token=${encodeURIComponent(token || "")}`, "_blank");
  };

  const renderForm = (onSubmit: () => void, submitLabel: string, isPending: boolean) => (
    <div className="space-y-4 max-h-[60vh] overflow-y-auto px-1 -mx-1">
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <Label className="text-xs">Gateway ID</Label>
          <Input value={form.gatewayId || ""} onChange={(e) => setForm({ ...form, gatewayId: e.target.value })} placeholder="e.g. SashaKC" />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Display Name</Label>
          <Input value={form.displayName || ""} onChange={(e) => setForm({ ...form, displayName: e.target.value })} placeholder="My Gateway" />
        </div>
      </div>

      <div className="space-y-1">
        <Label className="text-xs">Signal Server</Label>
        <Select
          value={(signalServers || []).find((s) => {
            const wsUrl = s.url.replace(/^http/, "ws");
            return s.id === form.stunServerUrl || s.url === form.stunServerUrl || wsUrl === form.stunServerUrl;
          })?.id || ""}
          onValueChange={(id) => {
            const ss = (signalServers || []).find((s) => s.id === id);
            if (ss) {
              setForm({
                ...form,
                stunServerUrl: ss.url.replace(/^http/, "ws"),
                apiSecret: (ss as any).apiSecret || form.apiSecret || "",
                iceServers: (ss as any).iceServers || form.iceServers || "",
                turnServer: (ss as any).turnServer || form.turnServer || "",
                turnSecret: (ss as any).turnSecret || form.turnSecret || "",
              });
            }
          }}
        >
          <SelectTrigger className="h-9">
            <SelectValue placeholder="Select a signal server..." />
          </SelectTrigger>
          <SelectContent>
            {(signalServers || []).filter((s) => s.enabled).map((ss) => (
              <SelectItem key={ss.id} value={ss.id}>
                {ss.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-[10px] text-muted-foreground">STUN/TURN and API secret are inherited from the signal server config.</p>
      </div>

      <div className="space-y-1">
        <Label className="text-xs">Backends <span className="text-muted-foreground font-normal">(optional)</span></Label>
        <Input value={form.backends || ""} onChange={(e) => setForm({ ...form, backends: e.target.value })} placeholder="Name=rdp://host:3389;eddsa" />
        <p className="text-[10px] text-muted-foreground">Pre-configured endpoints. Leave empty to use custom IP connections only. Format: Name=url;flags, comma-separated.</p>
        <ul className="text-[10px] text-muted-foreground list-disc pl-4 space-y-0.5">
          <li><code className="bg-muted px-0.5 rounded">noauth</code> — skip JWT verification for this backend</li>
          <li><code className="bg-muted px-0.5 rounded">eddsa</code> — passwordless RDP using EdDSA certificates</li>
          <li><code className="bg-muted px-0.5 rounded">stripauth</code> — remove auth headers before forwarding to backend</li>
        </ul>
      </div>

      <div className="space-y-1">
        <Label className="text-xs">Punchd Client TideCloak Config</Label>
        <Textarea
          value={form.tidecloakConfigB64 || ""}
          onChange={(e) => {
            const val = e.target.value.trim();
            // Accept raw JSON or base64
            if (val.startsWith("{")) {
              try {
                JSON.parse(val);
                setForm({ ...form, tidecloakConfigB64: btoa(val) });
              } catch {
                setForm({ ...form, tidecloakConfigB64: val });
              }
            } else {
              setForm({ ...form, tidecloakConfigB64: val });
            }
          }}
          rows={3}
          placeholder='Paste the TideCloak adapter config JSON'
          className="font-mono text-xs"
        />
        <p className="text-[10px] text-muted-foreground">
          Download from TideCloak: Clients &rarr; <strong>{authConfig?.resource || "myclient"}</strong> &rarr; Installation. Paste JSON or base64.
        </p>
      </div>

      <div className="grid grid-cols-3 gap-3">
        <div className="space-y-1">
          <Label className="text-xs">Listen Port</Label>
          <Input type="number" value={form.listenPort || 7891} onChange={(e) => setForm({ ...form, listenPort: parseInt(e.target.value) || 7891 })} />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Health Port</Label>
          <Input type="number" value={form.healthPort || 7892} onChange={(e) => setForm({ ...form, healthPort: parseInt(e.target.value) || 7892 })} />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">TLS Hostname</Label>
          <Input value={form.tlsHostname || ""} onChange={(e) => setForm({ ...form, tlsHostname: e.target.value })} />
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <Switch checked={form.https !== false} onCheckedChange={(v) => setForm({ ...form, https: v })} />
          <Label className="text-xs">HTTPS</Label>
        </div>
        <div className="flex items-center gap-2">
          <Switch checked={form.vpnEnabled || false} onCheckedChange={(v) => setForm({ ...form, vpnEnabled: v })} />
          <Label className="text-xs">VPN Enabled</Label>
        </div>
      </div>

      {form.vpnEnabled && (
        <div className="space-y-1">
          <Label className="text-xs">VPN Subnet</Label>
          <Input value={form.vpnSubnet || "10.66.0.0/24"} onChange={(e) => setForm({ ...form, vpnSubnet: e.target.value })} />
        </div>
      )}

      <DialogFooter>
        <Button type="button" variant="outline" onClick={() => { setCreating(false); setEditing(null); }}>Cancel</Button>
        <Button onClick={onSubmit} disabled={isPending || !form.gatewayId}>
          {isPending ? "Saving..." : submitLabel}
        </Button>
      </DialogFooter>
    </div>
  );

  return (
    <div className="p-4 sm:p-6 space-y-4 sm:space-y-6">
      <SshPublicKeyBanner />

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-xl sm:text-2xl font-semibold tracking-tight flex items-center gap-2">
            <Router className="h-5 w-5 sm:h-6 sm:w-6" />
            Punchd
          </h1>
          <p className="text-sm text-muted-foreground">
            Manage Punchd gateway configurations. Download as TOML for deployment.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <RefreshButton onClick={() => void refreshNow()} isRefreshing={isFetching} secondsRemaining={secondsRemaining} />
          <Button onClick={handleCreate} className="shrink-0">
            <Plus className="h-4 w-4 sm:mr-2" />
            <span className="hidden sm:inline">Add Gateway</span>
          </Button>
        </div>
      </div>

      <Tabs defaultValue="gateways" className="space-y-4">
        <TabsList>
          <TabsTrigger value="gateways" className="gap-1.5"><Settings className="h-3.5 w-3.5" /> Gateways</TabsTrigger>
          <TabsTrigger value="configs" className="gap-1.5"><FileDown className="h-3.5 w-3.5" /> Configuration</TabsTrigger>
        </TabsList>

        <TabsContent value="gateways">
          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Gateway</TableHead>
                    <TableHead className="hidden md:table-cell">STUN Server</TableHead>
                    <TableHead className="hidden lg:table-cell">Backends</TableHead>
                    <TableHead>VPN</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(configs || []).map((config) => (
                    <TableRow key={config.id}>
                      <TableCell>
                        <div>
                          <p className="font-medium">{config.displayName || config.gatewayId}</p>
                          <p className="text-xs text-muted-foreground font-mono flex items-center gap-1">
                            {config.gatewayId}
                            <button onClick={() => handleCopyId(config.gatewayId)} className="hover:text-foreground">
                              {copied === config.gatewayId ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                            </button>
                          </p>
                        </div>
                      </TableCell>
                      <TableCell className="hidden md:table-cell">
                        <p className="text-xs font-mono text-muted-foreground truncate max-w-[200px]">{config.stunServerUrl || "—"}</p>
                      </TableCell>
                      <TableCell className="hidden lg:table-cell">
                        <p className="text-xs text-muted-foreground truncate max-w-[200px]">{config.backends || "—"}</p>
                      </TableCell>
                      <TableCell>
                        {config.vpnEnabled ? (
                          <Badge variant="outline" className="gap-1 bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950/30 dark:text-blue-400">
                            <Wifi className="h-3 w-3" /> On
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-muted-foreground">Off</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button size="icon" variant="ghost" title="Download gateway.toml" onClick={() => handleDownload(config)}>
                            <Download className="h-4 w-4" />
                          </Button>
                          {config.vpnEnabled && (
                            <Button size="icon" variant="ghost" title="Download VPN config" onClick={() => handleDownloadVpn(config)}>
                              <Wifi className="h-4 w-4" />
                            </Button>
                          )}
                          <Button size="icon" variant="ghost" onClick={() => handleEdit(config)}>
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button size="icon" variant="ghost" onClick={() => setDeleting(config)}>
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                  {(!configs || configs.length === 0) && !isLoading && (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                        No gateway configs. Click "Add Gateway" to create one.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="configs">
          {(!configs || configs.length === 0) ? (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                No gateway configs. Create a gateway first to download configuration files.
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {(configs || []).map((config) => (
                <Card key={config.id}>
                  <CardContent className="p-4 sm:p-6">
                    <div className="flex items-center gap-3 mb-4">
                      <Router className="h-5 w-5 text-muted-foreground" />
                      <div>
                        <h3 className="font-medium">{config.displayName || config.gatewayId}</h3>
                        <p className="text-xs text-muted-foreground font-mono">{config.gatewayId}</p>
                      </div>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      {/* TideCloak Adapter Config */}
                      <div className="rounded-lg border border-border p-4 space-y-3">
                        <div className="flex items-center gap-2">
                          <Shield className="h-4 w-4 text-[hsl(var(--neon-cyan))]" />
                          <span className="text-sm font-medium">tidecloak.json</span>
                        </div>
                        <p className="text-xs text-muted-foreground">
                          TideCloak OIDC adapter config for the Punchd client. Place in the client's working directory.
                        </p>
                        <Button
                          variant="outline"
                          size="sm"
                          className="w-full gap-2"
                          disabled={!config.tidecloakConfigB64}
                          onClick={() => handleDownloadTidecloak(config)}
                        >
                          <Download className="h-3.5 w-3.5" />
                          {config.tidecloakConfigB64 ? "Download" : "Not configured"}
                        </Button>
                      </div>

                      {/* Gateway TOML Config */}
                      <div className="rounded-lg border border-border p-4 space-y-3">
                        <div className="flex items-center gap-2">
                          <Settings className="h-4 w-4 text-[hsl(var(--neon-cyan))]" />
                          <span className="text-sm font-medium">gateway.toml</span>
                        </div>
                        <p className="text-xs text-muted-foreground">
                          Gateway bridge configuration. Place in the Punchd gateway's working directory.
                        </p>
                        <Button
                          variant="outline"
                          size="sm"
                          className="w-full gap-2"
                          onClick={() => handleDownload(config)}
                        >
                          <Download className="h-3.5 w-3.5" />
                          Download
                        </Button>
                      </div>

                      {/* VPN Config */}
                      <div className="rounded-lg border border-border p-4 space-y-3">
                        <div className="flex items-center gap-2">
                          <Wifi className="h-4 w-4 text-[hsl(var(--neon-cyan))]" />
                          <span className="text-sm font-medium">vpn-config.toml</span>
                        </div>
                        <p className="text-xs text-muted-foreground">
                          VPN client configuration with signal server and auth settings.
                        </p>
                        <Button
                          variant="outline"
                          size="sm"
                          className="w-full gap-2"
                          disabled={!config.vpnEnabled}
                          onClick={() => handleDownloadVpn(config)}
                        >
                          <Download className="h-3.5 w-3.5" />
                          {config.vpnEnabled ? "Download" : "VPN not enabled"}
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* Create/Edit/Delete dialogs */}
      <>
        <Dialog open={creating} onOpenChange={setCreating}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Create Gateway Config</DialogTitle>
              <DialogDescription>Configure a new gateway bridge. Download the TOML file after creation.</DialogDescription>
            </DialogHeader>
            {renderForm(() => createMutation.mutate(form), "Create", createMutation.isPending)}
          </DialogContent>
        </Dialog>

        <Dialog open={!!editing} onOpenChange={(open) => !open && setEditing(null)}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Edit Gateway Config</DialogTitle>
              <DialogDescription>Update configuration for {editing?.gatewayId}</DialogDescription>
            </DialogHeader>
            {renderForm(() => editing && updateMutation.mutate({ id: editing.id, data: form }), "Save Changes", updateMutation.isPending)}
          </DialogContent>
        </Dialog>

        <AlertDialog open={!!deleting} onOpenChange={(open) => !open && setDeleting(null)}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Delete gateway config?</AlertDialogTitle>
              <AlertDialogDescription>
                This will remove the configuration for <strong>{deleting?.gatewayId}</strong>. The bridge will continue running with its local config.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction onClick={() => deleting && deleteMutation.mutate(deleting.id)}>Delete</AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </>
    </div>
  );
}
