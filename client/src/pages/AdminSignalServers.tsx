import { useState } from "react";
import { useQuery, useMutation, useIsFetching } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { queryClient } from "@/lib/queryClient";
import { useAutoRefresh } from "@/hooks/useAutoRefresh";
import { Plus, Pencil, Trash2, Radio, Search, Loader2, CheckCircle, XCircle, Wifi } from "lucide-react";
import type { SignalServer } from "@shared/schema";
import { api } from "@/lib/api";
import { RefreshButton } from "@/components/RefreshButton";

interface SignalServerFormData {
  name: string;
  url: string;
  description: string;
  enabled: boolean;
}

const defaultFormData: SignalServerFormData = {
  name: "",
  url: "",
  description: "",
  enabled: true,
};

function SignalServerForm({
  initialData,
  onSubmit,
  onCancel,
  isLoading,
}: {
  initialData?: SignalServerFormData;
  onSubmit: (data: SignalServerFormData) => void;
  onCancel: () => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState<SignalServerFormData>(initialData || defaultFormData);
  const [testStatus, setTestStatus] = useState<"idle" | "testing" | "success" | "error">("idle");
  const [testMessage, setTestMessage] = useState<string>("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  const handleTestConnection = async () => {
    if (!formData.url) {
      setTestStatus("error");
      setTestMessage("Please enter a URL first");
      return;
    }

    setTestStatus("testing");
    setTestMessage("");

    try {
      const healthUrl = formData.url.replace(/\/$/, "") + "/health";
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const resp = await fetch(healthUrl, { signal: controller.signal });
      clearTimeout(timeout);

      if (resp.ok) {
        const data = await resp.json();
        setTestStatus("success");
        setTestMessage(`Online — ${data.wafs ?? 0} WAFs, ${data.clients ?? 0} clients`);
      } else {
        setTestStatus("error");
        setTestMessage(`Server returned ${resp.status}`);
      }
    } catch (err) {
      setTestStatus("error");
      setTestMessage(err instanceof Error && err.name === "AbortError" ? "Connection timeout" : "Cannot reach server");
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="name">Server Name</Label>
        <Input
          id="name"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          placeholder="Production Signal Server"
          required
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="url">Server URL</Label>
        <Input
          id="url"
          value={formData.url}
          onChange={(e) => setFormData({ ...formData, url: e.target.value })}
          placeholder="https://tidestun.codesyo.com:9090"
          required
        />
        <p className="text-xs text-muted-foreground">
          The signal server URL (HTTPS). WAFs register here for P2P signaling and HTTP relay.
        </p>
      </div>

      <div className="flex items-center gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={handleTestConnection}
          disabled={testStatus === "testing" || !formData.url}
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

      <div className="space-y-2">
        <Label htmlFor="description">Description (optional)</Label>
        <Textarea
          id="description"
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          placeholder="Signal server for production WAF endpoints"
          rows={2}
        />
      </div>

      <div className="flex items-center justify-between">
        <div>
          <Label htmlFor="enabled">Enabled</Label>
          <p className="text-xs text-muted-foreground">Show WAF endpoints from this server on the dashboard</p>
        </div>
        <Switch
          id="enabled"
          checked={formData.enabled}
          onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
        />
      </div>

      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={isLoading}>
          {isLoading ? "Saving..." : initialData ? "Update Server" : "Add Server"}
        </Button>
      </DialogFooter>
    </form>
  );
}

export default function AdminSignalServers() {
  const { toast } = useToast();
  const [search, setSearch] = useState("");
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingServer, setEditingServer] = useState<SignalServer | null>(null);

  const { data: signalServers, isLoading, refetch } = useQuery<SignalServer[]>({
    queryKey: ["/api/admin/signal-servers"],
    queryFn: api.admin.signalServers.list,
  });

  const isFetching = useIsFetching({ queryKey: ["/api/admin/signal-servers"] }) > 0;
  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 30,
    refresh: refetch,
    isBlocked: isFetching,
  });

  const createMutation = useMutation({
    mutationFn: (data: SignalServerFormData) => api.admin.signalServers.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/signal-servers"] });
      setIsDialogOpen(false);
      toast({ title: "Signal server added successfully" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to add signal server", description: error.message, variant: "destructive" });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: SignalServerFormData }) =>
      api.admin.signalServers.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/signal-servers"] });
      setEditingServer(null);
      setIsDialogOpen(false);
      toast({ title: "Signal server updated successfully" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to update signal server", description: error.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.admin.signalServers.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/signal-servers"] });
      toast({ title: "Signal server deleted successfully" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to delete signal server", description: error.message, variant: "destructive" });
    },
  });

  const handleSubmit = (data: SignalServerFormData) => {
    if (editingServer) {
      updateMutation.mutate({ id: editingServer.id, data });
    } else {
      createMutation.mutate(data);
    }
  };

  const handleEdit = (server: SignalServer) => {
    setEditingServer(server);
    setIsDialogOpen(true);
  };

  const handleCloseDialog = () => {
    setIsDialogOpen(false);
    setEditingServer(null);
  };

  const filteredServers = signalServers?.filter(
    (s) =>
      s.name.toLowerCase().includes(search.toLowerCase()) ||
      s.url.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-4 sm:p-6 space-y-4 sm:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-xl sm:text-2xl font-semibold tracking-tight flex items-center gap-2">
            <Radio className="h-5 w-5 sm:h-6 sm:w-6" />
            Signal Servers
          </h1>
          <p className="text-sm text-muted-foreground">
            Manage signal servers for WAF endpoints, P2P signaling, and HTTP relay
          </p>
        </div>

        <div className="flex items-center gap-2">
          <RefreshButton
            onClick={() => void refreshNow()}
            isRefreshing={isFetching}
            secondsRemaining={secondsRemaining}
            title="Refresh now"
          />

          <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
            <DialogTrigger asChild>
              <Button onClick={() => setEditingServer(null)} className="shrink-0">
                <Plus className="h-4 w-4 sm:mr-2" />
                <span className="hidden sm:inline">Add Server</span>
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-md">
              <DialogHeader>
                <DialogTitle>{editingServer ? "Edit Signal Server" : "Add Signal Server"}</DialogTitle>
                <DialogDescription>
                  {editingServer
                    ? "Update the signal server configuration"
                    : "Add a new signal server for WAF endpoint discovery"}
                </DialogDescription>
              </DialogHeader>
              <SignalServerForm
                initialData={
                  editingServer
                    ? {
                        name: editingServer.name,
                        url: editingServer.url,
                        description: editingServer.description || "",
                        enabled: editingServer.enabled,
                      }
                    : undefined
                }
                onSubmit={handleSubmit}
                onCancel={handleCloseDialog}
                isLoading={createMutation.isPending || updateMutation.isPending}
              />
            </DialogContent>
          </Dialog>
        </div>
      </div>

      <Card>
        <CardHeader className="pb-4">
          <div className="flex items-center gap-4">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search signal servers..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
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
                  <TableHead className="hidden md:table-cell">URL</TableHead>
                  <TableHead className="hidden sm:table-cell">Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredServers.map((server) => (
                  <TableRow key={server.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div>
                          <p className="font-medium">{server.name}</p>
                          {server.description && (
                            <p className="text-xs text-muted-foreground line-clamp-1">
                              {server.description}
                            </p>
                          )}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      <code className="text-xs bg-muted px-2 py-1 rounded font-mono">
                        {server.url}
                      </code>
                    </TableCell>
                    <TableCell className="hidden sm:table-cell">
                      <Badge variant={server.enabled ? "default" : "secondary"}>
                        {server.enabled ? "Enabled" : "Disabled"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => handleEdit(server)}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => deleteMutation.mutate(server.id)}
                          disabled={deleteMutation.isPending}
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
              <Radio className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="font-medium">No signal servers configured</h3>
              <p className="text-sm text-muted-foreground mt-1">
                {search
                  ? "Try a different search term"
                  : "Add a signal server to discover WAF endpoints"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <h2 className="text-lg font-medium">About Signal Servers</h2>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>
            Signal servers handle P2P signaling, HTTP relay, and WAF endpoint discovery.
            WAF instances register with the signal server to make their backends available.
          </p>
          <p>
            Each signal server can host multiple WAFs, and each WAF can expose multiple backends
            (web apps, APIs, etc.). Users see all available endpoints on their dashboard.
          </p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li>Deploy signal servers on VMs with stable public IPs (alongside coturn for TURN/STUN)</li>
            <li>WAFs connect via WebSocket and register their backends</li>
            <li>HTTP traffic is relayed through the signal server, with P2P upgrade when possible</li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
