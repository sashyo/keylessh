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
import { Plus, Pencil, Trash2, Network, Search, Star, Loader2, CheckCircle, XCircle, Wifi } from "lucide-react";
import type { Bridge } from "@shared/schema";
import { api, testBridgeConnection } from "@/lib/api";
import { RefreshButton } from "@/components/RefreshButton";

interface BridgeFormData {
  name: string;
  url: string;
  description: string;
  enabled: boolean;
  isDefault: boolean;
}

const defaultFormData: BridgeFormData = {
  name: "",
  url: "",
  description: "",
  enabled: true,
  isDefault: false,
};

function BridgeForm({
  initialData,
  onSubmit,
  onCancel,
  isLoading,
}: {
  initialData?: BridgeFormData;
  onSubmit: (data: BridgeFormData) => void;
  onCancel: () => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState<BridgeFormData>(initialData || defaultFormData);
  const [testStatus, setTestStatus] = useState<"idle" | "testing" | "success" | "error">("idle");
  const [testMessage, setTestMessage] = useState<string>("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  const handleTestConnection = async () => {
    if (!formData.url) {
      setTestStatus("error");
      setTestMessage("Please enter a bridge URL first");
      return;
    }

    setTestStatus("testing");
    setTestMessage("");

    try {
      // Test with a non-routable IP to verify bridge is reachable
      // The TCP connection will fail but if bridge responds, it's working
      const result = await testBridgeConnection(formData.url, "192.0.2.1", 22, 3000);
      if (result.message === "Bridge connection failed") {
        setTestStatus("error");
        setTestMessage("Cannot connect to bridge");
      } else {
        setTestStatus("success");
        setTestMessage("Bridge is reachable");
      }
    } catch (err) {
      setTestStatus("error");
      setTestMessage(err instanceof Error ? err.message : "Test failed");
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="name">Bridge Name</Label>
        <Input
          id="name"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          placeholder="Local Bridge"
          required
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="url">WebSocket URL</Label>
        <Input
          id="url"
          value={formData.url}
          onChange={(e) => setFormData({ ...formData, url: e.target.value })}
          placeholder="wss://bridge.example.com/ws/tcp"
          required
        />
        <p className="text-xs text-muted-foreground">
          The WebSocket endpoint for the SSH bridge relay service
        </p>
      </div>

      {/* Test Connection Button */}
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
          placeholder="Internal bridge for local network servers"
          rows={2}
        />
      </div>

      <div className="flex items-center justify-between">
        <div>
          <Label htmlFor="enabled">Enabled</Label>
          <p className="text-xs text-muted-foreground">Allow servers to use this bridge</p>
        </div>
        <Switch
          id="enabled"
          checked={formData.enabled}
          onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
        />
      </div>

      <div className="flex items-center justify-between">
        <div>
          <Label htmlFor="isDefault">Default Bridge</Label>
          <p className="text-xs text-muted-foreground">Use for servers without a specific bridge assigned</p>
        </div>
        <Switch
          id="isDefault"
          checked={formData.isDefault}
          onCheckedChange={(checked) => setFormData({ ...formData, isDefault: checked })}
        />
      </div>

      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={isLoading}>
          {isLoading ? "Saving..." : initialData ? "Update Bridge" : "Add Bridge"}
        </Button>
      </DialogFooter>
    </form>
  );
}

export default function AdminBridges() {
  const { toast } = useToast();
  const [search, setSearch] = useState("");
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingBridge, setEditingBridge] = useState<Bridge | null>(null);

  const { data: bridges, isLoading, refetch } = useQuery<Bridge[]>({
    queryKey: ["/api/admin/bridges"],
    queryFn: api.admin.bridges.list,
  });

  const isFetching = useIsFetching({ queryKey: ["/api/admin/bridges"] }) > 0;
  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 30,
    refresh: refetch,
    isBlocked: isFetching,
  });

  const createMutation = useMutation({
    mutationFn: (data: BridgeFormData) => api.admin.bridges.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/bridges"] });
      setIsDialogOpen(false);
      toast({ title: "Bridge created successfully" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to create bridge", description: error.message, variant: "destructive" });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: BridgeFormData }) =>
      api.admin.bridges.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/bridges"] });
      setEditingBridge(null);
      setIsDialogOpen(false);
      toast({ title: "Bridge updated successfully" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to update bridge", description: error.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.admin.bridges.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/bridges"] });
      toast({ title: "Bridge deleted successfully" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to delete bridge", description: error.message, variant: "destructive" });
    },
  });

  const setDefaultMutation = useMutation({
    mutationFn: (id: string) => api.admin.bridges.update(id, { isDefault: true }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/bridges"] });
      toast({ title: "Default bridge updated" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to set default bridge", description: error.message, variant: "destructive" });
    },
  });

  const handleSubmit = (data: BridgeFormData) => {
    if (editingBridge) {
      updateMutation.mutate({ id: editingBridge.id, data });
    } else {
      createMutation.mutate(data);
    }
  };

  const handleEdit = (bridge: Bridge) => {
    setEditingBridge(bridge);
    setIsDialogOpen(true);
  };

  const handleCloseDialog = () => {
    setIsDialogOpen(false);
    setEditingBridge(null);
  };

  const filteredBridges = bridges?.filter(
    (bridge) =>
      bridge.name.toLowerCase().includes(search.toLowerCase()) ||
      bridge.url.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-4 sm:p-6 space-y-4 sm:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-xl sm:text-2xl font-semibold tracking-tight flex items-center gap-2">
            <Network className="h-5 w-5 sm:h-6 sm:w-6" />
            SSH Bridges
          </h1>
          <p className="text-sm text-muted-foreground">
            Manage WebSocket relay bridges for SSH connections
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
              <Button onClick={() => setEditingBridge(null)} className="shrink-0">
                <Plus className="h-4 w-4 sm:mr-2" />
                <span className="hidden sm:inline">Add Bridge</span>
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-md">
              <DialogHeader>
                <DialogTitle>{editingBridge ? "Edit Bridge" : "Add New Bridge"}</DialogTitle>
                <DialogDescription>
                  {editingBridge
                    ? "Update the bridge configuration"
                    : "Configure a new SSH relay bridge"}
                </DialogDescription>
              </DialogHeader>
              <BridgeForm
                initialData={
                  editingBridge
                    ? {
                        name: editingBridge.name,
                        url: editingBridge.url,
                        description: editingBridge.description || "",
                        enabled: editingBridge.enabled,
                        isDefault: editingBridge.isDefault,
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
                placeholder="Search bridges..."
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
          ) : filteredBridges && filteredBridges.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Bridge</TableHead>
                  <TableHead className="hidden md:table-cell">URL</TableHead>
                  <TableHead className="hidden sm:table-cell">Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredBridges.map((bridge) => (
                  <TableRow key={bridge.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div>
                          <div className="flex items-center gap-2">
                            <p className="font-medium">{bridge.name}</p>
                            {bridge.isDefault && (
                              <Badge variant="secondary" className="gap-1 text-xs">
                                <Star className="h-3 w-3" />
                                Default
                              </Badge>
                            )}
                          </div>
                          {bridge.description && (
                            <p className="text-xs text-muted-foreground line-clamp-1">
                              {bridge.description}
                            </p>
                          )}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      <code className="text-xs bg-muted px-2 py-1 rounded font-mono">
                        {bridge.url}
                      </code>
                    </TableCell>
                    <TableCell className="hidden sm:table-cell">
                      <Badge variant={bridge.enabled ? "default" : "secondary"}>
                        {bridge.enabled ? "Enabled" : "Disabled"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        {!bridge.isDefault && bridge.enabled && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => setDefaultMutation.mutate(bridge.id)}
                            disabled={setDefaultMutation.isPending}
                            title="Set as default"
                          >
                            <Star className="h-4 w-4" />
                          </Button>
                        )}
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => handleEdit(bridge)}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => deleteMutation.mutate(bridge.id)}
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
              <Network className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="font-medium">No bridges found</h3>
              <p className="text-sm text-muted-foreground mt-1">
                {search
                  ? "Try a different search term"
                  : "Add a bridge to connect to SSH servers through a relay"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <h2 className="text-lg font-medium">About SSH Bridges</h2>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>
            SSH bridges are WebSocket relay services that allow your browser to connect to SSH servers
            that may not be directly accessible from the internet.
          </p>
          <p>
            Use cases include:
          </p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li>Connecting to servers on private networks through a local bridge</li>
            <li>Load balancing SSH connections across multiple bridges</li>
            <li>Regional bridges for lower latency connections</li>
          </ul>
          <p>
            If no bridge is assigned to a server, the default bridge (or the BRIDGE_URL environment
            variable) will be used.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
