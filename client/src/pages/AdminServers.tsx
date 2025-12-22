import { useState } from "react";
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
import { Plus, Pencil, Trash2, Server, Search } from "lucide-react";
import type { Server as ServerType } from "@shared/schema";
import { api } from "@/lib/api";
import { UpgradeBanner } from "@/components/UpgradeBanner";

interface ServerFormData {
  name: string;
  host: string;
  port: number;
  environment: string;
  tags: string;
  sshUsers: string;
  enabled: boolean;
  healthCheckUrl: string;
}

const defaultFormData: ServerFormData = {
  name: "",
  host: "",
  port: 22,
  environment: "production",
  tags: "",
  sshUsers: "root",
  enabled: true,
  healthCheckUrl: "",
};

function ServerForm({
  initialData,
  onSubmit,
  onCancel,
  isLoading,
}: {
  initialData?: ServerFormData;
  onSubmit: (data: ServerFormData) => void;
  onCancel: () => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState<ServerFormData>(initialData || defaultFormData);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
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

      <div className="grid grid-cols-2 gap-4">
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

      <div className="space-y-2">
        <Label htmlFor="healthCheckUrl">Health Check URL (optional)</Label>
        <Input
          id="healthCheckUrl"
          value={formData.healthCheckUrl}
          onChange={(e) => setFormData({ ...formData, healthCheckUrl: e.target.value })}
          placeholder="http://192.168.1.100:8080/health"
          data-testid="input-server-health-check"
        />
        <p className="text-xs text-muted-foreground">
          API endpoint to check if server is online. If not set, status will show as unknown.
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

  const { data: servers, isLoading, refetch } = useQuery<ServerType[]>({
    queryKey: ["/api/admin/servers"],
  });

  const { data: serverLimit, refetch: refetchServerLimit } = useQuery({
    queryKey: ["/api/admin/license/check/server"],
    queryFn: () => api.admin.license.checkLimit("server"),
  });
  const isFetching = useIsFetching({ queryKey: ["/api/admin/servers"] }) > 0;
  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 15,
    refresh: () => Promise.all([refetch(), refetchServerLimit()]),
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
        healthCheckUrl: data.healthCheckUrl || null,
      };
      return apiRequest("POST", "/api/admin/servers", serverData);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/servers"] });
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
        healthCheckUrl: data.healthCheckUrl || null,
      };
      return apiRequest("PATCH", `/api/admin/servers/${id}`, serverData);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/servers"] });
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
      queryClient.invalidateQueries({ queryKey: ["/api/admin/license/check/server"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/servers"] });
      toast({ title: "Server deleted successfully" });
    },
    onError: (error) => {
      toast({ title: "Failed to delete server", description: error.message, variant: "destructive" });
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

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2" data-testid="admin-servers-title">
            <Server className="h-6 w-6" />
            Manage Servers
          </h1>
          <p className="text-muted-foreground">
            Add, edit, and remove SSH servers
          </p>
        </div>

        <Button
          variant="outline"
          onClick={() => void refreshNow()}
          disabled={isFetching}
          data-testid="refresh-servers"
          title="Refresh now"
        >
          Refresh{secondsRemaining !== null ? ` (auto in ${secondsRemaining}s)` : ""}
        </Button>

        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button
              onClick={() => setEditingServer(null)}
              disabled={serverLimit ? !serverLimit.allowed : false}
              title={
                serverLimit && !serverLimit.allowed
                  ? `Server limit reached (${serverLimit.current}/${serverLimit.limit}). Upgrade your plan to add more.`
                  : undefined
              }
              data-testid="add-server-button"
            >
              <Plus className="h-4 w-4 mr-2" />
              Add Server
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
                      healthCheckUrl: editingServer.healthCheckUrl || "",
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

      {serverLimit && !serverLimit.allowed && (
        <UpgradeBanner
          message={`Server limit reached (${serverLimit.current}/${serverLimit.limit}) on the ${serverLimit.tierName} plan. Upgrade to add more servers.`}
          current={serverLimit.current}
          limit={serverLimit.limit}
          tierName={serverLimit.tierName}
        />
      )}

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
                  <TableHead>Environment</TableHead>
                  <TableHead>SSH Users</TableHead>
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
                    <TableCell>
                      <Badge variant="secondary" className="text-xs">
                        {server.environment}
                      </Badge>
                    </TableCell>
                    <TableCell>
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
                    <TableCell>
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
