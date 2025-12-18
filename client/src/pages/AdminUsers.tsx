import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
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
import { Users, Pencil, Search, Shield, User as UserIcon } from "lucide-react";
import type { User, Server } from "@shared/schema";

export default function AdminUsers() {
  const { toast } = useToast();
  const [search, setSearch] = useState("");
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [formData, setFormData] = useState<{ role: string; allowedServers: string[] }>({
    role: "user",
    allowedServers: [],
  });

  const { data: users, isLoading: usersLoading } = useQuery<User[]>({
    queryKey: ["/api/admin/users"],
  });

  const { data: servers } = useQuery<Server[]>({
    queryKey: ["/api/admin/servers"],
  });

  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: { role: string; allowedServers: string[] } }) => {
      return apiRequest("PATCH", `/api/admin/users/${id}`, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      setEditingUser(null);
      toast({ title: "User updated successfully" });
    },
    onError: (error) => {
      toast({ title: "Failed to update user", description: error.message, variant: "destructive" });
    },
  });

  const handleEdit = (user: User) => {
    setEditingUser(user);
    setFormData({
      role: user.role,
      allowedServers: user.allowedServers || [],
    });
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (editingUser) {
      updateMutation.mutate({ id: editingUser.id, data: formData });
    }
  };

  const handleServerToggle = (serverId: string) => {
    setFormData((prev) => ({
      ...prev,
      allowedServers: prev.allowedServers.includes(serverId)
        ? prev.allowedServers.filter((id) => id !== serverId)
        : [...prev.allowedServers, serverId],
    }));
  };

  const filteredUsers = users?.filter(
    (user) =>
      user.username.toLowerCase().includes(search.toLowerCase()) ||
      user.email.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-6 space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2" data-testid="admin-users-title">
          <Users className="h-6 w-6" />
          Manage Users
        </h1>
        <p className="text-muted-foreground">
          Manage user roles and server access permissions
        </p>
      </div>

      <Card>
        <div className="p-4 border-b border-border">
          <div className="relative max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search users..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
              data-testid="search-users"
            />
          </div>
        </div>
        <CardContent className="p-0">
          {usersLoading ? (
            <div className="p-4 space-y-3">
              {[1, 2, 3].map((i) => (
                <div key={i} className="flex items-center gap-4">
                  <Skeleton className="h-10 w-10 rounded-full" />
                  <div className="flex-1 space-y-2">
                    <Skeleton className="h-4 w-32" />
                    <Skeleton className="h-3 w-48" />
                  </div>
                  <Skeleton className="h-6 w-16" />
                </div>
              ))}
            </div>
          ) : filteredUsers && filteredUsers.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Server Access</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredUsers.map((user) => (
                  <TableRow key={user.id} data-testid={`user-row-${user.id}`}>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10">
                          {user.role === "admin" ? (
                            <Shield className="h-4 w-4 text-primary" />
                          ) : (
                            <UserIcon className="h-4 w-4 text-primary" />
                          )}
                        </div>
                        <div>
                          <p className="font-medium">{user.username}</p>
                          <p className="text-xs text-muted-foreground">{user.email}</p>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={user.role === "admin" ? "default" : "secondary"}>
                        {user.role === "admin" ? "Administrator" : "User"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {user.allowedServers?.length ? (
                          <>
                            {user.allowedServers.slice(0, 2).map((serverId) => {
                              const server = servers?.find((s) => s.id === serverId);
                              return (
                                <Badge key={serverId} variant="outline" className="text-xs">
                                  {server?.name || serverId}
                                </Badge>
                              );
                            })}
                            {user.allowedServers.length > 2 && (
                              <Badge variant="outline" className="text-xs">
                                +{user.allowedServers.length - 2}
                              </Badge>
                            )}
                          </>
                        ) : (
                          <span className="text-xs text-muted-foreground">No access</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => handleEdit(user)}
                        data-testid={`edit-user-${user.id}`}
                      >
                        <Pencil className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <Users className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="font-medium">No users found</h3>
              <p className="text-sm text-muted-foreground mt-1">
                {search ? "Try a different search term" : "No users have logged in yet"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={!!editingUser} onOpenChange={(open) => !open && setEditingUser(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Edit User</DialogTitle>
            <DialogDescription>
              Update {editingUser?.username}'s role and server access
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label>Role</Label>
              <Select value={formData.role} onValueChange={(value) => setFormData({ ...formData, role: value })}>
                <SelectTrigger data-testid="select-user-role">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="user">User</SelectItem>
                  <SelectItem value="admin">Administrator</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Server Access</Label>
              <div className="border rounded-md p-3 space-y-2 max-h-48 overflow-auto">
                {servers && servers.length > 0 ? (
                  servers.map((server) => (
                    <label
                      key={server.id}
                      className="flex items-center gap-3 p-2 rounded-md hover-elevate cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={formData.allowedServers.includes(server.id)}
                        onChange={() => handleServerToggle(server.id)}
                        className="rounded border-input"
                      />
                      <div className="flex-1">
                        <p className="text-sm font-medium">{server.name}</p>
                        <p className="text-xs text-muted-foreground font-mono">
                          {server.host}
                        </p>
                      </div>
                    </label>
                  ))
                ) : (
                  <p className="text-sm text-muted-foreground text-center py-4">
                    No servers available
                  </p>
                )}
              </div>
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setEditingUser(null)}>
                Cancel
              </Button>
              <Button type="submit" disabled={updateMutation.isPending} data-testid="submit-user-form">
                {updateMutation.isPending ? "Saving..." : "Save Changes"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
