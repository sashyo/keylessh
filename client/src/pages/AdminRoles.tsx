import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
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
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
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
import { api } from "@/lib/api";
import { KeyRound, Pencil, Plus, Trash2, Search } from "lucide-react";
import type { AdminRole } from "@shared/schema";

export default function AdminRoles() {
  const { toast } = useToast();
  const [search, setSearch] = useState("");
  const [editingRole, setEditingRole] = useState<AdminRole | null>(null);
  const [creatingRole, setCreatingRole] = useState(false);
  const [deletingRole, setDeletingRole] = useState<AdminRole | null>(null);
  const [formData, setFormData] = useState<{ name: string; description: string }>({
    name: "",
    description: "",
  });

  const { data: rolesData, isLoading: rolesLoading } = useQuery({
    queryKey: ["/api/admin/roles"],
    queryFn: api.admin.roles.list,
  });

  const roles = rolesData?.roles || [];

  const createMutation = useMutation({
    mutationFn: (data: { name: string; description?: string }) => api.admin.roles.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/roles"] });
      setCreatingRole(false);
      setFormData({ name: "", description: "" });
      toast({ title: "Role created successfully" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to create role", description: error.message, variant: "destructive" });
    },
  });

  const updateMutation = useMutation({
    mutationFn: (data: { name: string; description?: string }) => api.admin.roles.update(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/roles"] });
      setEditingRole(null);
      toast({ title: "Role updated successfully" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to update role", description: error.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (roleName: string) => api.admin.roles.delete(roleName),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/roles"] });
      setDeletingRole(null);
      setEditingRole(null);
      toast({ title: "Role deleted successfully" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to delete role", description: error.message, variant: "destructive" });
    },
  });

  const handleEdit = (role: AdminRole) => {
    setEditingRole(role);
    setFormData({
      name: role.name,
      description: role.description || "",
    });
  };

  const handleCreate = () => {
    setFormData({ name: "", description: "" });
    setCreatingRole(true);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (editingRole) {
      updateMutation.mutate({
        name: formData.name,
        description: formData.description || undefined,
      });
    }
  };

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createMutation.mutate({
      name: formData.name,
      description: formData.description || undefined,
    });
  };

  const handleDeleteConfirm = () => {
    if (deletingRole) {
      deleteMutation.mutate(deletingRole.name);
    }
  };

  const filteredRoles = roles.filter(
    (role) =>
      role.name.toLowerCase().includes(search.toLowerCase()) ||
      (role.description?.toLowerCase().includes(search.toLowerCase()) ?? false)
  );

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2" data-testid="admin-roles-title">
            <KeyRound className="h-6 w-6" />
            Manage Roles
          </h1>
          <p className="text-muted-foreground">
            Create and manage user roles for access control
          </p>
        </div>
        <Button onClick={handleCreate} data-testid="add-role-button">
          <Plus className="h-4 w-4 mr-2" />
          Add Role
        </Button>
      </div>

      <Card>
        <div className="p-4 border-b border-border">
          <div className="relative max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search roles..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
              data-testid="search-roles"
            />
          </div>
        </div>
        <CardContent className="p-0">
          {rolesLoading ? (
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
          ) : filteredRoles.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Role Name</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredRoles.map((role) => (
                  <TableRow key={role.id} data-testid={`role-row-${role.id}`}>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10">
                          <KeyRound className="h-4 w-4 text-primary" />
                        </div>
                        <p className="font-medium">{role.name}</p>
                      </div>
                    </TableCell>
                    <TableCell>
                      <p className="text-sm text-muted-foreground">
                        {role.description || "No description"}
                      </p>
                    </TableCell>
                    <TableCell>
                      <Badge variant={role.clientRole ? "secondary" : "default"}>
                        {role.clientRole ? "Client Role" : "Realm Role"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => handleEdit(role)}
                          data-testid={`edit-role-${role.id}`}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => setDeletingRole(role)}
                          data-testid={`delete-role-${role.id}`}
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
              <KeyRound className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="font-medium">No roles found</h3>
              <p className="text-sm text-muted-foreground mt-1">
                {search ? "Try a different search term" : "Create a role to get started"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Edit Role Dialog */}
      <Dialog open={!!editingRole} onOpenChange={(open) => !open && setEditingRole(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Role</DialogTitle>
            <DialogDescription>
              Update the role description
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label>Role Name</Label>
              <Input
                value={formData.name}
                disabled
                className="bg-muted"
              />
              <p className="text-xs text-muted-foreground">Role names cannot be changed</p>
            </div>

            <div className="space-y-2">
              <Label>Description</Label>
              <Textarea
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                placeholder="Describe the role's purpose..."
                rows={3}
              />
            </div>

            <DialogFooter className="flex justify-between sm:justify-between">
              <Button
                type="button"
                variant="destructive"
                onClick={() => editingRole && setDeletingRole(editingRole)}
                data-testid="delete-role-button"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Delete
              </Button>
              <div className="flex gap-2">
                <Button type="button" variant="outline" onClick={() => setEditingRole(null)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={updateMutation.isPending} data-testid="submit-role-form">
                  {updateMutation.isPending ? "Saving..." : "Save Changes"}
                </Button>
              </div>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Create Role Dialog */}
      <Dialog open={creatingRole} onOpenChange={(open) => !open && setCreatingRole(false)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Add New Role</DialogTitle>
            <DialogDescription>
              Create a new role for access control
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleCreateSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="roleName">Role Name</Label>
              <Input
                id="roleName"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="e.g., developer"
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="roleDescription">Description</Label>
              <Textarea
                id="roleDescription"
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                placeholder="Describe the role's purpose..."
                rows={3}
              />
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setCreatingRole(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? "Creating..." : "Create Role"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deletingRole} onOpenChange={(open) => !open && setDeletingRole(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Role</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete the role "{deletingRole?.name}"? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteConfirm}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
