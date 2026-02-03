import { useState } from "react";
import { useQuery, useMutation, useIsFetching } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription } from "@/components/ui/alert";
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
import { useAutoRefresh } from "@/hooks/useAutoRefresh";
import { Users, Pencil, Search, Shield, User as UserIcon, Plus, Trash2, X, Link, Unlink, Copy, Check, AlertCircle, Clock } from "lucide-react";
import type { AdminUser } from "@shared/schema";
import type { AccessApproval } from "@/lib/api";
import { UpgradeBanner } from "@/components/UpgradeBanner";
import { RefreshButton } from "@/components/RefreshButton";

interface EditFormData {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  assignedRoles: string[];
}

export default function AdminUsers() {
  const { toast } = useToast();
  const [search, setSearch] = useState("");
  const [editingUser, setEditingUser] = useState<AdminUser | null>(null);
  const [creatingUser, setCreatingUser] = useState(false);
  const [deletingUser, setDeletingUser] = useState<AdminUser | null>(null);
  const [copyStatus, setCopyStatus] = useState<string>("");
  const [formData, setFormData] = useState<EditFormData>({
    id: "",
    firstName: "",
    lastName: "",
    email: "",
    assignedRoles: [],
  });
  const [initialRoles, setInitialRoles] = useState<string[]>([]);
  const [removedPendingRoles, setRemovedPendingRoles] = useState<string[]>([]);
  const [createFormData, setCreateFormData] = useState({
    username: "",
    firstName: "",
    lastName: "",
    email: "",
  });

  const { data: users, isLoading: usersLoading, refetch: refetchUsers } = useQuery<AdminUser[]>({
    queryKey: ["/api/admin/users"],
    queryFn: api.admin.users.list,
  });

  const { data: userLimit, refetch: refetchUserLimit } = useQuery({
    queryKey: ["/api/admin/license/check/user"],
    queryFn: () => api.admin.license.checkLimit("user"),
  });

  const { data: licenseInfo, refetch: refetchLicense } = useQuery({
    queryKey: ["/api/admin/license"],
    queryFn: api.admin.license.get,
  });
  const isFetchingUsers = useIsFetching({ queryKey: ["/api/admin/users"] }) > 0;
  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 15,
    refresh: () => Promise.all([refetchUsers(), refetchUserLimit(), refetchLicense(), refetchAccessApprovals()]),
    isBlocked: isFetchingUsers,
  });

  const { data: rolesData } = useQuery({
    queryKey: ["/api/admin/roles/all"],
    queryFn: api.admin.roles.listAll,
  });

  const { data: accessApprovals, refetch: refetchAccessApprovals } = useQuery<AccessApproval[]>({
    queryKey: ["/api/admin/access-approvals"],
    queryFn: api.admin.accessApprovals.list,
  });

  const allRoles = rolesData?.roles || [];

  // Helper to get pending roles for a specific user
  const getPendingRolesForUser = (username: string | undefined): string[] => {
    if (!username || !accessApprovals) return [];
    return accessApprovals
      .filter((approval) => approval.username === username && !approval.commitReady)
      .map((approval) => approval.role);
  };

  const updateProfileMutation = useMutation({
    mutationFn: (data: { id: string; firstName: string; lastName: string; email: string }) =>
      api.admin.users.updateProfile(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/users"] });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to update user profile", description: error.message, variant: "destructive" });
    },
  });

  const updateRolesMutation = useMutation({
    mutationFn: (data: { id: string; rolesToAdd?: string[]; rolesToRemove?: string[] }) =>
      api.admin.users.updateRoles(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/access-approvals"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/users"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/access-approvals"] });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to update user roles", description: error.message, variant: "destructive" });
    },
  });

  const createMutation = useMutation({
    mutationFn: (data: { username: string; firstName: string; lastName: string; email: string }) =>
      api.admin.users.add(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/license/check/user"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/users"] });
      setCreatingUser(false);
      setCreateFormData({ username: "", firstName: "", lastName: "", email: "" });
      toast({ title: "User created successfully" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to create user", description: error.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (userId: string) => api.admin.users.delete(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/license/check/user"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/access-approvals"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/users"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/access-approvals"] });
      setDeletingUser(null);
      setEditingUser(null);
      toast({ title: "User deleted successfully" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to delete user", description: error.message, variant: "destructive" });
    },
  });

  const setEnabledMutation = useMutation({
    mutationFn: ({ userId, enabled }: { userId: string; enabled: boolean }) =>
      api.admin.users.setEnabled(userId, enabled),
    onSuccess: (_, { enabled }) => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/license"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/users"] });
      toast({ title: enabled ? "User enabled" : "User disabled" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to update user status", description: error.message, variant: "destructive" });
    },
  });

  const handleEdit = (user: AdminUser) => {
    const userRoles = Array.isArray(user.role) ? user.role : user.role ? [user.role] : [];
    setEditingUser(user);
    setInitialRoles(userRoles);
    setRemovedPendingRoles([]);
    setFormData({
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      assignedRoles: userRoles,
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingUser) return;

    const profileChanged =
      editingUser.firstName !== formData.firstName ||
      editingUser.lastName !== formData.lastName ||
      editingUser.email !== formData.email;

    const rolesToAdd = formData.assignedRoles.filter((role) => !initialRoles.includes(role));
    const rolesToRemove = initialRoles.filter((role) => !formData.assignedRoles.includes(role));
    const rolesChanged = rolesToAdd.length > 0 || rolesToRemove.length > 0;

    try {
      if (profileChanged) {
        await updateProfileMutation.mutateAsync({
          id: formData.id,
          firstName: formData.firstName,
          lastName: formData.lastName,
          email: formData.email,
        });
      }

      if (rolesChanged) {
        await updateRolesMutation.mutateAsync({
          id: formData.id,
          rolesToAdd: rolesToAdd.length > 0 ? rolesToAdd : undefined,
          rolesToRemove: rolesToRemove.length > 0 ? rolesToRemove : undefined,
        });
      }

      setEditingUser(null);
      toast({ title: "User updated successfully" });
    } catch {
      // Errors are handled by individual mutations
    }
  };

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createMutation.mutate(createFormData);
  };

  const handleDeleteConfirm = () => {
    if (deletingUser) {
      deleteMutation.mutate(deletingUser.id);
    }
  };

  const assignRole = (roleName: string) => {
    setFormData((prev) => ({
      ...prev,
      assignedRoles: [...prev.assignedRoles, roleName],
    }));
  };

  const unassignRole = (roleName: string) => {
    setFormData((prev) => ({
      ...prev,
      assignedRoles: prev.assignedRoles.filter((r) => r !== roleName),
    }));
  };

  const handleCopyTideLink = async () => {
    if (!editingUser) return;
    try {
      const currentUrl = window.location.origin;
      const response = await api.admin.users.getTideLinkUrl(editingUser.id, currentUrl);
      await navigator.clipboard.writeText(response.linkUrl);
      setCopyStatus("Copied!");
      setTimeout(() => setCopyStatus(""), 2000);
    } catch {
      setCopyStatus("Failed to copy");
      setTimeout(() => setCopyStatus(""), 2000);
    }
  };

  // Get pending roles for the currently editing user
  const editingUserPendingRoles = editingUser ? getPendingRolesForUser(editingUser.username) : [];
  const effectivePendingRoles = editingUserPendingRoles.filter((r) => !removedPendingRoles.includes(r));

  // Newly added roles (not yet saved) should show as pending by default
  const newlyAddedRoles = formData.assignedRoles.filter((r) => !initialRoles.includes(r));
  // Committed (green) roles: in assignedRoles, in initialRoles, and not pending from API
  const committedRoles = formData.assignedRoles.filter(
    (r) => initialRoles.includes(r) && !effectivePendingRoles.includes(r)
  );
  // All pending roles to display: API pending + newly added
  const allPendingDisplay = [...effectivePendingRoles, ...newlyAddedRoles];

  const removePendingRole = (roleName: string) => {
    if (editingUserPendingRoles.includes(roleName)) {
      setRemovedPendingRoles((prev) => [...prev, roleName]);
    }
    if (formData.assignedRoles.includes(roleName)) {
      unassignRole(roleName);
    }
  };

  const availableRoles = allRoles
    .map((role) => role.name)
    .filter((roleName) => !formData.assignedRoles.includes(roleName) && !effectivePendingRoles.includes(roleName));

  const filteredUsers = users?.filter(
    (user) =>
      user.username?.toLowerCase().includes(search.toLowerCase()) ||
      user.email.toLowerCase().includes(search.toLowerCase()) ||
      user.firstName.toLowerCase().includes(search.toLowerCase()) ||
      user.lastName.toLowerCase().includes(search.toLowerCase())
  );

  const isUpdating = updateProfileMutation.isPending || updateRolesMutation.isPending;

  return (
    <div className="p-4 sm:p-6 space-y-4 sm:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-xl sm:text-2xl font-semibold tracking-tight flex items-center gap-2" data-testid="admin-users-title">
            <Users className="h-5 w-5 sm:h-6 sm:w-6" />
            Manage Users
          </h1>
          <p className="text-sm text-muted-foreground">
            Manage user accounts, roles, and permissions
          </p>
        </div>
        <div className="flex items-center gap-2">
          <RefreshButton
            onClick={() => void refreshNow()}
            isRefreshing={isFetchingUsers}
            secondsRemaining={secondsRemaining}
            data-testid="refresh-users"
            title="Refresh now"
          />
          <Button
            onClick={() => setCreatingUser(true)}
            disabled={userLimit ? !userLimit.allowed : false}
            title={
              userLimit && !userLimit.allowed
                ? `User limit reached (${userLimit.current}/${userLimit.limit}). Upgrade your plan to add more.`
                : "Add User"
            }
            data-testid="add-user-button"
            className="shrink-0"
          >
            <Plus className="h-4 w-4 sm:mr-2" />
            <span className="hidden sm:inline">Add User</span>
          </Button>
        </div>
      </div>

      {userLimit && !userLimit.allowed && (
        <UpgradeBanner
          message={`User limit reached (${userLimit.current}/${userLimit.limit}) on the ${userLimit.tierName} plan. Upgrade to add more users.`}
          current={userLimit.current}
          limit={userLimit.limit}
          tierName={userLimit.tierName}
        />
      )}

      {licenseInfo?.overLimit?.users.isOverLimit && (
        <Alert className="bg-red-50 border-red-200 dark:bg-red-950/20 dark:border-red-800">
          <AlertCircle className="h-4 w-4 text-red-600 dark:text-red-400" />
          <AlertDescription className="text-red-800 dark:text-red-200">
            <strong>User limit exceeded.</strong> You have {licenseInfo.overLimit.users.enabled} enabled users but your plan allows {licenseInfo.overLimit.users.limit}.
            Please disable {licenseInfo.overLimit.users.overBy} user(s) or upgrade your plan.
          </AlertDescription>
        </Alert>
      )}

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
                  <TableHead className="hidden sm:table-cell">Roles</TableHead>
                  <TableHead className="hidden md:table-cell">Account Status</TableHead>
                  <TableHead className="hidden lg:table-cell">Access</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredUsers.map((user) => {
                  const userRoles = Array.isArray(user.role) ? user.role : user.role ? [user.role] : [];
                  const isAdmin = userRoles.some((r) => r.toLowerCase().includes("admin"));
                  return (
                    <TableRow key={user.id} data-testid={`user-row-${user.id}`}>
                      <TableCell>
                        <div className="flex items-center gap-3">
                          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10">
                            {isAdmin ? (
                              <Shield className="h-4 w-4 text-primary" />
                            ) : (
                              <UserIcon className="h-4 w-4 text-primary" />
                            )}
                          </div>
                          <div>
                            <p className="font-medium">{user.firstName} {user.lastName}</p>
                            <p className="text-xs text-muted-foreground">{user.email}</p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="hidden sm:table-cell">
                        {(() => {
                          const pendingRoles = getPendingRolesForUser(user.username);
                          // Roles only in pending (not yet in user.role)
                          const pendingNewRoles = pendingRoles.filter((r) => !userRoles.includes(r));
                          // All roles to display: active + pending-only (deduplicated)
                          const allDisplayRoles = [...userRoles, ...pendingNewRoles];
                          const totalRoles = allDisplayRoles.length;
                          const displayLimit = 2;
                          const displayRoles = allDisplayRoles.slice(0, displayLimit);
                          const remainingCount = totalRoles - displayLimit;

                          return (
                            <div className="flex flex-wrap gap-1">
                              {totalRoles > 0 ? (
                                <>
                                  {displayRoles.map((role) => {
                                    // A role is pending if it has an active change request
                                    const isPending = pendingRoles.includes(role);
                                    return isPending ? (
                                      <Badge
                                        key={role}
                                        variant="outline"
                                        className="text-xs text-muted-foreground bg-muted/50"
                                      >
                                        <Clock className="h-3 w-3 mr-1" />
                                        {role}
                                      </Badge>
                                    ) : (
                                      <Badge
                                        key={role}
                                        variant="outline"
                                        className="text-xs bg-green-50 text-green-700 border-green-200 dark:bg-green-950/30 dark:text-green-400 dark:border-green-800"
                                      >
                                        {role}
                                      </Badge>
                                    );
                                  })}
                                  {remainingCount > 0 && (
                                    <Badge variant="outline" className="text-xs">
                                      +{remainingCount}
                                    </Badge>
                                  )}
                                </>
                              ) : (
                                <span className="text-xs text-muted-foreground">No roles</span>
                              )}
                            </div>
                          );
                        })()}
                      </TableCell>
                      <TableCell className="hidden md:table-cell">
                        {user.linked ? (
                          <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200 dark:bg-green-950/30 dark:text-green-400 dark:border-green-800">
                            <Link className="h-3 w-3 mr-1" />
                            Linked
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-muted-foreground">
                            <Unlink className="h-3 w-3 mr-1" />
                            Not linked
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="hidden lg:table-cell">
                        {isAdmin ? (
                          <span className="text-xs text-muted-foreground">Admin (cannot disable)</span>
                        ) : (
                          <div className="flex items-center gap-2">
                            <Switch
                              checked={user.enabled}
                              onCheckedChange={(enabled) =>
                                setEnabledMutation.mutate({ userId: user.id, enabled })
                              }
                              disabled={setEnabledMutation.isPending}
                            />
                            <span className={`text-xs ${user.enabled ? "text-green-600 dark:text-green-400" : "text-muted-foreground"}`}>
                              {user.enabled ? "Enabled" : "Disabled"}
                            </span>
                          </div>
                        )}
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
                  );
                })}
              </TableBody>
            </Table>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <Users className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="font-medium">No users found</h3>
              <p className="text-sm text-muted-foreground mt-1">
                {search ? "Try a different search term" : "No users have been created yet"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Edit User Dialog */}
      <Dialog open={!!editingUser} onOpenChange={(open) => !open && setEditingUser(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Edit User</DialogTitle>
            <DialogDescription>
              Update user details and manage role assignments
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* User Details */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>First Name</Label>
                <Input
                  value={formData.firstName}
                  onChange={(e) => setFormData({ ...formData, firstName: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label>Last Name</Label>
                <Input
                  value={formData.lastName}
                  onChange={(e) => setFormData({ ...formData, lastName: e.target.value })}
                  required
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label>Email</Label>
              <Input
                type="email"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                required
              />
            </div>

            {/* Dual-Panel Role Manager */}
            <div className="space-y-2">
              <Label>Manage Roles</Label>
              {!editingUser?.linked && (
                <p className="text-sm text-amber-600 dark:text-amber-400">
                  User must be linked to their Tide account before roles can be assigned.
                </p>
              )}
              <div
                className={`grid grid-cols-1 sm:grid-cols-2 gap-4 ${!editingUser?.linked ? "opacity-50 pointer-events-none" : ""}`}
              >
                {/* Assigned Roles */}
                <div className="border rounded-md">
                  <div className="p-2 bg-muted/50 border-b">
                    <h4 className="text-sm font-medium">Assigned Roles</h4>
                  </div>
                  <ScrollArea className="h-32">
                    <div className="p-2 space-y-1">
                      {/* Committed/active roles (green) */}
                      {committedRoles.map((roleName) => (
                        <div
                          key={roleName}
                          className="flex items-center justify-between p-2 rounded-md text-sm bg-green-50 dark:bg-green-950/30"
                        >
                          <span className="text-green-700 dark:text-green-400">{roleName}</span>
                          <Button
                            type="button"
                            size="icon"
                            variant="ghost"
                            className="h-6 w-6"
                            onClick={() => unassignRole(roleName)}
                            disabled={!editingUser?.linked}
                          >
                            <X className="h-3 w-3" />
                          </Button>
                        </div>
                      ))}
                      {/* Pending roles (API pending + newly added) */}
                      {allPendingDisplay.map((roleName) => (
                        <div
                          key={`pending-${roleName}`}
                          className="flex items-center justify-between p-2 rounded-md bg-muted/50 text-sm"
                        >
                          <div className="flex items-center gap-2">
                            <Clock className="h-3 w-3 text-muted-foreground" />
                            <span className="text-muted-foreground">{roleName}</span>
                          </div>
                          <Button
                            type="button"
                            size="icon"
                            variant="ghost"
                            className="h-6 w-6"
                            onClick={() => removePendingRole(roleName)}
                            disabled={!editingUser?.linked}
                          >
                            <X className="h-3 w-3" />
                          </Button>
                        </div>
                      ))}
                      {committedRoles.length === 0 && allPendingDisplay.length === 0 && (
                        <p className="text-sm text-muted-foreground text-center py-4">
                          No roles assigned
                        </p>
                      )}
                    </div>
                  </ScrollArea>
                </div>

                {/* Available Roles */}
                <div className="border rounded-md">
                  <div className="p-2 bg-muted/50 border-b">
                    <h4 className="text-sm font-medium">Available Roles</h4>
                  </div>
                  <ScrollArea className="h-32">
                    <div className="p-2 space-y-1">
                      {availableRoles.length > 0 ? (
                        availableRoles.map((roleName) => (
                          <div
                            key={roleName}
                            className="flex items-center justify-between p-2 rounded-md hover:bg-secondary/50 text-sm cursor-pointer"
                            onClick={() => editingUser?.linked && assignRole(roleName)}
                          >
                            <span>{roleName}</span>
                            <Button
                              type="button"
                              size="icon"
                              variant="ghost"
                              className="h-6 w-6"
                              onClick={(e) => {
                                e.stopPropagation();
                                assignRole(roleName);
                              }}
                              disabled={!editingUser?.linked}
                            >
                              <Plus className="h-3 w-3" />
                            </Button>
                          </div>
                        ))
                      ) : (
                        <p className="text-sm text-muted-foreground text-center py-4">
                          {committedRoles.length + allPendingDisplay.length > 0
                            ? "All roles assigned"
                            : "No roles available"}
                        </p>
                      )}
                    </div>
                  </ScrollArea>
                </div>
              </div>
            </div>

            {/* Link Tide Account */}
            {!editingUser?.linked && (
              <div className="space-y-2">
                <Label>Link Tide Account</Label>
                <div className="flex items-center gap-2">
                  <Button type="button" variant="outline" onClick={handleCopyTideLink}>
                    <Copy className="h-4 w-4 mr-2" />
                    Copy Tide Link
                  </Button>
                  {copyStatus && (
                    <span className="text-sm text-muted-foreground flex items-center gap-1">
                      <Check className="h-4 w-4 text-green-600 dark:text-green-400" />
                      {copyStatus}
                    </span>
                  )}
                </div>
              </div>
            )}

            <DialogFooter className="flex justify-between sm:justify-between">
              <Button
                type="button"
                variant="destructive"
                onClick={() => editingUser && setDeletingUser(editingUser)}
                data-testid="delete-user-button"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Delete
              </Button>
              <div className="flex gap-2">
                <Button type="button" variant="outline" onClick={() => setEditingUser(null)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={isUpdating} data-testid="submit-user-form">
                  {isUpdating ? "Saving..." : "Save Changes"}
                </Button>
              </div>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Create User Dialog */}
      <Dialog open={creatingUser} onOpenChange={(open) => !open && setCreatingUser(false)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Add New User</DialogTitle>
            <DialogDescription>
              Create a new user account in the system
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleCreateSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                value={createFormData.username}
                onChange={(e) => setCreateFormData({ ...createFormData, username: e.target.value })}
                placeholder="johndoe"
                required
              />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="firstName">First Name</Label>
                <Input
                  id="firstName"
                  value={createFormData.firstName}
                  onChange={(e) => setCreateFormData({ ...createFormData, firstName: e.target.value })}
                  placeholder="John"
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="lastName">Last Name</Label>
                <Input
                  id="lastName"
                  value={createFormData.lastName}
                  onChange={(e) => setCreateFormData({ ...createFormData, lastName: e.target.value })}
                  placeholder="Doe"
                  required
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                value={createFormData.email}
                onChange={(e) => setCreateFormData({ ...createFormData, email: e.target.value })}
                placeholder="john@example.com"
                required
              />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setCreatingUser(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? "Creating..." : "Create User"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deletingUser} onOpenChange={(open) => !open && setDeletingUser(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete User</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete {deletingUser?.firstName} {deletingUser?.lastName}? This action cannot be undone.
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
