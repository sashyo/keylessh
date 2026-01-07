import { useMemo, useState } from "react";
import { useQuery, useMutation, useIsFetching } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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
import { api, type PolicyTemplate, type TemplateParameter } from "@/lib/api";
import { useAutoRefresh } from "@/hooks/useAutoRefresh";
import { RefreshButton } from "@/components/RefreshButton";
import { useAuth, useAuthConfig } from "@/contexts/AuthContext";
import { KeyRound, Pencil, Plus, Trash2, Search, Shield, FileCode } from "lucide-react";
import type { AdminRole } from "@shared/schema";
import { ADMIN_ROLE_SET } from "@shared/config/roles";
import { createSshPolicyRequest, createSshPolicyRequestWithCode, bytesToBase64, SSH_MODEL_IDS, SSH_FORSETI_CONTRACT } from "@/lib/sshPolicy";

// SSH signing contract types
const SSH_CONTRACT_TYPES = {
  BASIC: "BasicCustom<SSH>:BasicCustom<1>",
  DYNAMIC: "DynamicCustom<SSH>:DynamicCustom<1>",
  DYNAMIC_APPROVED: "DynamicApprovedCustom<SSH>:DynamicApprovedCustom<1>",
} as const;

type SshContractType = typeof SSH_CONTRACT_TYPES[keyof typeof SSH_CONTRACT_TYPES];

interface PolicyConfig {
  enabled: boolean;
  contractType: SshContractType;
  approvalType: "implicit" | "explicit";
  executionType: "public" | "private";
  threshold: number;
}

const defaultPolicyConfig: PolicyConfig = {
  enabled: true,
  contractType: SSH_CONTRACT_TYPES.BASIC,
  approvalType: "implicit",
  executionType: "private",
  threshold: 1,
};

export default function AdminRoles() {
  const { toast } = useToast();
  const { initializeTideRequest } = useAuth();
  const authConfig = useAuthConfig();
  const [search, setSearch] = useState("");
  const [editingRole, setEditingRole] = useState<AdminRole | null>(null);
  const [creatingRole, setCreatingRole] = useState(false);
  const [deletingRole, setDeletingRole] = useState<AdminRole | null>(null);
  const [createAsSshRole, setCreateAsSshRole] = useState(true);
  const [isCreatingPolicy, setIsCreatingPolicy] = useState(false);
  const [formData, setFormData] = useState<{ name: string; description: string }>({
    name: "",
    description: "",
  });
  const [policyConfig, setPolicyConfig] = useState<PolicyConfig>(defaultPolicyConfig);
  const [selectedTemplateId, setSelectedTemplateId] = useState<string | null>(null);
  const [templateParams, setTemplateParams] = useState<Record<string, any>>({});

  const normalizeSshRoleName = (value: string) => {
    const trimmed = value.trim();
    if (!trimmed) return "";
    if (/^ssh[:\-]/i.test(trimmed)) return trimmed;
    return `ssh:${trimmed}`;
  };

  const { data: rolesData, isLoading: rolesLoading, refetch: refetchRoles } = useQuery({
    queryKey: ["/api/admin/roles"],
    queryFn: api.admin.roles.list,
  });
  const isFetchingRoles = useIsFetching({ queryKey: ["/api/admin/roles"] }) > 0;
  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 15,
    refresh: () => refetchRoles(),
    isBlocked: isFetchingRoles,
  });

  const roles = rolesData?.roles || [];

  // Query for policy templates
  const { data: templatesData } = useQuery({
    queryKey: ["/api/admin/policy-templates"],
    queryFn: api.admin.policyTemplates.list,
  });
  const templates = templatesData?.templates || [];

  // Query for admin users to calculate approval threshold
  const { data: usersData } = useQuery({
    queryKey: ["/api/admin/users"],
    queryFn: api.admin.users.list,
  });

  // Query for access approvals to identify pending admin role assignments
  const { data: accessApprovalsData } = useQuery({
    queryKey: ["/api/admin/access-approvals"],
    queryFn: api.admin.accessApprovals.list,
  });

  // Calculate required approval threshold: 70% of active admins (min 1)
  // Active admins = enabled + linked + isAdmin - those with pending (not yet committed) admin role
  const activeAdminCount = useMemo(() => {
    if (!usersData) return 0;

    // Get usernames of users with pending (not committed) admin role assignments
    const pendingAdminUsernames = new Set(
      (accessApprovalsData || [])
        .filter((approval) =>
          ADMIN_ROLE_SET.has(approval.role) &&
          !approval.commitReady // Not yet approved/committed
        )
        .map((approval) => approval.username)
    );

    // Filter to get active admins, excluding those with pending admin role
    return usersData.filter((u) =>
      u.enabled &&
      u.linked &&
      u.isAdmin &&
      !pendingAdminUsernames.has(u.username || "")
    ).length;
  }, [usersData, accessApprovalsData]);

  const calculatedThreshold = useMemo(() => {
    return Math.max(1, Math.floor(activeAdminCount * 0.7));
  }, [activeAdminCount]);

  // Helper to get selected template
  const selectedTemplate = selectedTemplateId
    ? templates.find((t) => t.id === selectedTemplateId)
    : null;

  // Replace placeholders in template code
  const replacePlaceholders = (code: string, params: Record<string, any>): string => {
    let result = code;
    for (const [key, value] of Object.entries(params)) {
      const placeholder = `{{${key}}}`;
      result = result.replace(new RegExp(placeholder.replace(/[{}]/g, '\\$&'), 'g'), String(value));
    }
    return result;
  };

  const createMutation = useMutation({
    mutationFn: (data: { name: string; description?: string; policy?: PolicyConfig }) =>
      api.admin.roles.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/roles"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/roles"] });
      setCreatingRole(false);
      setFormData({ name: "", description: "" });
      setPolicyConfig(defaultPolicyConfig);
      setSelectedTemplateId(null);
      setTemplateParams({});
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
      void queryClient.refetchQueries({ queryKey: ["/api/admin/roles"] });
      setEditingRole(null);
      toast({ title: "Role updated successfully" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to update role", description: error.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (roleName: string) => api.admin.roles.delete(roleName),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/roles"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/roles"] });
      // Also invalidate role approvals since an approval may have been created
      queryClient.invalidateQueries({ queryKey: ["/api/admin/role-approvals"] });
      setDeletingRole(null);
      setEditingRole(null);
      // Show appropriate message based on whether an approval was created
      if (data.approvalCreated) {
        toast({ title: "Approval request created", description: "Role has users assigned. An approval request has been created for review." });
      } else {
        toast({ title: "Role deleted successfully" });
      }
    },
    onError: (error: Error) => {
      toast({ title: "Failed to delete role", description: error.message, variant: "destructive" });
    },
  });

  // State for editing policy
  const [editingPolicyConfig, setEditingPolicyConfig] = useState<PolicyConfig | null>(null);
  const [loadingPolicy, setLoadingPolicy] = useState(false);
  const [isUpdatingPolicy, setIsUpdatingPolicy] = useState(false);
  const [editSelectedTemplateId, setEditSelectedTemplateId] = useState<string | null>(null);
  const [editTemplateParams, setEditTemplateParams] = useState<Record<string, any>>({});

  const handleEdit = async (role: AdminRole) => {
    setEditingRole(role);
    setFormData({
      name: role.name,
      description: role.description || "",
    });

    // If it's an SSH role, fetch the current policy
    if (/^ssh[:\-]/i.test(role.name)) {
      setLoadingPolicy(true);
      setEditingPolicyConfig(null);
      setEditSelectedTemplateId(null);
      setEditTemplateParams({});
      try {
        const { policy } = await api.admin.roles.policies.get(role.name);
        if (policy) {
          setEditingPolicyConfig({
            enabled: true,
            contractType: policy.contractType as SshContractType || SSH_CONTRACT_TYPES.BASIC,
            approvalType: policy.approvalType || "implicit",
            executionType: policy.executionType || "private",
            threshold: policy.threshold || 1,
          });
        } else {
          // No existing policy
          setEditingPolicyConfig({
            ...defaultPolicyConfig,
            enabled: false,
          });
        }
      } catch {
        // No policy found, allow creating one
        setEditingPolicyConfig({
          ...defaultPolicyConfig,
          enabled: false,
        });
      } finally {
        setLoadingPolicy(false);
      }
    } else {
      setEditingPolicyConfig(null);
    }
  };

  const handleCreate = () => {
    setFormData({ name: "", description: "" });
    setCreateAsSshRole(true);
    setPolicyConfig(defaultPolicyConfig);
    setSelectedTemplateId(null);
    setTemplateParams({});
    setCreatingRole(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingRole) return;

    // Update role description
    updateMutation.mutate({
      name: formData.name,
      description: formData.description || undefined,
    });

    // If policy config changed for SSH role, create new pending policy request
    if (editingPolicyConfig && editingPolicyConfig.enabled && /^ssh[:\-]/i.test(editingRole.name)) {
      setIsUpdatingPolicy(true);
      try {
        let policyRequest;
        let usedContractCode: string;
        const editSelectedTemplate = editSelectedTemplateId
          ? templates.find((t) => t.id === editSelectedTemplateId)
          : null;

        if (editSelectedTemplate) {
          // Generate contract code from template with placeholders replaced
          usedContractCode = replacePlaceholders(editSelectedTemplate.csCode, editTemplateParams);

          // Compile and create policy request with custom contract code
          const { request } = await createSshPolicyRequestWithCode({
            roleName: editingRole.name,
            threshold: calculatedThreshold,
            approvalType: editingPolicyConfig.approvalType,
            executionType: editingPolicyConfig.executionType,
            modelId: SSH_MODEL_IDS.BASIC,
            resource: authConfig.resource,
            vendorId: authConfig.vendorId,
            contractCode: usedContractCode,
          });
          policyRequest = request;
        } else {
          // Compile and create policy request with default contract
          usedContractCode = SSH_FORSETI_CONTRACT;
          policyRequest = await createSshPolicyRequest({
            roleName: editingRole.name,
            threshold: calculatedThreshold,
            approvalType: editingPolicyConfig.approvalType,
            executionType: editingPolicyConfig.executionType,
            modelId: SSH_MODEL_IDS.BASIC,
            resource: authConfig.resource,
            vendorId: authConfig.vendorId,
          });
        }

        // Initialize the request with user's Tide credentials
        const initializedRequest = await initializeTideRequest(policyRequest);

        // Submit to server for pending approval storage
        const response = await fetch("/api/admin/ssh-policies/pending", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${localStorage.getItem("access_token")}`,
          },
          body: JSON.stringify({
            policyRequest: bytesToBase64(initializedRequest.encode()),
            roleName: editingRole.name,
            contractCode: usedContractCode,
          }),
        });

        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.error || "Failed to create policy request");
        }

        toast({ title: "Policy update request created", description: "Pending admin approval" });
      } catch (error) {
        console.error("Failed to create policy update request:", error);
        toast({
          title: "Policy update failed",
          description: error instanceof Error ? error.message : "Unknown error",
          variant: "destructive",
        });
      } finally {
        setIsUpdatingPolicy(false);
      }
    }
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = createAsSshRole ? normalizeSshRoleName(formData.name) : formData.name.trim();
    if (!name) {
      toast({ title: "Role name is required", variant: "destructive" });
      return;
    }

    // First create the role
    createMutation.mutate({
      name,
      description: formData.description || undefined,
      policy: createAsSshRole && policyConfig.enabled ? policyConfig : undefined,
    });

    // If policy is enabled, create the PolicySignRequest with Forseti contract
    if (createAsSshRole && policyConfig.enabled) {
      setIsCreatingPolicy(true);
      try {
        let policyRequest;
        let usedContractCode: string;

        // Check if using a template or default
        if (selectedTemplate) {
          // Generate contract code from template with placeholders replaced
          usedContractCode = replacePlaceholders(selectedTemplate.csCode, templateParams);

          // Compile and create policy request with custom contract code
          const { request } = await createSshPolicyRequestWithCode({
            roleName: name,
            threshold: calculatedThreshold,
            approvalType: policyConfig.approvalType,
            executionType: policyConfig.executionType,
            modelId: SSH_MODEL_IDS.BASIC,
            resource: authConfig.resource,
            vendorId: authConfig.vendorId,
            contractCode: usedContractCode,
          });
          policyRequest = request;
        } else {
          // Compile and create policy request with default contract
          usedContractCode = SSH_FORSETI_CONTRACT;
          policyRequest = await createSshPolicyRequest({
            roleName: name,
            threshold: calculatedThreshold,
            approvalType: policyConfig.approvalType,
            executionType: policyConfig.executionType,
            modelId: SSH_MODEL_IDS.BASIC,
            resource: authConfig.resource,
            vendorId: authConfig.vendorId,
          });
        }

        // Initialize the request with user's Tide credentials
        const initializedRequest = await initializeTideRequest(policyRequest);

        // Submit to server for pending approval storage
        const response = await fetch("/api/admin/ssh-policies/pending", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${localStorage.getItem("access_token")}`,
          },
          body: JSON.stringify({
            policyRequest: bytesToBase64(initializedRequest.encode()),
            roleName: name,
            contractCode: usedContractCode,
          }),
        });

        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.error || "Failed to create policy request");
        }

        toast({ title: "Policy request created", description: "Pending admin approval" });
      } catch (error) {
        console.error("Failed to create policy request:", error);
        toast({
          title: "Policy creation failed",
          description: error instanceof Error ? error.message : "Unknown error",
          variant: "destructive",
        });
      } finally {
        setIsCreatingPolicy(false);
      }
    }
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

  const sshRoleCount = useMemo(
    () => roles.filter((r) => /^ssh[:\-]/i.test(r.name)).length,
    [roles]
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
          <p className="text-xs text-muted-foreground">
            SSH username roles use the format <span className="font-mono">ssh:&lt;username&gt;</span> (e.g.{" "}
            <span className="font-mono">ssh:root</span>) — {sshRoleCount} configured.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <RefreshButton
            onClick={() => void refreshNow()}
            isRefreshing={isFetchingRoles}
            secondsRemaining={secondsRemaining}
            data-testid="refresh-roles"
            title="Refresh now"
          />
          <Button onClick={handleCreate} data-testid="add-role-button">
            <Plus className="h-4 w-4 mr-2" />
            Add Role
          </Button>
        </div>
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
                        <div className="flex items-center gap-2">
                          <p className="font-medium">{role.name}</p>
                          {/^(ssh[:\-])/i.test(role.name) && (
                            <Badge variant="outline" className="text-xs label-info">
                              SSH
                            </Badge>
                          )}
                        </div>
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
        <DialogContent className="max-w-md max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit Role</DialogTitle>
            <DialogDescription>
              Update the role settings
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

            {/* Policy Configuration Section - only for SSH roles */}
            {editingRole && /^ssh[:\-]/i.test(editingRole.name) && (
              <div className="space-y-4 pt-4 border-t">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-muted-foreground" />
                  <h4 className="font-medium">SSH Signing Policy</h4>
                </div>

                {loadingPolicy ? (
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <div className="h-4 w-4 border-2 border-muted-foreground border-t-transparent rounded-full animate-spin" />
                    Loading policy...
                  </div>
                ) : editingPolicyConfig ? (
                  <>
                    <div className="flex items-center gap-2">
                      <Checkbox
                        id="editPolicyEnabled"
                        checked={editingPolicyConfig.enabled}
                        onCheckedChange={(v) => setEditingPolicyConfig({ ...editingPolicyConfig, enabled: Boolean(v) })}
                      />
                      <Label htmlFor="editPolicyEnabled" className="text-sm font-normal">
                        {editingPolicyConfig.enabled ? "Update signing policy" : "Create signing policy for this role"}
                      </Label>
                    </div>

                    {editingPolicyConfig.enabled && (
                      <div className="space-y-4 pl-6">
                        {/* Template Selection */}
                        <div className="space-y-2">
                          <div className="flex items-center gap-2">
                            <FileCode className="h-4 w-4 text-muted-foreground" />
                            <Label htmlFor="editTemplateSelect">Policy Template</Label>
                          </div>
                          <Select
                            value={editSelectedTemplateId || "default"}
                            onValueChange={(v) => {
                              if (v === "default") {
                                setEditSelectedTemplateId(null);
                                setEditTemplateParams({});
                              } else {
                                setEditSelectedTemplateId(v);
                                const template = templates.find((t) => t.id === v);
                                if (template) {
                                  const defaults: Record<string, any> = {};
                                  template.parameters.forEach((p) => {
                                    if (p.defaultValue !== undefined) {
                                      defaults[p.name] = p.defaultValue;
                                    }
                                  });
                                  setEditTemplateParams(defaults);
                                }
                              }
                            }}
                          >
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="default">Default SSH Policy</SelectItem>
                              {templates.map((t) => (
                                <SelectItem key={t.id} value={t.id}>
                                  {t.name}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>

                        {/* Template Parameters */}
                        {editSelectedTemplateId && (
                          (() => {
                            const editSelectedTemplate = templates.find((t) => t.id === editSelectedTemplateId);
                            return editSelectedTemplate && editSelectedTemplate.parameters.length > 0 ? (
                              <div className="space-y-3 p-3 border rounded-md bg-muted/50">
                                <p className="text-xs font-medium">Template Parameters</p>
                                {editSelectedTemplate.parameters.map((param) => (
                                  <div key={param.name} className="space-y-1">
                                    <Label className="text-xs">
                                      {param.name}
                                      {param.required && <span className="text-destructive ml-1">*</span>}
                                    </Label>
                                    {param.helpText && (
                                      <p className="text-xs text-muted-foreground">{param.helpText}</p>
                                    )}
                                    {param.type === "select" && (
                                      <Select
                                        value={editTemplateParams[param.name] || param.defaultValue?.toString() || ""}
                                        onValueChange={(v) => setEditTemplateParams({ ...editTemplateParams, [param.name]: v })}
                                      >
                                        <SelectTrigger className="h-8 text-sm">
                                          <SelectValue />
                                        </SelectTrigger>
                                        <SelectContent>
                                          {param.options?.map((opt) => (
                                            <SelectItem key={opt} value={opt}>{opt}</SelectItem>
                                          ))}
                                        </SelectContent>
                                      </Select>
                                    )}
                                    {param.type === "string" && (
                                      <Input
                                        value={editTemplateParams[param.name] || ""}
                                        onChange={(e) => setEditTemplateParams({ ...editTemplateParams, [param.name]: e.target.value })}
                                        className="h-8 text-sm"
                                      />
                                    )}
                                    {param.type === "number" && (
                                      <Input
                                        type="number"
                                        value={editTemplateParams[param.name] || ""}
                                        onChange={(e) => setEditTemplateParams({ ...editTemplateParams, [param.name]: parseInt(e.target.value) || 0 })}
                                        className="h-8 text-sm"
                                      />
                                    )}
                                  </div>
                                ))}
                              </div>
                            ) : null;
                          })()
                        )}

                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <Label>Approval Type</Label>
                            <Select
                              value={editingPolicyConfig.approvalType}
                              onValueChange={(v) => setEditingPolicyConfig({ ...editingPolicyConfig, approvalType: v as "implicit" | "explicit" })}
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="implicit">Implicit</SelectItem>
                                <SelectItem value="explicit">Explicit</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>

                          <div className="space-y-2">
                            <Label>Execution Type</Label>
                            <Select
                              value={editingPolicyConfig.executionType}
                              onValueChange={(v) => setEditingPolicyConfig({ ...editingPolicyConfig, executionType: v as "public" | "private" })}
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="public">Public</SelectItem>
                                <SelectItem value="private">Private</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        </div>

                        {editingPolicyConfig.approvalType === "explicit" && (
                          <div className="space-y-2">
                            <Label>Approval Threshold</Label>
                            <div className="flex items-center gap-2 p-2 bg-muted rounded-md">
                              <span className="font-medium">{calculatedThreshold}</span>
                              <span className="text-muted-foreground text-sm">
                                (70% of {activeAdminCount} active admin{activeAdminCount !== 1 ? "s" : ""})
                              </span>
                            </div>
                            <p className="text-xs text-muted-foreground">
                              Automatically calculated based on active admins
                            </p>
                          </div>
                        )}

                        <p className="text-xs bg-amber-50 text-amber-800 dark:bg-amber-950/30 dark:text-amber-400 p-2 rounded">
                          Updating the policy will create a new pending approval request that must be approved by admins.
                        </p>
                      </div>
                    )}
                  </>
                ) : null}
              </div>
            )}

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
                <Button type="submit" disabled={updateMutation.isPending || isUpdatingPolicy} data-testid="submit-role-form">
                  {updateMutation.isPending || isUpdatingPolicy ? "Saving..." : "Save Changes"}
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
              <div className="flex items-center gap-2">
                <Checkbox
                  id="createAsSshRole"
                  checked={createAsSshRole}
                  onCheckedChange={(v) => setCreateAsSshRole(Boolean(v))}
                />
                <Label htmlFor="createAsSshRole" className="text-sm font-normal">
                  SSH role (auto-prefix <span className="font-mono">ssh:</span>)
                </Label>
              </div>
              <Input
                id="roleName"
                value={formData.name}
                onChange={(e) => {
                  const raw = e.target.value;
                  setFormData({
                    ...formData,
                    name: createAsSshRole ? normalizeSshRoleName(raw) : raw,
                  });
                }}
                placeholder={createAsSshRole ? "e.g., root" : "e.g., developer"}
                required
              />
              {createAsSshRole && (
                <p className="text-xs text-muted-foreground">
                  This will create a role like <span className="font-mono">ssh:root</span>, which grants SSH username access.
                </p>
              )}
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

            {/* Policy Configuration Section - only for SSH roles */}
            {createAsSshRole && (
              <div className="space-y-4 pt-4 border-t">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-muted-foreground" />
                  <h4 className="font-medium">SSH Signing Policy</h4>
                </div>
                <p className="text-xs text-muted-foreground">
                  Configure the Tide policy for SSH challenge signing with this role.
                </p>

                <div className="flex items-center gap-2">
                  <Checkbox
                    id="policyEnabled"
                    checked={policyConfig.enabled}
                    onCheckedChange={(v) => setPolicyConfig({ ...policyConfig, enabled: Boolean(v) })}
                  />
                  <Label htmlFor="policyEnabled" className="text-sm font-normal">
                    Create signing policy for this role
                  </Label>
                </div>

                {policyConfig.enabled && (
                  <div className="space-y-4 pl-6">
                    {/* Template Selection */}
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <FileCode className="h-4 w-4 text-muted-foreground" />
                        <Label htmlFor="templateSelect">Policy Template</Label>
                      </div>
                      <Select
                        value={selectedTemplateId || "default"}
                        onValueChange={(v) => {
                          if (v === "default") {
                            setSelectedTemplateId(null);
                            setTemplateParams({});
                          } else {
                            setSelectedTemplateId(v);
                            // Initialize params with defaults
                            const template = templates.find((t) => t.id === v);
                            if (template) {
                              const defaults: Record<string, any> = {};
                              template.parameters.forEach((p) => {
                                if (p.defaultValue !== undefined) {
                                  defaults[p.name] = p.defaultValue;
                                }
                              });
                              setTemplateParams(defaults);
                            }
                          }
                        }}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="default">Default SSH Policy</SelectItem>
                          {templates.map((t) => (
                            <SelectItem key={t.id} value={t.id}>
                              {t.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <p className="text-xs text-muted-foreground">
                        {selectedTemplate
                          ? selectedTemplate.description
                          : "Uses the built-in SSH signing policy contract"}
                      </p>
                    </div>

                    {/* Template Parameter Inputs */}
                    {selectedTemplate && selectedTemplate.parameters.length > 0 && (
                      <div className="space-y-3 p-3 border rounded-md bg-muted/50">
                        <p className="text-xs font-medium">Template Parameters</p>
                        {selectedTemplate.parameters.map((param) => (
                          <div key={param.name} className="space-y-1">
                            <Label className="text-xs">
                              {param.name}
                              {param.required && <span className="text-destructive ml-1">*</span>}
                            </Label>
                            {param.helpText && (
                              <p className="text-xs text-muted-foreground">{param.helpText}</p>
                            )}
                            {param.type === "string" && (
                              <Input
                                value={templateParams[param.name] || ""}
                                onChange={(e) => setTemplateParams({ ...templateParams, [param.name]: e.target.value })}
                                placeholder={param.defaultValue?.toString() || ""}
                                required={param.required}
                                className="h-8 text-sm"
                              />
                            )}
                            {param.type === "number" && (
                              <Input
                                type="number"
                                value={templateParams[param.name] || ""}
                                onChange={(e) => setTemplateParams({ ...templateParams, [param.name]: parseInt(e.target.value) || 0 })}
                                placeholder={param.defaultValue?.toString() || ""}
                                required={param.required}
                                className="h-8 text-sm"
                              />
                            )}
                            {param.type === "boolean" && (
                              <div className="flex items-center gap-2">
                                <Checkbox
                                  checked={templateParams[param.name] || false}
                                  onCheckedChange={(v) => setTemplateParams({ ...templateParams, [param.name]: Boolean(v) })}
                                />
                                <span className="text-xs">{templateParams[param.name] ? "Yes" : "No"}</span>
                              </div>
                            )}
                            {param.type === "select" && (
                              <Select
                                value={templateParams[param.name] || param.defaultValue?.toString() || ""}
                                onValueChange={(v) => setTemplateParams({ ...templateParams, [param.name]: v })}
                              >
                                <SelectTrigger className="h-8 text-sm">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  {param.options?.map((opt) => (
                                    <SelectItem key={opt} value={opt}>{opt}</SelectItem>
                                  ))}
                                </SelectContent>
                              </Select>
                            )}
                          </div>
                        ))}
                      </div>
                    )}

                    <div className="space-y-2">
                      <Label htmlFor="contractType">Contract Type</Label>
                      <Select
                        value={policyConfig.contractType}
                        onValueChange={(v) => setPolicyConfig({ ...policyConfig, contractType: v as SshContractType })}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value={SSH_CONTRACT_TYPES.BASIC}>
                            Basic - All data at creation time
                          </SelectItem>
                          <SelectItem value={SSH_CONTRACT_TYPES.DYNAMIC}>
                            Dynamic - Challenge can change
                          </SelectItem>
                          <SelectItem value={SSH_CONTRACT_TYPES.DYNAMIC_APPROVED}>
                            Dynamic Approved - With human readable approval
                          </SelectItem>
                        </SelectContent>
                      </Select>
                      <p className="text-xs text-muted-foreground">
                        Contract ID: <code className="bg-muted px-1 rounded">{policyConfig.contractType}</code>
                      </p>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label htmlFor="approvalType">Approval Type</Label>
                        <Select
                          value={policyConfig.approvalType}
                          onValueChange={(v) => setPolicyConfig({ ...policyConfig, approvalType: v as "implicit" | "explicit" })}
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="implicit">Implicit</SelectItem>
                            <SelectItem value="explicit">Explicit</SelectItem>
                          </SelectContent>
                        </Select>
                        <p className="text-xs text-muted-foreground">
                          {policyConfig.approvalType === "implicit"
                            ? "No manual approval required"
                            : "Requires user approval"}
                        </p>
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="executionType">Execution Type</Label>
                        <Select
                          value={policyConfig.executionType}
                          onValueChange={(v) => setPolicyConfig({ ...policyConfig, executionType: v as "public" | "private" })}
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="public">Public</SelectItem>
                            <SelectItem value="private">Private</SelectItem>
                          </SelectContent>
                        </Select>
                        <p className="text-xs text-muted-foreground">
                          {policyConfig.executionType === "public"
                            ? "Anyone can execute"
                            : "Role-based execution"}
                        </p>
                      </div>
                    </div>

                    {policyConfig.approvalType === "explicit" && (
                      <div className="space-y-2">
                        <Label htmlFor="threshold">Approval Threshold</Label>
                        <div className="flex items-center gap-2 p-2 bg-muted rounded-md">
                          <span className="font-medium">{calculatedThreshold}</span>
                          <span className="text-muted-foreground text-sm">
                            (70% of {activeAdminCount} active admin{activeAdminCount !== 1 ? "s" : ""})
                          </span>
                        </div>
                        <p className="text-xs text-muted-foreground">
                          Automatically calculated based on active admins
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setCreatingRole(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={createMutation.isPending || isCreatingPolicy}>
                {createMutation.isPending || isCreatingPolicy ? "Creating..." : "Create Role"}
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
