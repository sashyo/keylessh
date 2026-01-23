import { useState } from "react";
import { useQuery, useMutation, useIsFetching } from "@tanstack/react-query";
import Editor from "@monaco-editor/react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { useAuth } from "@/contexts/AuthContext";
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
import { FileCode, Pencil, Plus, Trash2, Search, Code, Variable } from "lucide-react";

const DEFAULT_CS_CODE = `using Ork.Forseti.Sdk;
using System;
using System.Collections.Generic;
using System.Text;

/// <summary>
/// Forseti contract - start here.
/// </summary>
public class Contract : IAccessPolicy
{
    // These policy parameters are filled in by the policy "params" map.
    // Marking them Required ensures missing values result in deny/validation failures.
    [PolicyParam(Required = true, Description = "Role required for SSH access (e.g., ssh:root)")]
    public string Role { get; set; }

    [PolicyParam(Required = true, Description = "Resource identifier for role checks")]
    public string Resource { get; set; }

    // Called for every request. Validate the request data payload and return Allow/Deny.
    // For SSH signing, ctx.Data is the SSHv2 publickey auth "to-be-signed" payload.
    public PolicyDecision ValidateData(DataContext ctx)
    {
        throw new NotImplementedException("Implement SSH challenge validation in ValidateData().");
    }

    // Called for explicit approvals. Validate that the approvers are allowed to approve this request.
    public PolicyDecision ValidateApprovers(ApproversContext ctx)
    {
        throw new NotImplementedException("Implement approver validation in ValidateApprovers().");
    }

    // Called for execution. Validate that the executor (caller) is allowed to execute this request.
    public PolicyDecision ValidateExecutor(ExecutorContext ctx)
    {
        throw new NotImplementedException("Implement executor validation in ValidateExecutor().");
    }
}`;

interface TemplateFormData {
  name: string;
  description: string;
  csCode: string;
  parameters: TemplateParameter[];
}

const defaultFormData: TemplateFormData = {
  name: "",
  description: "",
  csCode: DEFAULT_CS_CODE,
  parameters: [],
};

export default function AdminPolicyTemplates() {
  const { toast } = useToast();
  const { canManageTemplates } = useAuth();
  const canEdit = canManageTemplates();
  const [search, setSearch] = useState("");
  const [editingTemplate, setEditingTemplate] = useState<PolicyTemplate | null>(null);
  const [creatingTemplate, setCreatingTemplate] = useState(false);
  const [deletingTemplate, setDeletingTemplate] = useState<PolicyTemplate | null>(null);
  const [formData, setFormData] = useState<TemplateFormData>(defaultFormData);

  const { data: templatesData, isLoading, refetch } = useQuery({
    queryKey: ["/api/admin/policy-templates"],
    queryFn: api.admin.policyTemplates.list,
  });
  const isFetching = useIsFetching({ queryKey: ["/api/admin/policy-templates"] }) > 0;
  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 30,
    refresh: () => refetch(),
    isBlocked: isFetching,
  });

  const templates = templatesData?.templates || [];

  const createMutation = useMutation({
    mutationFn: (data: Omit<TemplateFormData, "parameters"> & { parameters: TemplateParameter[] }) =>
      api.admin.policyTemplates.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/policy-templates"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/policy-templates"] });
      setCreatingTemplate(false);
      setFormData(defaultFormData);
      toast({ title: "Template created successfully" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to create template", description: error.message, variant: "destructive" });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<TemplateFormData> }) =>
      api.admin.policyTemplates.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/policy-templates"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/policy-templates"] });
      setEditingTemplate(null);
      setFormData(defaultFormData);
      toast({ title: "Template updated successfully" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to update template", description: error.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.admin.policyTemplates.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/policy-templates"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/policy-templates"] });
      setDeletingTemplate(null);
      setEditingTemplate(null);
      toast({ title: "Template deleted successfully" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to delete template", description: error.message, variant: "destructive" });
    },
  });

  const handleEdit = (template: PolicyTemplate) => {
    setEditingTemplate(template);
    setFormData({
      name: template.name,
      description: template.description,
      csCode: template.csCode,
      parameters: template.parameters || [],
    });
  };

  const handleCreate = () => {
    setFormData(defaultFormData);
    setCreatingTemplate(true);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name.trim()) {
      toast({ title: "Template name is required", variant: "destructive" });
      return;
    }
    if (!formData.description.trim()) {
      toast({ title: "Description is required", variant: "destructive" });
      return;
    }
    if (!formData.csCode.trim()) {
      toast({ title: "Contract code is required", variant: "destructive" });
      return;
    }

    const entryTypeMatch = formData.csCode.match(
      /public\s+(?:\w+\s+)*class\s+(\w+)\s*:\s*IAccessPolicy/
    );
    if (!entryTypeMatch || entryTypeMatch[1] !== "Contract") {
      toast({
        title: "Invalid contract entry type",
        description: "Your contract must declare `public class Contract : IAccessPolicy`.",
        variant: "destructive",
      });
      return;
    }

    if (editingTemplate) {
      updateMutation.mutate({ id: editingTemplate.id, data: formData });
    } else {
      createMutation.mutate(formData);
    }
  };

  const handleDeleteConfirm = () => {
    if (deletingTemplate) {
      deleteMutation.mutate(deletingTemplate.id);
    }
  };

  const addParameter = () => {
    setFormData({
      ...formData,
      parameters: [
        ...formData.parameters,
        {
          name: "",
          type: "string",
          helpText: "",
          required: true,
          defaultValue: "",
        },
      ],
    });
  };

  const updateParameter = (index: number, field: keyof TemplateParameter, value: any) => {
    const updated = [...formData.parameters];
    updated[index] = { ...updated[index], [field]: value };
    setFormData({ ...formData, parameters: updated });
  };

  const removeParameter = (index: number) => {
    const updated = formData.parameters.filter((_, i) => i !== index);
    setFormData({ ...formData, parameters: updated });
  };

  const filteredTemplates = templates.filter(
    (template) =>
      template.name.toLowerCase().includes(search.toLowerCase()) ||
      template.description.toLowerCase().includes(search.toLowerCase())
  );

  const isDialogOpen = creatingTemplate || !!editingTemplate;
  const isSubmitting = createMutation.isPending || updateMutation.isPending;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <FileCode className="h-6 w-6" />
            Policy Templates
          </h1>
          <p className="text-muted-foreground">
            Create reusable C# Forseti contract templates for SSH signing policies
          </p>
          <p className="text-xs text-muted-foreground">
            Use <code className="bg-muted px-1 rounded">{"{{PARAM_NAME}}"}</code> placeholders in your code for configurable values.
          </p>
          <p className="text-xs text-muted-foreground">
            Entry type must be <code className="bg-muted px-1 rounded">Contract</code>:{" "}
            <code className="bg-muted px-1 rounded">public class Contract : IAccessPolicy</code>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <RefreshButton
            onClick={() => void refreshNow()}
            isRefreshing={isFetching}
            secondsRemaining={secondsRemaining}
            title="Refresh now"
          />
          {canEdit && (
            <Button onClick={handleCreate}>
              <Plus className="h-4 w-4 mr-2" />
              Create Template
            </Button>
          )}
        </div>
      </div>

      <Card>
        <div className="p-4 border-b border-border">
          <div className="relative max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search templates..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>
        </div>
        <CardContent className="p-0">
          {isLoading ? (
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
          ) : filteredTemplates.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Template Name</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Parameters</TableHead>
                  <TableHead>Created By</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredTemplates.map((template) => (
                  <TableRow key={template.id}>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10">
                          <Code className="h-4 w-4 text-primary" />
                        </div>
                        <div className="flex items-center gap-2">
                          <p className="font-medium">{template.name}</p>
                          {template.createdBy === "system" && (
                            <Badge variant="secondary" className="text-xs">
                              System
                            </Badge>
                          )}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <p className="text-sm text-muted-foreground line-clamp-2">
                        {template.description}
                      </p>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {template.parameters.slice(0, 3).map((param) => (
                          <Badge key={param.name} variant="outline" className="text-xs">
                            {param.name}
                          </Badge>
                        ))}
                        {template.parameters.length > 3 && (
                          <Badge variant="outline" className="text-xs">
                            +{template.parameters.length - 3}
                          </Badge>
                        )}
                        {template.parameters.length === 0 && (
                          <span className="text-xs text-muted-foreground">None</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground">
                        {template.createdBy}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      {canEdit && (
                        <div className="flex justify-end gap-2">
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => handleEdit(template)}
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          {template.createdBy !== "system" && (
                            <Button
                              size="icon"
                              variant="ghost"
                              onClick={() => setDeletingTemplate(template)}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          )}
                        </div>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <FileCode className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="font-medium">No templates found</h3>
              <p className="text-sm text-muted-foreground mt-1">
                {search ? "Try a different search term" : "Create a template to get started"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create/Edit Dialog */}
      <Dialog open={isDialogOpen} onOpenChange={(open) => {
        if (!open) {
          setCreatingTemplate(false);
          setEditingTemplate(null);
        }
      }}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editingTemplate ? "Edit Template" : "Create Template"}</DialogTitle>
            <DialogDescription>
              {editingTemplate
                ? "Update the template configuration and contract code"
                : "Create a reusable policy template with configurable parameters"}
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="name">Template Name</Label>
                <Input
                  id="name"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="e.g., SSH Access Policy"
                  required
                />
              </div>
              <div className="space-y-2 col-span-2">
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Describe what this template does and when to use it..."
                  rows={2}
                  required
                />
              </div>
            </div>

            {/* Contract Code Editor */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>Contract Code (C#)</Label>
                <p className="text-xs text-muted-foreground">
                  Use <code className="bg-muted px-1 rounded">{"{{PARAM_NAME}}"}</code> for dynamic values
                </p>
              </div>
              <div className="border rounded-md overflow-hidden">
                <Editor
                  height="300px"
                  language="csharp"
                  theme="vs-dark"
                  value={formData.csCode}
                  onChange={(value) => setFormData({ ...formData, csCode: value || "" })}
                  options={{
                    minimap: { enabled: false },
                    fontSize: 13,
                    lineNumbers: "on",
                    scrollBeyondLastLine: false,
                    wordWrap: "on",
                    automaticLayout: true,
                  }}
                />
              </div>
            </div>

            {/* Parameters Section */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Variable className="h-4 w-4 text-muted-foreground" />
                  <Label>Template Parameters</Label>
                </div>
                <Button type="button" variant="outline" size="sm" onClick={addParameter}>
                  <Plus className="h-4 w-4 mr-1" />
                  Add Parameter
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Define parameters that admins will fill in when using this template.
              </p>

              {formData.parameters.length === 0 ? (
                <div className="border rounded-md p-4 text-center text-sm text-muted-foreground">
                  No parameters defined. Add parameters to make your template configurable.
                </div>
              ) : (
                <div className="space-y-4">
                  {formData.parameters.map((param, index) => (
                    <div key={index} className="border rounded-md p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium">Parameter {index + 1}</span>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          onClick={() => removeParameter(index)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                      <div className="grid grid-cols-2 gap-3">
                        <div className="space-y-1">
                          <Label className="text-xs">Name (placeholder)</Label>
                          <Input
                            value={param.name}
                            onChange={(e) => updateParameter(index, "name", e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, "_"))}
                            placeholder="e.g., APPROVAL_TYPE"
                            className="font-mono text-sm"
                          />
                          <p className="text-xs text-muted-foreground">
                            Use in code as: <code>{`{{${param.name || "NAME"}}}`}</code>
                          </p>
                        </div>
                        <div className="space-y-1">
                          <Label className="text-xs">Type</Label>
                          <Select
                            value={param.type}
                            onValueChange={(v) => updateParameter(index, "type", v)}
                          >
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="string">Text</SelectItem>
                              <SelectItem value="number">Number</SelectItem>
                              <SelectItem value="boolean">Yes/No</SelectItem>
                              <SelectItem value="select">Select (Dropdown)</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="space-y-1 col-span-2">
                          <Label className="text-xs">Help Text</Label>
                          <Input
                            value={param.helpText}
                            onChange={(e) => updateParameter(index, "helpText", e.target.value)}
                            placeholder="Explain what this parameter does..."
                          />
                        </div>
                        <div className="space-y-1">
                          <Label className="text-xs">Default Value</Label>
                          <Input
                            value={param.defaultValue?.toString() || ""}
                            onChange={(e) => updateParameter(index, "defaultValue", e.target.value)}
                            placeholder="Optional default"
                          />
                        </div>
                        <div className="flex items-center gap-2 pt-5">
                          <Switch
                            checked={param.required}
                            onCheckedChange={(v) => updateParameter(index, "required", v)}
                          />
                          <Label className="text-xs">Required</Label>
                        </div>
                        {param.type === "select" && (
                          <div className="space-y-1 col-span-2">
                            <Label className="text-xs">Options (comma-separated)</Label>
                            <Input
                              value={param.options?.join(", ") || ""}
                              onChange={(e) => updateParameter(index, "options", e.target.value.split(",").map(s => s.trim()).filter(Boolean))}
                              placeholder="e.g., option1, option2, option3"
                            />
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <DialogFooter className="flex justify-between sm:justify-between">
              {editingTemplate && editingTemplate.createdBy !== "system" && (
                <Button
                  type="button"
                  variant="destructive"
                  onClick={() => setDeletingTemplate(editingTemplate)}
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  Delete
                </Button>
              )}
              {(!editingTemplate || editingTemplate.createdBy === "system") && <div />}
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setCreatingTemplate(false);
                    setEditingTemplate(null);
                  }}
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={isSubmitting}>
                  {isSubmitting ? "Saving..." : editingTemplate ? "Save Changes" : "Create Template"}
                </Button>
              </div>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deletingTemplate} onOpenChange={(open) => !open && setDeletingTemplate(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Template</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{deletingTemplate?.name}"? This action cannot be undone.
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
