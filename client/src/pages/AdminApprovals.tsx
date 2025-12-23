import { useState, useEffect, useCallback } from "react";
import { useQuery, useMutation, useIsFetching } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
import { queryClient } from "@/lib/queryClient";
import { api, AccessApproval, PendingSshPolicy, SshPolicyDecision } from "@/lib/api";
import { useAutoRefresh } from "@/hooks/useAutoRefresh";
import { CheckSquare, X, Upload, User, Shield, FileKey, Eye, Check, Clock, CheckCircle2, XCircle, ChevronDown, ChevronRight, Code, Trash2, Undo2 } from "lucide-react";
import { SSH_FORSETI_CONTRACT } from "@/lib/sshPolicy";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { RefreshButton } from "@/components/RefreshButton";

type TabType = "access" | "policies";

// Helper to convert base64 to Uint8Array
function base64ToBytes(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

// Helper to convert Uint8Array to base64
function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Access Approvals Tab Component - Uses TideCloak API with Tide Enclave
function AccessApprovalsTab() {
  const { toast } = useToast();
  const { vuid, approveTideRequests } = useAuth();
  const [approvals, setApprovals] = useState<AccessApproval[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const fetchAccessApprovals = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await api.admin.accessApprovals.list();
      setApprovals(data);
      // Invalidate query cache so badge count updates
      queryClient.invalidateQueries({ queryKey: ["/api/admin/access-approvals"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/access-approvals"] });
    } catch (error) {
      console.error("Error fetching access approvals:", error);
      toast({
        title: "Failed to fetch approvals",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  }, [toast]);

  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 15,
    refresh: fetchAccessApprovals,
    isBlocked: isLoading,
  });

  // Fetch approvals on mount and when vuid changes
  useEffect(() => {
    void refreshNow();
  }, [vuid, refreshNow]);

  const handleCommit = async (id: string) => {
    const approval = approvals.find((a) => a.id === id);
    if (!approval) {
      toast({ title: "Could not find access request", variant: "destructive" });
      return;
    }

    try {
      await api.admin.accessApprovals.commit(approval.retrievalInfo);
      toast({ title: "Access approval committed successfully" });
      // Small delay to allow TideCloak to process the change
      await new Promise((resolve) => setTimeout(resolve, 500));
      await refreshNow();
    } catch (error) {
      console.error("Error committing access approval:", error);
      toast({
        title: "Failed to commit approval",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  const handleReview = async (id: string) => {
    const approval = approvals.find((a) => a.id === id);
    if (!approval) {
      toast({ title: "Could not find access request", variant: "destructive" });
      return;
    }

    if (approval.decisionMade) {
      toast({ title: "Access request has already been reviewed" });
      return;
    }

    try {
      // Get raw change set request for signing
      const { rawRequest } = await api.admin.accessApprovals.getRaw(approval.retrievalInfo);

      if (!rawRequest) {
        toast({ title: "Failed to get request for signing", variant: "destructive" });
        return;
      }

      // Convert base64 to Uint8Array for Tide enclave
      const requestBytes = base64ToBytes(rawRequest);

      // Call Tide enclave for approval (opens popup for cryptographic signing)
      const approvalResponses = await approveTideRequests([
        {
          id: "User Context Approval",
          request: requestBytes,
        },
      ]);

      const response = approvalResponses[0];

      if (response.approved) {
        // Submit the signed approval
        const signedRequestBase64 = bytesToBase64(response.approved.request);
        await api.admin.accessApprovals.approve(approval.retrievalInfo, signedRequestBase64);
        toast({ title: "Access request approved successfully" });
        // Small delay to allow TideCloak to process the change
        await new Promise((resolve) => setTimeout(resolve, 500));
        await refreshNow();
      } else if (response.denied) {
        // Submit rejection
        await api.admin.accessApprovals.reject(approval.retrievalInfo);
        toast({ title: "Access request denied" });
        // Small delay to allow TideCloak to process the change
        await new Promise((resolve) => setTimeout(resolve, 500));
        await refreshNow();
      } else {
        // Still pending - no response from enclave
        toast({ title: "No response from approval enclave", variant: "destructive" });
      }
    } catch (error) {
      console.error("Error reviewing access request:", error);
      toast({
        title: "Failed to review request",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  const handleCancel = async (id: string) => {
    const approval = approvals.find((a) => a.id === id);
    if (!approval) {
      toast({ title: "Could not find access request", variant: "destructive" });
      return;
    }

    try {
      await api.admin.accessApprovals.cancel(approval.retrievalInfo);
      toast({ title: "Access request cancelled successfully" });
      // Small delay to allow TideCloak to process the change
      await new Promise((resolve) => setTimeout(resolve, 500));
      await refreshNow();
    } catch (error) {
      console.error("Error cancelling access request:", error);
      toast({
        title: "Failed to cancel request",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  const formatDate = (timestamp: string) => {
    return new Date(timestamp).toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const refreshControls = (
    <div className="p-4 border-b border-border flex items-center justify-end">
      <RefreshButton
        onClick={() => void refreshNow()}
        isRefreshing={isLoading}
        secondsRemaining={secondsRemaining}
        data-testid="refresh-approvals"
        title="Refresh now"
      />
    </div>
  );

  if (isLoading && approvals.length === 0) {
    return (
      <div>
        {refreshControls}
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
      </div>
    );
  }

  if (!approvals || approvals.length === 0) {
    return (
      <div>
        {refreshControls}
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <User className="h-12 w-12 text-muted-foreground mb-4" />
          <h3 className="font-medium">No pending access requests</h3>
          <p className="text-sm text-muted-foreground mt-1">
            User access change requests will appear here.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div>
      {refreshControls}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>User</TableHead>
            <TableHead>Role</TableHead>
            <TableHead>Client</TableHead>
            <TableHead>Created</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {approvals.map((approval) => (
            <TableRow key={approval.id}>
              <TableCell>
                <div className="flex items-center gap-2">
                  <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10 text-primary">
                    <User className="h-4 w-4" />
                  </div>
                  <span className="font-medium">{approval.username}</span>
                </div>
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm">{approval.role}</span>
                </div>
              </TableCell>
              <TableCell>
                <span className="text-sm text-muted-foreground">{approval.clientId}</span>
              </TableCell>
              <TableCell>
                <span className="text-sm text-muted-foreground">{formatDate(approval.timestamp)}</span>
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <Badge
                    variant="outline"
                    className={
                      approval.commitReady
                        ? "bg-green-50 text-green-700 border-green-200 dark:bg-green-950/30 dark:text-green-400 dark:border-green-800"
                        : "bg-yellow-50 text-yellow-700 border-yellow-200 dark:bg-yellow-950/30 dark:text-yellow-400 dark:border-yellow-800"
                    }
                  >
                    {approval.commitReady ? "Ready to Commit" : "Pending Review"}
                  </Badge>
                  {approval.rejectionFound && (
                    <span title="Rejection found - investigate in logs page">🚩</span>
                  )}
                </div>
              </TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-1">
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() =>
                      approval.commitReady ? handleCommit(approval.id) : handleReview(approval.id)
                    }
                    title={approval.commitReady ? "Commit access change" : "Review access request"}
                    className={approval.commitReady ? "text-cyan-600 dark:text-cyan-400" : ""}
                  >
                    {approval.commitReady ? (
                      <Upload className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => handleCancel(approval.id)}
                    title="Cancel access request"
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function formatPolicyTimestamp(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}

function getPolicyStatusBadge(status: string) {
  switch (status) {
    case "pending":
      return <Badge variant="outline" className="bg-yellow-50 text-yellow-700 border-yellow-200 dark:bg-yellow-950/30 dark:text-yellow-400 dark:border-yellow-800"><Clock className="h-3 w-3 mr-1" />Pending</Badge>;
    case "approved":
      return <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200 dark:bg-green-950/30 dark:text-green-400 dark:border-green-800"><CheckCircle2 className="h-3 w-3 mr-1" />Approved</Badge>;
    case "committed":
      return <Badge variant="outline" className="bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950/30 dark:text-blue-400 dark:border-blue-800"><Check className="h-3 w-3 mr-1" />Committed</Badge>;
    case "cancelled":
      return <Badge variant="outline" className="bg-gray-50 text-gray-700 border-gray-200 dark:bg-gray-900/30 dark:text-gray-400 dark:border-gray-700"><XCircle className="h-3 w-3 mr-1" />Cancelled</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

// Policy Approvals Tab Component - SSH Signing Policy Approvals
// Matches swarm's implementation with table view, multi-select, and Tide enclave
function PolicyApprovalsTab() {
  const { toast } = useToast();
  const { vuid, approveTideRequests, executeTideRequest } = useAuth();
  const [selectedPolicies, setSelectedPolicies] = useState<string[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState<PendingSshPolicy | null>(null);
  const [policyDecisions, setPolicyDecisions] = useState<SshPolicyDecision[]>([]);
  const [contractExpanded, setContractExpanded] = useState(false);

  const { data: policiesData, isLoading: policiesLoading, refetch: refetchPolicies } = useQuery({
    queryKey: ["/api/admin/ssh-policies/pending"],
    queryFn: api.admin.sshPolicies.listPending,
  });

  const isFetchingPolicies = useIsFetching({ queryKey: ["/api/admin/ssh-policies/pending"] }) > 0;
  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 15,
    refresh: refetchPolicies,
    isBlocked: isFetchingPolicies || isProcessing,
  });

  const policies = policiesData?.policies || [];

  // Check if policy is ready to commit (threshold met)
  const canCommit = (policy: PendingSshPolicy): boolean => {
    return policy.commitReady === true || (policy.approvalCount || 0) >= policy.threshold;
  };

  // View policy details
  const handleViewPolicy = async (policy: PendingSshPolicy) => {
    setSelectedPolicy(policy);
    setContractExpanded(false);
    try {
      const { decisions } = await api.admin.sshPolicies.getPending(policy.id);
      setPolicyDecisions(decisions || []);
    } catch (error) {
      console.error("Error fetching policy decisions:", error);
      setPolicyDecisions([]);
    }
  };

  // Check if current user has already made a decision on this policy
  const hasUserDecided = (policy: PendingSshPolicy): boolean => {
    const approvedBy = policy.approvedBy || [];
    const deniedBy = policy.deniedBy || [];
    return approvedBy.includes(vuid) || deniedBy.includes(vuid);
  };

  // Format date from unix timestamp
  const formatDate = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  // Review policies using Tide enclave - opens approval popup (Swarm-style)
  const reviewPolicies = async (policyIds: string[]) => {
    const policiesToReview = policies
      .filter(p => policyIds.includes(p.id) && !hasUserDecided(p));

    if (policiesToReview.length === 0) {
      toast({ title: "All selected policies have already been reviewed", variant: "destructive" });
      return;
    }

    setIsProcessing(true);
    try {
      const requests = policiesToReview.map(p => ({
        id: p.id,
        request: base64ToBytes(p.policyRequestData),
      }));

      const approvalResponses = await approveTideRequests(requests);

      let approvedCount = 0;
      let deniedCount = 0;

      for (const response of approvalResponses) {
        const policy = policiesToReview.find(p => p.id === response.id);
        if (!policy) continue;

        if (response.approved) {
          // Send the full signed request to the API (Swarm-style)
          const signedRequestBase64 = bytesToBase64(response.approved.request);
          await api.admin.sshPolicies.approve(signedRequestBase64, false);
          approvedCount++;
        } else if (response.denied) {
          // For denied, send original request with rejected=true (Swarm-style)
          await api.admin.sshPolicies.approve(policy.policyRequestData, true);
          deniedCount++;
        }
      }

      if (approvedCount > 0) toast({ title: `${approvedCount} policy(ies) approved` });
      if (deniedCount > 0) toast({ title: `${deniedCount} policy(ies) rejected` });
      if (approvedCount === 0 && deniedCount === 0) {
        toast({ title: "No decisions received from Tide enclave", variant: "destructive" });
      }

      queryClient.invalidateQueries({ queryKey: ["/api/admin/ssh-policies/pending"] });
      setSelectedPolicies([]);
    } catch (error) {
      console.error("Error reviewing policies:", error);
      toast({
        title: "Failed to review policies",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    } finally {
      setIsProcessing(false);
    }
  };

  // Commit policies using Tide enclave - gets final signatures
  const commitPolicies = async (policyIds: string[]) => {
    const policiesToCommit = policies
      .filter(p => policyIds.includes(p.id) && p.commitReady);

    if (policiesToCommit.length === 0) {
      toast({ title: "No policies ready to commit", variant: "destructive" });
      return;
    }

    // Check for duplicate roles
    const roles = policiesToCommit.map(p => p.roleId);
    const uniqueRoles = new Set(roles);
    if (roles.length !== uniqueRoles.size) {
      toast({
        title: "Cannot commit multiple policies for the same role simultaneously",
        variant: "destructive"
      });
      return;
    }

    setIsProcessing(true);
    let successCount = 0;

    try {
      // Dynamic import to avoid loading heimdall-tide at page mount
      const { PolicySignRequest } = await import("heimdall-tide");

      for (const policy of policiesToCommit) {
        try {
          // Decode the stored request into a PolicySignRequest object
          // This is critical - the PolicySignRequest.encode() method
          // properly attaches the policy to the request for Ork
          const requestBytes = base64ToBytes(policy.policyRequestData);
          const policyRequest = PolicySignRequest.decode(requestBytes);

          // Re-encode to get the properly formatted request with policy attached
          const signatures = await executeTideRequest(policyRequest.encode());
          const policySignature = signatures[0];

          if (!policySignature) {
            throw new Error("No signature received");
          }

          await api.admin.sshPolicies.commit(policy.id, bytesToBase64(policySignature));
          successCount++;
        } catch (error) {
          console.error(`Failed to commit policy ${policy.id}:`, error);
        }
      }

      if (successCount > 0) {
        toast({ title: `Successfully committed ${successCount} policy(ies)` });
      }

      queryClient.invalidateQueries({ queryKey: ["/api/admin/ssh-policies/pending"] });
      setSelectedPolicies([]);
    } catch (error) {
      console.error("Error committing policies:", error);
      toast({
        title: "Failed to commit policies",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    } finally {
      setIsProcessing(false);
    }
  };

  // Delete a policy
  const deletePolicy = async (policyId: string) => {
    if (!confirm("Are you sure you want to delete this policy request?")) {
      return;
    }

    try {
      await api.admin.sshPolicies.cancel(policyId);
      toast({ title: "Policy deleted" });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/ssh-policies/pending"] });
    } catch (error) {
      console.error("Error deleting policy:", error);
      toast({
        title: "Failed to delete policy",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  // Revoke user's decision on a policy
  const revokeDecision = async (policyId: string) => {
    if (!confirm("Are you sure you want to revoke your decision on this policy?")) {
      return;
    }

    try {
      await api.admin.sshPolicies.revoke(policyId);
      toast({ title: "Decision revoked successfully" });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/ssh-policies/pending"] });
    } catch (error) {
      console.error("Error revoking decision:", error);
      toast({
        title: "Failed to revoke decision",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  // Toggle selection
  const toggleSelection = (id: string) => {
    setSelectedPolicies(prev =>
      prev.includes(id) ? prev.filter(p => p !== id) : [...prev, id]
    );
  };

  const toggleSelectAll = () => {
    if (selectedPolicies.length === policies.length) {
      setSelectedPolicies([]);
    } else {
      setSelectedPolicies(policies.map(p => p.id));
    }
  };

  const refreshControls = (
    <div className="p-4 border-b border-border flex items-center justify-end">
      <RefreshButton
        onClick={() => void refreshNow()}
        isRefreshing={isFetchingPolicies || isProcessing}
        secondsRemaining={secondsRemaining}
        data-testid="refresh-policies"
        title="Refresh now"
      />
    </div>
  );

  if (policiesLoading && policies.length === 0) {
    return (
      <div>
        {refreshControls}
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
      </div>
    );
  }

  if (!policies || policies.length === 0) {
    return (
      <div>
        {refreshControls}
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <FileKey className="h-12 w-12 text-muted-foreground mb-4" />
          <h3 className="font-medium">No pending policy changes</h3>
          <p className="text-sm text-muted-foreground mt-1">
            SSH signing policy requests will appear here for approval.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div>
      {refreshControls}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Role</TableHead>
            <TableHead>Requested By</TableHead>
            <TableHead>Progress</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Created</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {policies.map((policy) => (
            <TableRow key={policy.id}>
              <TableCell>
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-muted-foreground" />
                  <span className="font-mono">{policy.roleId}</span>
                </div>
              </TableCell>
              <TableCell>{policy.requestedByEmail || policy.requestedBy}</TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <span className="text-green-600 dark:text-green-400">{policy.approvalCount || 0}</span>
                  <span className="text-muted-foreground">/</span>
                  <span>{policy.threshold}</span>
                  {policy.rejectionCount ? (
                    <span className="text-red-600 dark:text-red-400 text-sm">({policy.rejectionCount} rejected)</span>
                  ) : null}
                </div>
              </TableCell>
              <TableCell>{getPolicyStatusBadge(policy.status)}</TableCell>
              <TableCell className="text-sm text-muted-foreground">
                {formatPolicyTimestamp(policy.createdAt)}
              </TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-1">
                  {!hasUserDecided(policy) ? (
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => reviewPolicies([policy.id])}
                      disabled={isProcessing}
                      title="Review via Tide enclave"
                    >
                      <Eye className="h-4 w-4" />
                    </Button>
                  ) : (
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => revokeDecision(policy.id)}
                      disabled={isProcessing}
                      title="Revoke your decision"
                      className="text-orange-600 dark:text-orange-400"
                    >
                      <Undo2 className="h-4 w-4" />
                    </Button>
                  )}
                  {canCommit(policy) && (
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => commitPolicies([policy.id])}
                      disabled={isProcessing}
                      title="Commit policy"
                      className="text-green-600 dark:text-green-400"
                    >
                      <Upload className="h-4 w-4" />
                    </Button>
                  )}
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => handleViewPolicy(policy)}
                    title="View details"
                  >
                    <Code className="h-4 w-4" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => deletePolicy(policy.id)}
                    disabled={isProcessing}
                    title="Delete request"
                    className="text-red-600 dark:text-red-400"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      {/* Policy Details Dialog */}
      <Dialog open={!!selectedPolicy} onOpenChange={(open) => !open && setSelectedPolicy(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Review Policy Request</DialogTitle>
            <DialogDescription>
              SSH signing policy for role: <span className="font-mono">{selectedPolicy?.roleId}</span>
            </DialogDescription>
          </DialogHeader>

          {selectedPolicy && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-muted-foreground">Requested By</p>
                  <p className="font-medium">{selectedPolicy.requestedByEmail || selectedPolicy.requestedBy}</p>
                </div>
                <div>
                  <div className="text-muted-foreground">Status</div>
                  <div>{getPolicyStatusBadge(selectedPolicy.status)}</div>
                </div>
                <div>
                  <p className="text-muted-foreground">Threshold</p>
                  <p className="font-medium">{selectedPolicy.threshold} approval(s) required</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Progress</p>
                  <p className="font-medium">
                    <span className="text-green-600 dark:text-green-400">{selectedPolicy.approvalCount || 0}</span> approved,{" "}
                    <span className="text-red-600 dark:text-red-400">{selectedPolicy.rejectionCount || 0}</span> rejected
                  </p>
                </div>
                <div>
                  <p className="text-muted-foreground">Created</p>
                  <p className="font-medium">{formatPolicyTimestamp(selectedPolicy.createdAt)}</p>
                </div>
              </div>

              {policyDecisions.length > 0 && (
                <div className="border rounded-lg p-3">
                  <p className="text-sm font-medium mb-2">Decisions</p>
                  <div className="space-y-2">
                    {policyDecisions.map((decision, i) => (
                      <div key={i} className="flex items-center justify-between text-sm">
                        <span>{decision.decidedByEmail || decision.decidedBy}</span>
                        {decision.decision === "approved" ? (
                          <Badge variant="outline" className="bg-green-50 text-green-700 dark:bg-green-950/30 dark:text-green-400">
                            <Check className="h-3 w-3 mr-1" />Approved
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="bg-red-50 text-red-700 dark:bg-red-950/30 dark:text-red-400">
                            <X className="h-3 w-3 mr-1" />Rejected
                          </Badge>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <Collapsible open={contractExpanded} onOpenChange={setContractExpanded}>
                <CollapsibleTrigger asChild>
                  <Button variant="ghost" size="sm" className="w-full justify-start gap-2 text-muted-foreground hover:text-foreground">
                    {contractExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                    <Code className="h-4 w-4" />
                    View Forseti Contract
                  </Button>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <div className="mt-2 border rounded-lg bg-muted/50">
                    <pre className="p-3 text-xs font-mono overflow-x-auto max-h-48 overflow-y-auto whitespace-pre-wrap">
                      {SSH_FORSETI_CONTRACT}
                    </pre>
                  </div>
                </CollapsibleContent>
              </Collapsible>

              <DialogFooter className="flex gap-2">
                {(selectedPolicy.status === "pending" || selectedPolicy.status === "approved") && (
                  <>
                    <Button
                      variant="outline"
                      onClick={async () => {
                        await deletePolicy(selectedPolicy.id);
                        setSelectedPolicy(null);
                      }}
                      disabled={isProcessing}
                    >
                      Delete Request
                    </Button>
                    {!hasUserDecided(selectedPolicy) && (
                      <Button
                        onClick={async () => {
                          await reviewPolicies([selectedPolicy.id]);
                          // Refresh to get updated state
                          const { policy, decisions } = await api.admin.sshPolicies.getPending(selectedPolicy.id);
                          setSelectedPolicy(policy);
                          setPolicyDecisions(decisions || []);
                        }}
                        disabled={isProcessing}
                      >
                        <Eye className="h-4 w-4 mr-1" />
                        {isProcessing ? "Processing..." : "Review via Enclave"}
                      </Button>
                    )}
                    {hasUserDecided(selectedPolicy) && (
                      <Button
                        variant="outline"
                        onClick={async () => {
                          await revokeDecision(selectedPolicy.id);
                          // Refresh to get updated state
                          try {
                            const { policy, decisions } = await api.admin.sshPolicies.getPending(selectedPolicy.id);
                            setSelectedPolicy(policy);
                            setPolicyDecisions(decisions || []);
                          } catch {
                            setSelectedPolicy(null);
                          }
                        }}
                        disabled={isProcessing}
                        className="text-orange-600 border-orange-300 hover:bg-orange-50 dark:text-orange-400 dark:border-orange-700 dark:hover:bg-orange-950/30"
                      >
                        <Undo2 className="h-4 w-4 mr-1" />
                        {isProcessing ? "Revoking..." : "Revoke Decision"}
                      </Button>
                    )}
                    {canCommit(selectedPolicy) && (
                      <Button
                        onClick={async () => {
                          await commitPolicies([selectedPolicy.id]);
                          setSelectedPolicy(null);
                        }}
                        disabled={isProcessing}
                        className="bg-green-600 hover:bg-green-700"
                      >
                        <Upload className="h-4 w-4 mr-1" />
                        {isProcessing ? "Committing..." : "Commit Policy"}
                      </Button>
                    )}
                  </>
                )}
                {(selectedPolicy.status === "committed" || selectedPolicy.status === "cancelled") && (
                  <Button variant="outline" onClick={() => setSelectedPolicy(null)}>
                    Close
                  </Button>
                )}
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// Main AdminApprovals Component
export default function AdminApprovals() {
  const [activeTab, setActiveTab] = useState<TabType>("access");

  const { data: accessApprovals } = useQuery({
    queryKey: ["/api/admin/access-approvals"],
    queryFn: api.admin.accessApprovals.list,
  });

  const { data: pendingPolicies } = useQuery({
    queryKey: ["/api/admin/ssh-policies/pending"],
    queryFn: api.admin.sshPolicies.listPending,
  });

  const accessPendingCount = accessApprovals?.length || 0;
  const policyPendingCount = pendingPolicies?.policies?.filter(p => p.status === "pending" || p.status === "approved").length || 0;

  return (
    <div className="p-6 space-y-6">
      <div className="space-y-1">
        <h1
          className="text-2xl font-semibold tracking-tight flex items-center gap-2"
          data-testid="admin-approvals-title"
        >
          <CheckSquare className="h-6 w-6" />
          Approvals
        </h1>
        <p className="text-muted-foreground">
          Review and approve pending access requests and policy changes.
        </p>
      </div>

      <Card>
        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as TabType)}>
          <div className="p-4 border-b border-border">
            <TabsList>
              <TabsTrigger value="access" className="flex items-center gap-2">
                Access
                {accessPendingCount > 0 && (
                  <Badge
                    variant="destructive"
                    className="ml-1 h-5 min-w-5 p-0 flex items-center justify-center text-xs"
                  >
                    {accessPendingCount > 99 ? "99+" : accessPendingCount}
                  </Badge>
                )}
              </TabsTrigger>
              <TabsTrigger value="policies" className="flex items-center gap-2">
                Policies
                {policyPendingCount > 0 && (
                  <Badge
                    variant="destructive"
                    className="ml-1 h-5 min-w-5 p-0 flex items-center justify-center text-xs"
                  >
                    {policyPendingCount > 99 ? "99+" : policyPendingCount}
                  </Badge>
                )}
              </TabsTrigger>
            </TabsList>
          </div>

          <CardContent className="p-0">
            <TabsContent value="access" className="m-0">
              <AccessApprovalsTab />
            </TabsContent>

            <TabsContent value="policies" className="m-0">
              <PolicyApprovalsTab />
            </TabsContent>
          </CardContent>
        </Tabs>
      </Card>
    </div>
  );
}
