import { useState, useEffect, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
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
import { api, AccessApproval } from "@/lib/api";
import { CheckSquare, X, Upload, User, Shield, FileKey, Eye } from "lucide-react";

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
    setApprovals([]);
    setIsLoading(true);
    try {
      const data = await api.admin.accessApprovals.list();
      setApprovals(data);
      // Invalidate query cache so badge count updates
      queryClient.invalidateQueries({ queryKey: ["/api/admin/access-approvals"] });
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

  // Fetch approvals on mount and when vuid changes
  useEffect(() => {
    fetchAccessApprovals();
  }, [vuid, fetchAccessApprovals]);

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
      await fetchAccessApprovals();
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
        await fetchAccessApprovals();
      } else if (response.denied) {
        // Submit rejection
        await api.admin.accessApprovals.reject(approval.retrievalInfo);
        toast({ title: "Access request denied" });
        // Small delay to allow TideCloak to process the change
        await new Promise((resolve) => setTimeout(resolve, 500));
        await fetchAccessApprovals();
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
      await fetchAccessApprovals();
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

  if (isLoading) {
    return (
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
    );
  }

  if (!approvals || approvals.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <User className="h-12 w-12 text-muted-foreground mb-4" />
        <h3 className="font-medium">No pending access requests</h3>
        <p className="text-sm text-muted-foreground mt-1">
          User access change requests will appear here.
        </p>
      </div>
    );
  }

  return (
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
                      ? "bg-green-50 text-green-700 border-green-200"
                      : "bg-yellow-50 text-yellow-700 border-yellow-200"
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
                  className={approval.commitReady ? "text-cyan-600" : ""}
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
  );
}

// Policy Approvals Tab Component (placeholder for future policy-related approvals)
function PolicyApprovalsTab() {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      <FileKey className="h-12 w-12 text-muted-foreground mb-4" />
      <h3 className="font-medium">No pending policy changes</h3>
      <p className="text-sm text-muted-foreground mt-1">
        Policy configuration changes will appear here for approval.
      </p>
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

  const accessPendingCount = accessApprovals?.length || 0;

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
