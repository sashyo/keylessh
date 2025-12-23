import { useEffect, useMemo, useRef, useState } from "react";
import type { RefObject } from "react";
import { useIsFetching, useQuery } from "@tanstack/react-query";
import { useLocation, useSearch } from "wouter";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
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
import { ScrollText, Activity, Shield, Plus, Check, X, Upload, Ban, Eye } from "lucide-react";
import { api, type TidecloakEvent, type SshPolicyLog, type PendingSshPolicy } from "@/lib/api";
import { AdminSessionHistoryContent } from "@/pages/AdminSessions";
import { queryClient } from "@/lib/queryClient";
import { useAutoRefresh } from "@/hooks/useAutoRefresh";
import { RefreshButton } from "@/components/RefreshButton";

type LogsTab = "access" | "sessions" | "policies";

type PageSizeMode = "auto" | "manual";

function getActionIcon(action: string) {
  switch (action) {
    case "created":
      return <Plus className="h-4 w-4" />;
    case "approved":
      return <Check className="h-4 w-4" />;
    case "rejected":
    case "denied":
      return <X className="h-4 w-4" />;
    case "committed":
      return <Upload className="h-4 w-4" />;
    case "cancelled":
      return <Ban className="h-4 w-4" />;
    default:
      return <Activity className="h-4 w-4" />;
  }
}

function getActionColor(action: string) {
  switch (action) {
    case "created":
      return "text-blue-600 dark:text-blue-400";
    case "approved":
      return "text-green-600 dark:text-green-400";
    case "rejected":
    case "denied":
      return "text-red-600 dark:text-red-400";
    case "committed":
      return "text-purple-600 dark:text-purple-400";
    case "cancelled":
      return "text-gray-500 dark:text-gray-400";
    default:
      return "text-muted-foreground";
  }
}

function formatEventTimestamp(timestampMs: number) {
  const date = new Date(timestampMs);
  return date.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });
}

function computeRowsForViewportHeight(viewportHeight: number): number {
  const headerPx = 48;
  const rowPx = 44;
  const availablePx = Math.max(0, viewportHeight - headerPx);
  const rows = Math.floor(availablePx / rowPx);
  return Math.max(5, Math.min(200, rows));
}

function AccessLogsTable({
  events,
  isLoading,
  page,
  pageSize,
  pageSizeSelectValue,
  onPageChange,
  onPageSizeSelect,
  tableViewportRef,
}: {
  events?: TidecloakEvent[];
  isLoading: boolean;
  page: number;
  pageSize: number;
  pageSizeSelectValue: string;
  onPageChange: (page: number) => void;
  onPageSizeSelect: (value: string) => void;
  tableViewportRef: RefObject<HTMLDivElement>;
}) {
  const hasNextPage = (events?.length || 0) === pageSize;

  return (
    <Card>
      <CardContent className="p-0">
        <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-border">
          <div className="text-sm text-muted-foreground">
            Page <span className="font-medium text-foreground">{page + 1}</span>
          </div>
          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 text-sm text-muted-foreground">
              Page size
              <Select
                value={pageSizeSelectValue}
                onValueChange={onPageSizeSelect}
              >
                <SelectTrigger className="h-8 w-[92px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="auto">Auto</SelectItem>
                  {[25, 50, 100, 200].map((size) => (
                    <SelectItem key={size} value={String(size)}>
                      {size}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => onPageChange(Math.max(0, page - 1))}
                disabled={page === 0 || isLoading}
              >
                Previous
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => onPageChange(page + 1)}
                disabled={!hasNextPage || isLoading}
              >
                Next
              </Button>
            </div>
          </div>
        </div>

        {isLoading ? (
          <div className="p-4 space-y-3">
            {[1, 2, 3, 4, 5].map((i) => (
                <div key={i} className="flex items-center gap-4">
                  <Skeleton className="h-4 w-40" />
                  <Skeleton className="h-4 w-28" />
                  <Skeleton className="h-4 w-40" />
                  <Skeleton className="h-4 w-44" />
                </div>
              ))}
            </div>
        ) : events && events.length > 0 ? (
          <div
            ref={tableViewportRef}
            className="h-[max(240px,calc(100vh-420px))] md:h-[max(320px,calc(100vh-360px))] overflow-auto"
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="min-w-[190px]">Timestamp</TableHead>
                  <TableHead className="min-w-[130px]">Event</TableHead>
                  <TableHead className="min-w-[180px]">Username</TableHead>
                  <TableHead className="min-w-[260px]">User ID</TableHead>
                  <TableHead className="min-w-[160px]">IP Address</TableHead>
                  <TableHead className="min-w-[200px]">Client</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((event) => (
                  <TableRow key={event.id}>
                    <TableCell className="text-sm whitespace-nowrap">
                      {formatEventTimestamp(event.time)}
                    </TableCell>
                    <TableCell className="text-sm">{event.type}</TableCell>
                    <TableCell className="text-sm">{event.details?.username || "-"}</TableCell>
                    <TableCell className="text-sm font-mono">{event.userId || "-"}</TableCell>
                    <TableCell className="text-sm font-mono">{event.ipAddress || "-"}</TableCell>
                    <TableCell className="text-sm font-mono">{event.clientId || "-"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <ScrollText className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="font-medium">No access logs found</h3>
            <p className="text-sm text-muted-foreground mt-1">
              TideCloak user events for this client will appear here (e.g. LOGIN)
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function AdminLogs() {
  const [, setLocation] = useLocation();
  const search = useSearch();
  const [accessPage, setAccessPage] = useState(0);
  const [policyPage, setPolicyPage] = useState(0);
  const [pageSizeMode, setPageSizeMode] = useState<PageSizeMode>("auto");
  const [policyPageSizeMode, setPolicyPageSizeMode] = useState<PageSizeMode>("auto");
  const [pageSize, setPageSize] = useState(100);
  const [policyPageSize, setPolicyPageSize] = useState(50);
  const accessTableViewportRef = useRef<HTMLDivElement>(null);
  const policyTableViewportRef = useRef<HTMLDivElement>(null);

  const tabFromUrl = useMemo<LogsTab>(() => {
    const params = new URLSearchParams(search);
    const tab = params.get("tab");
    if (tab === "sessions") return "sessions";
    if (tab === "policies") return "policies";
    return "access";
  }, [search]);

  const { data: accessEvents, isLoading: accessEventsLoading, refetch: refetchAccess } = useQuery({
    queryKey: ["/api/admin/logs/access", accessPage, pageSize],
    queryFn: () => api.admin.logs.access(pageSize, accessPage * pageSize),
    enabled: tabFromUrl === "access",
  });

  const { data: policyLogsData, isLoading: policyLogsLoading, refetch: refetchPolicies } = useQuery({
    queryKey: ["/api/admin/ssh-policies/logs", policyPage, policyPageSize],
    queryFn: () => api.admin.sshPolicies.getLogs(policyPageSize, policyPage * policyPageSize),
    enabled: tabFromUrl === "policies",
  });

  const isFetchingAccess = useIsFetching({ queryKey: ["/api/admin/logs/access"] }) > 0;
  const isFetchingSessions = useIsFetching({ queryKey: ["/api/admin/sessions"] }) > 0;
  const isFetchingPolicies = useIsFetching({ queryKey: ["/api/admin/ssh-policies/logs"] }) > 0;
  const isFetching = tabFromUrl === "access" ? isFetchingAccess : tabFromUrl === "sessions" ? isFetchingSessions : isFetchingPolicies;

  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 15,
    refresh: async () => {
      if (tabFromUrl === "access") {
        await refetchAccess();
        return;
      }
      if (tabFromUrl === "policies") {
        await refetchPolicies();
        return;
      }
      await queryClient.refetchQueries({ queryKey: ["/api/admin/sessions"] });
    },
    isBlocked: isFetching,
  });

  useEffect(() => {
    setAccessPage(0);
  }, [tabFromUrl, pageSize]);

  useEffect(() => {
    setPolicyPage(0);
  }, [tabFromUrl, policyPageSize]);

  useEffect(() => {
    if (pageSizeMode !== "auto") return;
    const el = accessTableViewportRef.current;
    if (!el) return;

    const ro = new ResizeObserver((entries) => {
      const h = entries[0]?.contentRect.height ?? 0;
      if (!h) return;
      setPageSize(computeRowsForViewportHeight(h));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [pageSizeMode, tabFromUrl, accessEventsLoading]);

  useEffect(() => {
    if (policyPageSizeMode !== "auto") return;
    const el = policyTableViewportRef.current;
    if (!el) return;

    const ro = new ResizeObserver((entries) => {
      const h = entries[0]?.contentRect.height ?? 0;
      if (!h) return;
      setPolicyPageSize(computeRowsForViewportHeight(h));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [policyPageSizeMode, tabFromUrl, policyLogsLoading]);

  const handleTabChange = (value: string) => {
    if (value === "sessions") {
      setLocation("/admin/logs?tab=sessions");
    } else if (value === "policies") {
      setLocation("/admin/logs?tab=policies");
    } else {
      setLocation("/admin/logs?tab=access");
    }
  };

  const policyLogs = policyLogsData?.logs || [];
  const [selectedPolicyId, setSelectedPolicyId] = useState<string | null>(null);
  const [policyDetails, setPolicyDetails] = useState<{ policy: PendingSshPolicy; decisions: any[] } | null>(null);
  const [policyDetailsLoading, setPolicyDetailsLoading] = useState(false);

  const handleViewPolicy = async (policyId: string) => {
    setSelectedPolicyId(policyId);
    setPolicyDetailsLoading(true);
    try {
      const result = await api.admin.sshPolicies.getPending(policyId);
      setPolicyDetails(result);
    } catch (error) {
      console.error("Failed to fetch policy details:", error);
      setPolicyDetails(null);
    } finally {
      setPolicyDetailsLoading(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <ScrollText className="h-6 w-6" />
            Logs
          </h1>
          <p className="text-muted-foreground">
            Review access changes and SSH session activity
          </p>
        </div>
        <RefreshButton
          onClick={() => void refreshNow()}
          isRefreshing={isFetching}
          secondsRemaining={secondsRemaining}
          data-testid="refresh-logs"
          title="Refresh now"
        />
      </div>

      <Tabs value={tabFromUrl} onValueChange={handleTabChange}>
        <TabsList>
          <TabsTrigger value="access">Access</TabsTrigger>
          <TabsTrigger value="sessions" className="gap-2">
            <Activity className="h-4 w-4" />
            Sessions
          </TabsTrigger>
          <TabsTrigger value="policies" className="gap-2">
            <Shield className="h-4 w-4" />
            Policies
          </TabsTrigger>
        </TabsList>

        <TabsContent value="access">
          <AccessLogsTable
            events={accessEvents as TidecloakEvent[] | undefined}
            isLoading={accessEventsLoading}
            page={accessPage}
            pageSize={pageSize}
            pageSizeSelectValue={pageSizeMode === "auto" ? "auto" : String(pageSize)}
            onPageChange={setAccessPage}
            onPageSizeSelect={(v) => {
              if (v === "auto") {
                setPageSizeMode("auto");
                return;
              }
              setPageSizeMode("manual");
              setPageSize(parseInt(v, 10));
            }}
            tableViewportRef={accessTableViewportRef}
          />
        </TabsContent>

        <TabsContent value="sessions">
          <AdminSessionHistoryContent embedded />
        </TabsContent>

        <TabsContent value="policies">
          <Card>
            <CardContent className="p-0">
              {/* Pagination controls */}
              <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-border">
                <div className="text-sm text-muted-foreground">
                  Page <span className="font-medium text-foreground">{policyPage + 1}</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="hidden sm:flex items-center gap-2 text-sm text-muted-foreground">
                    Page size
                    <Select
                      value={policyPageSizeMode === "auto" ? "auto" : String(policyPageSize)}
                      onValueChange={(v) => {
                        if (v === "auto") {
                          setPolicyPageSizeMode("auto");
                          return;
                        }
                        setPolicyPageSizeMode("manual");
                        setPolicyPageSize(parseInt(v, 10));
                      }}
                    >
                      <SelectTrigger className="h-8 w-[92px]">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="auto">Auto</SelectItem>
                        {[25, 50, 100].map((size) => (
                          <SelectItem key={size} value={String(size)}>
                            {size}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setPolicyPage(Math.max(0, policyPage - 1))}
                      disabled={policyPage === 0 || policyLogsLoading}
                    >
                      Previous
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setPolicyPage(policyPage + 1)}
                      disabled={policyLogs.length < policyPageSize || policyLogsLoading}
                    >
                      Next
                    </Button>
                  </div>
                </div>
              </div>

              {policyLogsLoading ? (
                <div className="p-4 space-y-3">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <div key={i} className="flex items-center gap-4">
                      <Skeleton className="h-4 w-40" />
                      <Skeleton className="h-4 w-28" />
                      <Skeleton className="h-4 w-40" />
                    </div>
                  ))}
                </div>
              ) : policyLogs.length > 0 ? (
                <div
                  ref={policyTableViewportRef}
                  className="h-[max(240px,calc(100vh-420px))] md:h-[max(320px,calc(100vh-360px))] overflow-auto"
                >
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="min-w-[190px]">Timestamp</TableHead>
                        <TableHead className="min-w-[110px]">Action</TableHead>
                        <TableHead className="min-w-[180px]">Role</TableHead>
                        <TableHead className="min-w-[200px]">Performed By</TableHead>
                        <TableHead className="min-w-[120px]">Progress</TableHead>
                        <TableHead className="min-w-[110px]">Status</TableHead>
                        <TableHead className="min-w-[80px]">Details</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {policyLogs.map((log) => (
                        <TableRow key={log.id}>
                          <TableCell className="text-sm whitespace-nowrap">
                            {formatEventTimestamp(log.createdAt * 1000)}
                          </TableCell>
                          <TableCell>
                            <div className={`flex items-center gap-1.5 text-sm font-medium ${getActionColor(log.action)}`}>
                              {getActionIcon(log.action)}
                              <span className="capitalize">{log.action === "denied" ? "rejected" : log.action}</span>
                            </div>
                          </TableCell>
                          <TableCell className="text-sm font-mono">{log.roleId || "N/A"}</TableCell>
                          <TableCell className="text-sm">{log.performedByEmail || log.performedBy}</TableCell>
                          <TableCell className="text-sm">
                            {log.policyThreshold ? (
                              <div className="flex items-center gap-1">
                                <span className="text-green-600 dark:text-green-400">{log.approvalCount || 0}</span>
                                <span className="text-muted-foreground">/</span>
                                <span>{log.policyThreshold}</span>
                                {(log.rejectionCount ?? 0) > 0 && (
                                  <span className="text-red-600 dark:text-red-400 text-xs ml-1">
                                    ({log.rejectionCount} ✗)
                                  </span>
                                )}
                              </div>
                            ) : (
                              <span className="text-muted-foreground">-</span>
                            )}
                          </TableCell>
                          <TableCell>
                            {log.policyStatus ? (
                              <Badge
                                variant="outline"
                                className={
                                  log.policyStatus === "pending" ? "bg-yellow-50 text-yellow-700 border-yellow-200 dark:bg-yellow-950/30 dark:text-yellow-400 dark:border-yellow-800" :
                                  log.policyStatus === "approved" ? "bg-green-50 text-green-700 border-green-200 dark:bg-green-950/30 dark:text-green-400 dark:border-green-800" :
                                  log.policyStatus === "committed" ? "bg-purple-50 text-purple-700 border-purple-200 dark:bg-purple-950/30 dark:text-purple-400 dark:border-purple-800" :
                                  log.policyStatus === "cancelled" ? "bg-gray-50 text-gray-700 border-gray-200 dark:bg-gray-900/30 dark:text-gray-400 dark:border-gray-700" :
                                  ""
                                }
                              >
                                {log.policyStatus}
                              </Badge>
                            ) : (
                              <span className="text-muted-foreground text-sm">-</span>
                            )}
                          </TableCell>
                          <TableCell>
                            {log.policyId && (
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-7 px-2"
                                onClick={() => handleViewPolicy(log.policyId)}
                              >
                                <Eye className="h-4 w-4" />
                              </Button>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <Shield className="h-12 w-12 text-muted-foreground mb-4" />
                  <h3 className="font-medium">No policy logs found</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    SSH policy activity will appear here
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Policy Details Dialog */}
      <Dialog open={selectedPolicyId !== null} onOpenChange={(open) => !open && setSelectedPolicyId(null)}>
        <DialogContent className="w-[90vw] max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Policy Details
            </DialogTitle>
          </DialogHeader>
          {policyDetailsLoading ? (
            <div className="space-y-4 p-4">
              <Skeleton className="h-4 w-3/4" />
              <Skeleton className="h-4 w-1/2" />
              <Skeleton className="h-32 w-full" />
            </div>
          ) : policyDetails ? (
            <div className="space-y-6">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-muted-foreground">Role</p>
                  <p className="font-mono font-medium">{policyDetails.policy.roleId}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Status</p>
                  <Badge
                    variant="outline"
                    className={
                      policyDetails.policy.status === "pending" ? "bg-yellow-50 text-yellow-700 border-yellow-200 dark:bg-yellow-950/30 dark:text-yellow-400 dark:border-yellow-800" :
                      policyDetails.policy.status === "approved" ? "bg-green-50 text-green-700 border-green-200 dark:bg-green-950/30 dark:text-green-400 dark:border-green-800" :
                      policyDetails.policy.status === "committed" ? "bg-purple-50 text-purple-700 border-purple-200 dark:bg-purple-950/30 dark:text-purple-400 dark:border-purple-800" :
                      policyDetails.policy.status === "cancelled" ? "bg-gray-50 text-gray-700 border-gray-200 dark:bg-gray-900/30 dark:text-gray-400 dark:border-gray-700" :
                      ""
                    }
                  >
                    {policyDetails.policy.status}
                  </Badge>
                </div>
                <div>
                  <p className="text-muted-foreground">Requested By</p>
                  <p className="font-medium">{policyDetails.policy.requestedByEmail}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Threshold</p>
                  <p className="font-medium">{policyDetails.policy.threshold} approval(s) required</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Created</p>
                  <p className="font-medium">{formatEventTimestamp(policyDetails.policy.createdAt * 1000)}</p>
                </div>
              </div>

              {/* Policy Source Code */}
              <div className="min-w-0">
                <p className="text-sm text-muted-foreground mb-2">Policy Source</p>
                <div className="bg-muted/50 border rounded-lg p-4 max-h-[300px] overflow-y-auto overflow-x-hidden">
                  <pre className="text-xs font-mono whitespace-pre-wrap break-all m-0">
                    {policyDetails.policy.policyRequestData}
                  </pre>
                </div>
              </div>

              {/* Decisions */}
              {policyDetails.decisions && policyDetails.decisions.length > 0 && (
                <div>
                  <p className="text-sm text-muted-foreground mb-2">Decisions ({policyDetails.decisions.length})</p>
                  <div className="space-y-2">
                    {policyDetails.decisions.map((decision: any) => (
                      <div key={decision.id} className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-2">
                          {decision.decision ? (
                            <Check className="h-4 w-4 text-green-600 dark:text-green-400" />
                          ) : (
                            <X className="h-4 w-4 text-red-600 dark:text-red-400" />
                          )}
                          <span className="text-sm">{decision.adminEmail}</span>
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {formatEventTimestamp(decision.createdAt * 1000)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              Failed to load policy details
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
