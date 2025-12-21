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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScrollText, Activity, Shield } from "lucide-react";
import { api, type TidecloakEvent, type SshPolicyLog } from "@/lib/api";
import { AdminSessionHistoryContent } from "@/pages/AdminSessions";
import { queryClient } from "@/lib/queryClient";
import { useAutoRefresh } from "@/hooks/useAutoRefresh";

type LogsTab = "access" | "sessions" | "policies";

type PageSizeMode = "auto" | "manual";

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
            className="h-[max(240px,calc(100vh-420px))] md:h-[max(320px,calc(100vh-360px))]"
          >
            <Table containerClassName="h-full overflow-x-auto overflow-y-hidden">
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
  const [page, setPage] = useState(0);
  const [pageSizeMode, setPageSizeMode] = useState<PageSizeMode>("auto");
  const [pageSize, setPageSize] = useState(100);
  const accessTableViewportRef = useRef<HTMLDivElement>(null);

  const tabFromUrl = useMemo<LogsTab>(() => {
    const params = new URLSearchParams(search);
    const tab = params.get("tab");
    if (tab === "sessions") return "sessions";
    if (tab === "policies") return "policies";
    return "access";
  }, [search]);

  const { data: accessEvents, isLoading: accessEventsLoading, refetch: refetchAccess } = useQuery({
    queryKey: ["/api/admin/logs/access", page, pageSize],
    queryFn: () => api.admin.logs.access(pageSize, page * pageSize),
    enabled: tabFromUrl === "access",
  });

  const { data: policyLogsData, isLoading: policyLogsLoading, refetch: refetchPolicies } = useQuery({
    queryKey: ["/api/admin/ssh-policies/logs"],
    queryFn: () => api.admin.sshPolicies.getLogs(100, 0),
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
    setPage(0);
  }, [tabFromUrl, pageSize]);

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
        <Button
          variant="outline"
          onClick={() => void refreshNow()}
          disabled={isFetching}
          data-testid="refresh-logs"
          title="Refresh now"
        >
          Refresh{secondsRemaining !== null ? ` (auto in ${secondsRemaining}s)` : ""}
        </Button>
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
            page={page}
            pageSize={pageSize}
            pageSizeSelectValue={pageSizeMode === "auto" ? "auto" : String(pageSize)}
            onPageChange={setPage}
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
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="min-w-[190px]">Timestamp</TableHead>
                      <TableHead className="min-w-[100px]">Action</TableHead>
                      <TableHead className="min-w-[180px]">Role</TableHead>
                      <TableHead className="min-w-[200px]">User</TableHead>
                      <TableHead className="min-w-[200px]">Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {policyLogs.map((log) => (
                      <TableRow key={log.id}>
                        <TableCell className="text-sm whitespace-nowrap">
                          {formatEventTimestamp(log.createdAt * 1000)}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={
                              log.action === "created" ? "bg-blue-50 text-blue-700 border-blue-200" :
                              log.action === "approved" ? "bg-green-50 text-green-700 border-green-200" :
                              log.action === "rejected" ? "bg-red-50 text-red-700 border-red-200" :
                              log.action === "committed" ? "bg-purple-50 text-purple-700 border-purple-200" :
                              log.action === "cancelled" ? "bg-gray-50 text-gray-700 border-gray-200" :
                              ""
                            }
                          >
                            {log.action}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm font-mono">{log.roleId || "-"}</TableCell>
                        <TableCell className="text-sm">{log.performedByEmail || log.performedBy}</TableCell>
                        <TableCell className="text-sm text-muted-foreground">{log.details || "-"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
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
    </div>
  );
}
