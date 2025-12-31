import { useQuery, useMutation, useIsFetching } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
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
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Activity,
  Search,
  Clock,
  Server,
  Ban,
  ChevronDown,
  ChevronRight,
  Upload,
  Download,
  Trash2,
  FolderPlus,
  ArrowRightLeft,
  Lock,
  FolderOpen,
  FileText,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { ActiveSession } from "@shared/schema";
import { api, type FileOperationLog } from "@/lib/api";
import { queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { useAutoRefresh } from "@/hooks/useAutoRefresh";
import { RefreshButton } from "@/components/RefreshButton";

// File operation icon helper
function getFileOpIcon(operation: string) {
  switch (operation) {
    case "upload":
      return <Upload className="h-3 w-3" />;
    case "download":
      return <Download className="h-3 w-3" />;
    case "delete":
      return <Trash2 className="h-3 w-3" />;
    case "mkdir":
      return <FolderPlus className="h-3 w-3" />;
    case "rename":
      return <ArrowRightLeft className="h-3 w-3" />;
    case "chmod":
      return <Lock className="h-3 w-3" />;
    default:
      return <FolderOpen className="h-3 w-3" />;
  }
}

// File operation color helper
function getFileOpColor(operation: string) {
  switch (operation) {
    case "upload":
      return "text-green-600";
    case "download":
      return "text-blue-600";
    case "delete":
      return "text-red-600";
    case "mkdir":
      return "text-yellow-600";
    case "rename":
      return "text-purple-600";
    case "chmod":
      return "text-orange-600";
    default:
      return "text-muted-foreground";
  }
}

// Component to show file operations for a session
function SessionFileOps({ sessionId }: { sessionId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/admin/sessions", sessionId, "file-operations"],
    queryFn: () => api.admin.sessions.getFileOperations(sessionId),
  });

  if (isLoading) {
    return (
      <div className="py-2 px-4">
        <Skeleton className="h-4 w-48" />
      </div>
    );
  }

  const operations = data?.operations || [];

  if (operations.length === 0) {
    return (
      <div className="py-2 px-4 text-sm text-muted-foreground">
        No file operations recorded
      </div>
    );
  }

  return (
    <div className="py-2 px-4 space-y-1">
      {operations.map((op) => (
        <div
          key={op.id}
          className="flex items-center gap-2 text-xs py-1 px-2 rounded bg-muted/50"
        >
          <span className={cn("flex-shrink-0", getFileOpColor(op.operation))}>
            {getFileOpIcon(op.operation)}
          </span>
          <Badge variant="outline" className="text-[10px] px-1 py-0">
            {op.operation}
          </Badge>
          <span className="font-mono truncate flex-1" title={op.path}>
            {op.path}
          </span>
          {op.targetPath && (
            <>
              <span className="text-muted-foreground">→</span>
              <span className="font-mono truncate" title={op.targetPath}>
                {op.targetPath}
              </span>
            </>
          )}
          <Badge
            variant={op.status === "success" ? "default" : "destructive"}
            className="text-[10px] px-1 py-0"
          >
            {op.status}
          </Badge>
          <span className="text-muted-foreground text-[10px]">
            {new Date(op.timestamp).toLocaleTimeString()}
          </span>
        </div>
      ))}
    </div>
  );
}

type PageSizeMode = "auto" | "manual";

function computeRowsForViewportHeight(viewportHeight: number): number {
  const headerPx = 48;
  const rowPx = 72;
  const availablePx = Math.max(0, viewportHeight - headerPx);
  const rows = Math.floor(availablePx / rowPx);
  return Math.max(5, Math.min(200, rows));
}

export function AdminActiveSessionsContent({ embedded = false }: { embedded?: boolean }) {
  const [search, setSearch] = useState("");
  const [terminatingSession, setTerminatingSession] = useState<ActiveSession | null>(null);
  const { toast } = useToast();

  const { data: sessions, isLoading, refetch } = useQuery<ActiveSession[]>({
    queryKey: ["/api/admin/sessions"],
  });
  const isFetchingSessions = useIsFetching({ queryKey: ["/api/admin/sessions"] }) > 0;
  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 10,
    refresh: () => refetch(),
    isBlocked: isFetchingSessions,
  });

  const terminateMutation = useMutation({
    mutationFn: (sessionId: string) => api.admin.sessions.terminate(sessionId),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/sessions"] });
      void queryClient.refetchQueries({ queryKey: ["/api/admin/sessions"] });
      toast({
        title: "Session terminated",
        description: result.terminated ? "Connection was disconnected." : "No active connection was found, session marked completed.",
      });
      setTerminatingSession(null);
    },
    onError: (error: Error) => {
      toast({ title: "Failed to terminate session", description: error.message, variant: "destructive" });
    },
  });

  const filteredSessions = sessions?.filter(
    (session) =>
      session.serverName?.toLowerCase().includes(search.toLowerCase()) ||
      session.sshUser.toLowerCase().includes(search.toLowerCase()) ||
      session.userId.toLowerCase().includes(search.toLowerCase())
  );

  const activeSessions = filteredSessions?.filter((s) => s.status === "active") || [];

  const formatDate = (date: Date | string | null) => {
    if (!date) return "-";
    return new Date(date).toLocaleString();
  };

  const formatDuration = (start: Date | string, end?: Date | string | null) => {
    const startDate = new Date(start);
    const endDate = end ? new Date(end) : new Date();
    const diff = endDate.getTime() - startDate.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    }
    return `${minutes}m`;
  };

  return (
    <div className={cn("space-y-6", !embedded && "p-6")}>
      {!embedded && (
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2" data-testid="admin-sessions-title">
              <Activity className="h-6 w-6" />
              Manage Sessions
            </h1>
            <p className="text-muted-foreground">
              View currently active SSH sessions and terminate if needed
            </p>
          </div>
          <RefreshButton
            onClick={() => void refreshNow()}
            isRefreshing={isFetchingSessions}
            secondsRemaining={secondsRemaining}
            data-testid="refresh-admin-sessions"
            title="Refresh now"
          />
        </div>
      )}

      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search sessions..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
            data-testid="search-sessions"
          />
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="default" className="gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-chart-2 animate-pulse" />
            {activeSessions.length} Active
          </Badge>
        </div>
      </div>

      <Card>
        <div className="p-4 border-b border-border">
          <h2 className="font-medium flex items-center gap-2">
            <Activity className="h-4 w-4 text-chart-2" />
            Active Sessions
          </h2>
        </div>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4 space-y-3">
              {[1, 2, 3, 4, 5].map((i) => (
                <div key={i} className="flex items-center gap-4">
                  <Skeleton className="h-8 w-8 rounded-md" />
                  <div className="flex-1 space-y-2">
                    <Skeleton className="h-4 w-32" />
                    <Skeleton className="h-3 w-24" />
                  </div>
                  <Skeleton className="h-5 w-20" />
                </div>
              ))}
            </div>
          ) : activeSessions.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Server</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>SSH User</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {activeSessions.map((session) => (
                  <TableRow key={session.id} data-testid={`active-session-${session.id}`}>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <div className="flex h-8 w-8 items-center justify-center rounded-md bg-chart-2/10">
                          <Server className="h-4 w-4 text-chart-2" />
                        </div>
                        <div>
                          <p className="font-medium">{session.serverName}</p>
                          <p className="text-xs text-muted-foreground font-mono">
                            {session.serverHost}
                          </p>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="space-y-0.5">
                        <div className="text-sm font-medium">
                          {session.userUsername || "Unknown"}
                        </div>
                        <div className="text-xs font-mono text-muted-foreground">
                          {session.userId}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono">
                        {session.sshUser}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm">
                      {formatDate(session.startedAt)}
                    </TableCell>
                    <TableCell className="text-sm font-mono">
                      {formatDuration(session.startedAt)}
                    </TableCell>
                    <TableCell>
                      <Badge variant="default" className="gap-1.5">
                        <span className="h-1.5 w-1.5 rounded-full bg-chart-2 animate-pulse" />
                        Active
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        variant="destructive"
                        className="gap-2"
                        onClick={() => setTerminatingSession(session)}
                        data-testid={`terminate-session-${session.id}`}
                      >
                        <Ban className="h-4 w-4" />
                        Terminate
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <Activity className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="font-medium">No active sessions</h3>
              <p className="text-sm text-muted-foreground mt-1">
                {search ? "Try a different search term" : "Active SSH sessions will appear here"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <AlertDialog open={!!terminatingSession} onOpenChange={(open) => !open && setTerminatingSession(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Terminate session?</AlertDialogTitle>
            <AlertDialogDescription>
              This will immediately disconnect the user from the SSH server and mark the session as completed.
            </AlertDialogDescription>
          </AlertDialogHeader>
          {terminatingSession && (
            <div className="text-sm text-muted-foreground space-y-1">
              <div>
                <span className="font-medium text-foreground">Server:</span> {terminatingSession.serverName}{" "}
                <span className="font-mono">({terminatingSession.serverHost})</span>
              </div>
              <div>
                <span className="font-medium text-foreground">User:</span>{" "}
                <span className="font-mono">{terminatingSession.userId}</span>
              </div>
              <div>
                <span className="font-medium text-foreground">SSH User:</span>{" "}
                <span className="font-mono">{terminatingSession.sshUser}</span>
              </div>
            </div>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={terminateMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={!terminatingSession || terminateMutation.isPending}
              onClick={() => terminatingSession && terminateMutation.mutate(terminatingSession.id)}
            >
              Terminate
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

export function AdminSessionHistoryContent({ embedded = false }: { embedded?: boolean }) {
  const [historyPage, setHistoryPage] = useState(0);
  const [historyPageSizeMode, setHistoryPageSizeMode] = useState<PageSizeMode>("auto");
  const [historyPageSize, setHistoryPageSize] = useState(25);
  const historyTableViewportRef = useRef<HTMLDivElement>(null);
  const [expandedSessions, setExpandedSessions] = useState<Set<string>>(new Set());

  const toggleSessionExpanded = (sessionId: string) => {
    setExpandedSessions((prev) => {
      const next = new Set(prev);
      if (next.has(sessionId)) {
        next.delete(sessionId);
      } else {
        next.add(sessionId);
      }
      return next;
    });
  };

  const { data: sessions, isLoading } = useQuery<ActiveSession[]>({
    queryKey: ["/api/admin/sessions"],
  });

  const inactiveSessions = sessions?.filter((s) => s.status !== "active") || [];
  const historySessions = inactiveSessions.length > 0 ? inactiveSessions : sessions || [];

  useEffect(() => {
    setHistoryPage(0);
  }, [historyPageSize]);

  useEffect(() => {
    if (historyPageSizeMode !== "auto") return;
    const el = historyTableViewportRef.current;
    if (!el) return;

    const ro = new ResizeObserver((entries) => {
      const h = entries[0]?.contentRect.height ?? 0;
      if (!h) return;
      setHistoryPageSize(computeRowsForViewportHeight(h));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [historyPageSizeMode, historySessions.length, embedded]);

  const historyTotal = historySessions.length;
  const historyPageCount = Math.max(1, Math.ceil(historyTotal / historyPageSize));
  const historyPageClamped = Math.min(historyPage, historyPageCount - 1);

  const pagedHistorySessions = useMemo(() => {
    const start = historyPageClamped * historyPageSize;
    const end = start + historyPageSize;
    return historySessions.slice(start, end);
  }, [historySessions, historyPageClamped, historyPageSize]);

  const formatDate = (date: Date | string | null) => {
    if (!date) return "-";
    return new Date(date).toLocaleString();
  };

  const formatDuration = (start: Date | string, end?: Date | string | null) => {
    const startDate = new Date(start);
    const endDate = end ? new Date(end) : new Date();
    const diff = endDate.getTime() - startDate.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    }
    return `${minutes}m`;
  };

  const cardContent = (
    <Card>
        <div className="p-4 border-b border-border">
          <div className="flex items-center justify-between gap-3">
            <h2 className="font-medium flex items-center gap-2">
              <Clock className="h-4 w-4" />
              Sessions
            </h2>
            <div className="flex items-center gap-2">
              <div className="hidden sm:flex items-center gap-2 text-sm text-muted-foreground">
                Page size
                <Select
                  value={historyPageSizeMode === "auto" ? "auto" : String(historyPageSize)}
                  onValueChange={(v) => {
                    if (v === "auto") {
                      setHistoryPageSizeMode("auto");
                      return;
                    }
                    setHistoryPageSizeMode("manual");
                    setHistoryPageSize(parseInt(v, 10));
                  }}
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
              <Button
                size="sm"
                variant="outline"
                onClick={() => setHistoryPage(Math.max(0, historyPageClamped - 1))}
                disabled={historyPageClamped === 0 || isLoading}
              >
                Previous
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setHistoryPage(historyPageClamped + 1)}
                disabled={historyPageClamped + 1 >= historyPageCount || isLoading}
              >
                Next
              </Button>
            </div>
          </div>
        </div>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4 space-y-3">
              {[1, 2, 3, 4, 5].map((i) => (
                <div key={i} className="flex items-center gap-4">
                  <Skeleton className="h-8 w-8 rounded-md" />
                  <div className="flex-1 space-y-2">
                    <Skeleton className="h-4 w-32" />
                    <Skeleton className="h-3 w-24" />
                  </div>
                  <Skeleton className="h-5 w-20" />
                </div>
              ))}
            </div>
          ) : historySessions.length > 0 ? (
            <div
              ref={historyTableViewportRef}
              className="h-[max(240px,calc(100vh-420px))] md:h-[max(320px,calc(100vh-360px))] overflow-auto"
            >
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[40px]"></TableHead>
                    <TableHead>Server</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead>SSH User</TableHead>
                    <TableHead>Started</TableHead>
                    <TableHead>Ended</TableHead>
                    <TableHead>Duration</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pagedHistorySessions.map((session) => {
                    const isExpanded = expandedSessions.has(session.id);
                    return (
                      <>
                        <TableRow
                          key={session.id}
                          data-testid={`session-${session.id}`}
                          className="cursor-pointer hover:bg-muted/50"
                          onClick={() => toggleSessionExpanded(session.id)}
                        >
                          <TableCell className="w-[40px]">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 w-6 p-0"
                              onClick={(e) => {
                                e.stopPropagation();
                                toggleSessionExpanded(session.id);
                              }}
                            >
                              {isExpanded ? (
                                <ChevronDown className="h-4 w-4" />
                              ) : (
                                <ChevronRight className="h-4 w-4" />
                              )}
                            </Button>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-3">
                              <div className="flex h-8 w-8 items-center justify-center rounded-md bg-muted">
                                <Server className="h-4 w-4 text-muted-foreground" />
                              </div>
                              <div>
                                <p className="font-medium">{session.serverName}</p>
                                <p className="text-xs text-muted-foreground font-mono">
                                  {session.serverHost}
                                </p>
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <div className="space-y-0.5">
                              <div className="text-sm font-medium">
                                {session.userUsername || "Unknown"}
                              </div>
                              <div className="text-xs font-mono text-muted-foreground">
                                {session.userId}
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className="font-mono">
                              {session.sshUser}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-sm">
                            {formatDate(session.startedAt)}
                          </TableCell>
                          <TableCell className="text-sm">
                            {formatDate(session.endedAt)}
                          </TableCell>
                          <TableCell className="text-sm font-mono">
                            {formatDuration(session.startedAt, session.endedAt)}
                          </TableCell>
                          <TableCell>
                            <Badge variant={session.status === "active" ? "default" : "secondary"}>
                              {session.status === "active" ? "Active" : "Completed"}
                            </Badge>
                          </TableCell>
                        </TableRow>
                        {isExpanded && (
                          <TableRow key={`${session.id}-fileops`} className="bg-muted/30">
                            <TableCell colSpan={8} className="p-0">
                              <div className="border-l-4 border-primary/20">
                                <div className="flex items-center gap-2 px-4 py-2 bg-muted/50 border-b">
                                  <FileText className="h-4 w-4 text-muted-foreground" />
                                  <span className="text-sm font-medium">File Operations</span>
                                </div>
                                <SessionFileOps sessionId={session.id} />
                              </div>
                            </TableCell>
                          </TableRow>
                        )}
                      </>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <Clock className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="font-medium">No session history</h3>
              <p className="text-sm text-muted-foreground mt-1">
                Completed sessions will appear here
              </p>
            </div>
          )}
        </CardContent>
      </Card>
  );

  if (embedded) {
    return cardContent;
  }

  return (
    <div className="p-6 space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
          <Clock className="h-6 w-6" />
          Session History
        </h1>
        <p className="text-muted-foreground">
          Review historical SSH sessions
        </p>
      </div>
      {cardContent}
    </div>
  );
}

export default function AdminSessions() {
  return <AdminActiveSessionsContent />;
}
