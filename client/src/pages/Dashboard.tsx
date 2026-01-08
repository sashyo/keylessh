import { useAuth } from "@/contexts/AuthContext";
import { useIsFetching, useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Server, Terminal, Clock, Activity, ArrowRight, HelpCircle, AlertCircle, X } from "lucide-react";
import { useCallback, useState } from "react";
import type { ServerWithAccess, ActiveSession } from "@shared/schema";
import { useAutoRefresh } from "@/hooks/useAutoRefresh";
import { RefreshButton } from "@/components/RefreshButton";
import { api } from "@/lib/api";

function ServerCard({ server, sshBlocked }: { server: ServerWithAccess; sshBlocked?: boolean }) {
  const [selectedUser, setSelectedUser] = useState<string>(server.allowedSshUsers[0] || "");
  const hasAnySshUser = server.allowedSshUsers.length > 0;
  const isDisabled = !server.enabled || server.status === "offline" || !selectedUser || sshBlocked;

  return (
    <Card className="group cyber-card hover-neon-glow" data-testid={`server-card-${server.id}`}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[hsl(var(--neon-cyan)/0.15)] border border-[hsl(var(--neon-cyan)/0.3)] group-hover:border-[hsl(var(--neon-cyan)/0.5)] transition-colors">
              <Server className="h-5 w-5 text-[hsl(var(--neon-cyan))]" />
            </div>
            <div>
              <CardTitle className="text-base">{server.name}</CardTitle>
              <CardDescription className="font-mono text-xs">
                {server.host}:{server.port}
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {server.status === "online" ? (
              <Badge variant="outline" className="gap-1.5 label-success">
                <span className="h-2 w-2 rounded-full bg-[hsl(var(--neon-green))] animate-pulse" />
                Online
              </Badge>
            ) : server.status === "offline" ? (
              <Badge variant="outline" className="gap-1.5 label-danger">
                <span className="h-2 w-2 rounded-full bg-[hsl(var(--neon-red))]" />
                Offline
              </Badge>
            ) : (
              <Badge variant="outline" className="gap-1.5">
                <HelpCircle className="h-3 w-3" />
                Unknown
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-1.5">
          <Badge variant="secondary" className="text-xs">
            {server.environment}
          </Badge>
          {server.tags?.map((tag) => (
            <Badge key={tag} variant="outline" className="text-xs">
              {tag}
            </Badge>
          ))}
        </div>

        <div className="space-y-2">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            SSH User
          </label>
          <Select value={selectedUser} onValueChange={setSelectedUser} disabled={!hasAnySshUser}>
            <SelectTrigger className="w-full" data-testid={`select-ssh-user-${server.id}`}>
              <SelectValue placeholder="Select SSH user" />
            </SelectTrigger>
            <SelectContent>
              {server.allowedSshUsers.map((user) => (
                <SelectItem key={user} value={user}>
                  {user}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {!hasAnySshUser && (
            <p className="text-xs text-muted-foreground">
              No SSH usernames are permitted for your account on this server. Ask an admin to grant a role like{" "}
              <span className="font-mono">ssh:{server.sshUsers?.[0] || "root"}</span>.
            </p>
          )}
        </div>

        {isDisabled ? (
          <Button
            className="w-full gap-2"
            disabled
            data-testid={`connect-button-${server.id}`}
          >
            <Terminal className="h-4 w-4" />
            {sshBlocked ? "SSH Disabled" : "Connect"}
            <ArrowRight className="h-4 w-4" />
          </Button>
        ) : (
          <Link href={`/app/console?serverId=${encodeURIComponent(server.id)}&user=${encodeURIComponent(selectedUser)}`}>
            <Button
              className="w-full gap-2 btn-primary-glow"
              data-testid={`connect-button-${server.id}`}
            >
              <Terminal className="h-4 w-4" />
              Connect
              <ArrowRight className="h-4 w-4" />
            </Button>
          </Link>
        )}
      </CardContent>
    </Card>
  );
}

function ServerCardSkeleton() {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <Skeleton className="h-10 w-10 rounded-lg" />
            <div className="space-y-2">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-3 w-24" />
            </div>
          </div>
          <Skeleton className="h-6 w-16" />
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-1.5">
          <Skeleton className="h-5 w-20" />
          <Skeleton className="h-5 w-16" />
        </div>
        <div className="space-y-2">
          <Skeleton className="h-3 w-16" />
          <Skeleton className="h-9 w-full" />
        </div>
        <Skeleton className="h-9 w-full" />
      </CardContent>
    </Card>
  );
}

function SessionItem({ session, onTerminate }: { session: ActiveSession; onTerminate: (id: string) => void }) {
  const [terminating, setTerminating] = useState(false);

  const handleTerminate = async () => {
    setTerminating(true);
    try {
      await onTerminate(session.id);
    } finally {
      setTerminating(false);
    }
  };

  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 py-3 px-4 hover-elevate rounded-md group" data-testid={`session-${session.id}`}>
      <div className="flex items-center gap-3 min-w-0">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-[hsl(var(--neon-green)/0.15)] border border-[hsl(var(--neon-green)/0.3)]">
          <Activity className="h-5 w-5 text-[hsl(var(--neon-green))]" />
        </div>
        <div className="min-w-0">
          <p className="text-sm font-medium truncate">{session.serverName}</p>
          <p className="text-xs text-muted-foreground font-mono truncate">
            {session.sshUser}@{session.serverHost}
          </p>
        </div>
      </div>
      <div className="flex items-center justify-between sm:justify-end gap-3 pl-13 sm:pl-0">
        <Badge variant="outline" className="text-xs gap-1 label-success shrink-0">
          <span className="h-1.5 w-1.5 rounded-full bg-[hsl(var(--neon-green))] animate-pulse" />
          Active
        </Badge>
        <div className="flex items-center gap-1">
          <Link href={`/app/console?serverId=${encodeURIComponent(session.serverId)}&user=${encodeURIComponent(session.sshUser)}`}>
            <Button size="sm" variant="ghost" className="group-hover:text-[hsl(var(--neon-cyan))] min-h-[44px] min-w-[44px]" data-testid={`reconnect-session-${session.id}`}>
              Reconnect
            </Button>
          </Link>
          <Button
            size="sm"
            variant="ghost"
            className="text-muted-foreground hover:text-destructive min-h-[44px] min-w-[44px]"
            onClick={handleTerminate}
            disabled={terminating}
            data-testid={`terminate-session-${session.id}`}
            title="Terminate session"
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { user } = useAuth();

  const { data: servers, isLoading: serversLoading, refetch: refetchServers } = useQuery<ServerWithAccess[]>({
    queryKey: ["/api/servers"],
  });

  const { data: sessions, isLoading: sessionsLoading, refetch: refetchSessions } = useQuery<ActiveSession[]>({
    queryKey: ["/api/sessions"],
  });

  const { data: sshAccessStatus } = useQuery({
    queryKey: ["/api/ssh/access-status"],
    queryFn: api.ssh.getAccessStatus,
  });

  const isSshBlocked = sshAccessStatus?.blocked === true;

  const isFetchingServers = useIsFetching({ queryKey: ["/api/servers"] }) > 0;
  const isFetchingSessions = useIsFetching({ queryKey: ["/api/sessions"] }) > 0;
  const isFetching = isFetchingServers || isFetchingSessions;

  const refreshAll = useCallback(async () => {
    await Promise.all([refetchServers(), refetchSessions()]);
  }, [refetchServers, refetchSessions]);

  const terminateSession = useCallback(async (sessionId: string) => {
    const token = localStorage.getItem("access_token");
    if (!token) return;

    await fetch(`/api/sessions/${sessionId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    await refetchSessions();
  }, [refetchSessions]);

  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 15,
    refresh: refreshAll,
    isBlocked: isFetching,
  });

  const activeSessions = sessions?.filter((s) => s.status === "active") || [];
  const recentSessions = sessions?.filter((s) => s.status !== "active").slice(0, 5) || [];

  return (
    <div className="p-4 sm:p-6 space-y-6 sm:space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-xl sm:text-2xl font-semibold tracking-tight" data-testid="dashboard-title">
            Welcome back, {user?.username}
          </h1>
          <p className="text-sm sm:text-base text-muted-foreground">
            Connect to your servers and manage your SSH sessions
          </p>
        </div>
        <RefreshButton
          onClick={() => void refreshNow()}
          isRefreshing={isFetching}
          secondsRemaining={secondsRemaining}
          data-testid="refresh-dashboard"
          title="Refresh now"
          className="self-end sm:self-auto"
        />
      </div>

      {isSshBlocked && (
        <Alert className="bg-red-50 border-red-200 dark:bg-red-950/20 dark:border-red-800">
          <AlertCircle className="h-4 w-4 text-red-600 dark:text-red-400" />
          <AlertDescription className="text-red-800 dark:text-red-200">
            <strong>SSH access disabled.</strong>{" "}
            {sshAccessStatus?.reason || "Your organization has exceeded the user limit. Please contact an administrator."}
          </AlertDescription>
        </Alert>
      )}

      {activeSessions.length > 0 && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base sm:text-lg font-medium flex items-center gap-2">
              <Activity className="h-5 w-5 text-[hsl(var(--neon-green))]" />
              Active Sessions
            </h2>
            <Badge variant="secondary" className="label-info">{activeSessions.length}</Badge>
          </div>
          <Card>
            <CardContent className="p-0 divide-y divide-border">
              {activeSessions.map((session) => (
                <SessionItem key={session.id} session={session} onTerminate={terminateSession} />
              ))}
            </CardContent>
          </Card>
        </div>
      )}

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base sm:text-lg font-medium flex items-center gap-2">
            <Server className="h-5 w-5 text-[hsl(var(--neon-cyan))]" />
            Available Servers
          </h2>
          {servers && <Badge variant="secondary" className="label-info">{servers.length}</Badge>}
        </div>

        {serversLoading ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {[1, 2, 3].map((i) => (
              <ServerCardSkeleton key={i} />
            ))}
          </div>
        ) : servers && servers.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {servers.map((server) => (
              <ServerCard key={server.id} server={server} sshBlocked={isSshBlocked} />
            ))}
          </div>
        ) : (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-12">
              <Server className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="font-medium">No servers available</h3>
              <p className="text-sm text-muted-foreground mt-1">
                Contact your administrator to get server access
              </p>
            </CardContent>
          </Card>
        )}
      </div>

      {recentSessions.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-base sm:text-lg font-medium flex items-center gap-2">
            <Clock className="h-5 w-5 text-[hsl(var(--neon-purple))]" />
            Recent Connections
          </h2>
          <Card>
            <CardContent className="p-0 divide-y divide-border">
              {recentSessions.map((session) => (
                <div key={session.id} className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 py-3 px-4">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-muted">
                      <Terminal className="h-5 w-5 text-muted-foreground" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-medium truncate">{session.serverName}</p>
                      <p className="text-xs text-muted-foreground font-mono truncate">
                        {session.sshUser}@{session.serverHost}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center justify-between sm:justify-end gap-3 pl-13 sm:pl-0">
                    <div className="text-xs text-muted-foreground">
                      {session.endedAt ? new Date(session.endedAt).toLocaleDateString() : ""}
                    </div>
                    <Link href={`/app/console?serverId=${encodeURIComponent(session.serverId)}&user=${encodeURIComponent(session.sshUser)}`}>
                      <Button size="sm" variant="ghost" className="min-h-[44px] min-w-[44px]" data-testid={`reconnect-recent-session-${session.id}`}>
                        Reconnect
                      </Button>
                    </Link>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
