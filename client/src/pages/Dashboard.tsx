import { useAuth } from "@/contexts/AuthContext";
import { useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Server, Terminal, Clock, Activity, ArrowRight, Wifi, WifiOff, HelpCircle } from "lucide-react";
import { useState } from "react";
import type { ServerWithAccess, ActiveSession } from "@shared/schema";

function ServerCard({ server }: { server: ServerWithAccess }) {
  const [selectedUser, setSelectedUser] = useState<string>(server.allowedSshUsers[0] || "");

  return (
    <Card className="group" data-testid={`server-card-${server.id}`}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
              <Server className="h-5 w-5 text-primary" />
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
              <Badge variant="outline" className="gap-1.5 bg-green-50 text-green-700 border-green-200">
                <Wifi className="h-3 w-3" />
                Online
              </Badge>
            ) : server.status === "offline" ? (
              <Badge variant="secondary" className="gap-1.5 bg-red-50 text-red-700 border-red-200">
                <WifiOff className="h-3 w-3" />
                Offline
              </Badge>
            ) : (
              <Badge variant="secondary" className="gap-1.5">
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
          <Select value={selectedUser} onValueChange={setSelectedUser}>
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
        </div>

        <Link href={`/app/console/${server.id}?user=${selectedUser}`}>
          <Button
            className="w-full gap-2"
            disabled={!server.enabled || server.status === "offline" || !selectedUser}
            data-testid={`connect-button-${server.id}`}
          >
            <Terminal className="h-4 w-4" />
            Connect
            <ArrowRight className="h-4 w-4" />
          </Button>
        </Link>
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

function SessionItem({ session }: { session: ActiveSession }) {
  return (
    <div className="flex items-center justify-between py-3 px-4 hover-elevate rounded-md" data-testid={`session-${session.id}`}>
      <div className="flex items-center gap-3">
        <div className="flex h-8 w-8 items-center justify-center rounded-md bg-chart-2/10">
          <Activity className="h-4 w-4 text-chart-2" />
        </div>
        <div>
          <p className="text-sm font-medium">{session.serverName}</p>
          <p className="text-xs text-muted-foreground font-mono">
            {session.sshUser}@{session.serverHost}
          </p>
        </div>
      </div>
      <div className="flex items-center gap-3">
        <div className="text-right">
          <Badge variant="outline" className="text-xs gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-chart-2 animate-pulse" />
            Active
          </Badge>
        </div>
        <Link href={`/app/console/${session.serverId}?user=${encodeURIComponent(session.sshUser)}`}>
          <Button size="sm" variant="ghost" data-testid={`reconnect-session-${session.id}`}>
            Reconnect
          </Button>
        </Link>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { user } = useAuth();
  
  const { data: servers, isLoading: serversLoading } = useQuery<ServerWithAccess[]>({
    queryKey: ["/api/servers"],
  });

  const { data: sessions, isLoading: sessionsLoading } = useQuery<ActiveSession[]>({
    queryKey: ["/api/sessions"],
  });

  const activeSessions = sessions?.filter((s) => s.status === "active") || [];
  const recentSessions = sessions?.filter((s) => s.status !== "active").slice(0, 5) || [];

  return (
    <div className="p-6 space-y-8">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight" data-testid="dashboard-title">
          Welcome back, {user?.username}
        </h1>
        <p className="text-muted-foreground">
          Connect to your servers and manage your SSH sessions
        </p>
      </div>

      {activeSessions.length > 0 && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-medium flex items-center gap-2">
              <Activity className="h-5 w-5 text-chart-2" />
              Active Sessions
            </h2>
            <Badge variant="secondary">{activeSessions.length}</Badge>
          </div>
          <Card>
            <CardContent className="p-0 divide-y divide-border">
              {activeSessions.map((session) => (
                <SessionItem key={session.id} session={session} />
              ))}
            </CardContent>
          </Card>
        </div>
      )}

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-medium flex items-center gap-2">
            <Server className="h-5 w-5" />
            Available Servers
          </h2>
          {servers && <Badge variant="secondary">{servers.length}</Badge>}
        </div>
        
        {serversLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[1, 2, 3].map((i) => (
              <ServerCardSkeleton key={i} />
            ))}
          </div>
        ) : servers && servers.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {servers.map((server) => (
              <ServerCard key={server.id} server={server} />
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
          <h2 className="text-lg font-medium flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Recent Connections
          </h2>
          <Card>
            <CardContent className="p-0 divide-y divide-border">
              {recentSessions.map((session) => (
                <div key={session.id} className="flex items-center justify-between py-3 px-4">
                  <div className="flex items-center gap-3">
                    <div className="flex h-8 w-8 items-center justify-center rounded-md bg-muted">
                      <Terminal className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <div>
                      <p className="text-sm font-medium">{session.serverName}</p>
                      <p className="text-xs text-muted-foreground font-mono">
                        {session.sshUser}@{session.serverHost}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="text-xs text-muted-foreground">
                      {session.endedAt ? new Date(session.endedAt).toLocaleDateString() : ""}
                    </div>
                    <Link href={`/app/console/${session.serverId}?user=${encodeURIComponent(session.sshUser)}`}>
                      <Button size="sm" variant="ghost" data-testid={`reconnect-recent-session-${session.id}`}>
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
