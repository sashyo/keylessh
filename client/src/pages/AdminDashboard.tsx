import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Server, Users, Activity, Shield, TrendingUp, AlertTriangle } from "lucide-react";
import type { Server as ServerType, User, ActiveSession } from "@shared/schema";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";

function StatCard({
  title,
  value,
  description,
  icon: Icon,
  trend,
}: {
  title: string;
  value: string | number;
  description: string;
  icon: typeof Server;
  trend?: { value: number; label: string };
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-4 pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold">{value}</div>
        <p className="text-xs text-muted-foreground mt-1">{description}</p>
        {trend && (
          <div className="flex items-center gap-1 mt-2">
            <TrendingUp className="h-3 w-3 text-chart-2" />
            <span className="text-xs text-chart-2">+{trend.value}% {trend.label}</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function StatCardSkeleton() {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-4 pb-2">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-4 w-4" />
      </CardHeader>
      <CardContent>
        <Skeleton className="h-8 w-16" />
        <Skeleton className="h-3 w-32 mt-2" />
      </CardContent>
    </Card>
  );
}

export default function AdminDashboard() {
  const { data: servers, isLoading: serversLoading } = useQuery<ServerType[]>({
    queryKey: ["/api/admin/servers"],
  });

  const { data: users, isLoading: usersLoading } = useQuery<User[]>({
    queryKey: ["/api/admin/users"],
  });

  const { data: sessions, isLoading: sessionsLoading } = useQuery<ActiveSession[]>({
    queryKey: ["/api/admin/sessions"],
  });

  const isLoading = serversLoading || usersLoading || sessionsLoading;

  const activeSessions = sessions?.filter((s) => s.status === "active") || [];
  const enabledServers = servers?.filter((s) => s.enabled) || [];
  const adminUsers = users?.filter((u) => u.role === "admin") || [];

  return (
    <div className="p-6 space-y-8">
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2" data-testid="admin-title">
            <Shield className="h-6 w-6 text-primary" />
            Admin Dashboard
          </h1>
          <p className="text-muted-foreground">
            System overview and management
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {isLoading ? (
          <>
            <StatCardSkeleton />
            <StatCardSkeleton />
            <StatCardSkeleton />
            <StatCardSkeleton />
          </>
        ) : (
          <>
            <StatCard
              title="Total Servers"
              value={servers?.length || 0}
              description={`${enabledServers.length} online`}
              icon={Server}
            />
            <StatCard
              title="Total Users"
              value={users?.length || 0}
              description={`${adminUsers.length} administrators`}
              icon={Users}
            />
            <StatCard
              title="Active Sessions"
              value={activeSessions.length}
              description="Currently connected"
              icon={Activity}
            />
            <StatCard
              title="System Health"
              value="Operational"
              description="All systems running"
              icon={Shield}
            />
          </>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-4">
            <div>
              <CardTitle className="text-lg">Active Sessions</CardTitle>
              <CardDescription>Currently connected users</CardDescription>
            </div>
            <Link href="/admin/sessions">
              <Button variant="ghost" size="sm">View all</Button>
            </Link>
          </CardHeader>
          <CardContent>
            {sessionsLoading ? (
              <div className="space-y-3">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="flex items-center gap-3">
                    <Skeleton className="h-8 w-8 rounded-md" />
                    <div className="space-y-1 flex-1">
                      <Skeleton className="h-4 w-32" />
                      <Skeleton className="h-3 w-24" />
                    </div>
                    <Skeleton className="h-5 w-16" />
                  </div>
                ))}
              </div>
            ) : activeSessions.length > 0 ? (
              <div className="space-y-3">
                {activeSessions.slice(0, 5).map((session) => (
                  <div key={session.id} className="flex items-center justify-between py-2">
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
                    <Badge variant="outline" className="text-xs gap-1">
                      <span className="h-1.5 w-1.5 rounded-full bg-chart-2 animate-pulse" />
                      Active
                    </Badge>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-8 text-center">
                <Activity className="h-8 w-8 text-muted-foreground mb-2" />
                <p className="text-sm text-muted-foreground">No active sessions</p>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-4">
            <div>
              <CardTitle className="text-lg">Server Status</CardTitle>
              <CardDescription>Infrastructure overview</CardDescription>
            </div>
            <Link href="/admin/servers">
              <Button variant="ghost" size="sm">Manage</Button>
            </Link>
          </CardHeader>
          <CardContent>
            {serversLoading ? (
              <div className="space-y-3">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="flex items-center gap-3">
                    <Skeleton className="h-8 w-8 rounded-md" />
                    <div className="space-y-1 flex-1">
                      <Skeleton className="h-4 w-32" />
                      <Skeleton className="h-3 w-24" />
                    </div>
                    <Skeleton className="h-5 w-16" />
                  </div>
                ))}
              </div>
            ) : servers && servers.length > 0 ? (
              <div className="space-y-3">
                {servers.slice(0, 5).map((server) => (
                  <div key={server.id} className="flex items-center justify-between py-2">
                    <div className="flex items-center gap-3">
                      <div className={`flex h-8 w-8 items-center justify-center rounded-md ${server.enabled ? "bg-chart-2/10" : "bg-muted"}`}>
                        <Server className={`h-4 w-4 ${server.enabled ? "text-chart-2" : "text-muted-foreground"}`} />
                      </div>
                      <div>
                        <p className="text-sm font-medium">{server.name}</p>
                        <p className="text-xs text-muted-foreground font-mono">
                          {server.host}:{server.port}
                        </p>
                      </div>
                    </div>
                    <Badge variant={server.enabled ? "default" : "secondary"} className="text-xs">
                      {server.enabled ? "Online" : "Offline"}
                    </Badge>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-8 text-center">
                <Server className="h-8 w-8 text-muted-foreground mb-2" />
                <p className="text-sm text-muted-foreground">No servers configured</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-chart-4" />
            System Alerts
          </CardTitle>
          <CardDescription>Recent system events and notifications</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <Shield className="h-8 w-8 text-chart-2 mb-2" />
            <p className="text-sm font-medium">All systems operational</p>
            <p className="text-xs text-muted-foreground mt-1">No alerts at this time</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
