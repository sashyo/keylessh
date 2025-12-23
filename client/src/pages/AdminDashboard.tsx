import { useIsFetching, useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Server, Users, Activity, Shield, TrendingUp, AlertTriangle } from "lucide-react";
import type { Server as ServerType, AdminUser, ActiveSession, ServerStatus } from "@shared/schema";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { ADMIN_ROLE_SET } from "@shared/config/roles";
import { useAutoRefresh } from "@/hooks/useAutoRefresh";
import { useCallback } from "react";
import { api } from "@/lib/api";
import type { LicenseInfo } from "@/lib/api";
import { RefreshButton } from "@/components/RefreshButton";

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
  const { data: servers, isLoading: serversLoading, refetch: refetchServers } = useQuery<ServerType[]>({
    queryKey: ["/api/admin/servers"],
  });

  const { data: serverStatusData, isLoading: serverStatusLoading, refetch: refetchServerStatus } = useQuery<{
    statuses: Record<string, ServerStatus>;
  }>({
    queryKey: ["/api/admin/servers/status"],
  });

  const { data: users, isLoading: usersLoading, refetch: refetchUsers } = useQuery<AdminUser[]>({
    queryKey: ["/api/admin/users"],
  });

  const { data: sessions, isLoading: sessionsLoading, refetch: refetchSessions } = useQuery<ActiveSession[]>({
    queryKey: ["/api/admin/sessions"],
  });

  const { data: accessApprovals } = useQuery({
    queryKey: ["/api/admin/access-approvals"],
    queryFn: api.admin.accessApprovals.list,
  });

  const { data: pendingPolicies } = useQuery({
    queryKey: ["/api/admin/ssh-policies/pending"],
    queryFn: api.admin.sshPolicies.listPending,
  });

  const { data: licenseInfo } = useQuery<LicenseInfo>({
    queryKey: ["/api/admin/license"],
    queryFn: api.admin.license.get,
  });

  const isFetchingServers = useIsFetching({ queryKey: ["/api/admin/servers"] }) > 0;
  const isFetchingUsers = useIsFetching({ queryKey: ["/api/admin/users"] }) > 0;
  const isFetchingSessions = useIsFetching({ queryKey: ["/api/admin/sessions"] }) > 0;
  const isFetching = isFetchingServers || isFetchingUsers || isFetchingSessions;

  const refreshAll = useCallback(async () => {
    await Promise.all([refetchServers(), refetchServerStatus(), refetchUsers(), refetchSessions()]);
  }, [refetchServers, refetchServerStatus, refetchUsers, refetchSessions]);

  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 15,
    refresh: refreshAll,
    isBlocked: isFetching,
  });

  const isLoading = serversLoading || serverStatusLoading || usersLoading || sessionsLoading;

  const activeSessions = sessions?.filter((s) => s.status === "active") || [];
  const enabledServers = servers?.filter((s) => s.enabled) || [];
  // AdminUser.role is an array of role names - match only known admin roles
  const adminUsers =
    users?.filter((u) => u.role?.some((r) => ADMIN_ROLE_SET.has(r))) || [];

  const statusById = serverStatusData?.statuses || {};
  const enabledOnlineCount =
    enabledServers.filter((s) => (statusById[s.id] || "unknown") === "online").length || 0;
  const enabledOfflineCount =
    enabledServers.filter((s) => (statusById[s.id] || "unknown") === "offline").length || 0;
  const enabledUnknownCount =
    enabledServers.filter((s) => (statusById[s.id] || "unknown") === "unknown").length || 0;

  const accessPendingCount = Array.isArray(accessApprovals) ? accessApprovals.length : 0;
  const policyPendingCount =
    pendingPolicies?.policies?.filter((p) => p.status === "pending" || p.status === "approved").length || 0;
  const licenseStatus = licenseInfo?.subscription?.status || "free";
  const hasBillingIssue = licenseStatus === "past_due";

  const systemAlerts: Array<{ severity: "critical" | "warning"; message: string; href?: string }> = [];
  if (enabledOfflineCount > 0) {
    systemAlerts.push({
      severity: "critical",
      message: `${enabledOfflineCount} enabled server(s) are offline`,
      href: "/admin/servers",
    });
  } else if (enabledUnknownCount > 0) {
    systemAlerts.push({
      severity: "warning",
      message: `${enabledUnknownCount} enabled server(s) have unknown status`,
      href: "/admin/servers",
    });
  }
  if (hasBillingIssue) {
    systemAlerts.push({
      severity: "critical",
      message: "Subscription payment is past due",
      href: "/admin/license",
    });
  }
  if (accessPendingCount + policyPendingCount > 0) {
    systemAlerts.push({
      severity: "warning",
      message: `${accessPendingCount + policyPendingCount} pending approval(s) require review`,
      href: "/admin/approvals",
    });
  }

  const systemHealthLabel = systemAlerts.some((a) => a.severity === "critical") ? "Degraded" : "Operational";
  const systemHealthDescription = systemAlerts.length > 0 ? `${systemAlerts.length} alert(s)` : "No active alerts";

  return (
    <div className="p-6 space-y-8">
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2" data-testid="admin-title">
            <Shield className="h-6 w-6 text-primary" />
            Admin Overview
          </h1>
          <p className="text-muted-foreground">
            System overview and management
          </p>
        </div>
        <RefreshButton
          onClick={() => void refreshNow()}
          isRefreshing={isFetching}
          secondsRemaining={secondsRemaining}
          data-testid="refresh-admin-dashboard"
          title="Refresh now"
        />
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
              description={`${enabledOnlineCount} online • ${enabledOfflineCount} offline`}
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
              value={systemHealthLabel}
              description={systemHealthDescription}
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
                  (() => {
                    const status = server.enabled ? (statusById[server.id] || "unknown") : "unknown";
                    const label = !server.enabled ? "Disabled" : status === "online" ? "Online" : status === "offline" ? "Offline" : "Unknown";
                    const badgeVariant =
                      !server.enabled ? "secondary" : status === "online" ? "default" : status === "offline" ? "destructive" : "secondary";
                    const iconBg =
                      !server.enabled ? "bg-muted" : status === "online" ? "bg-chart-2/10" : status === "offline" ? "bg-destructive/10" : "bg-muted";
                    const iconColor =
                      !server.enabled ? "text-muted-foreground" : status === "online" ? "text-chart-2" : status === "offline" ? "text-destructive" : "text-muted-foreground";
                    return (
                  <div key={server.id} className="flex items-center justify-between py-2">
                    <div className="flex items-center gap-3">
                      <div className={`flex h-8 w-8 items-center justify-center rounded-md ${iconBg}`}>
                        <Server className={`h-4 w-4 ${iconColor}`} />
                      </div>
                      <div>
                        <p className="text-sm font-medium">{server.name}</p>
                        <p className="text-xs text-muted-foreground font-mono">
                          {server.host}:{server.port}
                        </p>
                      </div>
                    </div>
                    <Badge variant={badgeVariant as any} className="text-xs">
                      {label}
                    </Badge>
                  </div>
                    );
                  })()
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
          {systemAlerts.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Shield className="h-8 w-8 text-chart-2 mb-2" />
              <p className="text-sm font-medium">All systems operational</p>
              <p className="text-xs text-muted-foreground mt-1">No alerts at this time</p>
            </div>
          ) : (
            <div className="space-y-3">
              {systemAlerts.map((a, i) => (
                <div key={i} className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <Badge variant={a.severity === "critical" ? "destructive" : "secondary"} className="text-xs">
                      {a.severity === "critical" ? "Critical" : "Warning"}
                    </Badge>
                    <span className="text-sm">{a.message}</span>
                  </div>
                  {a.href && (
                    <Link href={a.href}>
                      <Button size="sm" variant="ghost">Open</Button>
                    </Link>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
