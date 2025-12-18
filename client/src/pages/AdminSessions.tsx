import { useQuery } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Activity, Search, Clock, Server } from "lucide-react";
import { useState } from "react";
import type { ActiveSession } from "@shared/schema";

export default function AdminSessions() {
  const [search, setSearch] = useState("");

  const { data: sessions, isLoading } = useQuery<ActiveSession[]>({
    queryKey: ["/api/admin/sessions"],
  });

  const filteredSessions = sessions?.filter(
    (session) =>
      session.serverName?.toLowerCase().includes(search.toLowerCase()) ||
      session.sshUser.toLowerCase().includes(search.toLowerCase()) ||
      session.userId.toLowerCase().includes(search.toLowerCase())
  );

  const activeSessions = filteredSessions?.filter((s) => s.status === "active") || [];
  const inactiveSessions = filteredSessions?.filter((s) => s.status !== "active") || [];

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
    <div className="p-6 space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2" data-testid="admin-sessions-title">
          <Activity className="h-6 w-6" />
          All Sessions
        </h1>
        <p className="text-muted-foreground">
          Monitor active and historical SSH sessions
        </p>
      </div>

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
          <Badge variant="secondary">
            {inactiveSessions.length} Completed
          </Badge>
        </div>
      </div>

      {activeSessions.length > 0 && (
        <Card>
          <div className="p-4 border-b border-border">
            <h2 className="font-medium flex items-center gap-2">
              <Activity className="h-4 w-4 text-chart-2" />
              Active Sessions
            </h2>
          </div>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Server</TableHead>
                  <TableHead>SSH User</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Status</TableHead>
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
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <Card>
        <div className="p-4 border-b border-border">
          <h2 className="font-medium flex items-center gap-2">
            <Clock className="h-4 w-4" />
            Session History
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
          ) : filteredSessions && filteredSessions.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Server</TableHead>
                  <TableHead>SSH User</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead>Ended</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(inactiveSessions.length > 0 ? inactiveSessions : filteredSessions).map((session) => (
                  <TableRow key={session.id} data-testid={`session-${session.id}`}>
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
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <Activity className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="font-medium">No sessions found</h3>
              <p className="text-sm text-muted-foreground mt-1">
                {search ? "Try a different search term" : "No sessions have been created yet"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
