import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
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
import { ScrollText, CheckCircle, XCircle } from "lucide-react";

interface KeycloakEvent {
  id: string;
  time: number;
  type: string;
  clientId?: string;
  userId?: string;
  ipAddress: string;
  details?: {
    username?: string;
    [key: string]: any;
  };
}

function formatTimestamp(timestamp: number) {
  const date = new Date(timestamp);
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

function getStatusBadge(type: string) {
  const isSuccess = type === "LOGIN";
  return (
    <Badge variant={isSuccess ? "default" : "destructive"} className="gap-1">
      {isSuccess ? (
        <>
          <CheckCircle className="h-3 w-3" />
          Success
        </>
      ) : (
        <>
          <XCircle className="h-3 w-3" />
          Failed
        </>
      )}
    </Badge>
  );
}

export default function AdminLogs() {
  const [page] = useState(0);
  const pageSize = 100;

  const { data: events, isLoading } = useQuery<KeycloakEvent[]>({
    queryKey: ["/api/admin/logs/access", page, pageSize],
    queryFn: async () => {
      const response = await fetch(`/api/admin/logs/access?first=${page * pageSize}&max=${pageSize}`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token") || ""}`,
        },
      });
      if (!response.ok) {
        throw new Error("Failed to fetch access logs");
      }
      return response.json();
    },
  });

  return (
    <div className="p-6 space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
          <ScrollText className="h-6 w-6" />
          Access Logs
        </h1>
        <p className="text-muted-foreground">
          View user login activity and authentication events
        </p>
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4 space-y-3">
              {[1, 2, 3, 4, 5].map((i) => (
                <div key={i} className="flex items-center gap-4">
                  <Skeleton className="h-4 w-32" />
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="h-4 w-28" />
                  <Skeleton className="h-6 w-16" />
                </div>
              ))}
            </div>
          ) : events && events.length > 0 ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="min-w-[180px]">Timestamp</TableHead>
                    <TableHead className="min-w-[120px]">Username</TableHead>
                    <TableHead className="min-w-[140px]">Client ID</TableHead>
                    <TableHead className="min-w-[140px]">IP Address</TableHead>
                    <TableHead className="text-center min-w-[100px]">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {events.map((event) => (
                    <TableRow key={event.id}>
                      <TableCell className="text-sm whitespace-nowrap">
                        {formatTimestamp(event.time)}
                      </TableCell>
                      <TableCell>{event.details?.username || "-"}</TableCell>
                      <TableCell className="text-sm font-mono">
                        {event.clientId || "-"}
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {event.ipAddress}
                      </TableCell>
                      <TableCell className="text-center">
                        {getStatusBadge(event.type)}
                      </TableCell>
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
                Login events will appear here once users start authenticating
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
