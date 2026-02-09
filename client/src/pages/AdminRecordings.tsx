import { useQuery, useMutation, useIsFetching } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
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
import { Video, Search, Server, Trash2, Download, Play, HardDrive } from "lucide-react";
import { useState } from "react";
import { api, type RecordingSummary, type RecordingsListResponse, type RecordingDetails } from "@/lib/api";
import { queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAutoRefresh } from "@/hooks/useAutoRefresh";
import { RefreshButton } from "@/components/RefreshButton";
import { RecordingPlayer } from "@/components/RecordingPlayer";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function formatDuration(seconds: number | null): string {
  if (seconds === null || seconds === undefined) return "-";
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const secs = seconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes % 60}m ${secs}s`;
  }
  if (minutes > 0) {
    return `${minutes}m ${secs}s`;
  }
  return `${secs}s`;
}

function formatDate(date: string | null): string {
  if (!date) return "-";
  return new Date(date).toLocaleString();
}

export default function AdminRecordings() {
  const [search, setSearch] = useState("");
  const [deletingRecording, setDeletingRecording] = useState<RecordingSummary | null>(null);
  const [playingRecording, setPlayingRecording] = useState<RecordingDetails | null>(null);
  const [loadingRecordingId, setLoadingRecordingId] = useState<string | null>(null);
  const { toast } = useToast();

  const { data, isLoading, refetch } = useQuery<RecordingsListResponse>({
    queryKey: ["/api/admin/recordings", search],
    queryFn: () => api.admin.recordings.list({ search: search || undefined }),
  });
  const isFetching = useIsFetching({ queryKey: ["/api/admin/recordings"] }) > 0;
  const { secondsRemaining, refreshNow } = useAutoRefresh({
    intervalSeconds: 30,
    refresh: () => refetch(),
    isBlocked: isFetching,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.admin.recordings.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/recordings"] });
      toast({ title: "Recording deleted", description: "The recording has been permanently deleted." });
      setDeletingRecording(null);
    },
    onError: (error: Error) => {
      toast({ title: "Failed to delete recording", description: error.message, variant: "destructive" });
    },
  });

  const handlePlay = async (recording: RecordingSummary) => {
    setLoadingRecordingId(recording.id);
    try {
      const details = await api.admin.recordings.get(recording.id);
      setPlayingRecording(details);
    } catch (error) {
      toast({
        title: "Failed to load recording",
        description: (error as Error).message,
        variant: "destructive",
      });
    } finally {
      setLoadingRecordingId(null);
    }
  };

  const handleDownload = (id: string) => {
    const token = localStorage.getItem("access_token");
    const url = api.admin.recordings.getDownloadUrl(id);
    // Open in new window with auth
    const downloadUrl = `${url}?token=${encodeURIComponent(token || "")}`;
    window.open(downloadUrl, "_blank");
  };

  const recordings = data?.recordings || [];
  const totalCount = data?.totalCount || 0;
  const totalStorage = data?.totalStorage || 0;

  return (
    <div className="p-4 sm:p-6 space-y-4 sm:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-xl sm:text-2xl font-semibold tracking-tight flex items-center gap-2 text-foreground">
            <Video className="h-5 w-5 sm:h-6 sm:w-6" />
            Session Recordings
          </h1>
          <p className="text-sm sm:text-base text-muted-foreground">
            View and playback recorded SSH sessions for compliance audits
          </p>
        </div>
        <RefreshButton
          onClick={() => void refreshNow()}
          isRefreshing={isFetching}
          secondsRemaining={secondsRemaining}
          title="Refresh now"
          className="self-end sm:self-auto"
        />
      </div>

      <div className="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4">
        <div className="relative flex-1 sm:max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search recordings..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="secondary" className="gap-1.5">
            <Video className="h-3 w-3" />
            {totalCount} Recordings
          </Badge>
          <Badge variant="outline" className="gap-1.5">
            <HardDrive className="h-3 w-3" />
            {formatBytes(totalStorage)}
          </Badge>
        </div>
      </div>

      <Card>
        <div className="p-4 border-b border-border">
          <h2 className="font-medium flex items-center gap-2 text-foreground">
            <Video className="h-4 w-4" />
            Recorded Sessions
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
          ) : recordings.length > 0 ? (
            <>
              {/* Mobile card layout */}
              <div className="md:hidden divide-y divide-border">
                {recordings.map((recording) => (
                  <div key={recording.id} className="p-4 space-y-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-muted">
                          <Server className="h-5 w-5 text-muted-foreground" />
                        </div>
                        <div className="min-w-0">
                          <p className="font-medium text-foreground truncate">{recording.serverName}</p>
                          <p className="text-xs text-muted-foreground truncate">{recording.userEmail}</p>
                        </div>
                      </div>
                      <Badge variant="outline" className="font-mono shrink-0">
                        {recording.sshUser}
                      </Badge>
                    </div>
                    <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                      <span>{formatDate(recording.startedAt)}</span>
                      <span>•</span>
                      <span className="font-mono">{formatDuration(recording.duration)}</span>
                      <span>•</span>
                      <span>{formatBytes(recording.fileSize)}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="default"
                        className="gap-1 flex-1 min-h-[44px]"
                        onClick={() => handlePlay(recording)}
                        disabled={loadingRecordingId === recording.id}
                      >
                        <Play className="h-4 w-4" />
                        {loadingRecordingId === recording.id ? "Loading..." : "Play"}
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="min-h-[44px] min-w-[44px]"
                        onClick={() => handleDownload(recording.id)}
                      >
                        <Download className="h-4 w-4" />
                      </Button>
                      <Button
                        size="sm"
                        variant="destructive"
                        className="min-h-[44px] min-w-[44px]"
                        onClick={() => setDeletingRecording(recording)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
              {/* Desktop table layout */}
              <Table className="hidden md:table">
                <TableHeader>
                  <TableRow>
                    <TableHead>Server</TableHead>
                    <TableHead className="hidden lg:table-cell">User</TableHead>
                    <TableHead>SSH User</TableHead>
                    <TableHead>Date</TableHead>
                    <TableHead className="hidden xl:table-cell">Duration</TableHead>
                    <TableHead className="hidden xl:table-cell">Size</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {recordings.map((recording) => (
                    <TableRow key={recording.id}>
                      <TableCell>
                        <div className="flex items-center gap-3">
                          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-muted shrink-0">
                            <Server className="h-4 w-4 text-muted-foreground" />
                          </div>
                          <div className="min-w-0">
                            <p className="font-medium truncate">{recording.serverName}</p>
                            <p className="text-xs text-muted-foreground font-mono lg:hidden truncate">
                              {recording.userEmail}
                            </p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="hidden lg:table-cell">
                        <div className="space-y-0.5">
                          <div className="text-sm truncate max-w-[180px]">{recording.userEmail}</div>
                          <div className="text-xs font-mono text-muted-foreground">
                            {recording.userId.slice(0, 8)}...
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="font-mono">
                          {recording.sshUser}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm whitespace-nowrap">
                        {formatDate(recording.startedAt)}
                      </TableCell>
                      <TableCell className="hidden xl:table-cell text-sm font-mono">
                        {formatDuration(recording.duration)}
                      </TableCell>
                      <TableCell className="hidden xl:table-cell text-sm">
                        {formatBytes(recording.fileSize)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            size="sm"
                            variant="default"
                            className="gap-1 h-8 px-2 lg:px-3"
                            onClick={() => handlePlay(recording)}
                            disabled={loadingRecordingId === recording.id}
                            title="Play recording"
                          >
                            <Play className="h-4 w-4" />
                            <span className="hidden lg:inline">{loadingRecordingId === recording.id ? "..." : "Play"}</span>
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-8 w-8 p-0"
                            onClick={() => handleDownload(recording.id)}
                            title="Download recording"
                          >
                            <Download className="h-4 w-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            className="h-8 w-8 p-0"
                            onClick={() => setDeletingRecording(recording)}
                            title="Delete recording"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <Video className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="font-medium text-foreground">No recordings found</h3>
              <p className="text-sm text-muted-foreground mt-1">
                {search
                  ? "Try a different search term"
                  : "Session recordings will appear here when recording is enabled on servers"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deletingRecording} onOpenChange={(open) => !open && setDeletingRecording(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete recording?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete this session recording. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          {deletingRecording && (
            <div className="text-sm text-muted-foreground space-y-1">
              <div>
                <span className="font-medium text-foreground">Server:</span> {deletingRecording.serverName}
              </div>
              <div>
                <span className="font-medium text-foreground">User:</span> {deletingRecording.userEmail}
              </div>
              <div>
                <span className="font-medium text-foreground">Date:</span> {formatDate(deletingRecording.startedAt)}
              </div>
              <div>
                <span className="font-medium text-foreground">Duration:</span> {formatDuration(deletingRecording.duration)}
              </div>
            </div>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={!deletingRecording || deleteMutation.isPending}
              onClick={() => deletingRecording && deleteMutation.mutate(deletingRecording.id)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Recording Playback Dialog */}
      <Dialog open={!!playingRecording} onOpenChange={(open) => !open && setPlayingRecording(null)}>
        <DialogContent className="w-[95vw] max-w-4xl max-h-[85vh] sm:max-h-[90vh] flex flex-col p-3 sm:p-4 md:p-6">
          <DialogHeader className="pb-2 sm:pb-4 shrink-0">
            <DialogTitle className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2 text-base sm:text-lg">
              <div className="flex items-center gap-2">
                <Video className="h-4 w-4 sm:h-5 sm:w-5" />
                <span className="hidden sm:inline">Session Recording</span>
                <span className="sm:hidden">Recording</span>
              </div>
              {playingRecording && (
                <span className="text-xs sm:text-sm font-normal text-muted-foreground truncate">
                  {playingRecording.serverName} ({playingRecording.sshUser})
                </span>
              )}
            </DialogTitle>
          </DialogHeader>
          {playingRecording && (
            <div className="flex-1 min-h-0 overflow-y-auto -mx-3 px-3 sm:-mx-4 sm:px-4 md:-mx-6 md:px-6">
              <RecordingPlayer recording={playingRecording} />
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
