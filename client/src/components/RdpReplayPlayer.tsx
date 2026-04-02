/**
 * RDP Recording Replay Player
 *
 * Plays back RDP session recordings stored as WebM video.
 * Uses a standard HTML5 video element with playback controls.
 */

import { useMemo } from "react";
import type { RecordingDetails } from "@/lib/api";

export function RdpReplayPlayer({ recording }: { recording: RecordingDetails }) {
  const token = localStorage.getItem("access_token") || "";
  const videoUrl = useMemo(
    () => `/api/admin/recordings/${recording.id}/video?token=${encodeURIComponent(token)}`,
    [recording.id, token]
  );

  return (
    <div className="space-y-3 sm:space-y-4 w-full max-w-5xl mx-auto">
      <div className="bg-black rounded-lg overflow-hidden border border-border w-full">
        <div className="bg-gray-800 px-3 sm:px-4 py-1.5 sm:py-2 flex items-center gap-2">
          <div className="flex gap-1.5">
            <div className="w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full bg-red-500" />
            <div className="w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full bg-yellow-500" />
            <div className="w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full bg-green-500" />
          </div>
          <span className="text-gray-400 text-xs sm:text-sm ml-2 truncate">
            RDP Recording — {recording.serverName}
          </span>
        </div>
        <video
          src={videoUrl}
          controls
          className="w-full"
          style={{ aspectRatio: "16/9", background: "#1a1a1a" }}
        />
      </div>
      <div className="text-xs text-muted-foreground flex items-center justify-center gap-2 sm:gap-4 flex-wrap">
        {recording.duration != null && (
          <span>Duration: {Math.floor(recording.duration / 60)}:{String(Math.floor(recording.duration % 60)).padStart(2, "0")}</span>
        )}
        <span>Size: {(recording.fileSize / 1024).toFixed(1)} KB</span>
      </div>
    </div>
  );
}
