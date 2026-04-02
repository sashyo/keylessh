/**
 * RDP Recording Replay Player
 *
 * Plays back RDP session recordings stored as WebM video.
 * Fetches the video as a blob and uses a standard HTML5 video element.
 */

import { useState, useEffect, useRef } from "react";
import type { RecordingDetails } from "@/lib/api";

export function RdpReplayPlayer({ recording }: { recording: RecordingDetails }) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const token = localStorage.getItem("access_token") || "";

    fetch(`/api/admin/recordings/${recording.id}/video?token=${encodeURIComponent(token)}`)
      .then((r) => {
        if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
        return r.blob();
      })
      .then((blob) => {
        if (cancelled) return;
        if (blob.size === 0) {
          setError("No video data");
          setLoading(false);
          return;
        }
        const url = URL.createObjectURL(blob);
        setBlobUrl(url);
        setLoading(false);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err.message);
        setLoading(false);
      });

    return () => {
      cancelled = true;
      if (blobUrl) URL.revokeObjectURL(blobUrl);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recording.id]);

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
        <div style={{ aspectRatio: "16/9", background: "#1a1a1a", position: "relative" }}>
          {loading && (
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-gray-500 text-sm">Loading video...</span>
            </div>
          )}
          {error && (
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-red-400 text-sm">{error}</span>
            </div>
          )}
          {blobUrl && (
            <video
              ref={videoRef}
              src={blobUrl}
              controls
              autoPlay
              className="w-full h-full"
              style={{ display: "block" }}
            />
          )}
        </div>
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
