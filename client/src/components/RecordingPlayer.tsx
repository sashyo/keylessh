import { useState, useEffect, useRef, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";
import { Play, Pause, RotateCcw, FastForward } from "lucide-react";
import type { RecordingDetails } from "@/lib/api";

interface AsciicastHeader {
  version: number;
  width: number;
  height: number;
  timestamp?: number;
}

interface AsciicastEvent {
  time: number;
  type: "o" | "i"; // output or input
  data: string;
}

interface RecordingPlayerProps {
  recording: RecordingDetails;
}

export function RecordingPlayer({ recording }: RecordingPlayerProps) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const [terminalContent, setTerminalContent] = useState("");
  const terminalRef = useRef<HTMLPreElement>(null);
  const animationRef = useRef<number | null>(null);
  const startTimeRef = useRef<number>(0);
  const pausedAtRef = useRef<number>(0);

  // Parse asciicast v2 data
  const { header, events, duration } = parseAsciicast(recording.data);

  // Get terminal content up to a specific time
  const getContentAtTime = useCallback(
    (time: number): string => {
      let content = "";
      for (const event of events) {
        if (event.time > time) break;
        if (event.type === "o") {
          content += event.data;
        }
      }
      return content;
    },
    [events]
  );

  // Start/stop playback
  useEffect(() => {
    if (isPlaying) {
      startTimeRef.current = Date.now();
      pausedAtRef.current = currentTime;

      const runAnimation = () => {
        const elapsed = (Date.now() - startTimeRef.current) * playbackSpeed / 1000;
        const newTime = pausedAtRef.current + elapsed;

        if (newTime >= duration) {
          setCurrentTime(duration);
          setTerminalContent(getContentAtTime(duration));
          setIsPlaying(false);
          return;
        }

        setCurrentTime(newTime);
        setTerminalContent(getContentAtTime(newTime));
        animationRef.current = requestAnimationFrame(runAnimation);
      };

      animationRef.current = requestAnimationFrame(runAnimation);
    } else {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
        animationRef.current = null;
      }
    }

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isPlaying, playbackSpeed]);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalContent]);

  const handlePlayPause = () => {
    setIsPlaying(!isPlaying);
  };

  const handleReset = () => {
    setIsPlaying(false);
    setCurrentTime(0);
    pausedAtRef.current = 0;
    setTerminalContent("");
  };

  const handleSeek = (value: number[]) => {
    const newTime = value[0];
    setIsPlaying(false);
    setCurrentTime(newTime);
    pausedAtRef.current = newTime;
    setTerminalContent(getContentAtTime(newTime));
  };

  const handleSpeedChange = () => {
    const speeds = [0.5, 1, 2, 4];
    const currentIndex = speeds.indexOf(playbackSpeed);
    const nextIndex = (currentIndex + 1) % speeds.length;
    setPlaybackSpeed(speeds[nextIndex]);
  };

  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

  return (
    <div className="space-y-4">
      {/* Terminal Display */}
      <div
        className="bg-black rounded-lg overflow-hidden border border-border"
        style={{
          width: "100%",
          maxWidth: `${Math.min(header.width * 9, 900)}px`,
        }}
      >
        <div className="bg-gray-800 px-4 py-2 flex items-center gap-2">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500" />
            <div className="w-3 h-3 rounded-full bg-yellow-500" />
            <div className="w-3 h-3 rounded-full bg-green-500" />
          </div>
          <span className="text-gray-400 text-sm ml-2">
            {recording.serverName} - {recording.sshUser}@server
          </span>
        </div>
        <pre
          ref={terminalRef}
          className="p-4 text-green-400 font-mono text-sm overflow-auto whitespace-pre-wrap"
          style={{
            height: `${Math.min(header.height * 18, 400)}px`,
            backgroundColor: "#1a1a1a",
          }}
        >
          {terminalContent || <span className="text-gray-500">Press play to start...</span>}
        </pre>
      </div>

      {/* Playback Controls */}
      <div className="space-y-2">
        <div className="flex items-center gap-2 px-2">
          <span className="text-sm text-muted-foreground w-12">{formatTime(currentTime)}</span>
          <Slider
            value={[currentTime]}
            max={duration || 1}
            step={0.1}
            onValueChange={handleSeek}
            className="flex-1"
          />
          <span className="text-sm text-muted-foreground w-12 text-right">{formatTime(duration)}</span>
        </div>

        <div className="flex items-center justify-center gap-2">
          <Button size="sm" variant="outline" onClick={handleReset}>
            <RotateCcw className="h-4 w-4" />
          </Button>
          <Button size="sm" onClick={handlePlayPause}>
            {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
          </Button>
          <Button size="sm" variant="outline" onClick={handleSpeedChange} className="min-w-[60px]">
            <FastForward className="h-4 w-4 mr-1" />
            {playbackSpeed}x
          </Button>
        </div>
      </div>

      {/* Recording Info */}
      <div className="text-xs text-muted-foreground flex items-center justify-center gap-4">
        <span>Terminal: {header.width}x{header.height}</span>
        <span>Duration: {formatTime(duration)}</span>
        <span>Events: {events.length}</span>
      </div>
    </div>
  );
}

function parseAsciicast(data: string): {
  header: AsciicastHeader;
  events: AsciicastEvent[];
  duration: number;
} {
  const lines = data.trim().split("\n").filter(Boolean);
  let header: AsciicastHeader = { version: 2, width: 80, height: 24 };
  const events: AsciicastEvent[] = [];
  let maxTime = 0;

  for (let i = 0; i < lines.length; i++) {
    try {
      const parsed = JSON.parse(lines[i]);

      if (i === 0 && typeof parsed === "object" && "version" in parsed) {
        // This is the header
        header = {
          version: parsed.version || 2,
          width: parsed.width || 80,
          height: parsed.height || 24,
          timestamp: parsed.timestamp,
        };
      } else if (Array.isArray(parsed) && parsed.length >= 3) {
        // This is an event: [time, type, data]
        const [time, type, eventData] = parsed;
        if (typeof time === "number" && (type === "o" || type === "i")) {
          events.push({ time, type, data: eventData });
          if (time > maxTime) maxTime = time;
        }
      }
    } catch {
      // Skip invalid lines
    }
  }

  return { header, events, duration: maxTime };
}
