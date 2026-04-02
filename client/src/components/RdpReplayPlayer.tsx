/**
 * RDP Recording Replay Player
 *
 * Replays RDP PDU recordings using IronRDP WASM by creating a fake WebSocket
 * that feeds recorded server-to-client PDUs at the original timestamps.
 * IronRDP renders the frames to a canvas as if it were a live session.
 */

import { useState, useRef, useCallback, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";
import { Play, Pause, RotateCcw, FastForward } from "lucide-react";
import type { RecordingDetails } from "@/lib/api";

interface PduEvent {
  time: number;
  direction: "c2s" | "s2c";
  data: Uint8Array;
}

function parseRdpRecording(rawData: string): { events: PduEvent[]; duration: number } {
  const lines = rawData.trim().split("\n").filter(Boolean);
  const events: PduEvent[] = [];
  let duration = 0;

  for (const line of lines) {
    try {
      const parsed = JSON.parse(line);
      // Header line: { version: 1, format: "rdp-pdu", ... }
      if (!Array.isArray(parsed)) continue;
      // Event: [time, direction, base64data]
      const [time, dir, b64] = parsed;
      if (typeof time !== "number" || typeof b64 !== "string") continue;
      const raw = atob(b64);
      const bytes = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
      events.push({ time, direction: dir === "c2s" ? "c2s" : "s2c", data: bytes });
      if (time > duration) duration = time;
    } catch {
      // skip invalid lines
    }
  }

  return { events, duration };
}

/**
 * Fake WebSocket that replays recorded PDUs.
 * IronRDP WASM thinks it's connected to a real RDCleanPath server.
 */
class ReplayWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState = 0;
  protocol = "";
  extensions = "";
  bufferedAmount = 0;
  binaryType: BinaryType = "arraybuffer";
  url: string;

  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;

  private _listeners: Record<string, Function[]> = {};
  private _s2cEvents: PduEvent[];
  private _speed: number;
  private _timers: ReturnType<typeof setTimeout>[] = [];
  private _playing = false;
  private _currentIndex = 0;
  private _startTime = 0;
  private _pausedAt = 0;
  private _onProgress?: (time: number) => void;

  constructor(
    url: string,
    _protocols: string | string[] | undefined,
    s2cEvents: PduEvent[],
    speed: number,
    onProgress?: (time: number) => void
  ) {
    this.url = url;
    this._s2cEvents = s2cEvents;
    this._speed = speed;
    this._onProgress = onProgress;

    // Simulate async open
    setTimeout(() => {
      this.readyState = 1;
      this.protocol = "rdcleanpath";
      this._dispatch("open", new Event("open"));
      this._startPlayback();
    }, 10);
  }

  addEventListener(type: string, fn: Function) {
    if (!this._listeners[type]) this._listeners[type] = [];
    this._listeners[type].push(fn);
  }

  removeEventListener(type: string, fn: Function) {
    if (!this._listeners[type]) return;
    this._listeners[type] = this._listeners[type].filter((f) => f !== fn);
  }

  private _dispatch(type: string, event: Event) {
    const handler = (this as any)["on" + type];
    if (typeof handler === "function") handler(event);
    const listeners = this._listeners[type];
    if (listeners) listeners.forEach((fn) => fn(event));
  }

  send(_data: string | ArrayBuffer | Blob | ArrayBufferView) {
    // Silently consume c2s PDUs — IronRDP sends protocol messages we don't need
  }

  close(code?: number, reason?: string) {
    this._stopPlayback();
    this.readyState = 3;
    this._dispatch(
      "close",
      new CloseEvent("close", { code: code || 1000, reason: reason || "", wasClean: true })
    );
  }

  private _startPlayback() {
    this._playing = true;
    this._startTime = performance.now();
    this._scheduleEvents();
  }

  private _scheduleEvents() {
    if (!this._playing || this.readyState !== 1) return;

    for (let i = this._currentIndex; i < this._s2cEvents.length; i++) {
      const evt = this._s2cEvents[i];
      const delay = ((evt.time - this._pausedAt) * 1000) / this._speed;

      const timer = setTimeout(() => {
        if (!this._playing || this.readyState !== 1) return;
        this._currentIndex = i + 1;
        // Fire as binary message
        const payload = evt.data.buffer.slice(
          evt.data.byteOffset,
          evt.data.byteOffset + evt.data.byteLength
        );
        this._dispatch("message", new MessageEvent("message", { data: payload }));
        if (this._onProgress) this._onProgress(evt.time);
      }, Math.max(0, delay));

      this._timers.push(timer);
    }

    // Schedule end
    const lastTime = this._s2cEvents.length > 0
      ? this._s2cEvents[this._s2cEvents.length - 1].time
      : 0;
    const endDelay = ((lastTime - this._pausedAt + 0.5) * 1000) / this._speed;
    this._timers.push(
      setTimeout(() => {
        this._playing = false;
        this.close(1000, "Replay ended");
      }, Math.max(0, endDelay))
    );
  }

  _stopPlayback() {
    this._playing = false;
    for (const t of this._timers) clearTimeout(t);
    this._timers = [];
  }

  setSpeed(speed: number) {
    // Reschedule remaining events at new speed
    const elapsed = (performance.now() - this._startTime) * this._speed / 1000;
    this._pausedAt += elapsed;
    this._stopPlayback();
    this._speed = speed;
    this._playing = true;
    this._startTime = performance.now();
    this._scheduleEvents();
  }
}

export function RdpReplayPlayer({ recording }: { recording: RecordingDetails }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [hasStarted, setHasStarted] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const replayWsRef = useRef<ReplayWebSocket | null>(null);
  const wasmSessionRef = useRef<any>(null);

  const { events: allEvents, duration } = parseRdpRecording(recording.data);
  const s2cEvents = allEvents.filter((e) => e.direction === "s2c");

  const handlePlay = useCallback(async () => {
    if (hasStarted) return; // Can only start once — IronRDP manages its own state
    setHasStarted(true);
    setIsPlaying(true);
    setError(null);

    try {
      // Load IronRDP WASM
      const wasmModule = await import("/gateway/wasm/ironrdp_web.js" as any);
      await (wasmModule as any).default("/gateway/wasm/ironrdp_web_bg.wasm");
      (wasmModule as any).setup("warn");

      const canvas = canvasRef.current;
      if (!canvas) throw new Error("Canvas not found");

      // Set canvas size (use a reasonable desktop size)
      canvas.width = 1280;
      canvas.height = 720;

      // Install WebSocket shim so IronRDP uses our ReplayWebSocket
      const origWs = window.WebSocket;
      const onProgress = (time: number) => setCurrentTime(time);

      (window as any).WebSocket = function (url: string, protocols?: string | string[]) {
        // Restore original WebSocket immediately after IronRDP grabs it
        (window as any).WebSocket = origWs;
        const ws = new ReplayWebSocket(url, protocols, s2cEvents, playbackSpeed, onProgress);
        replayWsRef.current = ws;
        return ws;
      };
      (window as any).WebSocket.CONNECTING = 0;
      (window as any).WebSocket.OPEN = 1;
      (window as any).WebSocket.CLOSING = 2;
      (window as any).WebSocket.CLOSED = 3;

      // Build IronRDP session
      const builder = new (wasmModule as any).SessionBuilder();
      const session = await builder
        .username("replay")
        .password("replay")
        .destination("replay")
        .proxyAddress("wss://replay/ws/rdcleanpath")
        .authToken("replay")
        .renderCanvas(canvas)
        .desktopSize(new (wasmModule as any).DesktopSize(1280, 720))
        .connect();

      wasmSessionRef.current = session;
    } catch (err: any) {
      console.error("[RDP Replay] Error:", err);
      setError(err?.message || "Failed to start replay");
      setIsPlaying(false);
    }
  }, [hasStarted, s2cEvents, playbackSpeed]);

  const handleSpeedChange = useCallback(() => {
    const speeds = [0.5, 1, 2, 4];
    const idx = speeds.indexOf(playbackSpeed);
    const next = speeds[(idx + 1) % speeds.length];
    setPlaybackSpeed(next);
    if (replayWsRef.current) {
      replayWsRef.current.setSpeed(next);
    }
  }, [playbackSpeed]);

  const handleReset = useCallback(() => {
    // Clean up current session
    if (replayWsRef.current) {
      replayWsRef.current._stopPlayback();
      replayWsRef.current = null;
    }
    wasmSessionRef.current = null;
    setIsPlaying(false);
    setHasStarted(false);
    setCurrentTime(0);
    setError(null);
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (replayWsRef.current) {
        replayWsRef.current._stopPlayback();
      }
    };
  }, []);

  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

  return (
    <div className="space-y-3 sm:space-y-4 w-full max-w-5xl mx-auto">
      {/* Canvas Display */}
      <div className="bg-black rounded-lg overflow-hidden border border-border w-full">
        <div className="bg-gray-800 px-3 sm:px-4 py-1.5 sm:py-2 flex items-center gap-2">
          <div className="flex gap-1.5">
            <div className="w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full bg-red-500" />
            <div className="w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full bg-yellow-500" />
            <div className="w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full bg-green-500" />
          </div>
          <span className="text-gray-400 text-xs sm:text-sm ml-2 truncate">
            RDP Replay — {recording.serverName}
          </span>
        </div>
        <div className="relative" style={{ aspectRatio: "16/9", background: "#1a1a1a" }}>
          <canvas
            ref={canvasRef}
            className="w-full h-full"
            style={{ display: "block", objectFit: "contain" }}
          />
          {!hasStarted && !error && (
            <div className="absolute inset-0 flex items-center justify-center">
              <Button
                size="lg"
                onClick={handlePlay}
                className="gap-2"
              >
                <Play className="h-5 w-5" />
                Play RDP Recording
              </Button>
            </div>
          )}
          {error && (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-center space-y-2">
                <p className="text-red-400 text-sm">{error}</p>
                <Button size="sm" variant="outline" onClick={handleReset}>
                  Try Again
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Playback Controls */}
      <div className="space-y-2">
        <div className="flex items-center gap-2 px-1 sm:px-2">
          <span className="text-xs sm:text-sm text-muted-foreground w-10 sm:w-12">
            {formatTime(currentTime)}
          </span>
          <Slider
            value={[currentTime]}
            max={duration || 1}
            step={0.1}
            className="flex-1"
            disabled
          />
          <span className="text-xs sm:text-sm text-muted-foreground w-10 sm:w-12 text-right">
            {formatTime(duration)}
          </span>
        </div>

        <div className="flex items-center justify-center gap-1.5 sm:gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={handleReset}
            className="h-8 w-8 p-0 sm:h-9 sm:w-auto sm:px-3"
          >
            <RotateCcw className="h-4 w-4" />
          </Button>
          <Button
            size="sm"
            onClick={hasStarted ? undefined : handlePlay}
            disabled={hasStarted}
            className="h-8 w-8 p-0 sm:h-9 sm:w-auto sm:px-4"
          >
            {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={handleSpeedChange}
            className="h-8 px-2 sm:h-9 sm:px-3 min-w-[52px] sm:min-w-[60px]"
          >
            <FastForward className="h-3.5 w-3.5 sm:h-4 sm:w-4 mr-0.5 sm:mr-1" />
            <span className="text-xs sm:text-sm">{playbackSpeed}x</span>
          </Button>
        </div>
      </div>

      {/* Recording Info */}
      <div className="text-xs text-muted-foreground flex items-center justify-center gap-2 sm:gap-4 flex-wrap">
        <span>Duration: {formatTime(duration)}</span>
        <span>Events: {allEvents.length} ({s2cEvents.length} s2c)</span>
        <span>Size: {(recording.fileSize / 1024).toFixed(1)} KB</span>
      </div>
    </div>
  );
}
