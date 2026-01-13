import { useState, useEffect, useRef, useCallback, useMemo } from "react";
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

// ANSI color code to CSS color mapping
const ANSI_COLORS: Record<number, string> = {
  30: "#000000", // Black
  31: "#cc0000", // Red
  32: "#4e9a06", // Green
  33: "#c4a000", // Yellow
  34: "#3465a4", // Blue
  35: "#75507b", // Magenta
  36: "#06989a", // Cyan
  37: "#d3d7cf", // White
  90: "#555753", // Bright Black
  91: "#ef2929", // Bright Red
  92: "#8ae234", // Bright Green
  93: "#fce94f", // Bright Yellow
  94: "#729fcf", // Bright Blue
  95: "#ad7fa8", // Bright Magenta
  96: "#34e2e2", // Bright Cyan
  97: "#eeeeec", // Bright White
};

const ANSI_BG_COLORS: Record<number, string> = {
  40: "#000000",
  41: "#cc0000",
  42: "#4e9a06",
  43: "#c4a000",
  44: "#3465a4",
  45: "#75507b",
  46: "#06989a",
  47: "#d3d7cf",
  100: "#555753",
  101: "#ef2929",
  102: "#8ae234",
  103: "#fce94f",
  104: "#729fcf",
  105: "#ad7fa8",
  106: "#34e2e2",
  107: "#eeeeec",
};

interface TextStyle {
  color?: string;
  backgroundColor?: string;
  bold?: boolean;
  dim?: boolean;
  italic?: boolean;
  underline?: boolean;
}

interface StyledSegment {
  text: string;
  style: TextStyle;
}

// Parse ANSI escape sequences and return styled segments
function parseAnsiToSegments(input: string): StyledSegment[] {
  const segments: StyledSegment[] = [];
  let currentStyle: TextStyle = {};
  let currentText = "";
  let i = 0;

  // First, process backspaces and line clearing in the raw text
  let processedInput = processControlChars(input);

  while (i < processedInput.length) {
    // Check for escape sequence
    if (processedInput[i] === "\x1b" || processedInput[i] === "\u001b") {
      // Save current text if any
      if (currentText) {
        segments.push({ text: currentText, style: { ...currentStyle } });
        currentText = "";
      }

      // Check what type of escape sequence
      if (processedInput[i + 1] === "[") {
        // CSI sequence (Control Sequence Introducer)
        let j = i + 2;
        let params = "";

        // Collect parameters until we hit a letter
        while (j < processedInput.length && !/[A-Za-z]/.test(processedInput[j])) {
          params += processedInput[j];
          j++;
        }

        const command = processedInput[j];

        if (command === "m") {
          // SGR (Select Graphic Rendition) - color/style codes
          const codes = params ? params.split(";").map(Number) : [0];
          currentStyle = applyAnsiCodes(codes, currentStyle);
        }
        // Skip other CSI sequences (cursor movement, etc.)

        i = j + 1;
        continue;
      } else if (processedInput[i + 1] === "]") {
        // OSC sequence (Operating System Command) - window title, etc.
        // Skip until BEL (\x07) or ST (\x1b\\)
        let j = i + 2;
        while (j < processedInput.length) {
          if (processedInput[j] === "\x07" || processedInput[j] === "\u0007") {
            j++;
            break;
          }
          if (processedInput[j] === "\x1b" && processedInput[j + 1] === "\\") {
            j += 2;
            break;
          }
          j++;
        }
        i = j;
        continue;
      } else {
        // Unknown escape sequence, skip the escape character
        i++;
        continue;
      }
    }

    // Skip bell character
    if (processedInput[i] === "\x07" || processedInput[i] === "\u0007") {
      i++;
      continue;
    }

    // Regular character
    currentText += processedInput[i];
    i++;
  }

  // Add remaining text
  if (currentText) {
    segments.push({ text: currentText, style: { ...currentStyle } });
  }

  return segments;
}

// Process control characters like backspace and erase
function processControlChars(input: string): string {
  let result = "";
  let i = 0;

  while (i < input.length) {
    const char = input[i];

    // Handle backspace
    if (char === "\b" || char === "\x08") {
      // Remove last character from result
      if (result.length > 0 && result[result.length - 1] !== "\n") {
        result = result.slice(0, -1);
      }
      i++;
      continue;
    }

    // Handle carriage return (move to start of line)
    if (char === "\r") {
      // If followed by \n, it's a newline
      if (input[i + 1] === "\n") {
        result += "\r\n";
        i += 2;
        continue;
      }
      // Otherwise, move to start of current line (overwrite mode)
      const lastNewline = result.lastIndexOf("\n");
      if (lastNewline >= 0) {
        result = result.slice(0, lastNewline + 1);
      } else {
        result = "";
      }
      i++;
      continue;
    }

    result += char;
    i++;
  }

  return result;
}

// Apply ANSI SGR codes to style
function applyAnsiCodes(codes: number[], currentStyle: TextStyle): TextStyle {
  const style = { ...currentStyle };

  for (const code of codes) {
    if (code === 0) {
      // Reset
      return {};
    } else if (code === 1) {
      style.bold = true;
    } else if (code === 2) {
      style.dim = true;
    } else if (code === 3) {
      style.italic = true;
    } else if (code === 4) {
      style.underline = true;
    } else if (code === 22) {
      style.bold = false;
      style.dim = false;
    } else if (code === 23) {
      style.italic = false;
    } else if (code === 24) {
      style.underline = false;
    } else if (code >= 30 && code <= 37) {
      style.color = ANSI_COLORS[code];
    } else if (code >= 90 && code <= 97) {
      style.color = ANSI_COLORS[code];
    } else if (code === 39) {
      delete style.color;
    } else if (code >= 40 && code <= 47) {
      style.backgroundColor = ANSI_BG_COLORS[code];
    } else if (code >= 100 && code <= 107) {
      style.backgroundColor = ANSI_BG_COLORS[code];
    } else if (code === 49) {
      delete style.backgroundColor;
    }
  }

  return style;
}

// Convert style to CSS
function styleToCss(style: TextStyle): React.CSSProperties {
  const css: React.CSSProperties = {};

  if (style.color) {
    css.color = style.color;
  }
  if (style.backgroundColor) {
    css.backgroundColor = style.backgroundColor;
  }
  if (style.bold) {
    css.fontWeight = "bold";
  }
  if (style.dim) {
    css.opacity = 0.5;
  }
  if (style.italic) {
    css.fontStyle = "italic";
  }
  if (style.underline) {
    css.textDecoration = "underline";
  }

  return css;
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
  const { header, events, duration } = useMemo(
    () => parseAsciicast(recording.data),
    [recording.data]
  );

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

  // Render terminal content with ANSI colors
  const renderedContent = useMemo(() => {
    if (!terminalContent) return null;

    const segments = parseAnsiToSegments(terminalContent);

    return segments.map((segment, index) => {
      const css = styleToCss(segment.style);
      const hasStyle = Object.keys(css).length > 0;

      if (hasStyle) {
        return (
          <span key={index} style={css}>
            {segment.text}
          </span>
        );
      }
      return segment.text;
    });
  }, [terminalContent]);

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
    <div className="space-y-4 w-full max-w-4xl mx-auto">
      {/* Terminal Display - Standard size for all recordings */}
      <div className="bg-black rounded-lg overflow-hidden border border-border w-full">
        <div className="bg-gray-800 px-4 py-2 flex items-center gap-2">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500" />
            <div className="w-3 h-3 rounded-full bg-yellow-500" />
            <div className="w-3 h-3 rounded-full bg-green-500" />
          </div>
          <span className="text-gray-400 text-sm ml-2 truncate">
            {recording.serverName} - {recording.sshUser}@server
          </span>
        </div>
        <pre
          ref={terminalRef}
          className="p-4 text-gray-300 font-mono text-sm overflow-auto whitespace-pre-wrap h-[400px]"
          style={{
            backgroundColor: "#1a1a1a",
          }}
        >
          {renderedContent || <span className="text-gray-500">Press play to start...</span>}
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
