import { useState, useCallback, useEffect, useRef } from "react";
import type { SftpClient, SftpFileInfo } from "@/lib/sftp";
import { parseFileEntry, SftpError, SSH_FX } from "@/lib/sftp";

export interface UseSftpOptions {
  client: SftpClient | null;
  initialPath?: string;
}

export interface UseSftpReturn {
  // State
  currentPath: string;
  entries: SftpFileInfo[];
  loading: boolean;
  error: string | null;

  // Navigation
  navigateTo: (path: string) => Promise<void>;
  goUp: () => Promise<void>;
  refresh: () => Promise<void>;

  // File operations
  download: (path: string) => Promise<Blob>;
  upload: (file: File, destPath?: string) => Promise<void>;
  remove: (path: string) => Promise<void>;
  rename: (oldPath: string, newPath: string) => Promise<void>;
  mkdir: (name: string) => Promise<void>;
  chmod: (path: string, mode: number) => Promise<void>;

  // Selection
  selectedPaths: Set<string>;
  toggleSelection: (path: string) => void;
  clearSelection: () => void;
  selectAll: () => void;
}

export function useSftp({
  client,
  initialPath = "/",
}: UseSftpOptions): UseSftpReturn {
  const [currentPath, setCurrentPath] = useState(initialPath);
  const [entries, setEntries] = useState<SftpFileInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(new Set());

  // Track if component is mounted
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // Resolve initial path on first connection
  useEffect(() => {
    if (client && initialPath === "~") {
      client.realpath("~").then((resolved) => {
        if (mountedRef.current) {
          setCurrentPath(resolved);
        }
      }).catch(() => {
        // Fall back to root
        if (mountedRef.current) {
          setCurrentPath("/");
        }
      });
    }
  }, [client, initialPath]);

  // Load directory when path or client changes
  useEffect(() => {
    if (!client) {
      setEntries([]);
      return;
    }

    let cancelled = false;

    async function loadDirectory() {
      setLoading(true);
      setError(null);

      try {
        const rawEntries = await client!.listDirectory(currentPath);
        if (cancelled) return;

        const parsed = rawEntries
          .map((e) => parseFileEntry(e, currentPath))
          .sort((a, b) => {
            // Directories first, then alphabetical
            if (a.type === "directory" && b.type !== "directory") return -1;
            if (a.type !== "directory" && b.type === "directory") return 1;
            return a.name.localeCompare(b.name);
          });

        setEntries(parsed);
        setSelectedPaths(new Set());
      } catch (err) {
        if (cancelled) return;
        const message = err instanceof Error ? err.message : String(err);
        setError(message);
        setEntries([]);
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadDirectory();

    return () => {
      cancelled = true;
    };
  }, [client, currentPath]);

  const navigateTo = useCallback(async (path: string) => {
    setCurrentPath(path);
  }, []);

  const goUp = useCallback(async () => {
    if (currentPath === "/") return;
    const parts = currentPath.split("/").filter(Boolean);
    parts.pop();
    const parentPath = parts.length === 0 ? "/" : "/" + parts.join("/");
    setCurrentPath(parentPath);
  }, [currentPath]);

  const refresh = useCallback(async () => {
    if (!client) return;

    setLoading(true);
    setError(null);

    try {
      const rawEntries = await client.listDirectory(currentPath);
      const parsed = rawEntries
        .map((e) => parseFileEntry(e, currentPath))
        .sort((a, b) => {
          if (a.type === "directory" && b.type !== "directory") return -1;
          if (a.type !== "directory" && b.type === "directory") return 1;
          return a.name.localeCompare(b.name);
        });

      setEntries(parsed);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
    } finally {
      setLoading(false);
    }
  }, [client, currentPath]);

  const download = useCallback(
    async (path: string): Promise<Blob> => {
      if (!client) throw new Error("SFTP not connected");

      const data = await client.downloadFile(path);
      return new Blob([data]);
    },
    [client]
  );

  const upload = useCallback(
    async (file: File, destPath?: string): Promise<void> => {
      if (!client) throw new Error("SFTP not connected");

      const remotePath = destPath || `${currentPath}/${file.name}`;
      const buffer = await file.arrayBuffer();
      const data = new Uint8Array(buffer);

      await client.uploadFile(data, remotePath);
      await refresh();
    },
    [client, currentPath, refresh]
  );

  const remove = useCallback(
    async (path: string): Promise<void> => {
      if (!client) throw new Error("SFTP not connected");

      // Check if it's a directory
      try {
        const attrs = await client.stat(path);
        const isDir = (attrs.permissions ?? 0) & 0o40000;

        if (isDir) {
          await client.rmdir(path);
        } else {
          await client.remove(path);
        }

        await refresh();
      } catch (err) {
        if (err instanceof SftpError && err.code === SSH_FX.NO_SUCH_FILE) {
          await refresh();
          return;
        }
        throw err;
      }
    },
    [client, refresh]
  );

  const rename = useCallback(
    async (oldPath: string, newPath: string): Promise<void> => {
      if (!client) throw new Error("SFTP not connected");
      await client.rename(oldPath, newPath);
      await refresh();
    },
    [client, refresh]
  );

  const mkdir = useCallback(
    async (name: string): Promise<void> => {
      if (!client) throw new Error("SFTP not connected");
      const path = `${currentPath}/${name}`;
      await client.mkdir(path);
      await refresh();
    },
    [client, currentPath, refresh]
  );

  const chmod = useCallback(
    async (path: string, mode: number): Promise<void> => {
      if (!client) throw new Error("SFTP not connected");
      await client.setstat(path, { permissions: mode });
      await refresh();
    },
    [client, refresh]
  );

  const toggleSelection = useCallback((path: string) => {
    setSelectedPaths((prev) => {
      const next = new Set(prev);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  }, []);

  const clearSelection = useCallback(() => {
    setSelectedPaths(new Set());
  }, []);

  const selectAll = useCallback(() => {
    setSelectedPaths(new Set(entries.map((e) => e.path)));
  }, [entries]);

  return {
    currentPath,
    entries,
    loading,
    error,
    navigateTo,
    goUp,
    refresh,
    download,
    upload,
    remove,
    rename,
    mkdir,
    chmod,
    selectedPaths,
    toggleSelection,
    clearSelection,
    selectAll,
  };
}
