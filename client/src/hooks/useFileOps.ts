/**
 * Unified File Operations Hook
 * Provides file operations using SFTP, with fallback to SCP+exec when SFTP is not available
 */

import { useState, useCallback, useEffect, useRef } from "react";
import type { SftpClient, SftpFileInfo } from "@/lib/sftp";
import { parseFileEntry } from "@/lib/sftp";
import type { ScpClient, ExecFileEntry } from "@/lib/scp";
import * as scpExec from "@/lib/scp";
import type { SshClientSession } from "@microsoft/dev-tunnels-ssh";

export type FileTransferMode = "sftp" | "scp" | "none";

export type FileOpLogEvent = {
  operation: "upload" | "download" | "delete" | "mkdir" | "rename" | "chmod";
  path: string;
  targetPath?: string;
  fileSize?: number;
  mode: "sftp" | "scp";
  status: "success" | "error";
  errorMessage?: string;
};

export interface UseFileOpsOptions {
  // Either provide an SFTP client...
  sftpClient?: SftpClient | null;
  // ...or provide SCP client + session for exec commands
  scpClient?: ScpClient | null;
  session?: SshClientSession | null;
  initialPath?: string;
  // Optional callback for logging file operations
  onFileOp?: (event: FileOpLogEvent) => void;
}

export interface UseFileOpsReturn {
  // Mode indicator
  mode: FileTransferMode;

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

/**
 * Convert exec file entry to SFTP-compatible file info
 */
function execEntryToFileInfo(entry: ExecFileEntry): SftpFileInfo {
  const permissions = parsePermissions(entry.permissions);
  return {
    name: entry.name,
    path: entry.path,
    type: entry.type === "directory" ? "directory" : entry.type === "symlink" ? "symlink" : "file",
    size: entry.size,
    permissions: permissions & 0o7777, // Strip file type bits
    permissionsString: entry.permissions.substring(1), // Remove first char (file type)
    owner: 0, // We don't have numeric UIDs from ls output
    group: 0, // We don't have numeric GIDs from ls output
    modifiedAt: entry.modified,
    accessedAt: null, // ls doesn't provide access time
  };
}

/**
 * Parse permission string like "drwxr-xr-x" to numeric
 */
function parsePermissions(perms: string): number {
  if (perms.length < 10) return 0o644;

  let mode = 0;

  // Owner
  if (perms[1] === "r") mode |= 0o400;
  if (perms[2] === "w") mode |= 0o200;
  if (perms[3] === "x" || perms[3] === "s") mode |= 0o100;

  // Group
  if (perms[4] === "r") mode |= 0o040;
  if (perms[5] === "w") mode |= 0o020;
  if (perms[6] === "x" || perms[6] === "s") mode |= 0o010;

  // Others
  if (perms[7] === "r") mode |= 0o004;
  if (perms[8] === "w") mode |= 0o002;
  if (perms[9] === "x" || perms[9] === "t") mode |= 0o001;

  // File type
  if (perms[0] === "d") mode |= 0o40000;
  else if (perms[0] === "l") mode |= 0o120000;
  else mode |= 0o100000;

  return mode;
}

export function useFileOps({
  sftpClient,
  scpClient,
  session,
  initialPath = ".",
  onFileOp,
}: UseFileOpsOptions): UseFileOpsReturn {
  // Start with empty path - will be resolved when client connects
  const [currentPath, setCurrentPath] = useState("");
  const [entries, setEntries] = useState<SftpFileInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(new Set());
  const initialPathResolved = useRef(false);

  // Determine which mode we're in
  const mode: FileTransferMode = sftpClient ? "sftp" : (scpClient && session ? "scp" : "none");

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
    // Only resolve once per mount
    if (initialPathResolved.current) return;

    // Use realpath to resolve . or ~ to absolute path, or use initialPath directly if absolute
    const pathToResolve = (initialPath === "." || initialPath === "~") ? "." : initialPath;
    const needsResolution = initialPath === "." || initialPath === "~" || !initialPath.startsWith("/");

    if (sftpClient) {
      initialPathResolved.current = true;
      if (needsResolution) {
        sftpClient.realpath(pathToResolve).then((resolved) => {
          if (mountedRef.current) {
            setCurrentPath(resolved);
          }
        }).catch(() => {
          if (mountedRef.current) {
            setCurrentPath("/");
          }
        });
      } else {
        setCurrentPath(initialPath);
      }
    } else if (session) {
      initialPathResolved.current = true;
      if (needsResolution) {
        scpExec.realpath(session, pathToResolve).then((resolved) => {
          if (mountedRef.current) {
            setCurrentPath(resolved);
          }
        }).catch(() => {
          if (mountedRef.current) {
            setCurrentPath("/");
          }
        });
      } else {
        setCurrentPath(initialPath);
      }
    }
  }, [sftpClient, session, initialPath]);

  // Load directory when path or client changes
  useEffect(() => {
    if (mode === "none") {
      setEntries([]);
      return;
    }

    // Don't try to load until path is resolved to an absolute path
    if (!currentPath || currentPath === "~" || currentPath === ".") {
      return;
    }

    let cancelled = false;

    async function loadDirectory() {
      setLoading(true);
      setError(null);

      try {
        let parsed: SftpFileInfo[];

        if (sftpClient) {
          // Use SFTP
          const rawEntries = await sftpClient.listDirectory(currentPath);
          if (cancelled) return;

          parsed = rawEntries
            .map((e) => parseFileEntry(e, currentPath))
            .sort((a, b) => {
              if (a.type === "directory" && b.type !== "directory") return -1;
              if (a.type !== "directory" && b.type === "directory") return 1;
              return a.name.localeCompare(b.name);
            });
        } else if (session) {
          // Use exec ls
          const execEntries = await scpExec.listDirectory(session, currentPath);
          if (cancelled) return;

          parsed = execEntries.map(execEntryToFileInfo);
        } else {
          parsed = [];
        }

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
  }, [sftpClient, session, currentPath, mode]);

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
    if (mode === "none") return;

    setLoading(true);
    setError(null);

    try {
      let parsed: SftpFileInfo[];

      if (sftpClient) {
        const rawEntries = await sftpClient.listDirectory(currentPath);
        parsed = rawEntries
          .map((e) => parseFileEntry(e, currentPath))
          .sort((a, b) => {
            if (a.type === "directory" && b.type !== "directory") return -1;
            if (a.type !== "directory" && b.type === "directory") return 1;
            return a.name.localeCompare(b.name);
          });
      } else if (session) {
        const execEntries = await scpExec.listDirectory(session, currentPath);
        parsed = execEntries.map(execEntryToFileInfo);
      } else {
        parsed = [];
      }

      setEntries(parsed);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
    } finally {
      setLoading(false);
    }
  }, [sftpClient, session, currentPath, mode]);

  const download = useCallback(
    async (path: string): Promise<Blob> => {
      const currentMode = sftpClient ? "sftp" : "scp";
      try {
        let data: Uint8Array;
        if (sftpClient) {
          data = await sftpClient.downloadFile(path);
        } else if (scpClient) {
          data = await scpClient.downloadFile(path);
        } else {
          throw new Error("No file transfer client available");
        }
        onFileOp?.({
          operation: "download",
          path,
          fileSize: data.length,
          mode: currentMode,
          status: "success",
        });
        return new Blob([data]);
      } catch (err) {
        onFileOp?.({
          operation: "download",
          path,
          mode: currentMode,
          status: "error",
          errorMessage: err instanceof Error ? err.message : String(err),
        });
        throw err;
      }
    },
    [sftpClient, scpClient, onFileOp]
  );

  const upload = useCallback(
    async (file: File, destPath?: string): Promise<void> => {
      const remotePath = destPath || `${currentPath}/${file.name}`;
      const buffer = await file.arrayBuffer();
      const data = new Uint8Array(buffer);
      const currentMode = sftpClient ? "sftp" : "scp";

      try {
        if (sftpClient) {
          await sftpClient.uploadFile(data, remotePath);
        } else if (scpClient) {
          await scpClient.uploadFile(data, remotePath);
        } else {
          throw new Error("No file transfer client available");
        }
        onFileOp?.({
          operation: "upload",
          path: remotePath,
          fileSize: data.length,
          mode: currentMode,
          status: "success",
        });
        await refresh();
      } catch (err) {
        onFileOp?.({
          operation: "upload",
          path: remotePath,
          fileSize: data.length,
          mode: currentMode,
          status: "error",
          errorMessage: err instanceof Error ? err.message : String(err),
        });
        throw err;
      }
    },
    [sftpClient, scpClient, currentPath, refresh, onFileOp]
  );

  const remove = useCallback(
    async (path: string): Promise<void> => {
      const currentMode = sftpClient ? "sftp" : "scp";
      try {
        if (sftpClient) {
          const attrs = await sftpClient.stat(path);
          const isDir = (attrs.permissions ?? 0) & 0o40000;
          if (isDir) {
            await sftpClient.rmdir(path);
          } else {
            await sftpClient.remove(path);
          }
        } else if (session) {
          const { isDirectory } = await scpExec.stat(session, path);
          await scpExec.remove(session, path, isDirectory);
        } else {
          throw new Error("No client available");
        }
        onFileOp?.({
          operation: "delete",
          path,
          mode: currentMode,
          status: "success",
        });
        await refresh();
      } catch (err) {
        onFileOp?.({
          operation: "delete",
          path,
          mode: currentMode,
          status: "error",
          errorMessage: err instanceof Error ? err.message : String(err),
        });
        throw err;
      }
    },
    [sftpClient, session, refresh, onFileOp]
  );

  const rename = useCallback(
    async (oldPath: string, newPath: string): Promise<void> => {
      const currentMode = sftpClient ? "sftp" : "scp";
      try {
        if (sftpClient) {
          await sftpClient.rename(oldPath, newPath);
        } else if (session) {
          await scpExec.rename(session, oldPath, newPath);
        } else {
          throw new Error("No client available");
        }
        onFileOp?.({
          operation: "rename",
          path: oldPath,
          targetPath: newPath,
          mode: currentMode,
          status: "success",
        });
        await refresh();
      } catch (err) {
        onFileOp?.({
          operation: "rename",
          path: oldPath,
          targetPath: newPath,
          mode: currentMode,
          status: "error",
          errorMessage: err instanceof Error ? err.message : String(err),
        });
        throw err;
      }
    },
    [sftpClient, session, refresh, onFileOp]
  );

  const mkdir = useCallback(
    async (name: string): Promise<void> => {
      const path = `${currentPath}/${name}`;
      const currentMode = sftpClient ? "sftp" : "scp";

      try {
        if (sftpClient) {
          await sftpClient.mkdir(path);
        } else if (session) {
          await scpExec.mkdir(session, path);
        } else {
          throw new Error("No client available");
        }
        onFileOp?.({
          operation: "mkdir",
          path,
          mode: currentMode,
          status: "success",
        });
        await refresh();
      } catch (err) {
        onFileOp?.({
          operation: "mkdir",
          path,
          mode: currentMode,
          status: "error",
          errorMessage: err instanceof Error ? err.message : String(err),
        });
        throw err;
      }
    },
    [sftpClient, session, currentPath, refresh, onFileOp]
  );

  const chmod = useCallback(
    async (path: string, permissions: number): Promise<void> => {
      const currentMode = sftpClient ? "sftp" : "scp";
      try {
        if (sftpClient) {
          await sftpClient.setstat(path, { permissions });
        } else if (session) {
          // Convert numeric mode to octal string
          const octalMode = permissions.toString(8).padStart(4, "0");
          await scpExec.chmod(session, path, octalMode);
        } else {
          throw new Error("No client available");
        }
        onFileOp?.({
          operation: "chmod",
          path,
          mode: currentMode,
          status: "success",
        });
        await refresh();
      } catch (err) {
        onFileOp?.({
          operation: "chmod",
          path,
          mode: currentMode,
          status: "error",
          errorMessage: err instanceof Error ? err.message : String(err),
        });
        throw err;
      }
    },
    [sftpClient, session, refresh, onFileOp]
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
    mode,
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
