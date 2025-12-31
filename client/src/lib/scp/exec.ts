/**
 * SSH Exec-based File Operations
 * Uses shell commands via exec channels as a fallback when SFTP is not available
 */

import type { SshChannel, SshClientSession, SshDataWriter } from "@microsoft/dev-tunnels-ssh";

// Dynamic import of the actual message classes from CommonJS module
let ChannelRequestMessageCtor: any = null;

async function getChannelRequestMessageClass(): Promise<any> {
  if (ChannelRequestMessageCtor) return ChannelRequestMessageCtor;
  const mod = await import("@microsoft/dev-tunnels-ssh");
  ChannelRequestMessageCtor = mod.ChannelRequestMessage;
  return ChannelRequestMessageCtor;
}

/**
 * Create an exec request message for running a command
 */
async function createExecRequest(command: string): Promise<any> {
  const ChannelRequestMessage = await getChannelRequestMessageClass();
  const msg = new ChannelRequestMessage("exec", true);

  const originalOnWrite = Object.getPrototypeOf(msg).onWrite;

  msg.onWrite = function (writer: SshDataWriter) {
    originalOnWrite.call(this, writer);
    writer.writeString(command, "utf-8");
  };

  return msg;
}

/**
 * File entry from ls command
 */
export interface ExecFileEntry {
  name: string;
  path: string;
  type: "file" | "directory" | "symlink" | "other";
  size: number;
  permissions: string;
  owner: string;
  group: string;
  modified: Date;
}

/**
 * Execute a command and collect all output
 */
export async function execCommand(
  session: SshClientSession,
  command: string
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const channel = await session.openChannel("session");

  try {
    const execRequest = await createExecRequest(command);
    const result = await channel.request(execRequest);

    if (!result) {
      throw new Error("Exec request denied by server");
    }

    return await collectChannelOutput(channel);
  } finally {
    try {
      channel.dispose();
    } catch {
      // Ignore cleanup errors
    }
  }
}

/**
 * Collect all output from a channel until it closes
 */
async function collectChannelOutput(
  channel: SshChannel
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    let exitCode = 0;
    let closed = false;

    const timeout = setTimeout(() => {
      if (!closed) {
        closed = true;
        reject(new Error("Command execution timeout"));
      }
    }, 30000);

    channel.onDataReceived((data: Buffer) => {
      stdout += data.toString("utf-8");
      channel.adjustWindow(data.length);
    });

    // Handle extended data (stderr) - this may not be directly supported
    // by the library, but we'll try to capture what we can

    channel.onClosed(() => {
      if (!closed) {
        closed = true;
        clearTimeout(timeout);
        resolve({ stdout, stderr, exitCode });
      }
    });
  });
}

/**
 * List directory contents using ls -la
 */
export async function listDirectory(
  session: SshClientSession,
  path: string
): Promise<ExecFileEntry[]> {
  // Use ls with specific format for reliable parsing
  // -l = long format
  // -a = all files including hidden
  // --time-style=full-iso = consistent date format
  const command = `ls -la --time-style=full-iso "${path.replace(/"/g, '\\"')}" 2>/dev/null`;

  const { stdout } = await execCommand(session, command);

  return parseLsOutput(stdout, path);
}

/**
 * Parse ls -la output into file entries
 */
function parseLsOutput(output: string, basePath: string): ExecFileEntry[] {
  const lines = output.trim().split("\n");
  const entries: ExecFileEntry[] = [];

  for (const line of lines) {
    // Skip "total" line and empty lines
    if (!line || line.startsWith("total ")) continue;

    // Parse ls -la line format:
    // drwxr-xr-x 2 user group 4096 2024-01-01 12:00:00.000000000 +0000 name
    // -rw-r--r-- 1 user group 1234 2024-01-01 12:00:00.000000000 +0000 filename.txt
    const match = line.match(
      /^([drwxlsStT-]{10})\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\.\d+\s+[+-]\d{4}\s+(.+)$/
    );

    if (!match) {
      // Try simpler format without --time-style
      const simpleMatch = line.match(
        /^([drwxlsStT-]{10})\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+\s+\d+\s+[\d:]+)\s+(.+)$/
      );

      if (simpleMatch) {
        const [, perms, owner, group, size, dateStr, name] = simpleMatch;

        if (name === "." || name === "..") continue;

        entries.push({
          name,
          path: basePath === "/" ? `/${name}` : `${basePath}/${name}`,
          type: getFileType(perms),
          size: parseInt(size, 10),
          permissions: perms,
          owner,
          group,
          modified: new Date(dateStr),
        });
      }
      continue;
    }

    const [, perms, owner, group, size, date, time, name] = match;

    // Skip . and ..
    if (name === "." || name === "..") continue;

    // Handle symlinks (name -> target)
    const displayName = name.split(" -> ")[0];

    entries.push({
      name: displayName,
      path: basePath === "/" ? `/${displayName}` : `${basePath}/${displayName}`,
      type: getFileType(perms),
      size: parseInt(size, 10),
      permissions: perms,
      owner,
      group,
      modified: new Date(`${date}T${time}Z`),
    });
  }

  return entries.sort((a, b) => {
    // Directories first, then alphabetical
    if (a.type === "directory" && b.type !== "directory") return -1;
    if (a.type !== "directory" && b.type === "directory") return 1;
    return a.name.localeCompare(b.name);
  });
}

/**
 * Get file type from permission string
 */
function getFileType(perms: string): "file" | "directory" | "symlink" | "other" {
  switch (perms[0]) {
    case "d":
      return "directory";
    case "l":
      return "symlink";
    case "-":
      return "file";
    default:
      return "other";
  }
}

/**
 * Get the real path (resolve ~, symlinks, etc.)
 */
export async function realpath(
  session: SshClientSession,
  path: string
): Promise<string> {
  // Handle ~ specially
  if (path === "~" || path.startsWith("~/")) {
    const { stdout } = await execCommand(session, "echo $HOME");
    const home = stdout.trim();
    if (path === "~") return home;
    return home + path.substring(1);
  }

  const { stdout } = await execCommand(
    session,
    `readlink -f "${path.replace(/"/g, '\\"')}" 2>/dev/null || echo "${path.replace(/"/g, '\\"')}"`
  );
  return stdout.trim();
}

/**
 * Create a directory
 */
export async function mkdir(
  session: SshClientSession,
  path: string
): Promise<void> {
  const { stdout, stderr } = await execCommand(
    session,
    `mkdir -p "${path.replace(/"/g, '\\"')}" && echo OK`
  );

  if (!stdout.includes("OK")) {
    throw new Error(stderr || "Failed to create directory");
  }
}

/**
 * Remove a file or directory
 */
export async function remove(
  session: SshClientSession,
  path: string,
  isDirectory: boolean
): Promise<void> {
  const command = isDirectory
    ? `rmdir "${path.replace(/"/g, '\\"')}" && echo OK`
    : `rm "${path.replace(/"/g, '\\"')}" && echo OK`;

  const { stdout, stderr } = await execCommand(session, command);

  if (!stdout.includes("OK")) {
    throw new Error(stderr || "Failed to remove");
  }
}

/**
 * Rename a file or directory
 */
export async function rename(
  session: SshClientSession,
  oldPath: string,
  newPath: string
): Promise<void> {
  const { stdout, stderr } = await execCommand(
    session,
    `mv "${oldPath.replace(/"/g, '\\"')}" "${newPath.replace(/"/g, '\\"')}" && echo OK`
  );

  if (!stdout.includes("OK")) {
    throw new Error(stderr || "Failed to rename");
  }
}

/**
 * Change file permissions
 */
export async function chmod(
  session: SshClientSession,
  path: string,
  mode: string
): Promise<void> {
  const { stdout, stderr } = await execCommand(
    session,
    `chmod ${mode} "${path.replace(/"/g, '\\"')}" && echo OK`
  );

  if (!stdout.includes("OK")) {
    throw new Error(stderr || "Failed to change permissions");
  }
}

/**
 * Check if a path exists and get its type
 */
export async function stat(
  session: SshClientSession,
  path: string
): Promise<{ exists: boolean; isDirectory: boolean }> {
  const { stdout } = await execCommand(
    session,
    `test -e "${path.replace(/"/g, '\\"')}" && (test -d "${path.replace(/"/g, '\\"')}" && echo "DIR" || echo "FILE") || echo "NONE"`
  );

  const result = stdout.trim();
  return {
    exists: result !== "NONE",
    isDirectory: result === "DIR",
  };
}
