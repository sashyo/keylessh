/**
 * SFTP Protocol Constants and Types
 * Based on draft-ietf-secsh-filexfer-02 (SFTP v3) for OpenSSH compatibility
 */

// SFTP Packet Types
export const SSH_FXP = {
  INIT: 1,
  VERSION: 2,
  OPEN: 3,
  CLOSE: 4,
  READ: 5,
  WRITE: 6,
  LSTAT: 7,
  FSTAT: 8,
  SETSTAT: 9,
  FSETSTAT: 10,
  OPENDIR: 11,
  READDIR: 12,
  REMOVE: 13,
  MKDIR: 14,
  RMDIR: 15,
  REALPATH: 16,
  STAT: 17,
  RENAME: 18,
  READLINK: 19,
  SYMLINK: 20,
  // Response types
  STATUS: 101,
  HANDLE: 102,
  DATA: 103,
  NAME: 104,
  ATTRS: 105,
  EXTENDED: 200,
  EXTENDED_REPLY: 201,
} as const;

export type SftpPacketType = (typeof SSH_FXP)[keyof typeof SSH_FXP];

// File Open Flags (SSH_FXF_*)
export const SSH_FXF = {
  READ: 0x00000001,
  WRITE: 0x00000002,
  APPEND: 0x00000004,
  CREAT: 0x00000008,
  TRUNC: 0x00000010,
  EXCL: 0x00000020,
} as const;

// Attribute Flags (SSH_FILEXFER_ATTR_*)
export const SSH_FILEXFER_ATTR = {
  SIZE: 0x00000001,
  UIDGID: 0x00000002,
  PERMISSIONS: 0x00000004,
  ACMODTIME: 0x00000008,
  EXTENDED: 0x80000000,
} as const;

// Status Codes (SSH_FX_*)
export const SSH_FX = {
  OK: 0,
  EOF: 1,
  NO_SUCH_FILE: 2,
  PERMISSION_DENIED: 3,
  FAILURE: 4,
  BAD_MESSAGE: 5,
  NO_CONNECTION: 6,
  CONNECTION_LOST: 7,
  OP_UNSUPPORTED: 8,
} as const;

export type SftpStatusCode = (typeof SSH_FX)[keyof typeof SSH_FX];

// Status code to message mapping
export const SSH_FX_MESSAGES: Record<SftpStatusCode, string> = {
  [SSH_FX.OK]: "Success",
  [SSH_FX.EOF]: "End of file",
  [SSH_FX.NO_SUCH_FILE]: "No such file or directory",
  [SSH_FX.PERMISSION_DENIED]: "Permission denied",
  [SSH_FX.FAILURE]: "Operation failed",
  [SSH_FX.BAD_MESSAGE]: "Bad message",
  [SSH_FX.NO_CONNECTION]: "No connection",
  [SSH_FX.CONNECTION_LOST]: "Connection lost",
  [SSH_FX.OP_UNSUPPORTED]: "Operation not supported",
};

// File type bits (from permissions)
export const S_IFMT = 0o170000; // File type mask
export const S_IFSOCK = 0o140000; // Socket
export const S_IFLNK = 0o120000; // Symbolic link
export const S_IFREG = 0o100000; // Regular file
export const S_IFBLK = 0o060000; // Block device
export const S_IFDIR = 0o040000; // Directory
export const S_IFCHR = 0o020000; // Character device
export const S_IFIFO = 0o010000; // FIFO

// Permission bits
export const S_ISUID = 0o4000; // Set UID
export const S_ISGID = 0o2000; // Set GID
export const S_ISVTX = 0o1000; // Sticky bit
export const S_IRWXU = 0o0700; // Owner RWX
export const S_IRUSR = 0o0400; // Owner read
export const S_IWUSR = 0o0200; // Owner write
export const S_IXUSR = 0o0100; // Owner execute
export const S_IRWXG = 0o0070; // Group RWX
export const S_IRGRP = 0o0040; // Group read
export const S_IWGRP = 0o0020; // Group write
export const S_IXGRP = 0o0010; // Group execute
export const S_IRWXO = 0o0007; // Others RWX
export const S_IROTH = 0o0004; // Others read
export const S_IWOTH = 0o0002; // Others write
export const S_IXOTH = 0o0001; // Others execute

// SFTP protocol version we support
export const SFTP_VERSION = 3;

// Default chunk size for file transfers (32KB)
export const DEFAULT_CHUNK_SIZE = 32 * 1024;

// Maximum packet size
export const MAX_PACKET_SIZE = 256 * 1024;

/**
 * SFTP File Attributes
 */
export interface SftpAttrs {
  flags: number;
  size?: bigint;
  uid?: number;
  gid?: number;
  permissions?: number;
  atime?: number;
  mtime?: number;
  extended?: Array<{ type: string; data: string }>;
}

/**
 * SFTP Directory Entry (from READDIR)
 */
export interface SftpFileEntry {
  filename: string;
  longname: string; // ls -l style string
  attrs: SftpAttrs;
}

/**
 * Parsed file info for UI display
 */
export interface SftpFileInfo {
  name: string;
  path: string;
  type: "file" | "directory" | "symlink" | "other";
  size: number;
  permissions: number;
  permissionsString: string; // e.g., "rwxr-xr-x"
  owner: number;
  group: number;
  modifiedAt: Date | null;
  accessedAt: Date | null;
}

/**
 * SFTP Error class
 */
export class SftpError extends Error {
  constructor(
    public readonly code: SftpStatusCode,
    message?: string
  ) {
    super(message || SSH_FX_MESSAGES[code] || `SFTP error ${code}`);
    this.name = "SftpError";
  }
}

/**
 * Helper: Check if permissions indicate a directory
 */
export function isDirectory(permissions: number): boolean {
  return (permissions & S_IFMT) === S_IFDIR;
}

/**
 * Helper: Check if permissions indicate a regular file
 */
export function isRegularFile(permissions: number): boolean {
  return (permissions & S_IFMT) === S_IFREG;
}

/**
 * Helper: Check if permissions indicate a symbolic link
 */
export function isSymlink(permissions: number): boolean {
  return (permissions & S_IFMT) === S_IFLNK;
}

/**
 * Helper: Get file type from permissions
 */
export function getFileType(
  permissions: number
): "file" | "directory" | "symlink" | "other" {
  const type = permissions & S_IFMT;
  switch (type) {
    case S_IFDIR:
      return "directory";
    case S_IFREG:
      return "file";
    case S_IFLNK:
      return "symlink";
    default:
      return "other";
  }
}

/**
 * Helper: Convert permissions to string (e.g., "rwxr-xr-x")
 */
export function permissionsToString(permissions: number): string {
  const chars = ["-", "-", "-", "-", "-", "-", "-", "-", "-"];

  if (permissions & S_IRUSR) chars[0] = "r";
  if (permissions & S_IWUSR) chars[1] = "w";
  if (permissions & S_IXUSR) chars[2] = "x";
  if (permissions & S_IRGRP) chars[3] = "r";
  if (permissions & S_IWGRP) chars[4] = "w";
  if (permissions & S_IXGRP) chars[5] = "x";
  if (permissions & S_IROTH) chars[6] = "r";
  if (permissions & S_IWOTH) chars[7] = "w";
  if (permissions & S_IXOTH) chars[8] = "x";

  // Special bits
  if (permissions & S_ISUID) chars[2] = chars[2] === "x" ? "s" : "S";
  if (permissions & S_ISGID) chars[5] = chars[5] === "x" ? "s" : "S";
  if (permissions & S_ISVTX) chars[8] = chars[8] === "x" ? "t" : "T";

  return chars.join("");
}

/**
 * Helper: Parse permissions from octal string (e.g., "755" -> 0o755)
 */
export function parseOctalPermissions(octal: string): number {
  const num = parseInt(octal, 8);
  if (isNaN(num) || num < 0 || num > 0o7777) {
    throw new Error(`Invalid octal permissions: ${octal}`);
  }
  return num;
}

/**
 * Helper: Format file size for display
 */
export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

/**
 * Helper: Parse SftpFileEntry to SftpFileInfo
 */
export function parseFileEntry(entry: SftpFileEntry, basePath: string): SftpFileInfo {
  const permissions = entry.attrs.permissions ?? 0;
  const path = basePath.endsWith("/")
    ? `${basePath}${entry.filename}`
    : `${basePath}/${entry.filename}`;

  return {
    name: entry.filename,
    path,
    type: getFileType(permissions),
    size: Number(entry.attrs.size ?? BigInt(0)),
    permissions: permissions & 0o7777, // Strip file type bits
    permissionsString: permissionsToString(permissions),
    owner: entry.attrs.uid ?? 0,
    group: entry.attrs.gid ?? 0,
    modifiedAt: entry.attrs.mtime ? new Date(entry.attrs.mtime * 1000) : null,
    accessedAt: entry.attrs.atime ? new Date(entry.attrs.atime * 1000) : null,
  };
}
