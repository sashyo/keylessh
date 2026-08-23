/**
 * SSH host key verification.
 *
 * The browser SSH client accepted whatever host key was presented, so anything
 * in the relay path — a compromised gateway or signal server, or anyone able to
 * influence which endpoint the gateway dials — could impersonate a target host.
 * Publickey auth signs over the session id, so a man-in-the-middle cannot replay
 * the user's credentials to the real host, but it can present a convincing shell
 * and read everything typed into it.
 *
 * This pins the host key: the first connection records it, and every later one
 * must match. Fingerprints are formatted exactly as OpenSSH prints them, so a
 * value shown here can be compared against `ssh-keygen -lf` on the host itself.
 */

export type HostKeyStatus = "match" | "mismatch" | "unknown";

/** What the operator is shown when confirming a host on first contact. */
export interface HostKeyPrompt {
  host: string;
  port: number;
  algorithm: string;
  fingerprint: string;
  publicKey: string;
}

export interface HostKeyIdentity {
  /** SSH algorithm name, e.g. "ssh-ed25519". */
  algorithm: string;
  /** Base64 of the SSH wire-format public key blob. */
  publicKey: string;
}

export interface PinnedHostKey extends HostKeyIdentity {
  fingerprint: string;
}

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

/**
 * OpenSSH-style fingerprint: `SHA256:` followed by the base64 of the digest with
 * padding stripped, matching `ssh-keygen -lf` output so the two can be compared
 * by eye.
 */
export async function sshFingerprint(keyBlob: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", keyBlob as BufferSource);
  return `SHA256:${toBase64(new Uint8Array(digest)).replace(/=+$/, "")}`;
}

/**
 * Compare a presented key against what is pinned for a target.
 *
 * Comparison is on the key bytes, not the fingerprint: a fingerprint is a digest
 * of those bytes and adds nothing here, while comparing the bytes leaves no room
 * for a hash mismatch to be read as a key mismatch or vice versa.
 */
export function verifyHostKey(
  presented: HostKeyIdentity,
  pinned: PinnedHostKey | null | undefined,
): HostKeyStatus {
  if (!pinned) return "unknown";
  // A changed algorithm is a changed key, even if one is somehow a prefix of
  // the other, so both must agree.
  if (presented.algorithm !== pinned.algorithm) return "mismatch";
  return presented.publicKey === pinned.publicKey ? "match" : "mismatch";
}

/**
 * Stable identifier for the host being connected to.
 *
 * A server record is preferred: it survives the host changing address. Falling
 * back to host:port keeps ad-hoc connections — custom IPs, gateway backends
 * with no server record — pinnable too.
 */
export function hostKeyTarget(opts: { serverId?: string | null; host: string; port: number }): string {
  if (opts.serverId) return `server:${opts.serverId}`;
  return `addr:${opts.host.toLowerCase()}:${opts.port}`;
}

/** The line a user can compare against ~/.ssh/known_hosts on the host. */
export function knownHostsLine(host: string, key: HostKeyIdentity): string {
  return `${host} ${key.algorithm} ${key.publicKey}`;
}
