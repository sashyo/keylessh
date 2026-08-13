/**
 * The gateway's `backends` setting is a single string using the format
 * `Name=url;flag;flag, Name=url`. These helpers convert it to and from rows so
 * the console can edit backends as fields instead of hand-written text.
 *
 * Kept in sync with `parse_backends_str` in the gateway's config.rs.
 */

export type BackendProtocol = "rdp" | "ssh" | "http";

export interface BackendRow {
  name: string;
  url: string;
  /** Skip JWT verification for this backend. */
  noAuth: boolean;
  /** Strip auth headers before forwarding to the backend. */
  stripAuth: boolean;
  /** Passwordless RDP using EdDSA certificates. */
  eddsa: boolean;
}

export const EMPTY_BACKEND: BackendRow = {
  name: "",
  url: "",
  noAuth: false,
  stripAuth: false,
  eddsa: false,
};

/** Protocol the gateway infers from a backend URL. */
export function backendProtocol(url: string): BackendProtocol {
  const trimmed = url.trim().toLowerCase();
  if (trimmed.startsWith("rdp://")) return "rdp";
  if (trimmed.startsWith("ssh://")) return "ssh";
  return "http";
}

/**
 * Parse a backends string into rows. Malformed entries (no `=`, or an empty
 * URL) are dropped, matching what the gateway would refuse to load.
 */
export function parseBackends(input: string | null | undefined): BackendRow[] {
  if (!input) return [];

  return input
    .split(",")
    .map((entry) => {
      const eq = entry.indexOf("=");
      if (eq === -1) return null;

      const name = entry.slice(0, eq).trim();
      let url = entry.slice(eq + 1).trim().replace(/;+$/, "");

      const row: BackendRow = { ...EMPTY_BACKEND, name };

      // Flags are suffixes and may repeat in any order.
      for (;;) {
        const lower = url.toLowerCase();
        if (lower.endsWith(";noauth")) {
          row.noAuth = true;
          url = url.slice(0, -";noauth".length).trim();
        } else if (lower.endsWith(";stripauth")) {
          row.stripAuth = true;
          url = url.slice(0, -";stripauth".length).trim();
        } else if (lower.endsWith(";eddsa")) {
          row.eddsa = true;
          url = url.slice(0, -";eddsa".length).trim();
        } else {
          break;
        }
      }

      if (!name || !url) return null;
      return { ...row, url };
    })
    .filter((row): row is BackendRow => row !== null);
}

/** Render rows back to the gateway's backends string. Blank rows are skipped. */
export function serializeBackends(rows: BackendRow[]): string {
  return rows
    .filter((row) => row.name.trim() && row.url.trim())
    .map((row) => {
      const flags = [
        row.noAuth ? ";noauth" : "",
        row.stripAuth ? ";stripauth" : "",
        row.eddsa ? ";eddsa" : "",
      ].join("");
      return `${row.name.trim()}=${row.url.trim()}${flags}`;
    })
    .join(", ");
}
