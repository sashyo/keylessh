/**
 * @fileoverview Tests for the gateway backends DSL used by the console editor.
 *
 * The format (`Name=url;flag;flag, Name=url`) is parsed by the gateway in
 * parse_backends_str; these tests pin the console's parse/serialize to it.
 */

import { describe, it, expect } from "vitest";
import {
  parseBackends,
  serializeBackends,
  backendProtocol,
  type BackendRow,
} from "../../client/src/lib/backends";

describe("backendProtocol", () => {
  it("detects rdp, ssh, and defaults to http", () => {
    expect(backendProtocol("rdp://10.0.0.9:3389")).toBe("rdp");
    expect(backendProtocol("ssh://10.0.0.9:22")).toBe("ssh");
    expect(backendProtocol("http://10.0.0.9:8080")).toBe("http");
    expect(backendProtocol("https://app.internal")).toBe("http");
  });

  it("is case insensitive and ignores surrounding space", () => {
    expect(backendProtocol("  RDP://10.0.0.9:3389 ")).toBe("rdp");
  });
});

describe("parseBackends", () => {
  it("returns nothing for empty input", () => {
    expect(parseBackends("")).toEqual([]);
    expect(parseBackends(null)).toEqual([]);
    expect(parseBackends(undefined)).toEqual([]);
  });

  it("parses a single backend", () => {
    expect(parseBackends("App=http://10.0.0.5:8080")).toEqual([
      { name: "App", url: "http://10.0.0.5:8080", noAuth: false, stripAuth: false, eddsa: false },
    ]);
  });

  it("parses several backends with surrounding space", () => {
    const rows = parseBackends("App=http://10.0.0.5:8080, Desk = rdp://10.0.0.9:3389 ");

    expect(rows).toHaveLength(2);
    expect(rows[1]).toMatchObject({ name: "Desk", url: "rdp://10.0.0.9:3389" });
  });

  it("parses flags in any order and combination", () => {
    const rows = parseBackends("A=rdp://h:3389;eddsa, B=http://h:80;noauth;stripauth");

    expect(rows[0]).toMatchObject({ eddsa: true, noAuth: false, stripAuth: false });
    expect(rows[1]).toMatchObject({ noAuth: true, stripAuth: true, eddsa: false });
    expect(rows[0].url).toBe("rdp://h:3389");
    expect(rows[1].url).toBe("http://h:80");
  });

  it("is case insensitive on flags", () => {
    expect(parseBackends("A=rdp://h:3389;EdDSA")[0]).toMatchObject({ eddsa: true, url: "rdp://h:3389" });
  });

  it("tolerates trailing semicolons", () => {
    expect(parseBackends("A=http://h:80;;")[0].url).toBe("http://h:80");
  });

  it("drops entries the gateway would refuse", () => {
    expect(parseBackends("no-equals-sign")).toEqual([]);
    expect(parseBackends("A=")).toEqual([]);
    expect(parseBackends("=http://h:80")).toEqual([]);
  });

  it("keeps the valid entries alongside a malformed one", () => {
    const rows = parseBackends("Good=http://h:80, garbage, Also=ssh://h:22");

    expect(rows.map((r) => r.name)).toEqual(["Good", "Also"]);
  });
});

describe("serializeBackends", () => {
  const row = (over: Partial<BackendRow> = {}): BackendRow => ({
    name: "App",
    url: "http://10.0.0.5:8080",
    noAuth: false,
    stripAuth: false,
    eddsa: false,
    ...over,
  });

  it("renders name=url pairs", () => {
    expect(serializeBackends([row()])).toBe("App=http://10.0.0.5:8080");
  });

  it("appends set flags", () => {
    expect(serializeBackends([row({ url: "rdp://h:3389", eddsa: true })])).toBe("App=rdp://h:3389;eddsa");
    expect(serializeBackends([row({ noAuth: true, stripAuth: true })])).toBe(
      "App=http://10.0.0.5:8080;noauth;stripauth"
    );
  });

  it("joins multiple backends with a comma", () => {
    expect(serializeBackends([row(), row({ name: "Desk", url: "rdp://h:3389" })])).toBe(
      "App=http://10.0.0.5:8080, Desk=rdp://h:3389"
    );
  });

  it("skips rows the user has not filled in", () => {
    expect(serializeBackends([row(), row({ name: "", url: "" }), row({ name: "Half", url: "" })])).toBe(
      "App=http://10.0.0.5:8080"
    );
  });

  it("trims whitespace the user typed", () => {
    expect(serializeBackends([row({ name: "  App  ", url: "  http://h:80  " })])).toBe("App=http://h:80");
  });

  it("returns an empty string for no rows", () => {
    expect(serializeBackends([])).toBe("");
  });
});

describe("round trip", () => {
  it("preserves a config through parse and serialize", () => {
    const original = "App=http://10.0.0.5:8080, Desk=rdp://10.0.0.9:3389;eddsa, Shell=ssh://10.0.0.3:22;noauth";

    expect(serializeBackends(parseBackends(original))).toBe(original);
  });

  it("normalizes spacing without changing meaning", () => {
    const messy = "App = http://10.0.0.5:8080 ,Desk=rdp://10.0.0.9:3389;eddsa";

    const normalized = serializeBackends(parseBackends(messy));
    expect(normalized).toBe("App=http://10.0.0.5:8080, Desk=rdp://10.0.0.9:3389;eddsa");
    expect(parseBackends(normalized)).toEqual(parseBackends(messy));
  });
});
