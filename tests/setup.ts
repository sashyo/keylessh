import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

// Mock native ESM modules that fail to resolve in the test environment.
// secureFetch strips the origin back to a relative URL so existing tests
// that assert on relative paths keep working.
vi.mock("@tidecloak/js", () => ({
  IAMService: {
    getToken: vi.fn().mockResolvedValue("mock-token"),
    secureFetch: vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      // Strip origin (e.g. "http://localhost:3000/api/foo" → "/api/foo")
      try {
        const u = new URL(url);
        return globalThis.fetch(u.pathname + u.search + u.hash, init);
      } catch {
        return globalThis.fetch(url, init);
      }
    }),
    isLoggedIn: vi.fn().mockReturnValue(false),
    on: vi.fn().mockReturnThis(),
  },
}));

vi.mock("heimdall-tide", () => ({
  Policy: {},
  PolicySignRequest: {},
  TideMemory: {},
}));

vi.mock("asgard-tide", () => ({
  ApprovalType: {},
  ExecutionType: {},
}));

// Cleanup after each test case (for React component tests)
afterEach(() => {
  cleanup();
});

// Mock environment variables for tests
process.env.NODE_ENV = "test";
