/**
 * @fileoverview Tests for the React Query client and API request utilities.
 *
 * This file tests:
 * - apiRequest() - Generic HTTP request function with auth
 * - getQueryFn() - Query function factory for React Query
 * - queryClient - Configured QueryClient instance
 *
 * These utilities form the data fetching layer of the application,
 * handling authentication, error handling, and caching configuration.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { apiRequest, getQueryFn, queryClient } from "@/lib/queryClient";

// Mock the global fetch function
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Mock localStorage for token storage - verifies correct key is used
const TOKEN_KEY = "access_token";
let storedToken: string | null = null;
const localStorageMock = {
  getItem: vi.fn((key: string) => {
    // Only return token for the correct key to ensure code uses right key
    return key === TOKEN_KEY ? storedToken : null;
  }),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};
Object.defineProperty(global, "localStorage", { value: localStorageMock });

/**
 * Tests for the apiRequest() function.
 * This is the low-level HTTP request utility used by the API client.
 */
describe("apiRequest", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    storedToken = null;
  });

  // Basic GET request without authentication
  it("should make a GET request without data", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ data: "test" }),
    });

    const result = await apiRequest("GET", "/api/test");

    expect(mockFetch).toHaveBeenCalledWith("/api/test", {
      method: "GET",
      headers: {},
      body: undefined,
      credentials: "include",
    });
    expect(result).toEqual({ data: "test" });
  });

  // POST request with JSON body
  it("should make a POST request with data", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ success: true }),
    });

    const data = { name: "test" };
    const result = await apiRequest("POST", "/api/test", data);

    expect(mockFetch).toHaveBeenCalledWith("/api/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
      credentials: "include",
    });
    expect(result).toEqual({ success: true });
  });

  // Adds Bearer token from localStorage when available
  it("should include Authorization header when token exists", async () => {
    storedToken = "test-token";
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ data: "test" }),
    });

    await apiRequest("GET", "/api/test");

    // Verify getItem was called with the correct key
    expect(localStorageMock.getItem).toHaveBeenCalledWith(TOKEN_KEY);
    expect(mockFetch).toHaveBeenCalledWith("/api/test", {
      method: "GET",
      headers: { Authorization: "Bearer test-token" },
      body: undefined,
      credentials: "include",
    });
  });

  // Error handling: throws with status and message for non-ok responses
  it("should throw error on non-ok response", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: "Not Found",
      text: () => Promise.resolve("Resource not found"),
    });

    await expect(apiRequest("GET", "/api/test")).rejects.toThrow("404: Resource not found");
  });

  // Falls back to statusText when body is empty
  it("should use statusText when text() returns empty", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      text: () => Promise.resolve(""),
    });

    await expect(apiRequest("GET", "/api/test")).rejects.toThrow("500: Internal Server Error");
  });

  // PUT requests for updates
  it("should handle PUT requests", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ updated: true }),
    });

    await apiRequest("PUT", "/api/test", { id: 1, value: "new" });

    expect(mockFetch).toHaveBeenCalledWith("/api/test", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: 1, value: "new" }),
      credentials: "include",
    });
  });

  // DELETE requests typically don't have a body
  it("should handle DELETE requests", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ deleted: true }),
    });

    await apiRequest("DELETE", "/api/test/1");

    expect(mockFetch).toHaveBeenCalledWith("/api/test/1", {
      method: "DELETE",
      headers: {},
      body: undefined,
      credentials: "include",
    });
  });
});

/**
 * Tests for the getQueryFn() factory function.
 * Creates query functions for use with React Query's useQuery hook.
 */
describe("getQueryFn", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    storedToken = null;
  });

  /**
   * Tests with on401: "throw" behavior.
   * This mode throws an error on 401, forcing re-authentication.
   */
  describe("with on401: throw", () => {
    const queryFn = getQueryFn({ on401: "throw" });

    // Successful requests return parsed JSON data
    it("should return data on successful request", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ data: "test" }),
      });

      const result = await queryFn({ queryKey: ["/api", "test"] } as any);
      expect(result).toEqual({ data: "test" });
    });

    // 401 errors are thrown to trigger auth flows
    it("should throw on 401 response", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
        text: () => Promise.resolve("Unauthorized"),
      });

      await expect(queryFn({ queryKey: ["/api/protected"] } as any)).rejects.toThrow("401");
    });

    // Query key array is joined with / to form URL
    it("should join query key parts as URL", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      });

      await queryFn({ queryKey: ["/api", "users", "123"] } as any);

      expect(mockFetch).toHaveBeenCalledWith("/api/users/123", expect.any(Object));
    });
  });

  /**
   * Tests with on401: "returnNull" behavior.
   * This mode silently returns null on 401, useful for optional auth.
   */
  describe("with on401: returnNull", () => {
    const queryFn = getQueryFn({ on401: "returnNull" });

    // 401 returns null instead of throwing
    it("should return null on 401 response", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
      });

      const result = await queryFn({ queryKey: ["/api/protected"] } as any);
      expect(result).toBeNull();
    });

    // Other errors still throw
    it("should still throw on other errors", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Server Error",
        text: () => Promise.resolve("Internal error"),
      });

      await expect(queryFn({ queryKey: ["/api/test"] } as any)).rejects.toThrow("500");
    });

    // Success still returns data
    it("should return data on success", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ user: { id: 1 } }),
      });

      const result = await queryFn({ queryKey: ["/api/user"] } as any);
      expect(result).toEqual({ user: { id: 1 } });
    });
  });

  // Token is passed in Authorization header when available
  it("should include Authorization header when token exists", async () => {
    storedToken = "my-token";
    const queryFn = getQueryFn({ on401: "throw" });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({}),
    });

    await queryFn({ queryKey: ["/api/test"] } as any);

    // Verify getItem was called with the correct key
    expect(localStorageMock.getItem).toHaveBeenCalledWith(TOKEN_KEY);
    expect(mockFetch).toHaveBeenCalledWith("/api/test", {
      credentials: "include",
      headers: { Authorization: "Bearer my-token" },
    });
  });
});

/**
 * Tests for the configured QueryClient instance.
 * Verifies default options for caching and retry behavior.
 */
describe("queryClient", () => {
  // Should be a valid QueryClient with expected methods
  it("should be a QueryClient instance", () => {
    expect(queryClient).toBeDefined();
    expect(typeof queryClient.getQueryData).toBe("function");
    expect(typeof queryClient.setQueryData).toBe("function");
    expect(typeof queryClient.invalidateQueries).toBe("function");
  });

  // Retry is disabled to prevent hammering failed endpoints
  it("should have retry disabled by default", () => {
    const defaultOptions = queryClient.getDefaultOptions();
    expect(defaultOptions.queries?.retry).toBe(false);
  });

  // Don't refetch when window regains focus (manual refresh preferred)
  it("should have refetchOnWindowFocus disabled", () => {
    const defaultOptions = queryClient.getDefaultOptions();
    expect(defaultOptions.queries?.refetchOnWindowFocus).toBe(false);
  });

  // Data never goes stale automatically (explicit invalidation required)
  it("should have staleTime set to Infinity", () => {
    const defaultOptions = queryClient.getDefaultOptions();
    expect(defaultOptions.queries?.staleTime).toBe(Infinity);
  });

  // Mutations also don't retry
  it("should have mutation retry disabled", () => {
    const defaultOptions = queryClient.getDefaultOptions();
    expect(defaultOptions.mutations?.retry).toBe(false);
  });
});
