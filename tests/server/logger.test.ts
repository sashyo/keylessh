/**
 * @fileoverview Tests for the server-side logging utilities.
 *
 * This file tests:
 * - log() - Basic logging with timestamp and source
 * - logInfo() - Info level with ● prefix
 * - logWarn() - Warning level with ▲ prefix (uses console.warn)
 * - logError() - Error level with ✗ prefix (uses console.error)
 * - logDebug() - Debug level with ○ prefix (only when DEBUG env is set)
 * - logForseti() - Specialized logging for Forseti contract operations
 *
 * These logging functions provide consistent, formatted output for
 * server-side operations with appropriate log levels.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { log, logInfo, logWarn, logError, logDebug, logForseti } from "../../server/logger";

/**
 * Tests for all logging functions.
 * Uses mocked console methods to verify output format.
 */
describe("Logger Functions", () => {
  // Save original console methods
  const originalConsole = {
    log: console.log,
    warn: console.warn,
    error: console.error,
  };
  const originalEnv = process.env.DEBUG;

  beforeEach(() => {
    // Mock console methods
    console.log = vi.fn();
    console.warn = vi.fn();
    console.error = vi.fn();
    delete process.env.DEBUG;
  });

  afterEach(() => {
    // Restore console methods
    console.log = originalConsole.log;
    console.warn = originalConsole.warn;
    console.error = originalConsole.error;
    process.env.DEBUG = originalEnv;
  });

  /**
   * Tests for log() - basic logging.
   * Format: "HH:MM:SS [source] message"
   */
  describe("log", () => {
    // Default source is "server"
    it("should log message with default source", () => {
      log("Test message");
      expect(console.log).toHaveBeenCalledTimes(1);
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain("[server]");
      expect(call).toContain("Test message");
    });

    // Custom source can be provided
    it("should log message with custom source", () => {
      log("Test message", "custom");
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain("[custom]");
      expect(call).toContain("Test message");
    });

    // All logs include timestamp in HH:MM:SS format
    it("should include timestamp", () => {
      log("Test");
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toMatch(/\d{2}:\d{2}:\d{2}/);
    });
  });

  /**
   * Tests for logInfo() - info level logging.
   * Format: "HH:MM:SS ● [source] message"
   */
  describe("logInfo", () => {
    // Should use ● (filled circle) prefix for info
    it("should log info message with info prefix", () => {
      logInfo("Info message");
      expect(console.log).toHaveBeenCalledTimes(1);
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain("●");
      expect(call).toContain("[server]");
      expect(call).toContain("Info message");
    });

    // Custom source works with logInfo
    it("should use custom source", () => {
      logInfo("Info", "auth");
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain("[auth]");
    });
  });

  /**
   * Tests for logWarn() - warning level logging.
   * Format: "HH:MM:SS ▲ [source] message"
   * Uses console.warn instead of console.log
   */
  describe("logWarn", () => {
    // Should use ▲ (triangle) prefix for warnings
    it("should log warning message with warn prefix", () => {
      logWarn("Warning message");
      expect(console.warn).toHaveBeenCalledTimes(1);
      const call = (console.warn as any).mock.calls[0][0];
      expect(call).toContain("▲");
      expect(call).toContain("[server]");
      expect(call).toContain("Warning message");
    });

    // Uses console.warn, not console.log
    it("should use console.warn", () => {
      logWarn("Test warning");
      expect(console.warn).toHaveBeenCalled();
      expect(console.log).not.toHaveBeenCalled();
    });
  });

  /**
   * Tests for logError() - error level logging.
   * Format: "HH:MM:SS ✗ [source] message"
   * Uses console.error instead of console.log
   */
  describe("logError", () => {
    // Should use ✗ (cross) prefix for errors
    it("should log error message with error prefix", () => {
      logError("Error message");
      expect(console.error).toHaveBeenCalledTimes(1);
      const call = (console.error as any).mock.calls[0][0];
      expect(call).toContain("✗");
      expect(call).toContain("[server]");
      expect(call).toContain("Error message");
    });

    // Uses console.error, not console.log
    it("should use console.error", () => {
      logError("Test error");
      expect(console.error).toHaveBeenCalled();
      expect(console.log).not.toHaveBeenCalled();
    });

    // Custom source works with logError
    it("should use custom source", () => {
      logError("Error", "database");
      const call = (console.error as any).mock.calls[0][0];
      expect(call).toContain("[database]");
    });
  });

  /**
   * Tests for logDebug() - debug level logging.
   * Format: "HH:MM:SS ○ [source] message"
   * Only logs when process.env.DEBUG is set
   */
  describe("logDebug", () => {
    // Silent when DEBUG is not set (production mode)
    it("should NOT log when DEBUG is not set", () => {
      delete process.env.DEBUG;
      logDebug("Debug message");
      expect(console.log).not.toHaveBeenCalled();
    });

    // Logs when DEBUG is set (development mode)
    it("should log when DEBUG is set", () => {
      process.env.DEBUG = "true";
      logDebug("Debug message");
      expect(console.log).toHaveBeenCalledTimes(1);
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain("○");
      expect(call).toContain("Debug message");
    });

    // Custom source works when DEBUG is set
    it("should use custom source when DEBUG is set", () => {
      process.env.DEBUG = "1";
      logDebug("Debug", "test");
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain("[test]");
    });

    // Any truthy DEBUG value enables debug logging
    it("should work with any truthy DEBUG value", () => {
      process.env.DEBUG = "anything";
      logDebug("Test");
      expect(console.log).toHaveBeenCalled();
    });
  });

  /**
   * Tests for logForseti() - Forseti contract logging.
   * Format: "HH:MM:SS ● [forseti] action | key=value | key=value"
   * Specialized for logging contract compilation/execution
   */
  describe("logForseti", () => {
    // Logs action with key=value detail pairs
    it("should log forseti action with details", () => {
      logForseti("compile", { source: "test.cs", entryType: "TestPolicy" });
      expect(console.log).toHaveBeenCalledTimes(1);
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain("[forseti]");
      expect(call).toContain("compile");
      expect(call).toContain("source=test.cs");
      expect(call).toContain("entryType=TestPolicy");
    });

    // Uses info prefix (●)
    it("should include info prefix", () => {
      logForseti("execute", {});
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain("●");
    });

    // Objects are JSON stringified
    it("should handle object values by stringifying", () => {
      logForseti("validate", { config: { threshold: 2, enabled: true } });
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain('"threshold":2');
      expect(call).toContain('"enabled":true');
    });

    // Strings are output directly without quotes
    it("should handle string values without quotes", () => {
      logForseti("test", { message: "hello world" });
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain("message=hello world");
    });

    // Numbers are converted to strings
    it("should handle numeric values", () => {
      logForseti("stats", { count: 42, ratio: 0.5 });
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain("count=42");
      expect(call).toContain("ratio=0.5");
    });

    // Multiple details separated by |
    it("should separate multiple details with |", () => {
      logForseti("action", { a: "1", b: "2", c: "3" });
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain(" | ");
    });

    // Empty details object is valid
    it("should handle empty details", () => {
      logForseti("action", {});
      expect(console.log).toHaveBeenCalled();
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain("[forseti]");
      expect(call).toContain("action");
    });

    // Arrays are JSON stringified
    it("should handle arrays in details", () => {
      logForseti("list", { items: ["a", "b", "c"] });
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain('["a","b","c"]');
    });

    // Booleans are converted to strings
    it("should handle boolean values", () => {
      logForseti("check", { valid: true, complete: false });
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain("valid=true");
      expect(call).toContain("complete=false");
    });

    // Null values are output as "null"
    it("should handle null values", () => {
      logForseti("data", { value: null });
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain("value=null");
    });
  });

  /**
   * Tests for timestamp formatting.
   */
  describe("Timestamp Format", () => {
    // Uses 24-hour time format (14:30:45 not 2:30:45 PM)
    it("should use 24-hour format", () => {
      const mockDate = new Date("2024-01-15T14:30:45");
      vi.setSystemTime(mockDate);

      log("Test");
      const call = (console.log as any).mock.calls[0][0];
      expect(call).toContain("14:30:45");

      vi.useRealTimers();
    });
  });
});
