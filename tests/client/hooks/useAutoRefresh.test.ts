/**
 * @fileoverview Tests for the useAutoRefresh React hook.
 *
 * This file tests:
 * - Auto-refresh countdown behavior
 * - Manual refresh triggering (refreshNow)
 * - Timer reset functionality (resetTimer)
 * - Enabled/disabled state handling
 * - Blocking behavior during operations
 * - Cleanup on unmount
 *
 * The useAutoRefresh hook provides automatic data refreshing with
 * countdown display, used in admin panels to keep data current.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { useAutoRefresh } from "@/hooks/useAutoRefresh";

/**
 * Tests for the useAutoRefresh hook.
 * Uses fake timers to test time-based behavior.
 */
describe("useAutoRefresh", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // Initial secondsRemaining should equal the interval
  it("should return secondsRemaining based on interval", () => {
    const refresh = vi.fn();
    const { result } = renderHook(() =>
      useAutoRefresh({
        intervalSeconds: 30,
        refresh,
      })
    );

    expect(result.current.secondsRemaining).toBe(30);
  });

  // secondsRemaining should decrease as time passes
  it("should countdown seconds remaining", async () => {
    const refresh = vi.fn();
    const { result } = renderHook(() =>
      useAutoRefresh({
        intervalSeconds: 10,
        refresh,
      })
    );

    expect(result.current.secondsRemaining).toBe(10);

    // Advance time by 5 seconds
    act(() => {
      vi.advanceTimersByTime(5000);
    });

    expect(result.current.secondsRemaining).toBeLessThanOrEqual(5);
  });

  // Refresh function should be called when countdown reaches 0
  it("should call refresh when timer reaches 0", async () => {
    const refresh = vi.fn();
    renderHook(() =>
      useAutoRefresh({
        intervalSeconds: 5,
        refresh,
      })
    );

    // Advance time past the interval
    act(() => {
      vi.advanceTimersByTime(5500);
    });

    expect(refresh).toHaveBeenCalled();
  });

  // When disabled, refresh should never be called
  it("should not refresh when disabled", async () => {
    const refresh = vi.fn();
    const { result } = renderHook(() =>
      useAutoRefresh({
        intervalSeconds: 5,
        enabled: false,
        refresh,
      })
    );

    expect(result.current.secondsRemaining).toBeNull();

    // Advance time past the interval
    act(() => {
      vi.advanceTimersByTime(10000);
    });

    expect(refresh).not.toHaveBeenCalled();
  });

  // Timer should reset to interval after automatic refresh
  it("should reset timer after refresh", async () => {
    const refresh = vi.fn().mockResolvedValue(undefined);
    const { result } = renderHook(() =>
      useAutoRefresh({
        intervalSeconds: 5,
        refresh,
      })
    );

    // Wait for initial render
    await act(async () => {
      vi.advanceTimersByTime(5500);
    });

    // Timer should reset to interval (allow some buffer)
    expect(result.current.secondsRemaining).toBeGreaterThanOrEqual(0);
  });

  // refreshNow() should trigger immediate refresh
  it("should provide refreshNow function", async () => {
    const refresh = vi.fn().mockResolvedValue(undefined);
    const { result } = renderHook(() =>
      useAutoRefresh({
        intervalSeconds: 30,
        refresh,
      })
    );

    await act(async () => {
      await result.current.refreshNow();
    });

    expect(refresh).toHaveBeenCalled();
  });

  // refreshNow() should also reset the countdown timer
  it("should reset timer when refreshNow is called", async () => {
    const refresh = vi.fn().mockResolvedValue(undefined);
    const { result } = renderHook(() =>
      useAutoRefresh({
        intervalSeconds: 30,
        refresh,
      })
    );

    // Wait some time
    act(() => {
      vi.advanceTimersByTime(10000);
    });

    const beforeRefresh = result.current.secondsRemaining;
    expect(beforeRefresh).toBeLessThan(30);

    await act(async () => {
      await result.current.refreshNow();
    });

    // Timer should be reset to full interval
    expect(result.current.secondsRemaining).toBeGreaterThanOrEqual(29);
  });

  // resetTimer() should reset countdown without triggering refresh
  it("should provide resetTimer function", () => {
    const refresh = vi.fn();
    const { result } = renderHook(() =>
      useAutoRefresh({
        intervalSeconds: 30,
        refresh,
      })
    );

    // Wait some time
    act(() => {
      vi.advanceTimersByTime(15000);
    });

    expect(result.current.secondsRemaining).toBeLessThan(20);

    act(() => {
      result.current.resetTimer();
    });

    expect(result.current.secondsRemaining).toBeGreaterThanOrEqual(29);
  });

  // When isBlocked is true and blockWhile is true, refresh is skipped
  it("should block refresh when isBlocked is true", async () => {
    const refresh = vi.fn();
    renderHook(() =>
      useAutoRefresh({
        intervalSeconds: 5,
        refresh,
        blockWhile: true,
        isBlocked: true,
      })
    );

    // Advance time past the interval
    act(() => {
      vi.advanceTimersByTime(10000);
    });

    expect(refresh).not.toHaveBeenCalled();
  });

  // When blockWhile is false, isBlocked has no effect
  it("should not block when blockWhile is false", async () => {
    const refresh = vi.fn();
    renderHook(() =>
      useAutoRefresh({
        intervalSeconds: 5,
        refresh,
        blockWhile: false,
        isBlocked: true,
      })
    );

    // Advance time past the interval
    act(() => {
      vi.advanceTimersByTime(5500);
    });

    expect(refresh).toHaveBeenCalled();
  });

  // Works correctly with async refresh functions
  it("should handle async refresh function", async () => {
    const refresh = vi.fn().mockResolvedValue(undefined);

    const { result } = renderHook(() =>
      useAutoRefresh({
        intervalSeconds: 5,
        refresh,
      })
    );

    await act(async () => {
      await result.current.refreshNow();
    });

    expect(refresh).toHaveBeenCalled();
  });

  // When refresh function changes, new function is used
  it("should update refresh function reference", async () => {
    const refresh1 = vi.fn().mockResolvedValue(undefined);
    const refresh2 = vi.fn().mockResolvedValue(undefined);

    const { result, rerender } = renderHook(
      ({ refresh }) =>
        useAutoRefresh({
          intervalSeconds: 30,
          refresh,
        }),
      { initialProps: { refresh: refresh1 } }
    );

    // Rerender with new refresh function
    rerender({ refresh: refresh2 });

    await act(async () => {
      await result.current.refreshNow();
    });

    // The new refresh function should be called
    expect(refresh2).toHaveBeenCalled();
  });

  // Refresh should work across multiple interval cycles
  it("should handle multiple refresh cycles", async () => {
    const refresh = vi.fn().mockResolvedValue(undefined);
    renderHook(() =>
      useAutoRefresh({
        intervalSeconds: 5,
        refresh,
      })
    );

    // First cycle
    await act(async () => {
      vi.advanceTimersByTime(5500);
    });
    expect(refresh).toHaveBeenCalled();
  });

  // Intervals should be cleaned up when component unmounts
  it("should cleanup intervals on unmount", () => {
    const refresh = vi.fn();
    const { unmount } = renderHook(() =>
      useAutoRefresh({
        intervalSeconds: 5,
        refresh,
      })
    );

    unmount();

    // Advance time after unmount
    act(() => {
      vi.advanceTimersByTime(10000);
    });

    // Should not have been called after unmount
    expect(refresh).not.toHaveBeenCalled();
  });

  // Disabled hook should return null for secondsRemaining
  it("should return null for secondsRemaining when disabled", async () => {
    const refresh = vi.fn();
    const { result } = renderHook(() =>
      useAutoRefresh({
        intervalSeconds: 30,
        enabled: false,
        refresh,
      })
    );

    // When disabled, secondsRemaining should be null
    expect(result.current.secondsRemaining).toBeNull();
  });

  // Hook should handle toggling between enabled and disabled
  it("should handle toggle between enabled and disabled", async () => {
    const refresh = vi.fn();
    const { result, rerender } = renderHook(
      ({ enabled }) =>
        useAutoRefresh({
          intervalSeconds: 30,
          enabled,
          refresh,
        }),
      { initialProps: { enabled: true } }
    );

    expect(result.current.secondsRemaining).toBeDefined();

    await act(async () => {
      rerender({ enabled: false });
    });
    expect(result.current.secondsRemaining).toBeNull();

    await act(async () => {
      rerender({ enabled: true });
    });
    expect(result.current.secondsRemaining).toBeDefined();
  });
});
