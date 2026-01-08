/**
 * @fileoverview Tests for the utility functions in the client library.
 *
 * This file tests:
 * - cn() function - Tailwind CSS class name merger
 *
 * The cn() function combines clsx (conditional class joining) with
 * tailwind-merge (intelligent Tailwind class deduplication).
 * This is essential for building dynamic component styles.
 */

import { describe, it, expect } from "vitest";
import { cn } from "@/lib/utils";

/**
 * Tests for the cn (classNames) utility function.
 * cn() is used throughout the UI to merge CSS classes intelligently.
 */
describe("cn utility function", () => {
  // Basic usage: combine two class name strings
  it("should merge class names", () => {
    const result = cn("foo", "bar");
    expect(result).toBe("foo bar");
  });

  // Conditional classes using logical AND
  it("should handle conditional classes", () => {
    const isActive = true;
    const result = cn("base", isActive && "active");
    expect(result).toBe("base active");
  });

  // Falsy values (false, null, undefined) should be filtered out
  it("should filter out falsy values", () => {
    const result = cn("base", false, null, undefined, "valid");
    expect(result).toBe("base valid");
  });

  // tailwind-merge: later conflicting utilities override earlier ones
  // p-4 and p-2 conflict, so p-2 (last) wins
  it("should merge Tailwind classes correctly", () => {
    const result = cn("p-4", "p-2");
    expect(result).toBe("p-2");
  });

  // Responsive variants (md:, lg:) are kept separate, not merged
  it("should handle responsive variants correctly", () => {
    const result = cn("text-sm", "md:text-lg", "lg:text-xl");
    expect(result).toContain("text-sm");
    expect(result).toContain("md:text-lg");
    expect(result).toContain("lg:text-xl");
  });

  // No arguments should return empty string
  it("should handle empty input", () => {
    const result = cn();
    expect(result).toBe("");
  });

  // Can pass an array of class names
  it("should handle array of classes", () => {
    const result = cn(["foo", "bar"]);
    expect(result).toBe("foo bar");
  });

  // Object notation: keys are class names, values are booleans
  it("should handle object notation", () => {
    const result = cn({
      base: true,
      active: true,
      disabled: false,
    });
    expect(result).toBe("base active");
  });

  // Background colors conflict, last one wins
  it("should merge background colors correctly", () => {
    const result = cn("bg-red-500", "bg-blue-500");
    expect(result).toBe("bg-blue-500");
  });

  // State variants (hover:, focus:) are preserved
  it("should handle state variants", () => {
    const result = cn("hover:bg-gray-100", "focus:ring-2");
    expect(result).toContain("hover:bg-gray-100");
    expect(result).toContain("focus:ring-2");
  });

  // Complex real-world usage: base styles + conditional overrides
  it("should handle complex combinations", () => {
    const isError = true;
    const isDisabled = false;
    const result = cn(
      "px-4 py-2 rounded", // Base styles
      "bg-blue-500 text-white", // Default colors
      isError && "bg-red-500", // Error state overrides bg
      isDisabled && "opacity-50 cursor-not-allowed" // Disabled state (not applied)
    );
    // bg-red-500 should override bg-blue-500
    expect(result).toContain("bg-red-500");
    expect(result).not.toContain("bg-blue-500");
    // Disabled styles should not be present
    expect(result).not.toContain("opacity-50");
  });
});
