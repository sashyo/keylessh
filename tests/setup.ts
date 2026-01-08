import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

// Cleanup after each test case (for React component tests)
afterEach(() => {
  cleanup();
});

// Mock environment variables for tests
process.env.NODE_ENV = "test";
