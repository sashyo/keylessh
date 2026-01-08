import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  test: {
    // Global test settings
    globals: true,

    // Environment for DOM testing
    environment: "happy-dom",

    // Setup files to run before each test file
    setupFiles: ["./tests/setup.ts"],

    // Include patterns for test files
    include: [
      "tests/**/*.{test,spec}.{ts,tsx}",
      "client/src/**/*.{test,spec}.{ts,tsx}",
      "server/**/*.{test,spec}.{ts,tsx}",
      "shared/**/*.{test,spec}.{ts,tsx}",
    ],

    // Exclude patterns
    exclude: ["node_modules", "dist", "build"],

    // Coverage configuration
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      reportsDirectory: "./coverage",
      include: [
        "client/src/**/*.{ts,tsx}",
        "server/**/*.ts",
        "shared/**/*.ts",
      ],
      exclude: [
        "**/*.d.ts",
        "**/*.test.{ts,tsx}",
        "**/*.spec.{ts,tsx}",
        "**/node_modules/**",
      ],
    },

    // TypeScript configuration
    typecheck: {
      tsconfig: "./tsconfig.json",
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "client", "src"),
      "@shared": path.resolve(__dirname, "shared"),
    },
  },
});
