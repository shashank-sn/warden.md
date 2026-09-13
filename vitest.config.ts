import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "packages/*/test/**/*.test.ts",
      "action/test/**/*.test.ts",
      "action/test/**/*.test.mjs",
      "examples/**/*.test.ts",
      "scripts/**/*.test.mjs",
    ],
    coverage: {
      enabled: false,
    },
  },
});
