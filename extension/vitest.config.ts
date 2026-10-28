import { defineConfig } from "vitest/config";

export default defineConfig({
  define: { __LAB_RECORDER__: false },
  test: {
    environment: "jsdom",
    include: ["test/**/*.test.ts"],
  },
});
