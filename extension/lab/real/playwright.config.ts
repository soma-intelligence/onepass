// Runner of the real-site bench: one Playwright "test" (lab/real/run.ts) that
// drives every browser itself. The Playwright loader is used for its
// TypeScript transform (the product modules the bench imports use
// extensionless paths); the options come from `npm run lab:real-site -- ...`
// through LAB_REAL_ARGS (run.ts parses them).
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: /run\.ts$/,
  fullyParallel: false,
  workers: 1,
  // The bench time-boxes each site itself (90 s by default); the run has no limit.
  timeout: 0,
  retries: 0,
  reporter: [["list"]],
  outputDir: "../out/real-test-results",
  use: { trace: "off", screenshot: "off", video: "off" },
});
