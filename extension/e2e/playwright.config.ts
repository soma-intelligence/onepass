// End-to-end tests (spec 11.3, 11.4): headless Chromium with the unpacked
// extension, the local HTTPS test server and the real development native
// host. Run with `npm run e2e`.
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: /.*\.spec\.ts$/,
  globalSetup: "./global-setup.ts",
  // One browser and one host per test; workers share nothing but the build.
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  retries: 0,
  reporter: [["list"]],
  use: { trace: "off", screenshot: "off", video: "off" },
});
