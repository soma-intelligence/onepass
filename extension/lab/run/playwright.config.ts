// Autofill lab run (spec 7): headless Chromium with the unpacked extension,
// the lab server and the real native host loaded with the world's vault.
// Batches run in parallel (LAB_WORKERS, default 4); the smoke comparison runs
// after every batch. Run with `npm run lab:smoke` (seed lab-smoke-18, 12 sites)
// or with LAB_SEED / LAB_SITES / LAB_ONLY / LAB_OUT / LAB_BATCH set.
import { defineConfig } from "@playwright/test";

const SMOKE_CHECK = /smoke_matches_expected/;

export default defineConfig({
  testDir: ".",
  testMatch: /lab\.spec\.ts$/,
  globalSetup: "./global-setup.ts",
  fullyParallel: true,
  workers: Number(process.env.LAB_WORKERS || 4),
  // Each batch sets its own timeout from its size.
  timeout: 30 * 60_000,
  expect: { timeout: 15_000 },
  retries: 0,
  reporter: [["list"]],
  use: { trace: "off", screenshot: "off", video: "off" },
  projects: [
    { name: "batches", grepInvert: SMOKE_CHECK },
    { name: "smoke", grep: SMOKE_CHECK, dependencies: ["batches"] },
  ],
});
