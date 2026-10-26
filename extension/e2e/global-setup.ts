// Once per run: build the extension (regular and e2e builds), the native
// host, a fresh TLS certificate, and the encrypted fixture store. Paths are
// handed to the workers through E2E_STATE (a JSON file).
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { generateCert } from "./cert";
import { buildHost, prebuildFixtureCache } from "./host";

export interface E2EState {
  root: string;
  certDir: string;
  cache: string;
}

export default async function globalSetup(): Promise<() => Promise<void>> {
  const started = Date.now();
  const ext = fileURLToPath(new URL("../", import.meta.url));
  execFileSync(process.execPath, ["build.mjs", "chromium"], { cwd: ext, stdio: "inherit" });
  execFileSync(process.execPath, ["build.mjs", "chromium", "--e2e"], { cwd: ext, stdio: "inherit" });
  // The worker handle of the e2e build must never reach the regular build.
  if (readFileSync(join(ext, "dist/chromium/background.js"), "utf8").includes("__onepassE2E")) {
    throw new Error("e2e: dist/chromium/background.js contains the e2e worker handle");
  }
  buildHost();
  const root = mkdtempSync(join(tmpdir(), "onepass-e2e-"));
  const certDir = join(root, "cert");
  mkdirSync(certDir);
  generateCert(certDir);
  const cache = await prebuildFixtureCache(join(root, "prebuild"));
  const statePath = join(root, "state.json");
  const state: E2EState = { root, certDir, cache };
  writeFileSync(statePath, JSON.stringify(state));
  process.env.E2E_STATE = statePath;
  console.log(`e2e setup: ${((Date.now() - started) / 1000).toFixed(1)} s`);
  return async () => {
    rmSync(root, { recursive: true, force: true });
  };
}
