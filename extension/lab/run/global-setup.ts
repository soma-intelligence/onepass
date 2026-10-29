// Once per lab run (spec 7.1): build the extension and the native host as the
// e2e harness does, generate the world of LAB_SEED (LAB_SITES sites), write
// world.json and the fictional vault fixture.json under the output directory,
// stage the host with that vault outside the checkout, build the encrypted
// fixture cache once, and issue a certificate for every host of the world.
// Paths reach the workers through LAB_STATE (a JSON file).
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateCert } from "../../e2e/cert.ts";
import { buildHost, prebuildFixtureCache, type StagedHost, stageHost } from "../../e2e/host.ts";
import { generate, loadPatterns, parseDriverGroups, withDrivers } from "../gen/generate.ts";
import type { DriverGroup } from "../gen/model.ts";

export const EXT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
// First seed (n >= 2) whose 12 sites hold iframe_cross_site, shadow_closed, spa_rerender and split_otp
// and keep a lookalike, so the smoke plays the structural traps in a browser.
export const SMOKE_SEED = "lab-smoke-18";
export const SMOKE_SITES = 12;

export interface LabRunConfig {
  seed: string;
  sites: number;
  /** Only this site index, when set. */
  only?: number;
  /** Output directory (absolute). */
  out: string;
  /** Sites per paired profile. */
  batch: number;
  /** Driver sets played (LAB_DRIVERS, default "current"); each set gets its own profiles. */
  drivers: DriverGroup[];
}

/** The run configuration from the LAB_* environment variables (smoke defaults). */
export function runConfig(env: NodeJS.ProcessEnv = process.env): LabRunConfig {
  const seed = env.LAB_SEED || SMOKE_SEED;
  const sites = Number(env.LAB_SITES || SMOKE_SITES);
  const batch = Number(env.LAB_BATCH || 10);
  const only = env.LAB_ONLY !== undefined && env.LAB_ONLY !== "" ? Number(env.LAB_ONLY) : undefined;
  if (!Number.isInteger(sites) || sites < 1) throw new Error(`lab: LAB_SITES must be a positive integer (${env.LAB_SITES})`);
  if (!Number.isInteger(batch) || batch < 1) throw new Error(`lab: LAB_BATCH must be a positive integer (${env.LAB_BATCH})`);
  if (only !== undefined && !(Number.isInteger(only) && only >= 0 && only < sites)) {
    throw new Error(`lab: LAB_ONLY must be a site index below ${sites} (${env.LAB_ONLY})`);
  }
  const drivers = parseDriverGroups(env.LAB_DRIVERS || "current");
  const rawOut = env.LAB_OUT || join("lab", "out", seed);
  const out = isAbsolute(rawOut) ? rawOut : join(EXT_ROOT, rawOut);
  return { seed, sites, batch, out, drivers, ...(only !== undefined ? { only } : {}) };
}

/** Whether this run is the smoke regression (fixed seed and size, every site). */
export function isSmoke(c: LabRunConfig): boolean {
  return c.seed === SMOKE_SEED && c.sites === SMOKE_SITES && c.only === undefined && c.drivers.join(",") === "current";
}

export interface LabState {
  /** Temporary directory outside the checkout (cert, staged host, cache). */
  root: string;
  config: LabRunConfig;
  world: string;
  fixture: string;
  results: string;
  certDir: string;
  cache: string;
  host: StagedHost;
}

export default async function globalSetup(): Promise<() => Promise<void>> {
  const started = Date.now();
  const config = runConfig();
  execFileSync(process.execPath, ["build.mjs", "chromium", "--dev-host"], { cwd: EXT_ROOT, stdio: "inherit" });
  buildHost();
  const world = withDrivers(generate(config.seed, { sites: config.sites, patterns: loadPatterns() }), config.drivers);
  mkdirSync(config.out, { recursive: true });
  const worldPath = join(config.out, "world.json");
  const fixture = join(config.out, "fixture.json");
  const results = join(config.out, "results.jsonl");
  writeFileSync(worldPath, JSON.stringify(world, null, 2));
  writeFileSync(fixture, JSON.stringify(world.fixture, null, 2));
  writeFileSync(results, "");
  // Outside ~/Desktop and the like: the browser must not exec the host from a privacy-protected folder (host.ts).
  const root = mkdtempSync(join(tmpdir(), "onepass-lab-"));
  const certDir = join(root, "cert");
  generateCert(certDir, world.hosts);
  const host = stageHost(join(root, "host"), fixture);
  const cache = await prebuildFixtureCache(join(root, "prebuild"), host);
  const state: LabState = { root, config, world: worldPath, fixture, results, certDir, cache, host };
  const statePath = join(root, "state.json");
  writeFileSync(statePath, JSON.stringify(state));
  process.env.LAB_STATE = statePath;
  console.log(`lab setup: seed ${config.seed}, ${config.sites} sites, drivers ${config.drivers.join(",")}, ${((Date.now() - started) / 1000).toFixed(1)} s, out ${config.out}`);
  return async () => {
    rmSync(root, { recursive: true, force: true });
  };
}
