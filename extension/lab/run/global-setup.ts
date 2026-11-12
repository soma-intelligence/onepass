// Once per lab run (spec 7.1): build the extension and the native host as the
// e2e harness does, generate the world of LAB_SEED (LAB_SITES sites), write
// world.json and the fictional vault fixture.json under the output directory,
// stage the host with that vault outside the checkout, build the encrypted
// fixture cache once, and issue a certificate for every host of the world.
// Paths reach the workers through LAB_STATE (a JSON file).
// LAB_STARTS (start states), LAB_TRIGGERS (icon, shortcut) and LAB_ACCOUNTS
// (account profiles p0 to p3) widen the scenarios; their defaults leave the
// world and the smoke as they were. The host is probed once for the controls
// a locked start can use (host-control.ts).
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateCert } from "../../e2e/cert.ts";
import { buildHost, prebuildFixtureCache, type StagedHost, stageHost } from "../../e2e/host.ts";
import { buildLabExtension, LAB_DIST_ROOT } from "../build-marker.ts";
import {
  FIRST_LOGIN_VAULT, firstLoginHosts, firstLoginKey, generate, loadPatterns, parseDriverGroups, parseStarts, parseTriggers, type SmartTrigger, withDrivers, withoutSiteLogins, withStarts,
} from "../gen/generate.ts";
import type { DriverGroup, StartState } from "../gen/model.ts";
import { accountProfiles, DEFAULT_PROFILE_ID, fixtureFor } from "../gen/population.ts";
import { hostSupports } from "./host-control.ts";

export const EXT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
// First seed (n >= 2, generator version 2) whose 12 sites hold iframe_cross_site, shadow_closed,
// spa_rerender and split_otp, keep a lookalike, and show at least four layouts and three frameworks,
// so the smoke plays the structural traps and the version 2 looks in a browser (multi_step is site 10).
export const SMOKE_SEED = "lab-smoke-17";
export const SMOKE_SITES = 16;

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
  /** Simulated users (population.ts): 1 is the historical single user. */
  profiles: number;
  /** Start states played (LAB_STARTS, default "unlocked_warm"). */
  starts: StartState[];
  /** How smart_fill is started (LAB_TRIGGERS, default "icon"). */
  triggers: SmartTrigger[];
  /** Account profiles played instead of drawn ones (LAB_ACCOUNTS, "p0" to "p3"); never with LAB_PROFILES above 1. */
  accounts?: string[];
}

/** The run configuration from the LAB_* environment variables (smoke defaults). */
export function runConfig(env: NodeJS.ProcessEnv = process.env): LabRunConfig {
  const seed = env.LAB_SEED || SMOKE_SEED;
  const sites = Number(env.LAB_SITES || SMOKE_SITES);
  const batch = Number(env.LAB_BATCH || 10);
  const profiles = Number(env.LAB_PROFILES || 1);
  const only = env.LAB_ONLY !== undefined && env.LAB_ONLY !== "" ? Number(env.LAB_ONLY) : undefined;
  if (!Number.isInteger(sites) || sites < 1) throw new Error(`lab: LAB_SITES must be a positive integer (${env.LAB_SITES})`);
  if (!Number.isInteger(batch) || batch < 1) throw new Error(`lab: LAB_BATCH must be a positive integer (${env.LAB_BATCH})`);
  if (!Number.isInteger(profiles) || profiles < 1) throw new Error(`lab: LAB_PROFILES must be a positive integer (${env.LAB_PROFILES})`);
  if (only !== undefined && !(Number.isInteger(only) && only >= 0 && only < sites)) {
    throw new Error(`lab: LAB_ONLY must be a site index below ${sites} (${env.LAB_ONLY})`);
  }
  const drivers = parseDriverGroups(env.LAB_DRIVERS || "current");
  const starts = parseStarts(env.LAB_STARTS || "unlocked_warm");
  const triggers = parseTriggers(env.LAB_TRIGGERS || "icon");
  const accounts = env.LAB_ACCOUNTS ? accountProfiles(env.LAB_ACCOUNTS.split(",").map((x) => x.trim()).filter(Boolean)).map((p) => p.id) : undefined;
  if (accounts && profiles > 1) throw new Error("lab: LAB_ACCOUNTS and LAB_PROFILES above 1 do not mix (same profile ids)");
  const rawOut = env.LAB_OUT || join("lab", "out", seed);
  const out = isAbsolute(rawOut) ? rawOut : join(EXT_ROOT, rawOut);
  return { seed, sites, batch, out, drivers, profiles, starts, triggers, ...(accounts ? { accounts } : {}), ...(only !== undefined ? { only } : {}) };
}

/** Whether this run is the smoke regression (fixed seed and size, every site). */
export function isSmoke(c: LabRunConfig): boolean {
  return c.seed === SMOKE_SEED && c.sites === SMOKE_SITES && c.only === undefined && c.drivers.join(",") === "current" && c.profiles === 1
    && c.starts.join(",") === "unlocked_warm" && c.triggers.join(",") === "icon" && c.accounts === undefined;
}

export interface LabState {
  /** Temporary directory outside the checkout (cert, staged host, cache). */
  root: string;
  config: LabRunConfig;
  world: string;
  fixture: string;
  results: string;
  /** Verdicts of the country cases (one JSON line per case). */
  cases: string;
  certDir: string;
  cache: string;
  host: StagedHost;
  /** Extension folder of this run (dist-lab/<run>/chromium), never the shared dist/chromium. */
  extDir: string;
  /** Staged host and encrypted vault cache of every simulated user (the default one is `host` and `cache`). */
  profiles: Record<string, { host: StagedHost; cache: string }>;
  /** Controls the host binary has beyond its config of today (probed once; absent in a state from before the start states). */
  caps?: { deferredUnlock: boolean };
}

export default async function globalSetup(): Promise<() => Promise<void>> {
  const started = Date.now();
  const config = runConfig();
  // Own build folder per run (C1), checked against the requested classifier before anything runs.
  const built = buildLabExtension(LAB_DIST_ROOT, basename(config.out), {
    ONEPASS_CLASSIFIER: process.env.ONEPASS_CLASSIFIER, ONEPASS_MODEL_DIR: process.env.ONEPASS_MODEL_DIR,
  });
  buildHost();
  const generated = generate(config.seed, {
    sites: config.sites, patterns: loadPatterns(), profiles: config.profiles, ...(config.accounts ? { accounts: config.accounts } : {}),
  });
  const world = withStarts(withDrivers(generated, config.drivers), config.starts, config.triggers);
  mkdirSync(config.out, { recursive: true });
  const worldPath = join(config.out, "world.json");
  const fixture = join(config.out, "fixture.json");
  const results = join(config.out, "results.jsonl");
  const cases = join(config.out, "cases.jsonl");
  writeFileSync(join(config.out, "build-marker.json"), JSON.stringify(built.marker, null, 2));
  writeFileSync(worldPath, JSON.stringify(world, null, 2));
  writeFileSync(fixture, JSON.stringify(world.fixture, null, 2));
  writeFileSync(results, "");
  writeFileSync(cases, "");
  // Outside ~/Desktop and the like: the browser must not exec the host from a privacy-protected folder (host.ts).
  const root = mkdtempSync(join(tmpdir(), "onepass-lab-"));
  const certDir = join(root, "cert");
  generateCert(certDir, world.hosts);
  const host = stageHost(join(root, "host"), fixture);
  const cache = await prebuildFixtureCache(join(root, "prebuild"), host);
  // One staged host and cache per other profile: its own vault, built in parallel.
  const profiles: LabState["profiles"] = { [DEFAULT_PROFILE_ID]: { host, cache } };
  await Promise.all((world.profiles ?? []).filter((p) => p.id !== DEFAULT_PROFILE_ID).map(async (p) => {
    const file = join(config.out, `fixture-${p.id}.json`);
    writeFileSync(file, JSON.stringify(fixtureFor(p, world.sites, world.fixture), null, 2));
    const staged = stageHost(join(root, `host-${p.id}`), file);
    profiles[p.id] = { host: staged, cache: await prebuildFixtureCache(join(root, `prebuild-${p.id}`), staged) };
  }));
  // The save and ghost scenarios: each profile's vault again, without any login of the sites new_auto plays on
  // (spec 4.1, a first login ever on the site), staged under `<profile>/first-login`.
  const firstHosts = config.drivers.includes("save_ghost") ? firstLoginHosts(world) : [];
  if (firstHosts.length > 0) {
    const vaults = [{ id: DEFAULT_PROFILE_ID, vault: world.fixture },
      ...(world.profiles ?? []).filter((p) => p.id !== DEFAULT_PROFILE_ID).map((p) => ({ id: p.id, vault: fixtureFor(p, world.sites, world.fixture) }))];
    await Promise.all(vaults.map(async ({ id, vault }) => {
      const tag = `${id}-${FIRST_LOGIN_VAULT}`;
      const file = join(config.out, `fixture-${tag}.json`);
      writeFileSync(file, JSON.stringify(withoutSiteLogins(vault, firstHosts), null, 2));
      const staged = stageHost(join(root, `host-${tag}`), file);
      profiles[firstLoginKey(id)] = { host: staged, cache: await prebuildFixtureCache(join(root, `prebuild-${tag}`), staged) };
    }));
  }
  // Only a locked start asks: can the host leave an unlock to the stand-in's approval file?
  const caps = { deferredUnlock: config.starts.includes("locked") && hostSupports(host.bin, "unlock", "file") };
  const state: LabState = { root, config, extDir: built.dir, world: worldPath, fixture, results, cases, certDir, cache, host, profiles, caps };
  const statePath = join(root, "state.json");
  writeFileSync(statePath, JSON.stringify(state));
  process.env.LAB_STATE = statePath;
  const profilesLine = config.accounts ? `account profiles ${config.accounts.join(",")}` : `${config.profiles} profile(s)`;
  console.log(`lab setup: seed ${config.seed}, ${config.sites} sites, drivers ${config.drivers.join(",")}, ${profilesLine}, starts ${config.starts.join(",")}, `
    + `triggers ${config.triggers.join(",")}${config.starts.includes("locked") ? `, unlock ${caps.deferredUnlock ? "deferred (approval file)" : "instant (host lacks control deferred_unlock)"}` : ""}, `
    + `${((Date.now() - started) / 1000).toFixed(1)} s, out ${config.out}`);
  return async () => {
    rmSync(root, { recursive: true, force: true });
  };
}
