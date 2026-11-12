// Lab run (spec 7.2, 7.5): one test per batch of LAB_BATCH sites and driver
// set (current, smart_fill: never in the same profile, so one set's site
// memory never helps the other). A batch
// launches a fresh profile with the real extension, pairs once, then plays
// its scenarios one after the other (server reset, new tab, driver, oracle).
// A failed scenario is replayed once in a fresh paired profile: a pass on
// the second try is `flaky` (never for "nofill" scenarios: a forbidden fill
// or offer is a security event, kept as `fail`). Every result goes to
// results.jsonl. A batch test fails when any scenario leaks, when any
// response came from a non-loopback address or any request went to a host
// outside the world, when a browser failed to close (checked after every
// scenario was recorded), or when every one of its scenarios is a
// lab_error; the other verdicts are the report's business. In smoke mode a
// last test compares the verdicts with lab/smoke-expected.json.
// A batch also has one start state and one smart_fill trigger (LAB_STARTS,
// LAB_TRIGGERS): a locked or cold start restarts the profile's native host,
// and a site played twice in one profile would find the first play's site
// memory. Every result stores its gestures (count, kinds, biometric
// approvals) and whether the oracle saw the session; a scenario whose start
// state the host cannot be put in is `skipped`.
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test as base } from "@playwright/test";
import { loadCert } from "../../e2e/cert.ts";
import type { FixtureFile, GhostVariant, SaveVariant, Scenario, Site, World } from "../gen/model.ts";
import { type LabServer, startLabServer } from "../server/server.ts";
import { type Lab, launchLab, launchPlain, networkViolations, readState, readWorld } from "./browser.ts";
import { FIRST_LOGIN_VAULT, firstLoginHosts, firstLoginKey, groupOf, withoutSiteLogins } from "../gen/generate.ts";
import { type CaseOutcome, countryCase, ghost, lookalike, menuFill, oneClick, passkeyControl, saveTyped, type ScenarioEnv, smartFill } from "./drive.ts";
import { extensionDriver } from "./driver.ts";
import { fixtureFor, meantAccount, otherUsername, profileOf } from "../gen/population.ts";
import { EXT_ROOT, isSmoke, type LabState } from "./global-setup.ts";
import { afterReplay, fillCheck, judge, type Judgement, type Observation, oneClickOf, replayable, type Result, resultGestures, type Verdict } from "./oracle.ts";
import { type StartControl, startControl } from "./start-state.ts";

const state: LabState = readState();
const world: World = readWorld(state);
const { config } = state;
export const SMOKE_EXPECTED = join(EXT_ROOT, "lab", "smoke-expected.json");

const test = base.extend<object, { server: LabServer }>({
  server: [
    async ({}, use) => {
      const server = await startLabServer(world, loadCert(state.certDir));
      await use(server);
      await server.close();
    },
    { scope: "worker" },
  ],
});

/** Batches of LAB_BATCH sites; one profile per batch (each simulated user has its own vault and so its own browser). */
function batches(): Scenario[][] {
  const indices = world.sites.map((s) => s.index).filter((i) => config.only === undefined || i === config.only);
  // One profile per driver set, start state and smart_fill trigger (the historical start first: batch order as before).
  const groups = [...new Set(world.scenarios.map(setOf))];
  const out: Scenario[][] = [];
  for (const g of groups) {
    for (const p of world.profiles ?? [{ id: profileOf({}) }]) {
      for (let k = 0; k < indices.length; k += config.batch) {
        const chunk = new Set(indices.slice(k, k + config.batch));
        const batch = world.scenarios.filter((s) => chunk.has(s.site) && setOf(s) === g && profileOf(s) === p.id);
        if (batch.length > 0) out.push(batch);
      }
    }
  }
  return out;
}

/** What scenarios must share to share a browser profile: the driver set, the start state, the smart_fill trigger. */
function setOf(s: Scenario): string {
  return `${groupOf(s.driver)}|${s.start ?? "unlocked_warm"}|${s.shortcut ? "shortcut" : "icon"}`;
}

/** The start-state control of each lab profile (its host-visibility check is made once per profile). */
const controls = new WeakMap<Lab, StartControl>();
function controlOf(l: Lab): StartControl {
  let c = controls.get(l);
  if (!c) controls.set(l, (c = startControl(l.startHost)));
  return c;
}

const labError = (driver: Scenario["driver"], e: unknown): Observation => {
  const msg = (e as Error)?.message ?? String(e);
  return {
    driver, overlayShown: false, itemOffered: false, events: [], filled: {}, durationMs: 0,
    error: msg.startsWith("lab:") ? msg : `lab: ${msg}`,
  };
};

/** A fresh profile with the extension, paired (closed again if pairing fails). */
async function pairedLab(server: LabServer, profile: string): Promise<Lab> {
  const lab = await launchLab(state, world, server, profile);
  try {
    await lab.pair();
    return lab;
  } catch (e) {
    // Bench error path (the scenario becomes lab_error): the loopback registry still sees this close.
    await lab.close().catch(() => undefined);
    throw e;
  }
}

/** Close errors of a batch: kept (the batch goes red) without stopping its other scenarios. */
type CloseErrors = string[];

async function closeInto(errors: CloseErrors, what: string, close: () => Promise<void>): Promise<void> {
  await close().catch((e: unknown) => {
    errors.push(`${what}: ${((e as Error)?.message ?? String(e)).split("\n")[0]}`);
  });
}

/**
 * The staged vault a scenario plays with: its profile's, or for the save and ghost scenarios the same without
 * any login of the sites new_auto plays on (`<profile>/first-login`, global-setup.ts), when the run staged it.
 */
function vaultKey(s: Pick<Scenario, "driver" | "profile">): string {
  const id = profileOf(s);
  return groupOf(s.driver) === "save_ghost" && state.profiles[firstLoginKey(id)] ? firstLoginKey(id) : id;
}

/** The vault of each staged key, built once (the server's checks must expect what the extension is given). */
const vaults = new Map<string, FixtureFile>();
function vaultOf(key: string): FixtureFile {
  let v = vaults.get(key);
  if (!v) {
    const id = key.endsWith(`/${FIRST_LOGIN_VAULT}`) ? key.slice(0, -FIRST_LOGIN_VAULT.length - 1) : key;
    const p = world.profiles?.find((x) => x.id === id);
    v = p ? fixtureFor(p, world.sites, world.fixture) : world.fixture;
    if (id !== key) v = withoutSiteLogins(v, firstLoginHosts(world));
    vaults.set(key, v);
  }
  return v;
}

/** One attempt of a scenario; `lab` is the batch profile (unused by the passkey control). */
async function attempt(s: Scenario, site: Site, server: LabServer, lab: () => Promise<Lab>, closeErrors: CloseErrors): Promise<Observation> {
  server.reset();
  const vault = vaultOf(vaultKey(s));
  server.useFixture(vault);
  // Account profiles: the site takes the account the user means, and the driver knows the other one by its identifier.
  const profile = world.profiles?.find((p) => p.id === profileOf(s));
  const meant = profile ? meantAccount(profile, site, vault) : undefined;
  if (meant) server.useAccounts(new Map([[site.host, { username: meant.username, password: meant.password }]]));
  const otherUser = profile ? otherUsername(profile, site, vault) : undefined;
  if (s.driver === "passkey_control") {
    let plain;
    try {
      plain = await launchPlain(state, world, server);
    } catch (e) {
      return labError(s.driver, e);
    }
    try {
      return await passkeyControl(server, plain, site);
    } finally {
      // A non-loopback response fails the batch test (registry and close error).
      await closeInto(closeErrors, `${s.id} plain browser`, () => plain.close());
    }
  }
  let l: Lab;
  try {
    l = await lab();
  } catch (e) {
    return labError(s.driver, e);
  }
  const env: ScenarioEnv = {
    driver: extensionDriver(l), server, world, newPage: () => l.newPage(), start: controlOf(l), ...(otherUser !== undefined ? { otherUser } : {}),
    vaultHost: { bin: state.profiles[vaultKey(s)]!.host.bin, config: l.host.config },
  };
  switch (s.driver) {
    case "one_click": return oneClick(env, site, s);
    case "smart_fill": return smartFill(env, site, s.expect, s);
    case "menu_fill": return menuFill(env, site, s.behaviour, s);
    case "lookalike": return lookalike(env, site);
    case "ghost": return ghost(env, site, s.variant as GhostVariant, s);
    case "save_typed": return saveTyped(env, site, s.variant as SaveVariant, s);
  }
}

/** attempt(), with any unexpected throw turned into a bench error so the batch goes on. */
async function safeAttempt(s: Scenario, site: Site, server: LabServer, lab: () => Promise<Lab>, closeErrors: CloseErrors): Promise<Observation> {
  return attempt(s, site, server, lab, closeErrors).catch((e: unknown) => labError(s.driver, e));
}

/** The flags a repro needs beyond the seed and the site: the driver set, the profiles, the start state, the trigger. */
function reproFlags(s: Scenario): string {
  const profiles = config.accounts ? ` --accounts ${profileOf(s)}` : world.profiles ? ` --profiles ${world.profiles.length}` : "";
  return `${s.driver === "smart_fill" ? " --drivers smart_fill" : groupOf(s.driver) === "save_ghost" ? " --drivers save_ghost" : ""}${profiles}${s.start ? ` --starts ${s.start}` : ""}${s.shortcut ? " --triggers shortcut" : ""}`;
}

function record(s: Scenario, site: Site, j: Judgement, retried: boolean, durationMs: number, seen: Observation): Result {
  const oneClick = oneClickOf(s, j.verdict, seen);
  const r: Result = {
    worldSeed: world.seed, site: site.index, siteSeed: site.seed, flow: site.flow, traits: site.traits, lang: site.lang,
    labelLang: site.labelLang, profile: profileOf(s), driver: s.driver, ...(s.variant ? { variant: s.variant } : {}), expect: s.expect, ...(s.reason ? { reason: s.reason } : {}), verdict: j.verdict, ...(j.cause ? { cause: j.cause } : {}),
    retried, durationMs, repro: `npm run lab:repro -- --seed ${world.seed} --site ${site.index}${reproFlags(s)}`,
    ...(oneClick !== undefined ? { oneClick } : {}),
    // The gestures of the attempt the verdict stands on (gestures.ts), kinds only.
    ...resultGestures(s, site, j.verdict, seen),
    ...(seen.unlock ? { unlock: seen.unlock } : {}),
    ...(s.account ? { outcome: s.account.outcome } : {}),
  };
  appendFileSync(state.results, `${JSON.stringify(r)}\n`);
  return r;
}

test.describe.configure({ mode: "parallel" });

batches().forEach((scenarios, k) => {
  test(`batch ${k}`, async ({ server }) => {
    // Up to ~2.5 min per scenario with its replay, plus a pairing per profile.
    test.setTimeout(scenarios.length * 180_000 + 120_000);
    const seenViolations = networkViolations().length;
    let shared: Lab | undefined;
    // The staged vault of the batch (one driver set per batch): the profile's, or its first-login copy.
    const profile = scenarios[0] ? vaultKey(scenarios[0]) : profileOf({});
    const batchLab = async () => (shared ??= await pairedLab(server, profile));
    const verdicts: Verdict[] = [];
    const closeErrors: CloseErrors = [];
    try {
      for (const s of scenarios) {
        const site = world.sites[s.site]!;
        const first = await safeAttempt(s, site, server, batchLab, closeErrors);
        if (process.env.LAB_DEBUG) console.log(`[lab debug] ${s.id} ${JSON.stringify({ ...first, durationMs: undefined })}`);
        let j = judge(s, site, first, fillCheck(world, site, vaultOf(vaultKey(s))));
        // The attempt the verdict stands on (the replay for a flaky pass).
        let seen = first;
        let duration = first.durationMs;
        let retried = false;
        // A broken profile is not reused (bench error path: its close error is not the verdict).
        if (j.verdict === "lab_error" && shared) {
          const broken: Lab = shared;
          shared = undefined;
          await broken.close().catch(() => undefined);
        }
        // A forbidden fill or offer (expect nofill) and a safety failure (wrong item, auto-submit
        // outside a sign-in) are security events: never replayed into a pass.
        if (replayable(s, j)) {
          retried = true;
          let fresh: Lab | undefined;
          let second: Observation;
          try {
            second = await safeAttempt(s, site, server, async () => (fresh = await pairedLab(server, profile)), closeErrors);
          } finally {
            const used: Lab | undefined = fresh;
            if (used) await closeInto(closeErrors, `${s.id} replay profile`, () => used.close());
          }
          duration += second.durationMs;
          // A violation seen on the replay is kept, never dropped for the first failure.
          const settled = afterReplay(j, judge(s, site, second, fillCheck(world, site, vaultOf(vaultKey(s)))));
          j = settled.judgement;
          if (settled.replay) seen = second;
        }
        const r = record(s, site, j, retried, duration, seen);
        verdicts.push(r.verdict);
        console.log(`${s.id} ${site.flow} [${site.traits.join(",")}] expect ${s.expect}: ${r.verdict}${r.cause ? ` (${r.cause})` : ""}`
          + ` gestures ${r.gestures ?? 0}${r.biometric ? ` +${r.biometric} biometric` : ""}${r.oneGesture ? " (one gesture, signed in)" : ""}`);
      }
    } finally {
      // Always release the shared Chromium, its native host and its temporary profile.
      const last: Lab | undefined = shared;
      shared = undefined;
      if (last) await closeInto(closeErrors, "batch profile", () => last.close());
    }
    // Third net (e2e/fixtures.ts): no response from a non-loopback address, even on a bench-error path.
    expect(networkViolations().slice(seenViolations), "responses from a non-loopback address or requests to an unplanned host").toEqual([]);
    // Spec 11: a leak makes the run red.
    expect(verdicts, "a scenario leaked a secret").not.toContain("leak");
    expect(verdicts.length > 0 && verdicts.every((v) => v === "lab_error"), "every scenario of the batch is a lab_error").toBe(false);
    expect(closeErrors, "a browser of the batch failed to close").toEqual([]);
  });
});

/** One line of cases.jsonl. */
interface CaseResult { id: string; name: string; verdict: CaseOutcome["verdict"] | "flaky"; cause?: string; retried: boolean; durationMs: number }

// The country and region fixture cases (lab/gen/cases.ts), in the default
// profile and the current driver set; not for a single-site repro. A failed
// case is replayed once in a fresh paired profile: a pass then is `flaky`.
// Nor for a run of account profiles or without the historical start: they measure something else.
const playCases = config.only === undefined && (world.cases ?? []).length > 0 && config.accounts === undefined
  && world.scenarios.some((s) => groupOf(s.driver) === "current" && s.start === undefined);
if (playCases) {
  test("country cases", async ({ server }) => {
    const cases = world.cases ?? [];
    test.setTimeout(cases.length * 60_000 + 120_000);
    const seenViolations = networkViolations().length;
    const profile = profileOf({});
    const closeErrors: CloseErrors = [];
    let shared: Lab | undefined;
    const play = async (c: (typeof cases)[number], lab: () => Promise<Lab>): Promise<CaseOutcome> => {
      server.reset();
      server.useFixture(world.fixture);
      let l: Lab;
      try {
        l = await lab();
      } catch (e) {
        return { verdict: "lab_error", cause: (e as Error)?.message?.split("\n")[0] ?? String(e), durationMs: 0 };
      }
      return countryCase({ driver: extensionDriver(l), server, world, newPage: () => l.newPage() }, c);
    };
    try {
      for (const c of cases) {
        let out = await play(c, async () => (shared ??= await pairedLab(server, profile)));
        let verdict: CaseResult["verdict"] = out.verdict;
        let duration = out.durationMs;
        let retried = false;
        if (out.verdict === "lab_error" && shared) {
          const broken: Lab = shared;
          shared = undefined;
          await broken.close().catch(() => undefined);
        }
        if (out.verdict !== "pass") {
          retried = true;
          let fresh: Lab | undefined;
          try {
            const second = await play(c, async () => (fresh = await pairedLab(server, profile)));
            duration += second.durationMs;
            if (second.verdict === "pass") verdict = "flaky";
            else out = second;
          } finally {
            const used: Lab | undefined = fresh;
            if (used) await closeInto(closeErrors, `${c.id} replay profile`, () => used.close());
          }
        }
        const r: CaseResult = { id: c.id, name: c.name, verdict, ...(verdict !== "flaky" && out.cause ? { cause: out.cause } : {}), retried, durationMs: duration };
        appendFileSync(state.cases, `${JSON.stringify(r)}\n`);
        console.log(`${c.id} ${c.name}: ${verdict}${r.cause ? ` (${r.cause})` : ""}`);
      }
    } finally {
      const last: Lab | undefined = shared;
      shared = undefined;
      if (last) await closeInto(closeErrors, "cases profile", () => last.close());
    }
    expect(networkViolations().slice(seenViolations), "responses from a non-loopback address or requests to an unplanned host").toEqual([]);
    expect(closeErrors, "a browser of the country cases failed to close").toEqual([]);
  });
}

if (isSmoke(config)) {
  test("smoke_matches_expected", () => {
    const lines = readFileSync(state.results, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as Result);
    const caseLines = readFileSync(state.cases, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as CaseResult);
    const actual = Object.fromEntries([
      ...lines.map((r) => [`${r.site}:${r.driver}${r.variant ? `:${r.variant}` : ""}`, r.verdict === "flaky" ? "pass" : r.verdict]),
      ...caseLines.map((r) => [r.id, r.verdict === "flaky" ? "pass" : r.verdict]),
    ]);
    expect(existsSync(SMOKE_EXPECTED), `missing ${SMOKE_EXPECTED}; verdicts of this run:\n${JSON.stringify(actual, null, 2)}`).toBe(true);
    const expected = JSON.parse(readFileSync(SMOKE_EXPECTED, "utf8")) as Record<string, string>;
    const want = Object.fromEntries(Object.entries(expected).map(([id, v]) => [id, v === "flaky" ? "pass" : v]));
    expect(actual).toEqual(want);
  });
}
