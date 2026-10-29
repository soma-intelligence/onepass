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
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test as base } from "@playwright/test";
import { loadCert } from "../../e2e/cert.ts";
import type { Scenario, Site, World } from "../gen/model.ts";
import { type LabServer, startLabServer } from "../server/server.ts";
import { type Lab, launchLab, launchPlain, networkViolations, readState, readWorld } from "./browser.ts";
import { groupOf } from "../gen/generate.ts";
import { lookalike, menuFill, oneClick, passkeyControl, type ScenarioEnv, smartFill } from "./drive.ts";
import { extensionDriver } from "./driver.ts";
import { EXT_ROOT, isSmoke, type LabState } from "./global-setup.ts";
import { afterReplay, judge, type Judgement, type Observation, oneClickOf, replayable, type Result, type Verdict } from "./oracle.ts";

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

function batches(): Scenario[][] {
  const indices = world.sites.map((s) => s.index).filter((i) => config.only === undefined || i === config.only);
  const groups = [...new Set(world.scenarios.map((s) => groupOf(s.driver)))];
  const out: Scenario[][] = [];
  for (const g of groups) {
    for (let k = 0; k < indices.length; k += config.batch) {
      const chunk = new Set(indices.slice(k, k + config.batch));
      const batch = world.scenarios.filter((s) => chunk.has(s.site) && groupOf(s.driver) === g);
      if (batch.length > 0) out.push(batch);
    }
  }
  return out;
}

const labError = (driver: Scenario["driver"], e: unknown): Observation => {
  const msg = (e as Error)?.message ?? String(e);
  return {
    driver, overlayShown: false, itemOffered: false, events: [], filled: {}, durationMs: 0,
    error: msg.startsWith("lab:") ? msg : `lab: ${msg}`,
  };
};

/** A fresh profile with the extension, paired (closed again if pairing fails). */
async function pairedLab(server: LabServer): Promise<Lab> {
  const lab = await launchLab(state, world, server);
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

/** One attempt of a scenario; `lab` is the batch profile (unused by the passkey control). */
async function attempt(s: Scenario, site: Site, server: LabServer, lab: () => Promise<Lab>, closeErrors: CloseErrors): Promise<Observation> {
  server.reset();
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
  const env: ScenarioEnv = { driver: extensionDriver(l), server, world, newPage: () => l.newPage() };
  switch (s.driver) {
    case "one_click": return oneClick(env, site);
    case "smart_fill": return smartFill(env, site, s.expect);
    case "menu_fill": return menuFill(env, site);
    case "lookalike": return lookalike(env, site);
  }
}

/** attempt(), with any unexpected throw turned into a bench error so the batch goes on. */
async function safeAttempt(s: Scenario, site: Site, server: LabServer, lab: () => Promise<Lab>, closeErrors: CloseErrors): Promise<Observation> {
  return attempt(s, site, server, lab, closeErrors).catch((e: unknown) => labError(s.driver, e));
}

function record(s: Scenario, site: Site, j: Judgement, retried: boolean, durationMs: number, seen: Observation): Result {
  const oneClick = oneClickOf(s, j.verdict, seen);
  const r: Result = {
    worldSeed: world.seed, site: site.index, siteSeed: site.seed, flow: site.flow, traits: site.traits, lang: site.lang,
    labelLang: site.labelLang, driver: s.driver, expect: s.expect, ...(s.reason ? { reason: s.reason } : {}), verdict: j.verdict, ...(j.cause ? { cause: j.cause } : {}),
    retried, durationMs, repro: `npm run lab:repro -- --seed ${world.seed} --site ${site.index}${s.driver === "smart_fill" ? " --drivers smart_fill" : ""}`,
    ...(oneClick !== undefined ? { oneClick } : {}),
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
    const batchLab = async () => (shared ??= await pairedLab(server));
    const verdicts: Verdict[] = [];
    const closeErrors: CloseErrors = [];
    try {
      for (const s of scenarios) {
        const site = world.sites[s.site]!;
        const first = await safeAttempt(s, site, server, batchLab, closeErrors);
        if (process.env.LAB_DEBUG) console.log(`[lab debug] ${s.id} ${JSON.stringify({ ...first, durationMs: undefined })}`);
        let j = judge(s, site, first);
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
            second = await safeAttempt(s, site, server, async () => (fresh = await pairedLab(server)), closeErrors);
          } finally {
            const used: Lab | undefined = fresh;
            if (used) await closeInto(closeErrors, `${s.id} replay profile`, () => used.close());
          }
          duration += second.durationMs;
          // A violation seen on the replay is kept, never dropped for the first failure.
          const settled = afterReplay(j, judge(s, site, second));
          j = settled.judgement;
          if (settled.replay) seen = second;
        }
        const r = record(s, site, j, retried, duration, seen);
        verdicts.push(r.verdict);
        console.log(`${s.id} ${site.flow} [${site.traits.join(",")}] expect ${s.expect}: ${r.verdict}${r.cause ? ` (${r.cause})` : ""}`);
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

if (isSmoke(config)) {
  test("smoke_matches_expected", () => {
    const lines = readFileSync(state.results, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as Result);
    const actual = Object.fromEntries(lines.map((r) => [`${r.site}:${r.driver}`, r.verdict === "flaky" ? "pass" : r.verdict]));
    expect(existsSync(SMOKE_EXPECTED), `missing ${SMOKE_EXPECTED}; verdicts of this run:\n${JSON.stringify(actual, null, 2)}`).toBe(true);
    const expected = JSON.parse(readFileSync(SMOKE_EXPECTED, "utf8")) as Record<string, string>;
    const want = Object.fromEntries(Object.entries(expected).map(([id, v]) => [id, v === "flaky" ? "pass" : v]));
    expect(actual).toEqual(want);
  });
}
