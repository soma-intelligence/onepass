// @vitest-environment node
// "One gesture, signed in" in the report: by start state, trigger and flow
// family, over the scenarios whose goal is a session, with the unlock
// approval shown apart. Skipped scenarios stay out of every rate, and a run
// from before the gesture accounting reports exactly what it did.
import { describe, expect, it } from "vitest";
import { ACCOUNT_PROFILES } from "../../lab/gen/population.ts";
import { renderReport, summarize } from "../../lab/report.ts";
import type { Result, Verdict } from "../../lab/run/oracle.ts";

function res(n: number, verdict: Verdict, over: Partial<Result> = {}): Result {
  return {
    worldSeed: "w", site: n, siteSeed: `s${n}`, flow: "login_single", traits: [], lang: "en", labelLang: "en",
    driver: "smart_fill", expect: "pass", verdict, retried: false, durationMs: 10,
    repro: `npm run lab:repro -- --seed w --site ${n}`, ...over,
  };
}
/** A measured result: gesture kinds in order, the session seen or not. */
function played(n: number, verdict: Verdict, list: NonNullable<Result["gestureList"]>, signedIn: boolean, over: Partial<Result> = {}): Result {
  const gestures = list.filter((k) => k !== "unlock_approval").length;
  return res(n, verdict, {
    gestures, gestureList: list, biometric: list.length - gestures, signedIn, oneGesture: signedIn && gestures === 1,
    startState: "unlocked_warm", trigger: "field_icon", ...over,
  });
}
const meta = { date: "2026-11-10", commit: "abc1234", durationMin: 3 };
const world = { seed: "w", sites: 10 };

describe("one gesture, signed in", () => {
  const results = [
    played(0, "pass", ["field_icon"], true),
    played(1, "pass", ["field_icon", "site_submit"], true),
    played(2, "fail", ["field_icon"], false, { cause: "timeout" }),
    played(3, "pass", ["overlay_row"], true, { driver: "one_click", trigger: "overlay_row", flow: "sso" }),
    played(4, "pass", ["field_icon", "unlock_approval"], true, { startState: "locked", unlock: "instant" }),
    played(5, "pass", ["field_icon", "unlock_button", "unlock_approval", "menu_row", "site_submit"], true, { startState: "locked", unlock: "instant" }),
    played(6, "pass", ["shortcut"], true, { startState: "cold", trigger: "shortcut", flow: "login_totp" }),
    // A form flow has no session: gestures stored, no line in the table.
    res(7, "pass", { flow: "checkout_card", gestures: 2, gestureList: ["field_icon", "site_submit"], biometric: 0, startState: "unlocked_warm", trigger: "field_icon" }),
  ];
  const s = summarize(results);

  it("counts_by_start_state_trigger_and_family", () => {
    const cell = (start: string, trigger: string, family: string) => s.oneGesture.find((c) => c.start === start && c.trigger === trigger && c.family === family);
    expect(cell("unlocked_warm", "field_icon", "password")).toEqual({ start: "unlocked_warm", trigger: "field_icon", family: "password", total: 3, signedIn: 2, ok: 1, biometric: 0 });
    expect(cell("unlocked_warm", "overlay_row", "sso")).toMatchObject({ total: 1, signedIn: 1, ok: 1 });
    expect(cell("locked", "field_icon", "password")).toMatchObject({ total: 2, signedIn: 2, ok: 1, biometric: 1 });
    expect(cell("cold", "shortcut", "totp")).toMatchObject({ total: 1, ok: 1, biometric: 0 });
    expect(s.oneGesture.reduce((n, c) => n + c.total, 0)).toBe(7);
  });

  it("the_old_one_click_numbers_are_computed_as_before", () => {
    const old = [res(0, "pass", { oneClick: true }), res(1, "pass", { oneClick: false }), res(2, "fail", { oneClick: false, cause: "timeout" })];
    const before = summarize(old);
    const withGestures = summarize(old.map((r, k) => ({ ...r, gestures: k + 1, gestureList: [], biometric: 0, signedIn: r.verdict === "pass", oneGesture: false, startState: "unlocked_warm" as const })));
    expect(withGestures.oneClickTotal).toEqual(before.oneClickTotal);
    expect(withGestures.overall).toEqual(before.overall);
    expect(withGestures.goalMetTotal).toEqual(before.goalMetTotal);
  });

  it("renders_the_table_next_to_the_existing_ones", () => {
    const md = renderReport(world, s, meta);
    expect(md).toContain("## Réussite en un clic");
    expect(md).toContain("## Un geste, connecté");
    expect(md.indexOf("## Un geste, connecté")).toBeGreaterThan(md.indexOf("## Réussite en un clic"));
    expect(md.indexOf("## Un geste, connecté")).toBeLessThan(md.indexOf("## Taux de réussite"));
    expect(md).toContain("| État de départ | Déclencheur | password | totp | passkey | sso | multi_step | signup | Total |");
    expect(md).toContain("| déverrouillé, hôte en marche | icône du champ | 1/3 (33.3 %) | sans scénario | sans scénario | sans scénario | sans scénario | sans scénario | 1/3 (33.3 %) |");
    expect(md).toContain("| verrouillé | icône du champ | 1/2 (50.0 %), +1 biométrie : 1 |");
    expect(md).toContain("| hôte arrêté | raccourci clavier | sans scénario | 1/1 (100.0 %) |");
    // Every trigger of the task has its line, measured or not.
    expect(md).toContain("| déverrouillé, hôte en marche | raccourci clavier | sans scénario |");
    expect(md).toContain("| verrouillé | compte de l'overlay | sans scénario |");
    expect(md).not.toContain(String.fromCharCode(0x2014));
  });

  it("a_run_from_before_the_gesture_accounting_says_so", () => {
    const md = renderReport(world, summarize([res(0, "pass", { oneClick: true })]), meta);
    expect(md).toContain("## Un geste, connecté");
    expect(md).toContain("Ce passage date d'avant le comptage des gestes");
    expect(md).not.toContain("| État de départ |");
  });
});

describe("skipped scenarios", () => {
  it("stay_out_of_every_rate_and_are_listed_by_missing_control", () => {
    const base = [res(0, "pass", { oneClick: true }), res(1, "fail", { cause: "timeout", oneClick: false })];
    const skipped = [
      res(2, "skipped", { cause: "host lacks control deferred_unlock", startState: "locked" }),
      res(3, "skipped", { cause: "host lacks control deferred_unlock", startState: "locked" }),
    ];
    const a = summarize(base);
    const b = summarize([...base, ...skipped]);
    expect(b.overall).toEqual(a.overall);
    expect(b.byFlow).toEqual(a.byFlow);
    expect(b.byDriver).toEqual(a.byDriver);
    expect(b.oneClickTotal).toEqual(a.oneClickTotal);
    expect(b.skipped).toHaveLength(2);
    const md = renderReport(world, b, meta);
    expect(md).toContain("## Scénarios sautés");
    expect(md).toContain("- host lacks control deferred_unlock : 2 scénario(s), état de départ : locked");
    expect(renderReport(world, a, meta)).not.toContain("## Scénarios sautés");
  });
});

describe("account profiles in the report", () => {
  it("states_each_profiles_expected_outcome_and_what_happened", () => {
    const rs = [
      played(0, "pass", ["field_icon", "menu_row"], true, { profile: "p1", outcome: "asks" }),
      played(1, "pass", ["field_icon"], true, { profile: "p2", outcome: "one gesture" }),
      played(2, "fail", ["field_icon"], false, { profile: "p2", outcome: "one gesture", cause: "wrong_account" }),
    ];
    const s = summarize([...rs, played(3, "pass", ["field_icon"], true)]);
    // Several accounts on a site is another question: out of the main table.
    expect(s.oneGesture.reduce((n, c) => n + c.total, 0)).toBe(1);
    const md = renderReport({ ...world, profiles: [...ACCOUNT_PROFILES] }, s, meta);
    expect(md).toContain("### Plusieurs comptes sur un site");
    expect(md).toContain("| p1 | déverrouillé, hôte en marche | icône du champ | 1 | 1 | 0 | 0 |");
    expect(md).toContain("| p2 | déverrouillé, hôte en marche | icône du champ | 2 | 1 | 1 | 1 |");
    expect(md).toContain("- p1 : two accounts, no site memory");
    expect(md).toContain("- p3 : one exact-host item and one domain-wide item");
    expect(md).not.toContain("coffre du monde seul, pays US");
  });
});
