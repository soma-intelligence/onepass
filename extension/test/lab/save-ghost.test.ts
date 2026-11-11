// @vitest-environment node
// Task 12a: save and ghost scenario family, pure half: the generator emits every
// variant on stable ids, the oracle judges the new causes from crafted
// observations, the report has its "Save" and "Suggestion" tables. No browser.
import { describe, expect, it } from "vitest";
import {
  GHOST_VARIANTS, generate, groupOf, loadPatterns, parseDriverGroups, SAVE_VARIANTS, saveGhostScenarios, withDrivers, withStarts,
} from "../../lab/gen/generate.ts";
import type { Scenario, Site } from "../../lab/gen/model.ts";
import { isRed, renderReport, summarize } from "../../lab/report.ts";
import { judge, type Observation, replayable, type Result, SAFETY_CAUSES } from "../../lab/run/oracle.ts";
import { pendingDriver12b } from "../../lab/run/pending.ts";

const world = generate("pass6-test", { sites: 120, patterns: loadPatterns() });
const full = withDrivers(world, ["current", "save_ghost"]);
const sg = full.scenarios.filter((s) => s.driver === "ghost" || s.driver === "save_typed");

describe("generator", () => {
  it("emits_every_variant_with_stable_ids", () => {
    for (const v of SAVE_VARIANTS) expect(sg.some((s) => s.driver === "save_typed" && s.variant === v), v).toBe(true);
    for (const v of GHOST_VARIANTS) expect(sg.some((s) => s.driver === "ghost" && s.variant === v), v).toBe(true);
    for (const s of sg) {
      expect(s.id).toBe(`${s.driver === "ghost" ? "ghost" : "save"}:${s.variant}:${s.site}`);
      expect(s.expect).toBe("pass");
    }
    expect(new Set(sg.map((s) => s.id)).size).toBe(sg.length);
    const again = withDrivers(generate("pass6-test", { sites: 120, patterns: loadPatterns() }), ["current", "save_ghost"]);
    expect(again.scenarios.map((s) => s.id)).toEqual(full.scenarios.map((s) => s.id));
  });
  it("ghost_on_signup_and_save_on_login_sites", () => {
    for (const s of sg) {
      const flow = world.sites[s.site]!.flow;
      if (s.driver === "ghost") expect(flow).toBe("signup");
      else expect(["login_single", "login_username_first", "login_email_then_password"]).toContain(flow);
    }
  });
  it("leaves_the_base_world_alone", () => {
    expect(withDrivers(world, ["current"]).scenarios).toEqual(world.scenarios);
    expect(saveGhostScenarios(world.sites).length).toBe(sg.length);
  });
  it("played_in_three_start_states", () => {
    const played = withStarts(full, ["unlocked_warm", "locked", "cold"]).scenarios.filter((s) => s.driver === "ghost" || s.driver === "save_typed");
    expect(played.length).toBe(sg.length * 3);
    expect(played.some((s) => s.id.endsWith("@locked") && s.start === "locked")).toBe(true);
    expect(played.some((s) => s.id.endsWith("@cold") && s.start === "cold")).toBe(true);
  });
  it("driver_group_parsed_and_mapped", () => {
    expect(parseDriverGroups("current,save_ghost")).toEqual(["current", "save_ghost"]);
    expect(groupOf("ghost")).toBe("save_ghost");
    expect(groupOf("save_typed")).toBe("save_ghost");
    expect(groupOf("one_click")).toBe("current");
  });
});

const site: Site = {
  index: 0, seed: "s0", host: "keen-glade-90.test", brand: "Keen Glade", lang: "en", labelLang: "en",
  flow: "login_single", traits: [], fields: [], buttons: { submit: "Sign in" }, account: { username: "ada", password: "x" },
};
const sc = (driver: "ghost" | "save_typed", variant: string, over: Partial<Scenario> = {}): Scenario =>
  ({ id: `${driver === "ghost" ? "ghost" : "save"}:${variant}:0`, site: 0, driver, variant, expect: "pass", ...over }) as Scenario;
const obs = (driver: "ghost" | "save_typed", over: Partial<Observation> = {}): Observation =>
  ({ driver, overlayShown: false, itemOffered: false, events: [], filled: {}, durationMs: 1, ...over });

describe("oracle save", () => {
  it("auto_save_passes_for_new_and_second_account", () => {
    for (const v of ["new_auto", "second_account"]) {
      expect(judge(sc("save_typed", v), site, obs("save_typed", { savedLogins: 1, autoSaved: true }))).toEqual({ verdict: "pass" });
      expect(judge(sc("save_typed", v), site, obs("save_typed", { savedLogins: 0, cardShown: true }))).toEqual({ verdict: "fail", cause: "save_missing" });
    }
  });
  it("locked_start_turns_automatic_into_card", () => {
    const s = sc("save_typed", "new_auto", { start: "locked" });
    expect(judge(s, site, obs("save_typed", { cardShown: true }))).toEqual({ verdict: "pass" });
    expect(judge(s, site, obs("save_typed", { savedLogins: 1, autoSaved: true }))).toEqual({ verdict: "fail", cause: "save_unexpected" });
  });
  it("card_variants_want_a_card_and_no_automatic_save", () => {
    for (const v of ["update_card", "no_username", "spa_stays", "private_window"]) {
      expect(judge(sc("save_typed", v), site, obs("save_typed", { cardShown: true }))).toEqual({ verdict: "pass" });
      expect(judge(sc("save_typed", v), site, obs("save_typed", {}))).toEqual({ verdict: "fail", cause: "card_expected" });
      expect(judge(sc("save_typed", v), site, obs("save_typed", { cardShown: true, savedLogins: 1, autoSaved: true })))
        .toEqual({ verdict: "fail", cause: "save_unexpected" });
    }
  });
  it("failed_login_saves_nothing", () => {
    const s = sc("save_typed", "failed_login");
    expect(judge(s, site, obs("save_typed", { failedSignIn: true, savedLogins: 0 }))).toEqual({ verdict: "pass" });
    expect(judge(s, site, obs("save_typed", { failedSignIn: true, savedLogins: 1 }))).toEqual({ verdict: "fail", cause: "save_unexpected" });
  });
  it("auto_saved_on_failure_beats_pass_and_is_a_safety_cause", () => {
    const o = obs("save_typed", { failedSignIn: true, autoSaved: true, savedLogins: 1, cardShown: true });
    const j = judge(sc("save_typed", "new_auto"), site, o);
    expect(j).toEqual({ verdict: "fail", cause: "auto_saved_on_failure" });
    expect(SAFETY_CAUSES.has("auto_saved_on_failure")).toBe(true);
    expect(replayable(sc("save_typed", "failed_login"), j)).toBe(false);
    // Even an expected failure does not hide it.
    expect(judge(sc("save_typed", "failed_login", { expect: "xfail" }), site, o).cause).toBe("auto_saved_on_failure");
  });
  it("expected_failure_turns_xpass_when_met", () => {
    const s = sc("save_typed", "spa_stays", { expect: "xfail" });
    expect(judge(s, site, obs("save_typed", { cardShown: true }))).toEqual({ verdict: "xpass" });
    expect(judge(s, site, obs("save_typed", {}))).toEqual({ verdict: "xfail", cause: "card_expected" });
  });
});

describe("oracle ghost", () => {
  it("accept_variants", () => {
    for (const v of ["accept_tab", "accept_click"]) {
      expect(judge(sc("ghost", v), site, obs("ghost", { ghostShown: true, ghostAccepted: true }))).toEqual({ verdict: "pass" });
      expect(judge(sc("ghost", v), site, obs("ghost", {}))).toEqual({ verdict: "fail", cause: "no_ghost" });
      expect(judge(sc("ghost", v), site, obs("ghost", { ghostShown: true }))).toEqual({ verdict: "fail", cause: "ghost_not_accepted" });
    }
  });
  it("ignore_typing_never_fills", () => {
    const s = sc("ghost", "ignore_typing");
    expect(judge(s, site, obs("ghost", { ghostShown: true }))).toEqual({ verdict: "pass" });
    expect(judge(s, site, obs("ghost", { ghostShown: true, ghostAccepted: true }))).toEqual({ verdict: "fail", cause: "ghost_accepted_unasked" });
  });
  it("menu_and_fallbacks_pass_when_the_menu_opened", () => {
    for (const v of ["menu_arrow", "fallback_narrow", "fallback_transform"]) {
      expect(judge(sc("ghost", v), site, obs("ghost", { menuOpened: true }))).toEqual({ verdict: "pass" });
      expect(judge(sc("ghost", v), site, obs("ghost", {}))).toEqual({ verdict: "fail", cause: "no_menu" });
    }
  });
  it("ghost_in_page_dom_fails_whatever_else", () => {
    const o = obs("ghost", { ghostShown: true, ghostAccepted: true, ghostInPageDom: true });
    expect(judge(sc("ghost", "accept_tab"), site, o)).toEqual({ verdict: "fail", cause: "ghost_in_page_dom" });
    expect(judge(sc("ghost", "accept_tab", { expect: "xfail" }), site, o).cause).toBe("ghost_in_page_dom");
  });
  it("leak_still_wins", () => {
    const leak = { at: 1, host: "x.test", kind: "leak", secret: "password", field: "pw", owner: "k" } as const;
    expect(judge(sc("ghost", "accept_tab"), site, obs("ghost", { ghostInPageDom: true, events: [leak] })).verdict).toBe("leak");
  });
});

describe("pending driver stub", () => {
  it("marks_the_scenario_skipped", () => {
    const o = pendingDriver12b("ghost");
    expect(o.skipped).toBe("driver_pending_12b");
    expect(judge(sc("ghost", "accept_tab"), site, o)).toEqual({ verdict: "skipped", cause: "driver_pending_12b" });
  });
});

function res(n: number, driver: "ghost" | "save_typed", variant: string, verdict: Result["verdict"], over: Partial<Result> = {}): Result {
  return {
    worldSeed: "w", site: n, siteSeed: `s${n}`, flow: "login_single", traits: [], lang: "en", labelLang: "en",
    driver, variant, expect: "pass", verdict, retried: false, durationMs: 1, repro: "r", ...over,
  };
}

describe("report", () => {
  const rs: Result[] = [
    res(1, "save_typed", "new_auto", "pass"), res(1, "save_typed", "new_auto", "fail", { cause: "save_missing", startState: "locked" }),
    res(2, "save_typed", "failed_login", "fail", { cause: "auto_saved_on_failure" }),
    res(3, "save_typed", "spa_stays", "skipped", { cause: "driver_pending_12b" }),
    res(4, "ghost", "accept_tab", "pass"), res(4, "ghost", "accept_tab", "fail", { cause: "ghost_in_page_dom", startState: "cold" }),
    res(5, "ghost", "menu_arrow", "xfail", { cause: "no_menu" }),
  ];
  const s = summarize(rs);
  it("tables_by_variant_and_start", () => {
    const row = s.save.find((r) => r.variant === "new_auto" && r.start === "unlocked_warm")!;
    expect(row).toMatchObject({ total: 1, ok: 1, fail: 0 });
    expect(s.save.find((r) => r.variant === "new_auto" && r.start === "locked")).toMatchObject({ total: 1, ok: 0, fail: 1 });
    expect(s.save.find((r) => r.variant === "spa_stays")).toMatchObject({ total: 1, skipped: 1, ok: 0 });
    expect(s.ghost.find((r) => r.variant === "menu_arrow")).toMatchObject({ xfail: 1 });
  });
  it("skipped_stay_out_of_rates_but_in_the_table", () => {
    expect(s.overall.total).toBe(6);
  });
  it("red_on_the_two_new_violations", () => {
    expect(s.autoSavedOnFailure.length).toBe(1);
    expect(s.ghostInPageDom.length).toBe(1);
    expect(isRed(s)).toBe(true);
    expect(isRed(summarize([res(1, "save_typed", "new_auto", "pass")]))).toBe(false);
    expect(isRed(summarize([res(1, "ghost", "accept_tab", "fail", { cause: "ghost_in_page_dom" })]))).toBe(true);
  });
  it("markdown_has_sections_and_no_em_dash", () => {
    const md = renderReport({ seed: "w", sites: 10 }, s, {});
    expect(md).toContain("## Enregistrement");
    expect(md).toContain("## Suggestion");
    expect(md).toContain("auto_saved_on_failure");
    expect(md).toContain("ghost_in_page_dom");
    expect(md).not.toContain("—");
    const clean = renderReport({ seed: "w", sites: 10 }, summarize([]), {});
    expect(clean).not.toContain("## Enregistrement");
  });
  it("scenario_lines_name_the_variant", () => {
    expect(renderReport({ seed: "w", sites: 10 }, s, {})).toContain("save_typed:new_auto");
  });
});
