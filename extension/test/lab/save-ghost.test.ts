// @vitest-environment node
// Task 12a: save and ghost scenario family, pure half: the generator emits every
// variant on stable ids, the oracle judges the new causes from crafted
// observations, the report has its "Save" and "Suggestion" tables. No browser.
// Task 12b: the oracle's start-state rules, failed_login on a real refusal,
// ghost_in_page_dom as a safety cause, the fallbacks without a ghost.
import { describe, expect, it } from "vitest";
import {
  firstLoginHosts, firstLoginKey, GHOST_VARIANTS, generate, groupOf, loadPatterns, parseDriverGroups, SAVE_VARIANTS, saveGhostScenarios, withDrivers, withoutSiteLogins, withStarts,
} from "../../lab/gen/generate.ts";
import type { Scenario, Site } from "../../lab/gen/model.ts";
import { isRed, renderReport, summarize } from "../../lab/report.ts";
import { judge, type Observation, replayable, type Result, SAFETY_CAUSES } from "../../lab/run/oracle.ts";

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
  it("first_login_vault_drops_the_new_auto_sites_logins_only", () => {
    const hosts = firstLoginHosts(full);
    const newAuto = sg.filter((s) => s.variant === "new_auto").map((s) => world.sites[s.site]!.host);
    expect(hosts.sort()).toEqual([...new Set(newAuto)].sort());
    const on = (f: typeof world.fixture, h: string) => (f.items as { type: string; urls?: { url: string }[] }[])
      .filter((i) => i.type === "login" && (i.urls ?? []).some((u) => new URL(u.url).hostname === h)).length;
    const stripped = withoutSiteLogins(world.fixture, hosts);
    for (const h of hosts) {
      expect(on(world.fixture, h), h).toBeGreaterThan(0);
      expect(on(stripped, h), h).toBe(0);
    }
    const other = world.sites.find((x) => x.account && !hosts.includes(x.host) && on(world.fixture, x.host) > 0)!;
    expect(on(stripped, other.host)).toBe(on(world.fixture, other.host));
    expect(firstLoginKey("p0")).toBe("p0/first-login");
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
    // A silent save after the refusal is the safety cause (fix round 1 of task 12b), not a plain save_unexpected.
    expect(judge(s, site, obs("save_typed", { failedSignIn: true, savedLogins: 1 }))).toEqual({ verdict: "fail", cause: "auto_saved_on_failure" });
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

describe("oracle 12b fixes", () => {
  it("ghost_in_page_dom_is_a_safety_cause_never_replayed", () => {
    expect(SAFETY_CAUSES.has("ghost_in_page_dom")).toBe(true);
    const j = judge(sc("ghost", "ignore_typing"), site, obs("ghost", { ghostShown: true, ghostInPageDom: true }));
    expect(j).toEqual({ verdict: "fail", cause: "ghost_in_page_dom" });
    expect(replayable(sc("ghost", "ignore_typing"), j)).toBe(false);
  });
  it("failed_login_needs_a_real_refusal", () => {
    const s = sc("save_typed", "failed_login");
    expect(judge(s, site, obs("save_typed", { savedLogins: 0 }))).toEqual({ verdict: "fail", cause: "sign_in_not_refused" });
    expect(judge(s, site, obs("save_typed", { failedSignIn: false, cardShown: true }))).toEqual({ verdict: "fail", cause: "sign_in_not_refused" });
    expect(judge(s, site, obs("save_typed", { failedSignIn: true }))).toEqual({ verdict: "pass" });
    // A card on a refused sign-in saves nothing: not a failure of this variant.
    expect(judge(s, site, obs("save_typed", { failedSignIn: true, cardShown: true }))).toEqual({ verdict: "pass" });
  });
  it("locked_start_wants_the_card_for_every_save_variant", () => {
    for (const v of ["new_auto", "second_account", "update_card", "no_username", "spa_stays"]) {
      const s = sc("save_typed", v, { start: "locked" });
      expect(judge(s, site, obs("save_typed", { cardShown: true })), v).toEqual({ verdict: "pass" });
      expect(judge(s, site, obs("save_typed", {})), v).toEqual({ verdict: "fail", cause: "card_expected" });
      expect(judge(s, site, obs("save_typed", { savedLogins: 1 })), v).toEqual({ verdict: "fail", cause: "save_unexpected" });
      expect(judge(s, site, obs("save_typed", { autoSaved: true, cardShown: true })), v).toEqual({ verdict: "fail", cause: "save_unexpected" });
    }
  });
  it("cold_start_takes_the_automatic_save_or_the_card", () => {
    for (const v of ["new_auto", "second_account"]) {
      const s = sc("save_typed", v, { start: "cold" });
      expect(judge(s, site, obs("save_typed", { savedLogins: 1, autoSaved: true })), v).toEqual({ verdict: "pass" });
      expect(judge(s, site, obs("save_typed", { cardShown: true })), v).toEqual({ verdict: "pass" });
      expect(judge(s, site, obs("save_typed", {})), v).toEqual({ verdict: "fail", cause: "save_missing" });
      // Saved without telling the user: no toast is no pass.
      expect(judge(s, site, obs("save_typed", { savedLogins: 1 })), v).toEqual({ verdict: "fail", cause: "save_missing" });
    }
    // Unlocked: the card is no substitute for the automatic save.
    expect(judge(sc("save_typed", "new_auto"), site, obs("save_typed", { cardShown: true }))).toEqual({ verdict: "fail", cause: "save_missing" });
    // The card variants stay card variants in a cold start.
    expect(judge(sc("save_typed", "update_card", { start: "cold" }), site, obs("save_typed", { savedLogins: 1, autoSaved: true })))
      .toEqual({ verdict: "fail", cause: "save_unexpected" });
  });
  it("locked_ghost_passes_on_the_menu_that_asks_to_unlock", () => {
    for (const v of ["accept_tab", "accept_click", "ignore_typing", "menu_arrow", "fallback_narrow", "fallback_transform"]) {
      const s = sc("ghost", v, { start: "locked" });
      expect(judge(s, site, obs("ghost", { menuOpened: true })), v).toEqual({ verdict: "pass" });
      expect(judge(s, site, obs("ghost", {})), v).toEqual({ verdict: "fail", cause: "no_menu" });
    }
    // A ghost after an approved unlock is judged as from an open vault.
    expect(judge(sc("ghost", "accept_tab", { start: "locked" }), site, obs("ghost", { ghostShown: true }))).toEqual({ verdict: "fail", cause: "ghost_not_accepted" });
    // Cold: the host starts on the gesture, the ghost is owed.
    expect(judge(sc("ghost", "accept_tab", { start: "cold" }), site, obs("ghost", { menuOpened: true }))).toEqual({ verdict: "fail", cause: "no_ghost" });
  });
  it("a_typed_sign_in_as_another_account_is_no_wrong_item", () => {
    const signin = { at: 1, host: site.host, kind: "signin", user: "typed@lab-user.test" } as const;
    expect(judge(sc("save_typed", "new_auto"), site, obs("save_typed", { events: [signin], signedInAsTyped: true, savedLogins: 1, autoSaved: true })))
      .toEqual({ verdict: "pass" });
    // Not the identifier she typed (or unknown): a wrong item, as for any driver.
    expect(judge(sc("save_typed", "new_auto"), site, obs("save_typed", { events: [signin], signedInAsTyped: false, savedLogins: 1, autoSaved: true })))
      .toEqual({ verdict: "fail", cause: "wrong_item" });
    expect(judge(sc("save_typed", "new_auto"), site, obs("save_typed", { events: [signin], savedLogins: 1, autoSaved: true })))
      .toEqual({ verdict: "fail", cause: "wrong_item" });
    // Another driver signing that account in is still one.
    expect(judge(sc("ghost", "accept_tab"), site, obs("ghost", { events: [signin], ghostShown: true, ghostAccepted: true }))).toEqual({ verdict: "fail", cause: "wrong_item" });
  });
  it("silent_save_after_a_refused_sign_in_is_auto_saved_on_failure", () => {
    for (const v of ["failed_login", "new_auto", "update_card"]) {
      const j = judge(sc("save_typed", v), site, obs("save_typed", { failedSignIn: true, savedLogins: 1 }));
      expect(j, v).toEqual({ verdict: "fail", cause: "auto_saved_on_failure" });
      expect(replayable(sc("save_typed", v), j)).toBe(false);
    }
    expect(judge(sc("save_typed", "failed_login"), site, obs("save_typed", { failedSignIn: true, savedLogins: 0 }))).toEqual({ verdict: "pass" });
  });
  it("a_save_or_card_for_another_login_is_wrong_login", () => {
    expect(judge(sc("save_typed", "new_auto"), site, obs("save_typed", { savedLogins: 1, autoSaved: true, wrongLogin: true })))
      .toEqual({ verdict: "fail", cause: "wrong_login" });
    expect(judge(sc("save_typed", "update_card"), site, obs("save_typed", { cardShown: true, wrongLogin: true })))
      .toEqual({ verdict: "fail", cause: "wrong_login" });
    expect(judge(sc("save_typed", "update_card"), site, obs("save_typed", { cardShown: true, wrongLogin: false }))).toEqual({ verdict: "pass" });
  });
  it("lab_error_when_the_ghost_text_is_unreadable", () => {
    expect(judge(sc("ghost", "accept_tab"), site, obs("ghost", { ghostShown: true, ghostAccepted: true, error: "lab: ghost text unreadable" })).verdict)
      .toBe("lab_error");
  });
  it("fallbacks_want_the_menu_and_no_ghost", () => {
    for (const v of ["fallback_narrow", "fallback_transform"]) {
      expect(judge(sc("ghost", v), site, obs("ghost", { ghostShown: true, menuOpened: true })), v).toEqual({ verdict: "fail", cause: "ghost_not_fallen_back" });
    }
    // menu_arrow opens the menu from a ghost that did show.
    expect(judge(sc("ghost", "menu_arrow"), site, obs("ghost", { ghostShown: true, menuOpened: true }))).toEqual({ verdict: "pass" });
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
