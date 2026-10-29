// @vitest-environment node
// Report of the autofill lab (spec 8): rates exclude expected failures and
// bench errors, traits count each trait, the Markdown is French, free of the
// em dash and of any vault value, and leaks get their own section.
import { describe, expect, it } from "vitest";
import { generate, loadPatterns } from "../../lab/gen/generate.ts";
import type { Scenario, Site } from "../../lab/gen/model.ts";
import { isRed, renderReport, summarize } from "../../lab/report.ts";
import { afterReplay, judge, type Observation, oneClickOf, replayable, type Result, type Verdict } from "../../lab/run/oracle.ts";
import type { LabEvent } from "../../lab/server/ledger.ts";

function res(n: number, verdict: Verdict, over: Partial<Result> = {}): Result {
  return {
    worldSeed: "w", site: n, siteSeed: `s${n}`, flow: "login_single", traits: [], lang: "en", labelLang: "en",
    driver: "one_click", expect: "pass", verdict, retried: false, durationMs: 10,
    repro: `npm run lab:repro -- --seed w --site ${n}`, ...over,
  };
}

const meta = { date: "2026-10-26", commit: "abc1234", durationMin: 7 };
const world = { seed: "w", sites: 10 };

describe("lab report", () => {
  it("rate_excludes_xfail_and_lab_error", () => {
    const s = summarize([
      res(0, "pass"), res(1, "pass"), res(2, "fail", { cause: "timeout" }), res(3, "flaky"),
      res(4, "xfail"), res(5, "xpass"), res(6, "lab_error"),
    ]);
    expect(s.overall.total).toBe(7);
    expect(s.overall.rate).toBeCloseTo(3 / 4);
    expect(s.overall.xfail).toBe(1);
    expect(s.overall.xpass).toBe(1);
    expect(s.overall.labError).toBe(1);
    expect(summarize([res(0, "xfail")]).overall.rate).toBe(1);
  });

  it("groups_by_trait_count_each_trait", () => {
    const s = summarize([
      res(0, "pass", { traits: ["honeypot", "spa_rerender"] }),
      res(1, "fail", { traits: ["honeypot"], cause: "timeout" }),
      res(2, "pass"),
    ]);
    expect(s.byTrait.honeypot!.total).toBe(2);
    expect(s.byTrait.spa_rerender!.total).toBe(1);
    expect(s.byTrait["(aucun)"]!.total).toBe(1);
    expect(s.byFlow.login_single!.total).toBe(3);
    expect(s.byLang.en!.total).toBe(3);
    expect(s.byDriver.one_click!.total).toBe(3);
  });

  it("markdown_has_no_em_dash", () => {
    const s = summarize([res(0, "pass"), res(1, "fail", { cause: "timeout" }), res(2, "xfail", { cause: "no_overlay" }), res(3, "xpass"), res(4, "flaky")]);
    const md = renderReport(world, s, meta);
    expect(md).not.toContain("\u2014");
    expect(md).toContain("## Ce que l'extension ne fait pas encore");
    expect(md).toContain("npm run lab:repro -- --seed w --site 1");
    expect(md).toContain("## Instables");
  });

  it("markdown_has_no_secret", () => {
    const w = generate("report-secret-seed", { sites: 12, patterns: loadPatterns() });
    const results = w.scenarios.map((sc) => {
      const site = w.sites[sc.site]!;
      return res(site.index, "fail", { flow: site.flow, traits: site.traits, lang: site.lang, driver: sc.driver, cause: "timeout" });
    });
    const md = renderReport({ seed: w.seed, sites: w.sites.length }, summarize(results), meta);
    const secrets: string[] = [];
    for (const site of w.sites) {
      if (site.account) secrets.push(site.account.password, site.account.totpSecret ?? "");
    }
    for (const accounts of Object.values(w.idp)) for (const a of accounts) secrets.push(a.password);
    secrets.push(...JSON.stringify(w.fixture).match(/"(?:number|password|cvv|csc|secret|totp)[^"]*":\s*"([^"]{4,})"/g)?.map((m) => m.split('"')[3]!) ?? []);
    const real = secrets.filter((x) => x.length >= 4);
    expect(real.length).toBeGreaterThan(0);
    for (const x of real) expect(md).not.toContain(x);
  });

  it("xfail_grouped_by_reason_with_cause_fallback", () => {
    const s = summarize([
      res(0, "xfail", { reason: "R-16 passkeys", cause: "no_overlay" }),
      res(1, "xfail", { reason: "R-16 passkeys", cause: "timeout" }),
      res(2, "xfail", { cause: "chain_ended:done" }),
      res(3, "fail", { cause: "timeout" }),
    ]);
    const md = renderReport(world, s, meta);
    expect(md).toContain("- R-16 passkeys : 2 scénario(s)");
    expect(md).toContain("- chain_ended:done : 1 scénario(s)");
    expect(md).toContain("Causes d'échec récurrentes");
  });

  it("missing_meta_prints_unknown", () => {
    const md = renderReport(world, summarize([res(0, "pass")]), {});
    expect(md).toContain("Date : inconnue");
    expect(md).toContain("Commit : inconnu");
    expect(md).toContain("Durée : inconnue");
  });

  it("leaks_section", () => {
    const clean = renderReport(world, summarize([res(0, "pass")]), meta);
    expect(clean).toMatch(/## Fuites\n\nAucune\./);
    const leaky = summarize([res(0, "pass"), res(1, "leak", { cause: "leak:password:pw@evil.test" })]);
    expect(leaky.leaks).toHaveLength(1);
    const md = renderReport(world, leaky, meta);
    expect(md).toMatch(/## Fuites\n\n- site 1/);
    expect(md).toContain("leak:password:pw@evil.test");
    expect(md).not.toMatch(/## Fuites\n\nAucune\./);
  });
  it("passkey_control_is_a_bench_check_outside_the_rates", () => {
    const control = (n: number, verdict: Verdict, over: Partial<Result> = {}) =>
      res(n, verdict, { flow: "login_passkey", driver: "passkey_control", traits: ["iframe_same_origin"], lang: "fr", ...over });
    const s = summarize([
      res(0, "pass", { flow: "login_passkey", traits: ["iframe_same_origin"], lang: "fr" }),
      res(1, "fail", { cause: "timeout" }),
      control(0, "pass"), control(2, "fail", { cause: "rp_refused:bad_signature" }),
    ]);
    // Out of the overall, flow, trait and language rates...
    expect(s.overall.total).toBe(2);
    expect(s.overall.rate).toBeCloseTo(1 / 2);
    expect(s.byFlow.login_passkey!.total).toBe(1);
    expect(s.byTrait.iframe_same_origin!.total).toBe(1);
    expect(s.byLang.fr!.total).toBe(1);
    expect(s.failures.map((r) => r.driver)).toEqual(["one_click"]);
    // ...kept per driver and in its own section.
    expect(s.byDriver.passkey_control!.total).toBe(2);
    expect(s.control.total).toBe(2);
    expect(s.control.fail).toBe(1);
    expect(s.controlFailures.map((r) => r.site)).toEqual([2]);
    const md = renderReport(world, s, meta);
    expect(md).toContain("## Contrôle du banc");
    expect(md).toMatch(/## Contrôle du banc\n\n[^#]*Scénarios : 2, réussis : 1, échecs : 1/);
    expect(md).toMatch(/## Contrôle du banc\n[^#]*- site 2 \(login_passkey, passkey_control[^\n]*rp_refused:bad_signature/);
    const fails = md.slice(md.indexOf("## Échecs"), md.indexOf("## Réussites inattendues"));
    expect(fails).not.toContain("passkey_control");
    // A leak is never hidden, whichever driver saw it.
    const leaky = summarize([res(0, "pass"), control(0, "leak", { cause: "leak:password:pw@frame.test" })]);
    expect(leaky.leaks).toHaveLength(1);
    expect(renderReport(world, leaky, meta)).toContain("- Fuites : 1 (le passage est rouge)");
    const clean = renderReport(world, summarize([control(0, "pass")]), meta);
    expect(clean).toMatch(/## Contrôle du banc\n[^#]*Aucun échec/);
    expect(renderReport(world, summarize([res(0, "pass")]), meta)).toMatch(/## Contrôle du banc\n\nAucun scénario/);
  });

  it("lists_are_byte_stable_in_any_result_order", () => {
    const results = [
      res(3, "fail", { cause: "timeout" }), res(1, "leak", { cause: "leak:password:pw@evil.test", driver: "lookalike" }),
      res(1, "fail", { cause: "no_overlay" }), res(2, "xfail", { cause: "no_overlay" }), res(0, "flaky"), res(2, "flaky", { driver: "menu_fill" }),
    ];
    const a = renderReport(world, summarize(results), meta);
    const b = renderReport(world, summarize([...results].reverse()), meta);
    expect(a).toBe(b);
    expect(summarize(results).failures.map((r) => `${r.site}:${r.driver}`)).toEqual(["1:lookalike", "1:one_click", "3:one_click"]);
  });
});

// Task 11 (smart fill): wrong item and auto-submit outside a login are
// failures that turn the run red, and the report compares the one-click
// success of the current drivers with smart_fill, flow by flow.
const checkout: Site = {
  index: 7, seed: "s7", host: "amber-quay-12.test", brand: "Amber Quay", lang: "en", labelLang: "en",
  flow: "checkout_card", traits: [],
  fields: [
    { role: "cc_number", name: "ccnum", id: "ccnum", label: "Card number", type: "text" },
    { role: "cc_csc", name: "cvc", id: "cvc", label: "CVC", type: "text" },
  ],
  buttons: { submit: "Pay" }, cardTitle: "Carte Amber Quay",
};
const signinSite: Site = {
  ...checkout, index: 8, host: "keen-glade-90.test", flow: "login_single", cardTitle: undefined,
  fields: [{ role: "username", name: "user", id: "user", label: "User", type: "text" }, { role: "password", name: "pw", id: "pw", label: "Password", type: "password" }],
  buttons: { submit: "Sign in" }, account: { username: "ada", password: "x" }, itemTitle: "Keen Glade",
};
const totpSite: Site = { ...signinSite, index: 9, host: "otp-bay-3.test", flow: "login_totp" };
const sc = (site: Site, driver: Scenario["driver"] = "smart_fill", expectation: Scenario["expect"] = "pass"): Scenario =>
  ({ id: `${site.index}:${driver}`, site: site.index, driver, expect: expectation });
const ob = (over: Partial<Observation> = {}): Observation =>
  ({ driver: "smart_fill", overlayShown: true, itemOffered: true, events: [], filled: {}, durationMs: 10, ...over });
const ev = {
  submit: (host: string, at: number, ok = true, form = "checkout_card"): LabEvent => ({ at, host, kind: "submit", form, ok, fields: [] }),
  signin: (host: string, at: number, user: string): LabEvent => ({ at, host, kind: "signin", user }),
};

describe("smart fill metrics", () => {
  it("wrong_item_is_fail", () => {
    // A value of another vault item in the form: fail, whatever the site then accepted.
    const o = ob({ filled: { ccnum: true }, foreign: ["ccnum"], userSubmitAt: 20, events: [ev.submit(checkout.host, 30, false)] });
    expect(judge(sc(checkout), checkout, o)).toEqual({ verdict: "fail", cause: "wrong_item" });
    // Signed in as another account than the scenario's: the filled item was not the expected one.
    expect(judge(sc(signinSite, "one_click"), signinSite, ob({ driver: "one_click", events: [ev.signin(signinSite.host, 5, "bob")] })))
      .toEqual({ verdict: "fail", cause: "wrong_item" });
    // Never replayed into a pass: an expected failure with a wrong item is a failure too.
    expect(judge(sc(checkout, "smart_fill", "xfail"), checkout, ob({ foreign: ["ccnum"] }))).toEqual({ verdict: "fail", cause: "wrong_item" });
    // The right item stays a pass.
    expect(judge(sc(checkout), checkout, ob({ foreign: [], userSubmitAt: 20, events: [ev.submit(checkout.host, 30)] }))).toEqual({ verdict: "pass" });
  });

  it("auto_submit_outside_login_is_fail", () => {
    // OnePass sent the payment form before the user pressed its button.
    const early = ob({ userSubmitAt: 50, events: [ev.submit(checkout.host, 40)] });
    expect(judge(sc(checkout), checkout, early)).toEqual({ verdict: "fail", cause: "auto_submit_outside_login" });
    // No user submit at all: every post of the site is OnePass's.
    expect(judge(sc(checkout), checkout, ob({ events: [ev.submit(checkout.host, 40)] })))
      .toEqual({ verdict: "fail", cause: "auto_submit_outside_login" });
    // The user's own submit is not OnePass's.
    expect(judge(sc(checkout), checkout, ob({ userSubmitAt: 30, events: [ev.submit(checkout.host, 40)] }))).toEqual({ verdict: "pass" });
    // Login and its code step (otp is login family, spec 8.1) may be sent by OnePass.
    expect(judge(sc(signinSite), signinSite, ob({ events: [ev.submit(signinSite.host, 5, true, "login_single"), ev.signin(signinSite.host, 6, "ada")] })))
      .toEqual({ verdict: "pass" });
    expect(judge(sc(totpSite), totpSite, ob({ events: [ev.submit(totpSite.host, 5, true, "otp"), ev.signin(totpSite.host, 6, "ada")] })))
      .toEqual({ verdict: "pass" });
    // A leak still wins.
    const leak: LabEvent = { at: 41, host: "evil.test", kind: "leak", secret: "card", field: "ccnum", owner: checkout.host };
    expect(judge(sc(checkout), checkout, ob({ events: [ev.submit(checkout.host, 40), leak] })).verdict).toBe("leak");
  });

  it("report_has_one_click_rate_per_flow", () => {
    // One click: the goal met with a single gesture toward OnePass.
    expect(oneClickOf(sc(checkout), "pass", ob({ clicks: 1 }))).toBe(true);
    expect(oneClickOf(sc(checkout), "pass", ob({ clicks: 2 }))).toBe(false);
    expect(oneClickOf(sc(checkout), "fail", ob({ clicks: 1 }))).toBe(false);
    expect(oneClickOf(sc(checkout, "smart_fill", "nofill"), "pass", ob({ clicks: 0 }))).toBeUndefined();
    expect(oneClickOf(sc(signinSite, "lookalike", "nofill"), "pass", ob({ driver: "lookalike" }))).toBeUndefined();
    const s = summarize([
      res(0, "pass", { flow: "checkout_card", driver: "menu_fill", oneClick: false }),
      res(1, "pass", { flow: "checkout_card", driver: "menu_fill", oneClick: false }),
      res(0, "pass", { flow: "checkout_card", driver: "smart_fill", oneClick: true }),
      res(1, "pass", { flow: "checkout_card", driver: "smart_fill", oneClick: false }),
      res(2, "pass", { flow: "login_single", driver: "one_click", oneClick: true }),
      res(2, "pass", { flow: "login_single", driver: "smart_fill", oneClick: true }),
      res(3, "lab_error", { flow: "login_single", driver: "smart_fill" }),
      res(4, "pass", { flow: "login_single", driver: "lookalike", expect: "nofill" }),
    ]);
    expect(s.oneClick.checkout_card).toEqual({ current: { total: 2, ok: 0, rate: 0 }, smart_fill: { total: 2, ok: 1, rate: 0.5 } });
    expect(s.oneClick.login_single).toEqual({ current: { total: 1, ok: 1, rate: 1 }, smart_fill: { total: 1, ok: 1, rate: 1 } });
    expect(s.oneClickTotal).toEqual({ current: { total: 3, ok: 1, rate: 1 / 3 }, smart_fill: { total: 3, ok: 2, rate: 2 / 3 } });
    const md = renderReport(world, s, meta);
    expect(md).toContain("## Réussite en un clic");
    expect(md).toContain("| checkout_card | 0/2 (0.0 %) | 1/2 (50.0 %) |");
    expect(md).toContain("| login_single | 1/1 (100.0 %) | 1/1 (100.0 %) |");
    expect(md).toContain("| Total | 1/3 (33.3 %) | 2/3 (66.7 %) |");
    expect(md).not.toContain("\u2014");
  });

  it("run_red_on_wrong_item", () => {
    const clean = summarize([res(0, "pass"), res(1, "fail", { cause: "timeout" })]);
    expect(isRed(clean)).toBe(false);
    const wrong = summarize([res(0, "pass"), res(1, "fail", { driver: "smart_fill", flow: "address", cause: "wrong_item" })]);
    expect(wrong.wrongItem.map((r) => r.site)).toEqual([1]);
    expect(isRed(wrong)).toBe(true);
    const md = renderReport(world, wrong, meta);
    expect(md).toContain("- Mauvais élément (`wrong_item`) : 1 (le passage est rouge)");
    expect(md).toMatch(/## Mauvais élément rempli\n\n- site 1 \(address, smart_fill/);
    const auto = summarize([res(2, "fail", { flow: "signup", cause: "auto_submit_outside_login" })]);
    expect(auto.autoSubmitOutsideLogin).toHaveLength(1);
    expect(isRed(auto)).toBe(true);
    expect(renderReport(world, auto, meta)).toContain("- Envois automatiques hors connexion (`auto_submit_outside_login`) : 1 (le passage est rouge)");
    expect(isRed(summarize([res(3, "leak", { cause: "leak:password:pw@evil.test" })]))).toBe(true);
  });
  it("run_red_when_every_scenario_is_a_lab_error", () => {
    expect(isRed(summarize([res(0, "lab_error"), res(1, "lab_error")]))).toBe(true);
    expect(isRed(summarize([res(0, "pass"), res(1, "lab_error")]))).toBe(false);
    expect(isRed(summarize([]))).toBe(false);
  });

  it("replay_never_hides_a_safety_failure", () => {
    const fail = (cause: string) => ({ verdict: "fail" as const, cause });
    // A safety failure on the first attempt is final, like a nofill scenario's.
    expect(replayable(sc(checkout), fail("wrong_item"))).toBe(false);
    expect(replayable(sc(checkout), fail("auto_submit_outside_login"))).toBe(false);
    expect(replayable(sc(checkout, "smart_fill", "nofill"), fail("filled_where_forbidden"))).toBe(false);
    expect(replayable(sc(checkout), fail("timeout"))).toBe(true);
    expect(replayable(sc(checkout), { verdict: "pass" })).toBe(false);
    // A replay showing a violation replaces a plain first failure.
    expect(afterReplay(fail("timeout"), fail("wrong_item"))).toEqual({ judgement: fail("wrong_item"), replay: true });
    expect(afterReplay(fail("timeout"), fail("auto_submit_outside_login")))
      .toEqual({ judgement: fail("auto_submit_outside_login"), replay: true });
    expect(afterReplay(fail("timeout"), { verdict: "leak", cause: "leak:card:n@x.test" }))
      .toEqual({ judgement: { verdict: "leak", cause: "leak:card:n@x.test" }, replay: true });
    // A pass on the replay is flaky; another plain failure keeps the first one.
    expect(afterReplay(fail("timeout"), { verdict: "pass" })).toEqual({ judgement: { verdict: "flaky", cause: "timeout" }, replay: true });
    expect(afterReplay(fail("timeout"), fail("no_overlay"))).toEqual({ judgement: fail("timeout"), replay: false });
  });

  it("report_has_goal_met_rate_per_flow", () => {
    const s = summarize([
      res(0, "pass", { flow: "checkout_card", driver: "menu_fill", oneClick: false }),
      res(1, "fail", { flow: "checkout_card", driver: "menu_fill", oneClick: false, cause: "timeout" }),
      res(0, "flaky", { flow: "checkout_card", driver: "smart_fill", oneClick: false }),
      res(1, "pass", { flow: "checkout_card", driver: "smart_fill", oneClick: true }),
      res(2, "xfail", { flow: "login_single", driver: "one_click", oneClick: false }),
      res(2, "xpass", { flow: "login_single", driver: "smart_fill", oneClick: true }),
      res(3, "pass", { flow: "login_single", driver: "lookalike", expect: "nofill" }),
    ]);
    expect(s.goalMet.checkout_card).toEqual({ current: { total: 2, ok: 1, rate: 0.5 }, smart_fill: { total: 2, ok: 2, rate: 1 } });
    expect(s.goalMet.login_single).toEqual({ current: { total: 1, ok: 0, rate: 0 }, smart_fill: { total: 1, ok: 1, rate: 1 } });
    expect(s.goalMetTotal).toEqual({ current: { total: 3, ok: 1, rate: 1 / 3 }, smart_fill: { total: 3, ok: 3, rate: 1 } });
    const md = renderReport(world, s, meta);
    const section = md.slice(md.indexOf("## Réussite en un clic"), md.indexOf("## Taux de réussite"));
    expect(section).toContain("### But atteint, quel que soit le nombre de gestes");
    expect(section).toContain("| checkout_card | 1/2 (50.0 %) | 2/2 (100.0 %) |");
    expect(section).toContain("| Total | 1/3 (33.3 %) | 3/3 (100.0 %) |");
  });
});
