// @vitest-environment node
// Oracle of the autofill lab (spec 7.5): one verdict per scenario from the
// server events, the chain state and the DOM observation. A leak beats
// everything, bench errors are lab_error, cross-site frames and lookalikes
// expect nothing filled, expected failures turn into xpass when the goal is
// met, and a missed goal carries its cause.
import { describe, expect, it } from "vitest";
import type { Scenario, Site } from "../../lab/gen/model.ts";
import { judge, type Observation } from "../../lab/run/oracle.ts";
import type { LabEvent } from "../../lab/server/ledger.ts";

const login: Site = {
  index: 0, seed: "s0", host: "keen-glade-90.test", brand: "Keen Glade", lang: "en", labelLang: "en",
  flow: "login_single", traits: [],
  fields: [
    { role: "username", name: "user", id: "user", label: "User", type: "text" },
    { role: "password", name: "pw", id: "pw", label: "Password", type: "password" },
  ],
  buttons: { submit: "Sign in" }, account: { username: "ada", password: "x" }, itemTitle: "Keen Glade",
};
const sso: Site = {
  ...login, index: 1, host: "misty-glade-57.test", flow: "sso", fields: [], account: undefined,
  sso: { provider: "google", email: "ada@mail.test" }, itemTitle: "Misty Glade via Google",
};
const framed: Site = { ...login, index: 2, host: "fern-anchor-50.test", traits: ["iframe_cross_site"], frameHost: "other-site-3.test" };
const shadow: Site = { ...login, index: 3, host: "opal-kettle-14.test", traits: ["shadow_closed"] };

const scenario = (site: Site, expectation: Scenario["expect"], driver: Scenario["driver"] = "one_click"): Scenario =>
  ({ id: `${site.index}:${driver}`, site: site.index, driver, expect: expectation });

function obs(over: Partial<Observation> = {}): Observation {
  return { driver: "one_click", overlayShown: true, itemOffered: true, events: [], filled: {}, durationMs: 10, ...over };
}
const signin = (host: string, user: string, via?: "google" | "apple" | "microsoft"): LabEvent =>
  ({ at: 1, host, kind: "signin", user, ...(via ? { via } : {}) });
const submit = (host: string, ok: boolean, reason?: string): LabEvent =>
  ({ at: 1, host, kind: "submit", form: "login_single", ok, fields: ok ? [] : ["pw"], ...(reason ? { reason } : {}) });
const leak: LabEvent = { at: 1, host: "keen-glade-90.test.evil.test", kind: "leak", secret: "password", field: "pw", owner: "keen-glade-90.test" };

describe("judge", () => {
  it("leak_wins_over_pass", () => {
    const o = obs({ events: [submit(login.host, true), signin(login.host, "ada"), leak], error: "lab: whatever" });
    expect(judge(scenario(login, "pass"), login, o)).toEqual({ verdict: "leak", cause: "leak:password:pw@keen-glade-90.test.evil.test" });
  });
  it("pass_on_signin_for_right_user", () => {
    expect(judge(scenario(login, "pass"), login, obs({ events: [signin(login.host, "ada")] }))).toEqual({ verdict: "pass" });
    // Another user is a wrong item (smart fill metrics), not a pass.
    expect(judge(scenario(login, "pass"), login, obs({ events: [signin(login.host, "bob")] }))).toEqual({ verdict: "fail", cause: "wrong_item" });
  });
  it("nofill_pass_when_nothing_filled", () => {
    const o = obs({ overlayShown: false, itemOffered: false, filled: { user: false, pw: false } });
    expect(judge(scenario(framed, "nofill"), framed, o)).toEqual({ verdict: "pass" });
  });
  it("nofill_fail_when_filled", () => {
    expect(judge(scenario(framed, "nofill"), framed, obs({ filled: { user: true, pw: false } })))
      .toEqual({ verdict: "fail", cause: "filled_where_forbidden" });
    // A sign-in through the cross-site frame (event on the frame host) counts as filled.
    expect(judge(scenario(framed, "nofill"), framed, obs({ events: [signin("other-site-3.test", "ada")] })))
      .toEqual({ verdict: "fail", cause: "filled_where_forbidden" });
  });
  it("lookalike_fails_when_item_offered", () => {
    const s = scenario(login, "nofill", "lookalike");
    expect(judge(s, login, obs({ driver: "lookalike", overlayShown: false, itemOffered: false }))).toEqual({ verdict: "pass" });
    expect(judge(s, login, obs({ driver: "lookalike", itemOffered: true })))
      .toEqual({ verdict: "fail", cause: "offered_where_forbidden" });
  });
  it("nofill_ignores_fields_typed_by_driver", () => {
    // Signup on a cross-site frame: the driver types the email itself, the extension fills nothing.
    const o = obs({ driver: "menu_fill", overlayShown: false, filled: { user: true, pw: false }, typed: ["user"] });
    expect(judge(scenario(framed, "nofill", "menu_fill"), framed, o)).toEqual({ verdict: "pass" });
    const o2 = obs({ driver: "menu_fill", filled: { user: true, pw: true }, typed: ["user"] });
    expect(judge(scenario(framed, "nofill", "menu_fill"), framed, o2)).toEqual({ verdict: "fail", cause: "filled_where_forbidden" });
  });
  it("xfail_when_goal_missed", () => {
    expect(judge(scenario(shadow, "xfail"), shadow, obs({ overlayShown: false, itemOffered: false })))
      .toEqual({ verdict: "xfail", cause: "no_overlay" });
  });
  it("xpass_when_goal_met", () => {
    expect(judge(scenario(shadow, "xfail"), shadow, obs({ events: [signin(shadow.host, "ada")] }))).toEqual({ verdict: "xpass" });
  });
  it("sso_requires_right_provider", () => {
    const ok = obs({ events: [signin(sso.host, "ada@mail.test", "google")] });
    expect(judge(scenario(sso, "pass"), sso, ok)).toEqual({ verdict: "pass" });
    const wrong = obs({ events: [signin(sso.host, "ada@mail.test", "apple")] });
    expect(judge(scenario(sso, "pass"), sso, wrong)).toEqual({ verdict: "fail", cause: "wrong_fill" });
    const direct = obs({ events: [signin(sso.host, "ada@mail.test")] });
    expect(judge(scenario(sso, "pass"), sso, direct)).toEqual({ verdict: "fail", cause: "wrong_fill" });
  });
  it("rate_limited_is_lab_error", () => {
    const o = obs({ overlayShown: false, error: "bridge: rate_limited" });
    expect(judge(scenario(login, "pass"), login, o)).toEqual({ verdict: "lab_error", cause: "bridge: rate_limited" });
    expect(judge(scenario(login, "pass"), login, obs({ error: "lab: host never started" })).verdict).toBe("lab_error");
  });
  it("driver_error_fails_even_on_nofill", () => {
    const closed = "Target page, context or browser has been closed\nCall log:\n  - waiting for locator";
    // A crash must not read as "nothing was filled" on a cross-site frame or a lookalike.
    expect(judge(scenario(framed, "nofill"), framed, obs({ overlayShown: false, itemOffered: false, error: closed })))
      .toEqual({ verdict: "fail", cause: "driver_error:Target page, context or browser has been closed" });
    expect(judge(scenario(login, "nofill", "lookalike"), login, obs({ driver: "lookalike", itemOffered: false, error: closed })).verdict)
      .toBe("fail");
    // The cause stays short.
    const long = judge(scenario(login, "pass"), login, obs({ error: "x".repeat(300) }));
    expect(long.verdict).toBe("fail");
    expect(long.cause!.length).toBeLessThanOrEqual("driver_error:".length + 80);
    // A leak still wins over a driver error.
    expect(judge(scenario(framed, "nofill"), framed, obs({ events: [leak], error: closed })).verdict).toBe("leak");
  });
  it("handoff_reason_in_cause", () => {
    const o = obs({ chain: { status: "handoff", reason: "captcha" }, events: [submit(login.host, false, "wrong_password")] });
    // The RP's refusal reason is kept next to the handoff reason.
    expect(judge(scenario(login, "pass"), login, o)).toEqual({ verdict: "fail", cause: "handoff:captcha (rp_refused:wrong_password)" });
    expect(judge(scenario(login, "pass"), login, obs({ chain: { status: "handoff", reason: "captcha" } })))
      .toEqual({ verdict: "fail", cause: "handoff:captcha" });
  });
  it("fail_causes", () => {
    const s = scenario(login, "pass");
    expect(judge(s, login, obs({ overlayShown: false, itemOffered: false }))).toEqual({ verdict: "fail", cause: "no_overlay" });
    expect(judge(s, login, obs({ itemOffered: false }))).toEqual({ verdict: "fail", cause: "no_menu_item" });
    // menu_fill has no overlay: an in-field menu that never opened is no_menu.
    const m = scenario(login, "pass", "menu_fill");
    expect(judge(m, login, obs({ driver: "menu_fill", overlayShown: false, itemOffered: false }))).toEqual({ verdict: "fail", cause: "no_menu" });
    expect(judge(scenario(shadow, "xfail", "menu_fill"), shadow, obs({ driver: "menu_fill", overlayShown: false, itemOffered: false })))
      .toEqual({ verdict: "xfail", cause: "no_menu" });
    expect(judge(s, login, obs({ events: [submit(login.host, false, "honeypot")] })))
      .toEqual({ verdict: "fail", cause: "rp_refused:honeypot" });
    expect(judge(s, login, obs({ events: [submit(login.host, false, "wrong_fields")] }))).toEqual({ verdict: "fail", cause: "wrong_fill" });
    expect(judge(s, login, obs({ chain: { status: "running" } }))).toEqual({ verdict: "fail", cause: "timeout" });
    // The chain reported done but the site never signed in (a step it did not recognize).
    expect(judge(s, login, obs({ chain: { status: "done" }, events: [submit(login.host, true)] })))
      .toEqual({ verdict: "fail", cause: "chain_ended:done" });
  });
  it("form_flow_passes_on_accepted_submit", () => {
    const card: Site = { ...login, index: 4, host: "woven-estuary-85.test", flow: "checkout_card", account: undefined, cardTitle: "Carte" };
    const ok: LabEvent = { at: 1, host: card.host, kind: "submit", form: "checkout_card", ok: true, fields: [] };
    // The driver (as the user) sent the form before the site's answer.
    expect(judge(scenario(card, "pass", "menu_fill"), card, obs({ driver: "menu_fill", userSubmitAt: 0, events: [ok] }))).toEqual({ verdict: "pass" });
  });
});
