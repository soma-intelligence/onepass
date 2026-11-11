// @vitest-environment node
// Gesture accounting of the lab: every human-equivalent gesture is counted
// (the user's own press on the site's submit button included), the unlock
// approval apart as a biometric, and "one gesture, signed in" needs the
// session the oracle saw plus exactly one deliberate gesture.
import { describe, expect, it } from "vitest";
import type { Scenario, Site } from "../../lab/gen/model.ts";
import { biometricCount, flowFamily, gestureCount, gestureFields, Gestures, insertApprovals, triggerOf } from "../../lab/run/gestures.ts";
import { judge, type Observation, oneClickOf, resultGestures, signedInOf } from "../../lab/run/oracle.ts";
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
const card: Site = { ...login, index: 1, host: "opal-kettle-14.test", flow: "checkout_card", account: undefined, cardTitle: "Carte Opal" };
const scenario = (site: Site, driver: Scenario["driver"], over: Partial<Scenario> = {}): Scenario =>
  ({ id: `${site.index}:${driver}`, site: site.index, driver, expect: "pass", ...over });
const signin = (user: string): LabEvent => ({ at: 5, host: login.host, kind: "signin", user });
function obs(over: Partial<Observation> = {}): Observation {
  return { driver: "smart_fill", overlayShown: true, itemOffered: true, events: [], filled: {}, durationMs: 10, ...over };
}
function played(...kinds: Parameters<Gestures["add"]>[0][]): Gestures {
  let t = 0;
  const g = new Gestures(() => ++t);
  for (const k of kinds) g.add(k);
  return g;
}

describe("gesture counting", () => {
  it("counts_every_deliberate_gesture_and_the_biometric_apart", () => {
    const g = played("field_icon", "unlock_button", "unlock_approval", "menu_row", "site_submit");
    expect(gestureCount(g.list)).toBe(4);
    expect(biometricCount(g.list)).toBe(1);
    expect(g.list.map((x) => x.at)).toEqual([1, 2, 3, 4, 5]);
  });
  it("stores_kinds_only_never_a_target", () => {
    const g = new Gestures(() => 7);
    g.add("site_type", "email");
    expect(g.list).toEqual([{ kind: "site_type", target: "email", at: 7 }]);
    expect(gestureFields(g.list, undefined, "unlocked_warm", "field_icon")).toEqual(
      { gestures: 1, gestureList: ["site_type"], biometric: 0, startState: "unlocked_warm", trigger: "field_icon" });
  });
  it("an_approval_sits_after_the_gesture_it_answers", () => {
    const kinds = (g: Gestures) => g.list.map((x) => x.kind);
    // No unlock button pressed: the gesture that started OnePass asked for the unlock.
    const typedFirst = played("site_type", "field_icon", "site_submit");
    insertApprovals(typedFirst.list, 1, 9);
    expect(kinds(typedFirst)).toEqual(["site_type", "field_icon", "unlock_approval", "site_submit"]);
    const button = played("site_type", "menu_key", "unlock_button", "site_submit");
    insertApprovals(button.list, 1, 9);
    expect(kinds(button)).toEqual(["site_type", "menu_key", "unlock_button", "unlock_approval", "site_submit"]);
    // An unlock nobody asked: first, before anything the user did.
    const none = played("site_submit");
    insertApprovals(none.list, 1, 9);
    expect(kinds(none)).toEqual(["unlock_approval", "site_submit"]);
    insertApprovals(none.list, 0, 9);
    expect(none.list).toHaveLength(2);
  });
  it("trigger_follows_the_driver", () => {
    expect(triggerOf("one_click")).toBe("overlay_row");
    expect(triggerOf("menu_fill")).toBe("menu_key");
    expect(triggerOf("smart_fill")).toBe("field_icon");
    expect(triggerOf("smart_fill", { hasField: false })).toBe("toolbar");
    expect(triggerOf("smart_fill", { shortcut: true })).toBe("shortcut");
    expect(triggerOf("lookalike")).toBeUndefined();
  });
  it("families_cover_the_session_flows_only", () => {
    expect(flowFamily("login_username_first")).toBe("password");
    expect(flowFamily("sso")).toBe("sso");
    expect(flowFamily("signup")).toBe("signup");
    expect(flowFamily("checkout_card")).toBeUndefined();
  });
});

describe("one gesture, signed in", () => {
  it("one_gesture_and_a_session_is_the_headline", () => {
    const s = scenario(login, "smart_fill");
    const o = obs({ events: [signin("ada")], gestures: played("field_icon").list, clicks: 1 });
    const j = judge(s, login, o);
    expect(j.verdict).toBe("pass");
    expect(resultGestures(s, login, j.verdict, o)).toMatchObject({ gestures: 1, biometric: 0, signedIn: true, oneGesture: true, trigger: "field_icon" });
  });
  it("the_users_own_submit_makes_it_two", () => {
    // Fill, then the user presses the site's button: the old metric counted one click.
    const s = scenario(login, "smart_fill");
    const o = obs({ events: [signin("ada")], gestures: played("field_icon", "site_submit").list, clicks: 1 });
    const j = judge(s, login, o);
    expect(oneClickOf(s, j.verdict, o)).toBe(true);
    expect(resultGestures(s, login, j.verdict, o)).toMatchObject({ gestures: 2, gestureList: ["field_icon", "site_submit"], signedIn: true, oneGesture: false });
  });
  it("a_picker_choice_makes_it_two", () => {
    const s = scenario(login, "one_click");
    const o = obs({ driver: "one_click", events: [signin("ada")], gestures: played("picker_open", "picker").list });
    expect(resultGestures(s, login, "pass", o)).toMatchObject({ gestures: 2, oneGesture: false, trigger: "overlay_row" });
  });
  it("the_unlock_approval_is_plus_one_biometric_not_a_gesture", () => {
    const s = scenario(login, "smart_fill", { start: "locked" });
    const o = obs({ events: [signin("ada")], gestures: played("field_icon", "unlock_approval").list });
    expect(resultGestures(s, login, "pass", o)).toMatchObject({ gestures: 1, biometric: 1, signedIn: true, oneGesture: true, startState: "locked" });
  });
  it("no_session_no_headline", () => {
    const s = scenario(login, "smart_fill");
    const o = obs({ gestures: played("field_icon").list });
    const j = judge(s, login, o);
    expect(j.verdict).toBe("fail");
    expect(resultGestures(s, login, j.verdict, o)).toMatchObject({ gestures: 1, signedIn: false, oneGesture: false });
  });
  it("a_form_flow_has_no_session_to_see", () => {
    const s = scenario(card, "smart_fill");
    const o = obs({ gestures: played("field_icon", "site_submit").list });
    const r = resultGestures(s, card, "pass", o);
    expect(r.gestures).toBe(2);
    expect(r.signedIn).toBeUndefined();
    expect(r.oneGesture).toBeUndefined();
  });
  it("no_goal_no_measure", () => {
    expect(signedInOf(scenario(login, "smart_fill", { expect: "nofill" }), login, "pass", obs({ events: [signin("ada")] }))).toBeUndefined();
    expect(signedInOf(scenario(login, "smart_fill"), login, "lab_error", obs())).toBeUndefined();
    expect(signedInOf(scenario(login, "smart_fill"), login, "skipped", obs())).toBeUndefined();
    expect(signedInOf(scenario(login, "lookalike"), login, "pass", obs())).toBeUndefined();
  });
  it("a_session_seen_on_a_failed_verdict_does_not_count", () => {
    // A leak with a session is no success.
    expect(signedInOf(scenario(login, "smart_fill"), login, "leak", obs({ events: [signin("ada")] }))).toBe(false);
  });
});

describe("account profiles and skips in the oracle", () => {
  const second = { title: "Keen Glade (2)", username: "bob", outcome: "stated" };
  it("the_scenarios_account_is_the_one_that_must_sign_in", () => {
    const s = scenario(login, "smart_fill", { profile: "p2", account: second });
    expect(judge(s, login, obs({ events: [signin("bob")] }))).toEqual({ verdict: "pass" });
    expect(judge(s, login, obs({ events: [signin("ada")] }))).toEqual({ verdict: "fail", cause: "wrong_item" });
  });
  it("the_other_account_filled_is_a_wrong_account", () => {
    const s = scenario(login, "smart_fill", { profile: "p1", account: { title: "Keen Glade", username: "ada", outcome: "stated" } });
    const refused: LabEvent = { at: 2, host: login.host, kind: "submit", form: "login_single", ok: false, fields: ["user"], reason: "unknown_user" };
    expect(judge(s, login, obs({ events: [refused], otherAccount: true }))).toEqual({ verdict: "fail", cause: "wrong_account" });
  });
  it("a_missing_host_control_is_skipped_not_failed", () => {
    const s = scenario(login, "smart_fill", { start: "locked" });
    const j = judge(s, login, obs({ skipped: "host lacks control stop" }));
    expect(j).toEqual({ verdict: "skipped", cause: "host lacks control stop" });
    expect(oneClickOf(s, j.verdict, obs())).toBeUndefined();
  });
});
