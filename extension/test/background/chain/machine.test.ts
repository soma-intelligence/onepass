// The sign-in chain state machine (spec 8.6, 8.7): pure, driven by page
// analyses of the top frame, navigations, load completion and the clock.
import { describe, expect, it } from "vitest";
import type { Summary } from "../../../src/bridge/client";
import {
  type ChainAction,
  type ChainState,
  DEADLINE_MS,
  DONE_SETTLE_MS,
  REPEAT_MS,
  UNKNOWN_MS,
  chainView,
  navigated,
  nextDue,
  parseChainState,
  settled,
  startChain,
  step,
  stopChain,
  tick,
} from "../../../src/background/chain/machine";
import type { FormInfo, PageAnalysis } from "../../../src/shared/messages";

const SITE = "https://atlas-cloud.test";
const GOOGLE = "https://accounts.google.com";
const T0 = 1_000_000;

const summary = (id: string, extra: Partial<Summary> = {}): Summary => ({
  item_id: id,
  vault_id: "v1",
  vault_name: "Personnel",
  title: "Atlas Cloud",
  subtitle: "alex@atlas.dev",
  kind: "login",
  icon_letter: "A",
  icon_color: "#14532D",
  has_password: true,
  has_totp: false,
  methods: [],
  match: "domain",
  ...extra,
});

function page(forms: FormInfo[], extra: Partial<PageAnalysis> = {}, url = `${SITE}/login`): PageAnalysis {
  return { url, forms, captcha: false, push: false, providerButtons: [], accountChooser: [], ...extra };
}

const loginForm = (ref = "f1"): FormInfo => ({
  ref,
  kind: "login",
  fields: [
    { ref: "u1", role: "email" },
    { ref: "p1", role: "current_password" },
  ],
  submitRef: "b1",
});
const userOnly = (ref = "f1"): FormInfo => ({ ref, kind: "login", fields: [{ ref: "u1", role: "username" }] });
const passOnly = (ref = "f2"): FormInfo => ({ ref, kind: "login", fields: [{ ref: "p1", role: "current_password" }] });
const otpForm = (ref = "f3"): FormInfo => ({ ref, kind: "otp", fields: [{ ref: "o1", role: "otp" }] });

const types = (a: ChainAction[]) => a.map((x) => x.type);

function start(item = summary("it_01"), extra: Partial<Parameters<typeof startChain>[0]> = {}): ChainState {
  return startChain({ tabId: 7, item, siteOrigin: SITE, now: T0, ...extra });
}

describe("single page", () => {
  it("fills both fields, submits, then is done back on the site without a form", () => {
    let s = start();
    const r1 = step(s, page([loginForm()]), SITE, T0 + 100);
    expect(r1.actions).toEqual([
      { type: "fill", formRef: "f1", fields: ["username", "password"] },
      { type: "submit", formRef: "f1" },
    ]);
    s = navigated(r1.state, `${SITE}/home`, T0 + 500);
    const r2 = step(s, page([], {}, `${SITE}/home`), SITE, T0 + 700);
    expect(r2.actions).toEqual([]);
    expect(r2.state.status).toBe("running");
    const r3 = tick(r2.state, T0 + 700 + DONE_SETTLE_MS);
    expect(r3.actions).toEqual([{ type: "done" }]);
    expect(r3.state.status).toBe("done");
    const v = chainView(r3.state);
    expect(v.status).toBe("done");
    expect(v.steps.map((x) => x.label)).toEqual(["Identifiant et mot de passe remplis", "Connecté"]);
    expect(v.steps.every((x) => x.state === "done")).toBe(true);
  });

  it("does not act twice on re-analyses of the same page", () => {
    const r1 = step(start(), page([loginForm()]), SITE, T0 + 100);
    const r2 = step(r1.state, page([loginForm()]), SITE, T0 + 300);
    expect(r2.actions).toEqual([]);
    expect(r2.state.status).toBe("running");
  });

  it("a form appearing after a no-form analysis cancels the pending done", () => {
    let s = step(start(), page([loginForm()]), SITE, T0 + 100).state;
    s = navigated(s, `${SITE}/next`, T0 + 200);
    s = step(s, page([], {}, `${SITE}/next`), SITE, T0 + 300).state;
    const r = step(s, page([otpForm()], {}, `${SITE}/next`), SITE, T0 + 600);
    expect(types(r.actions)).toEqual(["stop"]);
    expect(r.state.reason).toBe("otp");
  });
});

describe("several steps with TOTP", () => {
  it("identifier, then password, then the TOTP code, then done", () => {
    let s = start(summary("it_01", { has_totp: true }));
    let r = step(s, page([userOnly()]), SITE, T0 + 100);
    expect(r.actions).toEqual([
      { type: "fill", formRef: "f1", fields: ["username"] },
      { type: "submit", formRef: "f1" },
    ]);
    s = navigated(r.state, `${SITE}/login/password`, T0 + 400);
    r = step(s, page([passOnly()], {}, `${SITE}/login/password`), SITE, T0 + 600);
    expect(r.actions).toEqual([
      { type: "fill", formRef: "f2", fields: ["password"] },
      { type: "submit", formRef: "f2" },
    ]);
    s = navigated(r.state, `${SITE}/login/code`, T0 + 900);
    r = step(s, page([otpForm()], {}, `${SITE}/login/code`), SITE, T0 + 1100);
    expect(r.actions).toEqual([
      { type: "fill", formRef: "f3", fields: ["totp"] },
      { type: "submit", formRef: "f3" },
    ]);
    s = navigated(r.state, `${SITE}/app`, T0 + 1500);
    s = step(s, page([], {}, `${SITE}/app`), SITE, T0 + 1600).state;
    r = tick(s, T0 + 1600 + DONE_SETTLE_MS);
    expect(r.state.status).toBe("done");
    expect(chainView(r.state).steps.map((x) => x.label)).toEqual([
      "Identifiant rempli",
      "Mot de passe rempli",
      "Code à usage unique rempli",
      "Connecté",
    ]);
    expect(chainView(r.state).steps[0]?.detail).toBe("alex@atlas.dev");
  });

  it("a code field without TOTP hands off (otp)", () => {
    const r = step(start(), page([otpForm()]), SITE, T0 + 100);
    expect(r.actions).toEqual([{ type: "stop", reason: "otp" }]);
    expect(r.state.status).toBe("handoff");
  });

  it("an OTP field inside a login form counts as a code step", () => {
    const f: FormInfo = { ref: "f9", kind: "login", fields: [{ ref: "o", role: "otp" }] };
    const r = step(start(summary("it_01", { has_totp: true })), page([f]), SITE, T0 + 100);
    expect(r.actions[0]).toEqual({ type: "fill", formRef: "f9", fields: ["totp"] });
  });
});

describe("provider chain (Google, two accounts)", () => {
  const site = summary("it_02", {
    title: "Atlas Pro",
    has_password: false,
    methods: [{ provider: "google", account_email: "alex.pro@example.com" }],
  });
  const account = summary("g_pro", { title: "Google", subtitle: "alex.pro@example.com", has_totp: true });

  it("clicks the provider button, picks alex.pro among two, fills Google pages, done back on the site", () => {
    let s = start(site, { provider: "google", providerAccount: account });
    const btns = { providerButtons: [{ provider: "google" as const, ref: "g1" }] };
    let r = step(s, page([loginForm()], btns), SITE, T0 + 100);
    expect(r.actions).toEqual([{ type: "click", ref: "g1" }]);

    s = navigated(r.state, `${GOOGLE}/o/oauth2/auth`, T0 + 400);
    const chooser = {
      accountChooser: [
        { email: "alex.perso@example.com", ref: "a1" },
        { email: "Alex.Pro@example.com", ref: "a2" },
      ],
    };
    r = step(s, page([], chooser, `${GOOGLE}/o/oauth2/auth`), GOOGLE, T0 + 600);
    expect(r.actions).toEqual([{ type: "click", ref: "a2" }]);

    // Google moves to the password step without a new document.
    r = step(r.state, page([passOnly("gp")], {}, `${GOOGLE}/signin/pwd`), GOOGLE, T0 + 900);
    expect(r.actions).toEqual([
      { type: "fill_provider", formRef: "gp", fields: ["password"] },
      { type: "submit", formRef: "gp" },
    ]);
    s = navigated(r.state, `${GOOGLE}/signin/challenge`, T0 + 1200);
    r = step(s, page([otpForm("go")], {}, `${GOOGLE}/signin/challenge`), GOOGLE, T0 + 1400);
    expect(r.actions).toEqual([
      { type: "fill_provider", formRef: "go", fields: ["totp"] },
      { type: "submit", formRef: "go" },
    ]);
    s = navigated(r.state, `${SITE}/app`, T0 + 1800);
    s = step(s, page([], {}, `${SITE}/app`), SITE, T0 + 1900).state;
    r = tick(s, T0 + 1900 + DONE_SETTLE_MS);
    expect(r.state.status).toBe("done");
    expect(chainView(r.state).steps.map((x) => x.label)).toEqual([
      "Clic sur « Continuer avec Google »",
      "Compte choisi : alex.pro@example.com",
      "Mot de passe Google rempli",
      "Code Google rempli",
      "Retour sur Atlas Cloud",
    ]);
  });

  it("no chooser entry for the linked email hands off (unknown)", () => {
    let s = start(site, { provider: "google", providerAccount: account });
    s = step(s, page([], { providerButtons: [{ provider: "google", ref: "g1" }] }), SITE, T0 + 100).state;
    s = navigated(s, `${GOOGLE}/chooser`, T0 + 200);
    const r = step(s, page([], { accountChooser: [{ email: "alex.perso@example.com", ref: "a1" }] }), GOOGLE, T0 + 300);
    expect(r.actions).toEqual([{ type: "stop", reason: "unknown" }]);
  });

  it("a look-alike provider host is out of the allowed list (domain)", () => {
    const s = start(site, { provider: "google", providerAccount: account });
    const r = step(s, page([passOnly()]), "https://accounts.google.com.evil.test", T0 + 100);
    expect(r.actions).toEqual([{ type: "stop", reason: "domain" }]);
    expect(chainView(r.state).host).toBe("accounts.google.com.evil.test");
  });

  it("a password chain does not accept the provider hosts", () => {
    const r = step(start(), page([passOnly()]), GOOGLE, T0 + 100);
    expect(r.state.reason).toBe("domain");
  });
});

describe("stop reasons", () => {
  it("domain: another site", () => {
    const r = step(start(), page([loginForm()]), "https://evil.test", T0 + 100);
    expect(r.actions).toEqual([{ type: "stop", reason: "domain" }]);
    expect(r.state.host).toBe("evil.test");
  });

  it("domain: a top frame commit outside the list stops at once", () => {
    const s = navigated(step(start(), page([loginForm()]), SITE, T0 + 100).state, "https://evil.test/phish", T0 + 300);
    expect(s.status).toBe("handoff");
    expect(chainView(s)).toMatchObject({ reason: "domain", host: "evil.test" });
    expect(navigated(start(), `${GOOGLE}/x`, T0 + 1).status).toBe("handoff");
    expect(navigated(start(), `${SITE}/next`, T0 + 1).status).toBe("running");
  });

  it("domain: plain HTTP on the same site", () => {
    const r = step(start(), page([loginForm()]), "http://atlas-cloud.test", T0 + 100);
    expect(r.state.reason).toBe("domain");
  });

  it("a subdomain of the site is allowed", () => {
    const r = step(start(), page([loginForm()]), "https://auth.atlas-cloud.test", T0 + 100);
    expect(types(r.actions)).toEqual(["fill", "submit"]);
  });

  it("captcha", () => {
    const r = step(start(), page([loginForm()], { captcha: true }), SITE, T0 + 100);
    expect(r.actions).toEqual([{ type: "stop", reason: "captcha" }]);
    expect(chainView(r.state).steps.at(-1)).toMatchObject({ label: "CAPTCHA détecté", state: "stopped" });
  });

  it("push", () => {
    const r = step(start(), page([], { push: true }), SITE, T0 + 100);
    expect(r.actions).toEqual([{ type: "stop", reason: "push" }]);
  });

  it("otp", () => {
    expect(step(start(), page([otpForm()]), SITE, T0 + 100).state.reason).toBe("otp");
  });

  it("unknown: no recognized field 4 s after the page settled", () => {
    let s = navigated(start(), `${SITE}/next`, T0 + 50);
    s = step(s, page([]), SITE, T0 + 100).state;
    s = settled(s, T0 + 200);
    expect(tick(s, T0 + 200 + UNKNOWN_MS - 1).actions).toEqual([]);
    const r = tick(s, T0 + 200 + UNKNOWN_MS);
    expect(r.actions).toEqual([{ type: "stop", reason: "unknown" }]);
  });

  it("unknown waits for the load to complete", () => {
    const s = step(navigated(start(), `${SITE}/next`, T0 + 50), page([]), SITE, T0 + 100).state;
    expect(tick(s, T0 + 100 + UNKNOWN_MS * 2).actions).toEqual([]);
  });

  it("the start page is loaded already: unknown 4 s after the click", () => {
    expect(tick(start(), T0 + UNKNOWN_MS).actions).toEqual([{ type: "stop", reason: "unknown" }]);
  });

  it("timeout after 60 s", () => {
    // Submitted, then a new page that never finishes loading.
    const s = navigated(step(start(), page([loginForm()]), SITE, T0 + 100).state, `${SITE}/slow`, T0 + 200);
    expect(tick(s, T0 + DEADLINE_MS - 1).state.status).toBe("running");
    const r = tick(s, T0 + DEADLINE_MS);
    expect(r.actions).toEqual([{ type: "stop", reason: "timeout" }]);
    // An analysis past the deadline stops as well, without acting.
    const r2 = step(s, page([passOnly()]), SITE, T0 + DEADLINE_MS + 5);
    expect(r2.actions).toEqual([{ type: "stop", reason: "timeout" }]);
  });

  it("user", () => {
    const s = stopChain(start(), "user", T0 + 10);
    expect(s.status).toBe("stopped");
    expect(chainView(s)).toMatchObject({ status: "stopped", reason: "user" });
    expect(step(s, page([loginForm()]), SITE, T0 + 20).actions).toEqual([]);
  });

  it("locked", () => {
    const s = stopChain(start(), "locked", T0 + 10);
    expect(chainView(s)).toMatchObject({ status: "handoff", reason: "locked" });
  });

  it("repeat: a submitted form still there 8 s later, same document", () => {
    const s = step(start(), page([loginForm()]), SITE, T0 + 100).state;
    const again = step(s, page([loginForm()]), SITE, T0 + 2000).state;
    expect(tick(again, T0 + 100 + REPEAT_MS - 1).actions).toEqual([]);
    expect(tick(again, T0 + 100 + REPEAT_MS).actions).toEqual([{ type: "stop", reason: "repeat" }]);
  });

  it("repeat: the same step again after a navigation (password refused)", () => {
    let s = step(start(), page([loginForm()]), SITE, T0 + 100).state;
    s = navigated(s, `${SITE}/login?error=1`, T0 + 500);
    const r = step(s, page([loginForm()], {}, `${SITE}/login?error=1`), SITE, T0 + 700);
    expect(r.actions).toEqual([{ type: "stop", reason: "repeat" }]);
  });
});

describe("auto-submit off", () => {
  it("fills without submitting", () => {
    const r = step(start(summary("it_01"), { autoSubmit: false }), page([loginForm()]), SITE, T0 + 100);
    expect(r.actions).toEqual([{ type: "fill", formRef: "f1", fields: ["username", "password"] }]);
  });
});

describe("resume from serialized state", () => {
  it("a JSON round trip does not submit the same page again", () => {
    const r1 = step(start(), page([loginForm()]), SITE, T0 + 100);
    const revived = parseChainState(JSON.parse(JSON.stringify(r1.state)));
    expect(revived).not.toBeNull();
    const r2 = step(revived!, page([loginForm()]), SITE, T0 + 2000);
    expect(r2.actions).toEqual([]);
    // And the next page still works.
    const s = navigated(r2.state, `${SITE}/home`, T0 + 2500);
    expect(step(s, page([], {}, `${SITE}/home`), SITE, T0 + 2600).state.status).toBe("running");
  });

  it("rejects malformed states", () => {
    expect(parseChainState(null)).toBeNull();
    expect(parseChainState({ v: 1, tabId: "7" })).toBeNull();
    const ok = JSON.parse(JSON.stringify(start()));
    expect(parseChainState({ ...ok, status: "weird" })).toBeNull();
    expect(parseChainState({ ...ok, steps: [{}] })).toBeNull();
  });

  it("holds no secret: only ids, labels, hosts and times", () => {
    const s = step(start(), page([loginForm()]), SITE, T0 + 100).state;
    const json = JSON.stringify(s);
    expect(json).not.toMatch(/password"\s*:\s*"[^"]/);
  });
});

describe("timers", () => {
  it("nextDue: deadline while a page loads, unknown delay when idle and settled", () => {
    let s = navigated(start(), `${SITE}/next`, T0 + 50);
    expect(nextDue(s)).toBe(T0 + DEADLINE_MS);
    s = settled(step(s, page([]), SITE, T0 + 100).state, T0 + 200);
    expect(nextDue(s)).toBe(T0 + 200 + UNKNOWN_MS);
    expect(nextDue(stopChain(s, "user", T0 + 300))).toBeNull();
  });
});
