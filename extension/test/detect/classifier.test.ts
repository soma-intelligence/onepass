// Pluggable field classifier (Task 15): the model proposes roles, the safety rules run after it
// and before the existing logic, and nothing a model says can make a refused field fillable.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  applySafetyRules,
  classifierFor,
  createModelHook,
  type FieldClassifier,
  heuristicClassifier,
  type ModelSessionLike,
  remoteSession,
  roleFitsControl,
  signupContext,
  toFieldRole,
  TransientRefusal,
} from "../../src/content/detect/classifier";
import { extractFeatures, type FieldFeatures } from "../../src/content/detect/features";
import { classifyField, type FieldElement, isFieldCandidate } from "../../src/content/detect/fields";
import { PASSWORD_TYPE_ROLES, type ScoredRole } from "../../src/content/detect/lexicon";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import type { FieldRole, PageAnalysis } from "../../src/shared/messages";
import { MODEL_LABELS, MODEL_ROLES, type ModelLabel } from "../../src/shared/model-labels";
import type { Role } from "../../lab/gen/model";
import { testGeometry } from "./helpers";

const root = join(__dirname, "..", "..");

/** Every FieldRole of messages.ts (kept in sync by the router's FIELD_ROLES test). */
const FIELD_ROLES: readonly FieldRole[] = [
  "username", "email", "current_password", "new_password", "confirm_password", "otp", "cc_name", "cc_number",
  "cc_exp", "cc_exp_month", "cc_exp_year", "cc_csc", "given_name", "family_name", "full_name", "tel",
  "organization", "bday", "address_line1", "address_line2", "city", "postal_code", "region", "country",
  "remember_me", "unknown",
];

const HONEYPOT_HTML = `<form action="/login">
  <input id="trap" name="password2" type="password" style="display:none">
  <input id="email" name="email" type="email" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button type="submit">Sign in</button>
</form>`;

function load(html: string): Document {
  document.documentElement.innerHTML = `<head><title>Sign in</title></head><body>${html}</body>`;
  return document;
}

function fieldsOf(html: string): FieldElement[] {
  return Array.from(load(html).querySelectorAll("input, select, textarea")).filter(isFieldCandidate);
}

/** jsdom has no layout: extractFeatures would read every field as zero_size. */
function withLayout(): void {
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (this: HTMLElement) {
    return { x: 0, y: 0, left: 0, top: 0, right: 200, bottom: 30, width: 200, height: 30, toJSON: () => ({}) } as DOMRect;
  });
}

afterEach(() => vi.restoreAllMocks());

describe("model labels", () => {
  it("are the lab Role list plus none, in the order of lab/gen/model.ts and ml/onepass_ml/labels.py", () => {
    const src = readFileSync(join(root, "lab/gen/model.ts"), "utf8");
    const roleType = /export type Role =([^;]+);/.exec(src)![1]!;
    const lab = Array.from(roleType.matchAll(/"([a-z_0-9]+)"/g), (m) => m[1]);
    expect(MODEL_ROLES).toEqual(lab);
    const py = readFileSync(join(root, "..", "ml/onepass_ml/labels.py"), "utf8");
    const roles = /ROLES = \(([^)]+)\)/.exec(py)![1]!;
    expect([...Array.from(roles.matchAll(/"([a-z_0-9]+)"/g), (m) => m[1]), "none"]).toEqual([...MODEL_LABELS]);
    // Type level: every model role is a lab Role and back.
    const asRole: readonly Role[] = MODEL_ROLES;
    expect(asRole.length).toBe(21);
  });
});

describe("toFieldRole", () => {
  it("toFieldRole maps password by form kind", () => {
    expect(toFieldRole("password", { signup: true })).toBe("new_password");
    expect(toFieldRole("password", { signup: false })).toBe("current_password");
  });

  it("maps every label to an existing FieldRole, none to unknown, in both contexts", () => {
    for (const signup of [true, false]) {
      for (const l of MODEL_LABELS) {
        const r = toFieldRole(l, { signup });
        expect(FIELD_ROLES, `${l} -> ${r}`).toContain(r);
        if (l === "none") expect(r).toBe("unknown");
        else expect(r).not.toBe("unknown");
      }
    }
    expect(toFieldRole("birth_date", { signup: false })).toBe("bday");
    expect(toFieldRole("new_password", { signup: false })).toBe("new_password");
    expect(toFieldRole("cc_csc", { signup: true })).toBe("cc_csc");
  });

  it("an unexpected label is unknown", () => {
    expect(toFieldRole("remember_me" as ModelLabel, { signup: false })).toBe("unknown");
    expect(toFieldRole("__proto__" as ModelLabel, { signup: false })).toBe("unknown");
  });

  it("signup context: an identifier and two password fields, one of them new", () => {
    expect(signupContext(["email", "new_password", "new_password"])).toBe(true);
    expect(signupContext(["username", "password", "new_password"])).toBe(true);
    // A change form keeps its current password, with or without an identifier (e2e change-password page).
    expect(signupContext(["password", "new_password", "new_password"])).toBe(false);
    expect(signupContext(["email", "password", "new_password", "new_password"])).toBe(false);
    // A login.
    expect(signupContext(["email", "password"])).toBe(false);
    expect(signupContext(["email", "password", "password"])).toBe(false);
  });
});

describe("applySafetyRules", () => {
  it("model saying password on a hidden honeypot fills nothing", async () => {
    const roles = applySafetyRules(fieldsOf(HONEYPOT_HTML), [{ role: "current_password", score: 0.99 }], { crossSite: false });
    expect(roles[0]!.role).toBe("unknown");
  });

  it("cross-site iframe fields stay unknown whatever the model says", () => {
    const fields = fieldsOf(HONEYPOT_HTML).slice(1);
    const said = [{ role: "email" as FieldRole, score: 0.99 }, { role: "current_password" as FieldRole, score: 0.99 }];
    expect(applySafetyRules(fields, said, { crossSite: false }, { geometry: testGeometry }).map((r) => r.role)).toEqual(["email", "current_password"]);
    expect(applySafetyRules(fields, said, { crossSite: true }, { geometry: testGeometry }).map((r) => r.role)).toEqual(["unknown", "unknown"]);
  });

  it("forces unknown on every non-visible feature visibility, even when the DOM check passes", () => {
    const fields = fieldsOf(`<form><input id="a" type="password"></form>`);
    for (const v of ["display_none", "offscreen", "opacity", "zero_size"] as const) {
      const f = { visibility: v } as FieldFeatures;
      const out = applySafetyRules(fields, [{ role: "current_password", score: 1 }], { crossSite: false }, { geometry: testGeometry, features: [f] });
      expect(out[0]!.role, v).toBe("unknown");
    }
    const ok = applySafetyRules(fields, [{ role: "current_password", score: 1 }], { crossSite: false }, { geometry: testGeometry, features: [{ visibility: "visible" } as FieldFeatures] });
    expect(ok[0]!.role).toBe("current_password");
  });

  it("never turns an unknown into something else, and a missing role is unknown", () => {
    const fields = fieldsOf(`<form><input id="a"><input id="b"></form>`);
    const out = applySafetyRules(fields, [{ role: "unknown", score: 0.99 }], { crossSite: false }, { geometry: testGeometry });
    expect(out.map((r) => r.role)).toEqual(["unknown", "unknown"]);
  });

  it("forces unknown on disabled, read-only and aria-hidden fields (existing visibility check)", () => {
    const fields = fieldsOf(`<form><input id="a" disabled><input id="b" readonly><div aria-hidden="true"><input id="c"></div></form>`);
    const said = fields.map(() => ({ role: "email" as FieldRole, score: 1 }));
    expect(applySafetyRules(fields, said, { crossSite: false }, { geometry: testGeometry }).map((r) => r.role)).toEqual(["unknown", "unknown", "unknown"]);
  });
});

describe("applySafetyRules: control type (final review I1)", () => {
  const ROLE_CASES = `<form>
    <input id="text" name="display">
    <textarea id="area" name="bio"></textarea>
    <input id="pw" name="secret" type="password">
    <input id="mail" name="contact" type="email">
    <select id="sel" name="choice"><option>a</option></select>
    <input id="tel" name="phone" type="tel">
  </form>`;
  const byId = (fields: FieldElement[], id: string) => fields.find((f) => f.id === id)!;
  const one = (el: FieldElement, role: FieldRole) =>
    applySafetyRules([el], [{ role, score: 0.99 }], { crossSite: false }, { geometry: testGeometry })[0]!;

  it.each(["current_password", "new_password", "confirm_password"] as const)("%s from the model never lands on a text input or a textarea", (role) => {
    const fields = fieldsOf(ROLE_CASES);
    for (const id of ["text", "area", "mail", "sel", "tel"]) {
      const el = byId(fields, id);
      const out = one(el, role);
      expect(out.role, id).not.toBe(role);
      expect(out, id).toEqual(classifyField(el));
    }
    expect(one(byId(fields, "pw"), role).role).toBe(role);
  });

  it("a password input takes only the roles the heuristic allows there (PASSWORD_TYPE_ROLES)", () => {
    const pw = byId(fieldsOf(ROLE_CASES), "pw");
    for (const role of FIELD_ROLES) {
      if (role === "unknown") continue;
      const out = one(pw, role);
      if (PASSWORD_TYPE_ROLES.has(role as ScoredRole)) expect(out.role, role).toBe(role);
      else expect(out, role).toEqual(classifyField(pw));
    }
    expect(one(pw, "email").role).not.toBe("email");
    expect(one(pw, "cc_number").role).not.toBe("cc_number");
  });

  it("card number, card security code and one-time code only on text-entry inputs", () => {
    const fields = fieldsOf(ROLE_CASES);
    for (const role of ["cc_number", "cc_csc", "otp"] as const) {
      for (const id of ["text", "tel"]) expect(one(byId(fields, id), role).role, `${role} ${id}`).toBe(role);
      for (const id of ["area", "sel", "mail"]) {
        const el = byId(fields, id);
        expect(one(el, role), `${role} ${id}`).toEqual(classifyField(el));
      }
    }
    expect(one(byId(fields, "pw"), "otp").role).toBe("otp");
  });

  it("an incompatible model role falls back to the field's heuristic role", () => {
    const fields = fieldsOf(`<form><input id="u" name="username"><input id="p" name="password" type="password"></form>`);
    const out = applySafetyRules(fields, [{ role: "current_password", score: 0.99 }, { role: "email", score: 0.99 }], { crossSite: false }, { geometry: testGeometry });
    expect(out.map((r) => r.role)).toEqual(["username", "current_password"]);
  });

  it("roles the control holds pass unchanged", () => {
    const fields = fieldsOf(ROLE_CASES);
    expect(one(byId(fields, "mail"), "email").role).toBe("email");
    expect(one(byId(fields, "sel"), "country").role).toBe("country");
    expect(one(byId(fields, "area"), "address_line1").role).toBe("address_line1");
    expect(roleFitsControl(byId(fields, "text"), "username")).toBe(true);
    expect(roleFitsControl(byId(fields, "text"), "current_password")).toBe(false);
  });
});

function fakeSession(kind: "gbm" | "encoder", labelOf: (f: FieldFeatures) => ModelLabel): ModelSessionLike {
  return { kind, predict: async (fs) => fs.map((f) => ({ label: labelOf(f), score: 0.9 })) };
}

describe("classifierFor", () => {
  it("missing or incompatible model falls back to heuristics", async () => {
    const c = await classifierFor("gbm", { load: async () => null });
    expect(c.kind).toBe("heuristic");
  });

  it("a load that throws, or a session of another kind, also falls back", async () => {
    expect((await classifierFor("gbm", { load: async () => { throw new Error("boom"); } })).kind).toBe("heuristic");
    expect((await classifierFor("gbm", { load: async () => fakeSession("encoder", () => "none") })).kind).toBe("heuristic");
    expect((await classifierFor("heuristic", { load: async () => fakeSession("gbm", () => "none") })).kind).toBe("heuristic");
  });

  it("maps model labels per form, password by signup context", async () => {
    const c = await classifierFor("encoder", { load: async () => fakeSession("encoder", (f) => (f.type === "password" ? "password" : "email")) });
    expect(c.kind).toBe("encoder");
    const out = await c.classify([], [{ type: "email" } as FieldFeatures, { type: "password" } as FieldFeatures]);
    expect(out.map((r) => r.role)).toEqual(["email", "current_password"]);
  });

  it("a session answering the wrong number of rows is refused for that form", async () => {
    const c = await classifierFor("gbm", { load: async () => ({ kind: "gbm", predict: async () => [] }) });
    await expect(c.classify([], [{ type: "email" } as FieldFeatures])).rejects.toThrow();
  });

  it("the heuristic classifier is today's classifyField", async () => {
    const fields = fieldsOf(HONEYPOT_HTML).slice(1);
    // autocomplete="username" decides the first field.
    expect((await heuristicClassifier.classify(fields, [])).map((r) => r.role)).toEqual(["username", "current_password"]);
  });
});

describe("remoteSession", () => {
  it("handshake: no model, an error or a cross-site frame give no session", async () => {
    expect(await remoteSession(async () => null, "gbm")).toBeNull();
    expect(await remoteSession(async () => ({ err: "invalid" }), "gbm")).toBeNull();
    expect(await remoteSession(async () => ({ ok: { kind: "gbm", crossSite: true } }), "gbm")).toBeNull();
    expect(await remoteSession(async () => ({ ok: { kind: "encoder", crossSite: false } }), "gbm")).toBeNull();
    expect(await remoteSession(async () => ({ ok: null }), "gbm")).toBeNull();
  });

  it("sends features only (no lab mark, no geometry, no page title), capped, and reads labels back", async () => {
    const sent: unknown[] = [];
    const s = await remoteSession(async (m) => {
      sent.push(m);
      const fields = (m as { fields: unknown[] }).fields;
      if (!fields.length) return { ok: { kind: "gbm", crossSite: false } };
      return { ok: { kind: "gbm", crossSite: false, labels: fields.map(() => ({ label: "email", score: 0.5 })) } };
    }, "gbm");
    expect(s).not.toBeNull();
    const f = { index: 0, tag: "input", name: "x".repeat(5000), lab: "3", width: 10, height: 10, pageTitle: "t", visibility: "visible" } as FieldFeatures;
    expect(await s!.predict([f])).toEqual([{ label: "email", score: 0.5 }]);
    const wire = (sent[1] as { type: string; fields: FieldFeatures[] });
    expect(wire.type).toBe("classify");
    expect(wire.fields[0]!.lab).toBeUndefined();
    expect(wire.fields[0]!.pageTitle).toBeUndefined();
    expect(wire.fields[0]!.width).toBe(0);
    expect(Array.from(wire.fields[0]!.name!).length).toBe(1024);
  });

  it("a reply with an unknown label, a bad score or a wrong length rejects", async () => {
    for (const labels of [[{ label: "admin", score: 1 }], [{ label: "email", score: "1" }], []]) {
      const s = await remoteSession(async (m) => {
        const fields = (m as { fields: unknown[] }).fields;
        return { ok: fields.length ? { kind: "gbm", crossSite: false, labels } : { kind: "gbm", crossSite: false } };
      }, "gbm");
      await expect(s!.predict([{ tag: "input" } as FieldFeatures])).rejects.toThrow();
    }
  });
});

describe("remoteSession refusals (final review M5)", () => {
  const sessionReplying = (reply: Record<string, unknown>) =>
    remoteSession(async (m) => {
      const fields = (m as { fields: unknown[] }).fields;
      return { ok: fields.length ? { kind: "gbm", crossSite: false, ...reply } : { kind: "gbm", crossSite: false } };
    }, "gbm");

  it("busy and rate are transient refusals; budget is a plain (definitive) failure", async () => {
    for (const refused of ["busy", "rate"]) {
      const s = await sessionReplying({ refused });
      await expect(s!.predict([{ tag: "input" } as FieldFeatures])).rejects.toBeInstanceOf(TransientRefusal);
    }
    const s = await sessionReplying({ refused: "budget" });
    const e = await s!.predict([{ tag: "input" } as FieldFeatures]).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(Error);
    expect(e).not.toBeInstanceOf(TransientRefusal);
  });
});

describe("createModelHook: only definitive answers are cached (final review M5)", () => {
  it("a busy or rate refusal is not cached: the form is asked again after the retry pause, then answered", async () => {
    for (const refused of ["busy", "rate"]) {
      const timers: { cb: () => void; ms: number }[] = [];
      let calls = 0;
      const classifier: FieldClassifier = {
        kind: "gbm",
        classify: async (_e, fs) => {
          calls++;
          if (calls === 1) throw new TransientRefusal(refused);
          return fs.map(() => ({ role: "email" as FieldRole, score: 1 }));
        },
      };
      const updated = vi.fn();
      const hook = createModelHook({ classifier, onUpdate: updated, debounceMs: 5, retryMs: 700, setTimer: (cb, ms) => timers.push({ cb, ms }) });
      const form = [{ tag: "input", name: "a" } as FieldFeatures];
      expect(hook.lookup(form)).toBeNull();
      expect(timers.map((t) => t.ms)).toEqual([5]);
      timers.shift()!.cb();
      await vi.waitFor(() => expect(updated).toHaveBeenCalledTimes(1));
      // Not cached: the next analysis asks again, after the retry pause rather than the debounce.
      expect(hook.lookup(form)).toBeNull();
      expect(timers.map((t) => t.ms)).toEqual([700]);
      timers.shift()!.cb();
      await vi.waitFor(() => expect(updated).toHaveBeenCalledTimes(2));
      expect(calls).toBe(2);
      expect(hook.lookup(form)).toEqual([{ role: "email", score: 1 }]);
      // Back to the debounce for the next new form.
      hook.lookup([{ tag: "input", name: "b" } as FieldFeatures]);
      expect(timers.map((t) => t.ms)).toEqual([5]);
    }
  });

  it("a budget refusal (or any other failure) is cached: heuristics, never asked again", async () => {
    let calls = 0;
    const s = await remoteSession(async (m) => {
      const fields = (m as { fields: unknown[] }).fields;
      if (fields.length) calls++;
      return { ok: fields.length ? { kind: "gbm", crossSite: false, refused: "budget" } : { kind: "gbm", crossSite: false } };
    }, "gbm");
    const classifier = await classifierFor("gbm", { load: async () => s });
    const updated = vi.fn();
    const hook = createModelHook({ classifier, onUpdate: updated, debounceMs: 0 });
    const form = [{ tag: "input", name: "a" } as FieldFeatures];
    hook.lookup(form);
    await vi.waitFor(() => expect(updated).toHaveBeenCalledTimes(1));
    expect(hook.lookup(form)).toBeNull();
    await new Promise((r) => setTimeout(r, 10));
    expect(calls).toBe(1);
  });
});

describe("createModelHook", () => {
  it("answers from its cache only, asks once per form, then reports an update", async () => {
    let calls = 0;
    const classifier: FieldClassifier = { kind: "gbm", classify: async (_e, fs) => (calls++, fs.map(() => ({ role: "email", score: 1 }))) };
    const updated = vi.fn();
    const hook = createModelHook({ classifier, onUpdate: updated, debounceMs: 0 });
    const form = [{ tag: "input", name: "a" } as FieldFeatures];
    expect(hook.lookup(form)).toBeNull();
    expect(hook.lookup(form)).toBeNull();
    await vi.waitFor(() => expect(updated).toHaveBeenCalledTimes(1));
    expect(calls).toBe(1);
    expect(hook.lookup(form)).toEqual([{ role: "email", score: 1 }]);
  });

  it("a failed form stays on heuristics and is not asked again", async () => {
    let calls = 0;
    const classifier: FieldClassifier = { kind: "gbm", classify: async () => { calls++; throw new Error("no"); } };
    const hook = createModelHook({ classifier, onUpdate: () => {}, debounceMs: 0 });
    const form = [{ tag: "input", name: "a" } as FieldFeatures];
    hook.lookup(form);
    await new Promise((r) => setTimeout(r, 10));
    expect(hook.lookup(form)).toBeNull();
    expect(calls).toBe(1);
  });

  it("the lab mark is not part of the cache key", async () => {
    const classifier: FieldClassifier = { kind: "gbm", classify: async (_e, fs) => fs.map(() => ({ role: "email", score: 1 })) };
    const hook = createModelHook({ classifier, onUpdate: () => {}, debounceMs: 0 });
    hook.lookup([{ tag: "input", name: "a" } as FieldFeatures]);
    await new Promise((r) => setTimeout(r, 10));
    expect(hook.lookup([{ tag: "input", name: "a", lab: "9" } as FieldFeatures])).toEqual([{ role: "email", score: 1 }]);
  });
});

describe("createModelHook under a mutating page (I2)", () => {
  it("a burst of 50 new forms sends one request after the debounce, the latest only; at most one in flight", async () => {
    const timers: (() => void)[] = [];
    const asked: string[] = [];
    let inFlight = 0;
    let maxInFlight = 0;
    let release: (() => void) | null = null;
    const classifier: FieldClassifier = {
      kind: "gbm",
      classify: (_e, fs) => {
        asked.push(fs[0]!.name!);
        maxInFlight = Math.max(maxInFlight, ++inFlight);
        return new Promise((r) => {
          release = () => {
            inFlight--;
            r(fs.map(() => ({ role: "email" as FieldRole, score: 1 })));
          };
        });
      },
    };
    const updated = vi.fn();
    const hook = createModelHook({ classifier, onUpdate: updated, setTimer: (cb) => timers.push(cb) });
    const form = (i: number) => [{ tag: "input", name: `f${i}` } as FieldFeatures];
    for (let i = 0; i < 50; i++) expect(hook.lookup(form(i))).toBeNull();
    expect(asked).toEqual([]);
    expect(timers).toHaveLength(1);
    timers.shift()!();
    expect(asked).toEqual(["f49"]);
    // More misses while the request runs: no second request, no timer.
    for (let i = 50; i < 100; i++) hook.lookup(form(i));
    expect(timers).toHaveLength(0);
    expect(asked).toHaveLength(1);
    release!();
    await vi.waitFor(() => expect(updated).toHaveBeenCalledTimes(1));
    // Then the latest pending one, after a new debounce.
    expect(timers).toHaveLength(1);
    timers.shift()!();
    expect(asked).toEqual(["f49", "f99"]);
    expect(maxInFlight).toBe(1);
    expect(hook.lookup(form(49))).toEqual([{ role: "email", score: 1 }]);
  });

  it("forms over the field budget are never sent", () => {
    const classify = vi.fn(async () => []);
    const hook = createModelHook({ classifier: { kind: "gbm", classify }, onUpdate: () => {}, debounceMs: 0 });
    expect(hook.lookup(Array.from({ length: 65 }, (_, i) => ({ tag: "input", name: `x${i}` }) as FieldFeatures))).toBeNull();
    expect(classify).not.toHaveBeenCalled();
  });
});

/** A hook that answers at once from a fixed labeller (as a warm cache would). */
function syncHook(labelOf: (f: FieldFeatures) => FieldRole, crossSite = false) {
  const seen: FieldFeatures[][] = [];
  return {
    seen,
    hook: { crossSite, lookup: (fs: FieldFeatures[]) => (seen.push(fs), fs.map((f) => ({ role: labelOf(f), score: 0.99 }))) },
  };
}

function analyze(html: string, model?: ReturnType<typeof syncHook>["hook"]): { a: PageAnalysis; refs: RefRegistry } {
  const doc = load(html);
  const refs = new RefRegistry();
  return { a: analyzeDocument(doc, refs, { url: "https://atlas-cloud.test/login", geometry: testGeometry, ...(model ? { model } : {}) }), refs };
}

function rolesById(a: PageAnalysis, refs: RefRegistry): Record<string, FieldRole> {
  const out: Record<string, FieldRole> = {};
  for (const f of a.forms) for (const x of f.fields) out[(refs.get(x.ref) as HTMLElement).id] = x.role;
  return out;
}

describe("detectForms with a model", () => {
  beforeEach(withLayout);

  it("uses the model's roles, after the safety rules, before the existing logic", () => {
    const html = `<form><input id="u" name="q1"><input id="p" name="q2" type="password"><button type="submit">Go</button></form>`;
    const { hook } = syncHook((f) => (f.type === "password" ? "current_password" : "username"));
    const { a, refs } = analyze(html, hook);
    expect(a.forms.map((f) => f.kind)).toEqual(["login"]);
    expect(rolesById(a, refs)).toEqual({ u: "username", p: "current_password" });
  });

  it.each([
    ["current-password", "password", "current_password", "username"],
    ["new-password", "password", "new_password", "email"],
    ["email", "email", "email", "current_password"],
    ["one-time-code", "text", "otp", "username"],
    ["cc-number", "text", "cc_number", "cc_exp"],
  ] as const)("R21: autocomplete=%s keeps its role whatever the model says, and is never sent to it", (ac, type, expected, companion) => {
    // The companion field (no autocomplete) makes a form of the right kind; the model disagrees on the autocomplete field.
    // The companion's control holds its role (a password role needs a type=password input, I1).
    const ctype = companion === "current_password" ? "password" : "text";
    const html = `<form><input id="u" name="q1" type="${ctype}"><input id="x" name="zz" type="${type}" autocomplete="${ac}"><button type="submit">Go</button></form>`;
    const { hook, seen } = syncHook((f) => (f.autocomplete !== undefined ? (expected === "current_password" ? "new_password" : "current_password") : companion));
    const { a, refs } = analyze(html, hook);
    expect(rolesById(a, refs).x).toBe(expected);
    expect(seen.flat().some((f) => f.autocomplete === ac)).toBe(false);
  });

  it("a form holding a type the detector skips (search) still gets the model's roles", () => {
    const html = `<div><input id="s" type="search" name="q"><input id="u" name="q1"><input id="p" name="q2" type="password"><button type="submit">Go</button></div>`;
    const { hook } = syncHook((f) => (f.type === "password" ? "current_password" : "username"));
    const { a, refs } = analyze(html, hook);
    expect(rolesById(a, refs)).toEqual({ u: "username", p: "current_password" });
  });

  it("a model saying password on a hidden honeypot fills nothing (the trap gets no role)", () => {
    const { hook } = syncHook((f) => (f.type === "password" ? "current_password" : "email"));
    const { a, refs } = analyze(HONEYPOT_HTML, hook);
    // #email carries autocomplete="username": that decides (R21).
    expect(rolesById(a, refs)).toEqual({ email: "username", password: "current_password" });
  });

  it("a field the features read as invisible stays unknown whatever the model says", () => {
    vi.restoreAllMocks();
    vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (this: HTMLElement) {
      const w = this.id === "p" ? 1 : 200;
      return { x: 0, y: 0, left: 0, top: 0, right: w, bottom: 30, width: w, height: 30, toJSON: () => ({}) } as DOMRect;
    });
    const html = `<form><input id="u" name="user"><input id="p" name="pass" type="password"></form>`;
    const { hook } = syncHook((f) => (f.type === "password" ? "current_password" : "username"));
    const { a, refs } = analyze(html, hook);
    expect(rolesById(a, refs).p).toBeUndefined();
  });

  it("in a cross-site frame the model is not consulted: today's roles, and the background refuses the fill", () => {
    const html = `<form><input id="u" name="username"><input id="p" name="password" type="password"></form>`;
    const { hook, seen } = syncHook(() => "cc_number", true);
    const { a, refs } = analyze(html, hook);
    const withModel = rolesById(a, refs);
    expect(seen).toEqual([]);
    const plain = analyze(html);
    expect(withModel).toEqual(rolesById(plain.a, plain.refs));
    expect(withModel).toEqual({ u: "username", p: "current_password" });
  });

  it("a model unknown removes the field; fields the model has no answer for keep heuristics", () => {
    const html = `<form><input id="e" name="email" type="email"><input id="p" name="password" type="password"><input id="r" type="checkbox" name="remember"><label for="r">Remember me</label></form>`;
    const { hook } = syncHook((f) => (f.type === "email" ? "unknown" : "current_password"));
    const { a, refs } = analyze(html, hook);
    expect(rolesById(a, refs)).toEqual({ p: "current_password", r: "remember_me" });
  });

  it("a model password on a text input or a textarea never makes it a password field (I1)", () => {
    const html = `<form><input id="u" name="user"><input id="n" name="display_name"><textarea id="t" name="bio"></textarea><input id="p" name="pw" type="password"><button type="submit">Go</button></form>`;
    const { hook } = syncHook((f) => (f.name === "user" ? "username" : "current_password"));
    const { a, refs } = analyze(html, hook);
    const roles = rolesById(a, refs);
    expect(roles.p).toBe("current_password");
    for (const id of ["n", "t"]) expect(["current_password", "new_password", "confirm_password"]).not.toContain(roles[id]);
  });

  it("a model email or card number on a password input never lands there (I1)", () => {
    const html = `<form><input id="u" name="user"><input id="p" name="pw" type="password"><button type="submit">Go</button></form>`;
    for (const said of ["email", "cc_number"] as const) {
      const { hook } = syncHook((f) => (f.type === "password" ? said : "username"));
      const { a, refs } = analyze(html, hook);
      expect(rolesById(a, refs).p, said).toBe("current_password");
    }
  });

  it("the heuristic path is unchanged by the control-type rules (no model)", () => {
    const html = `<form><input id="u" name="username"><input id="n" name="password_hint"><textarea id="t" name="notes"></textarea><input id="p" name="password" type="password"><button type="submit">Sign in</button></form>`;
    const expected: Record<string, FieldRole> = {};
    for (const el of fieldsOf(html)) {
      const r = classifyField(el).role;
      if (r !== "unknown") expected[el.id] = r;
    }
    const plain = analyze(html);
    expect(rolesById(plain.a, plain.refs)).toEqual(expected);
    expect(expected).toEqual({ u: "username", p: "current_password" });
  });

  it("without a model the analysis is today's, and extractFeatures is never run", () => {
    const html = `<form><input id="e" name="email" type="email"><input id="p" name="password" type="password"></form>`;
    const before = analyze(html);
    expect(rolesById(before.a, before.refs)).toEqual({ e: "email", p: "current_password" });
  });

  it("a page setting data-lab-field cannot influence classification", () => {
    const plain = `<form><input id="u" name="login"><input id="p" name="pw" type="password"></form>`;
    const marked = `<form><input id="u" name="login" data-lab-field="7"><input id="p" name="pw" type="password" data-lab-field="password"></form>`;
    const a = syncHook((f) => (f.lab !== undefined ? "cc_number" : f.type === "password" ? "current_password" : "username"));
    const b = syncHook((f) => (f.lab !== undefined ? "cc_number" : f.type === "password" ? "current_password" : "username"));
    const r1 = analyze(plain, a.hook);
    const roles1 = rolesById(r1.a, r1.refs);
    const r2 = analyze(marked, b.hook);
    expect(b.seen.flat().every((f) => f.lab === undefined)).toBe(true);
    expect(JSON.stringify(b.seen)).toBe(JSON.stringify(a.seen));
    expect(rolesById(r2.a, r2.refs)).toEqual(roles1);
    expect(roles1).toEqual({ u: "username", p: "current_password" });
    // The extractor reads the mark only when asked to (dataset builder).
    expect(extractFeatures(load(marked)).forms[0]!.fields[0]!.lab).toBeUndefined();
    expect(extractFeatures(load(marked), { labField: true }).forms[0]!.fields[0]!.lab).toBe("7");
  });
});
