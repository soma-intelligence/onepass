// Password policies of the lab's signup sites: seeded draw, rate, satisfiability,
// how pages state them and what the relying party enforces.
import { describe, expect, it } from "vitest";
import { generate, loadPatterns } from "../../lab/gen/generate.ts";
import type { PasswordPolicy, Site } from "../../lab/gen/model.ts";
import {
  drawPolicy, HINT_LANGS, passwordRules, policyAttrs, policyCategory, policyHint, policyViolation, satisfiable,
} from "../../lab/gen/policy.ts";
import { renderSitePage } from "../../lab/gen/render.ts";
import { Rng } from "../../lab/gen/rng.ts";

const patterns = loadPatterns();
const world = generate("policy-props", { sites: 1500, patterns });
const signups = world.sites.filter((s) => s.flow === "signup");
const policies = signups.flatMap((s) => (s.passwordPolicy ? [s] : []));

describe("signup policies", () => {
  it("same seed, same policies", () => {
    const a = generate("policy-det", { sites: 300, patterns });
    const b = generate("policy-det", { sites: 300, patterns });
    const pick = (w: typeof a) => w.sites.filter((s) => s.flow === "signup").map((s) => s.passwordPolicy ?? null);
    expect(pick(a).length).toBeGreaterThan(10);
    expect(JSON.stringify(pick(a))).toBe(JSON.stringify(pick(b)));
    expect(pick(a).some((p) => p !== null)).toBe(true);
    const c = generate("policy-other", { sites: 300, patterns });
    expect(JSON.stringify(pick(c))).not.toBe(JSON.stringify(pick(a)));
  });

  it("only signup sites carry a policy, about 60 % of them", () => {
    expect(world.sites.filter((s) => s.flow !== "signup").every((s) => s.passwordPolicy === undefined)).toBe(true);
    // Generator version 4 gives a quarter of the later sites to the forms flows: fewer signups than in version 3.
    expect(signups.length).toBeGreaterThan(75);
    const rate = policies.length / signups.length;
    expect(rate).toBeGreaterThan(0.5);
    expect(rate).toBeLessThan(0.7);
  });

  it("adding the policy shifts nothing else of a site", () => {
    const strip = (s: Site) => JSON.stringify({ ...s, passwordPolicy: undefined });
    const again = generate("policy-props", { sites: 1500, patterns });
    expect(again.sites.map(strip)).toEqual(world.sites.map(strip));
  });

  it("every drawn policy is satisfiable and states each part somewhere", () => {
    expect(policies.length).toBeGreaterThan(45);
    for (const s of policies) {
      const p = s.passwordPolicy!;
      if (p.min !== undefined && p.max !== undefined) expect(p.min).toBeLessThanOrEqual(p.max);
      if (p.max !== undefined) expect(p.max).toBeGreaterThanOrEqual(4 + (p.required ?? []).length);
      expect(satisfiable(p)).toBe(true);
      expect(p.min !== undefined || p.max !== undefined || (p.required ?? []).length > 0 || p.noSpecial === true || p.pattern !== undefined).toBe(true);
      // Attributes alone cannot state a class rule, except a no-special one through its pattern.
      if (p.via.length === 1 && p.via[0] === "attributes") expect(p.required ?? []).toEqual([]);
      if (p.via.length === 1 && p.via[0] === "attributes" && p.noSpecial) expect(p.pattern).toBeDefined();
      // Hints only in the languages that have a sentence.
      if (p.via.includes("hints")) expect(HINT_LANGS).toContain(s.lang);
    }
  });

  it("patterns are simple and safe", () => {
    const withPattern = policies.filter((s) => s.passwordPolicy!.pattern !== undefined);
    expect(withPattern.length).toBeGreaterThan(5);
    for (const s of withPattern) {
      const pat = s.passwordPolicy!.pattern!;
      expect(pat).toMatch(/^(\[[A-Za-z0-9-]+\]|\\S)\+$/); // one class, one quantifier, no group
      expect(() => new RegExp(`^(?:${pat})$`, "v")).not.toThrow();
    }
  });

  it("the draw covers every source and several languages", () => {
    const vias = new Set(policies.map((s) => s.passwordPolicy!.via.join("+")));
    expect(vias.size).toBeGreaterThanOrEqual(6);
    const cats = new Set(policies.map((s) => policyCategory(s)));
    for (const c of ["attributes", "passwordrules", "hints_readable", "hint_only_unsupported"]) expect(cats).toContain(c);
  });
});

describe("how a page states a policy", () => {
  const p: PasswordPolicy = { min: 10, max: 20, required: ["upper", "digit", "special"], via: ["attributes", "passwordrules", "hints"], pattern: "\\S+" };
  const esc = (s: string) => s;

  it("attributes and passwordrules", () => {
    expect(policyAttrs(p, esc)).toBe(' minlength="10" maxlength="20" pattern="\\S+" passwordrules="minlength: 10; maxlength: 20; required: upper; required: digit; required: special; allowed: upper, lower, digit, special"');
    expect(policyAttrs({ ...p, via: ["hints"] }, esc)).toBe("");
    expect(passwordRules({ min: 8, noSpecial: true, via: ["passwordrules"] })).toBe("minlength: 8; allowed: upper, lower, digit");
    expect(passwordRules({ required: ["digit"], via: ["passwordrules"] })).toBe("required: digit; allowed: upper, lower, digit, special");
  });

  it("hints in each language, none without a hint source", () => {
    expect(policyHint(p, "en")).toBe("Between 10 and 20 characters. Must contain at least one uppercase letter, one digit and one special character.");
    expect(policyHint(p, "fr")).toBe("Entre 10 et 20 caractères. Doit contenir au moins une majuscule, un chiffre et un caractère spécial.");
    expect(policyHint({ min: 9, noSpecial: true, via: ["hints"] }, "es")).toBe("Al menos 9 caracteres. Sin caracteres especiales.");
    expect(policyHint({ max: 12, via: ["hints"] }, "de")).toBe("Höchstens 12 Zeichen.");
    expect(policyHint({ ...p, via: ["attributes"] }, "en")).toBeUndefined();
    expect(policyHint(p, "it")).toBeUndefined();
  });

  it("the rendered signup page carries them on the new-password fields", () => {
    const site = policies.find((s) => s.passwordPolicy!.via.includes("attributes") && s.passwordPolicy!.min !== undefined && !s.traits.some((t) => t.startsWith("shadow") || t === "delayed_fields" || t.startsWith("iframe")));
    expect(site).toBeDefined();
    const doc = new DOMParser().parseFromString(renderSitePage(site!, "entry", {}), "text/html");
    const pws = [...doc.querySelectorAll<HTMLInputElement>("input[type=password]")];
    expect(pws.length).toBe(2);
    for (const el of pws) expect(el.getAttribute("minlength")).toBe(String(site!.passwordPolicy!.min));
    const hinted = policies.find((s) => s.passwordPolicy!.via.includes("hints") && !s.traits.some((t) => t.startsWith("shadow") || t === "delayed_fields" || t.startsWith("iframe")));
    const d2 = new DOMParser().parseFromString(renderSitePage(hinted!, "entry", {}), "text/html");
    expect(d2.querySelector(".hint")?.textContent).toBe(policyHint(hinted!.passwordPolicy!, hinted!.lang));
  });
});

describe("what the relying party enforces", () => {
  it("policyViolation", () => {
    const p: PasswordPolicy = { min: 10, max: 14, required: ["upper", "digit"], noSpecial: true, via: ["passwordrules"] };
    expect(policyViolation("Abcdefgh12", p)).toBeUndefined();
    expect(policyViolation("Abcdefg12", p)).toBe("min");
    expect(policyViolation("Abcdefghijklmn12", p)).toBe("max");
    expect(policyViolation("abcdefghij12", p)).toBe("required_upper");
    expect(policyViolation("Abcdefghijkl", p)).toBe("required_digit");
    expect(policyViolation("Abcdefgh12!", p)).toBe("no_special");
    expect(policyViolation("Abcdefgh1 2", { pattern: "\\S+", via: ["attributes"] })).toBe("pattern");
  });

  it("an unsatisfiable policy is detected", () => {
    expect(satisfiable({ min: 12, max: 8, via: ["attributes"] })).toBe(false);
    expect(satisfiable({ max: 6, required: ["upper", "digit", "special"], via: ["hints"] })).toBe(false);
    expect(satisfiable({ required: ["special"], noSpecial: true, via: ["hints"] })).toBe(false);
  });
});

describe("drawPolicy", () => {
  it("never states a hint outside the hint languages", () => {
    for (let i = 0; i < 200; i++) expect(drawPolicy(new Rng(`it${i}`), "it").via).not.toContain("hints");
  });
});

describe("policy stats", () => {
  it("counts policy refusals by category", async () => {
    const { policyRows } = await import("../../lab/policy-stats.ts");
    const mk = (site: number, verdict: string, cause?: string) => ({ site, verdict, expect: "pass", ...(cause ? { cause } : {}) }) as never;
    const w = { sites: [
      { flow: "signup", lang: "en", passwordPolicy: { via: ["attributes"], min: 8 } },
      { flow: "signup", lang: "de", passwordPolicy: { via: ["hints"], min: 8 } },
      { flow: "signup", lang: "fr" },
      { flow: "login_single", lang: "fr" },
    ] } as never;
    const rows = policyRows(w, [mk(0, "pass"), mk(0, "fail", "rp_refused:policy"), mk(1, "fail", "rp_refused:policy"), mk(2, "pass"), mk(3, "pass"), mk(1, "fail", "timeout")]);
    const by = Object.fromEntries(rows.map((r) => [r.category, r]));
    expect(by.attributes).toMatchObject({ scenarios: 2, pass: 1, policy: 1 });
    expect(by.hint_only_unsupported).toMatchObject({ scenarios: 2, policy: 1, other: 1 });
    expect(by.none).toMatchObject({ scenarios: 1, pass: 1 });
  });
});
