// Distiller of the corpus: merge of baseline and samples, stable output.
import { describe, expect, it } from "vitest";
import { distill, sampleFiles } from "../../lab/corpus/distill.ts";
import seed from "../../lab/corpus/seed-lexicon.json";
import type { Patterns, Sample } from "../../lab/corpus/types.ts";

const baseline = seed as unknown as Patterns;

function sample(over: Partial<Sample> = {}): Sample {
  return {
    source_url: "https://example.test/login", host: "example.test", category: "login",
    captured_at: "2026-10-26T00:00:00Z", extractor: 1, status: "ok", lang: "it",
    forms: [{
      step: "both", buttons: ["Accedi"],
      fields: [
        { tag: "input", type: "text", name: "utente", hasPattern: false, required: true, label: "Nome utente", visibility: "visible", role: "username" },
        { tag: "input", type: "password", name: "pwd", autocomplete: "current-password", hasPattern: false, required: true, label: "Parola chiave", visibility: "visible", role: "password" },
      ],
    }],
    providerButtons: ["google"],
    ...over,
  };
}

describe("distill", () => {
  it("stable_output", () => {
    const s = [sample(), sample({ host: "b.test", lang: "fr" })];
    expect(JSON.stringify(distill(s, baseline))).toBe(JSON.stringify(distill([...s].reverse(), baseline)));
  });
  it("merges_baseline", () => {
    const out = distill([sample()], baseline);
    expect(out.samples).toBe(1);
    expect(out.roles.username.labels.fr).toEqual(baseline.roles.username.labels.fr);
    expect(out.roles.username.labels.it).toContain("Nome utente");
    expect(out.roles.username.tokens).toContain("utente");
    expect(out.buttons.signin.it).toContain("Accedi");
    expect(out.structure.sso.google).toBeGreaterThan(0);
  });
  it("provider_buttons_stay_out_of_lexicon", () => {
    const s = sample({ forms: [{ step: "other", fields: [], buttons: ["Continuer avec Google", "Continue with Apple", "Sign in with Google", "PayPal", "Pay now"] }], lang: "en" });
    const out = distill([s], baseline);
    const all = Object.values(out.buttons).flatMap((m) => Object.values(m).flat());
    for (const t of ["Continuer avec Google", "Continue with Apple", "Sign in with Google", "PayPal"]) expect(all).not.toContain(t);
    expect(out.buttons.pay.en).toContain("Pay now");
  });
  it("keeps_natural_casing_smallest_original", () => {
    const fr = baseline.roles.email.labels.fr!;
    expect(fr).toContain("Adresse e-mail");
    const s = sample({ lang: "fr", forms: [{ step: "identifier", buttons: [], fields: [
      { tag: "input", type: "email", hasPattern: false, required: true, label: "adresse E-mail", visibility: "visible", role: "email" }] }] });
    const out = distill([s], baseline);
    expect(out.roles.email.labels.fr).toContain("Adresse e-mail");
    expect(out.roles.email.labels.fr).not.toContain("adresse E-mail");
  });
  it("autocomplete_rate_counts_correct_values_only", () => {
    const fld = (autocomplete: string) => ({ tag: "input", type: "text", autocomplete, hasPattern: false, required: false, label: "Courriel", visibility: "visible" as const, role: "email" as const });
    const mk = (ac: string) => sample({ forms: [{ step: "identifier", buttons: [], fields: [fld(ac)] }] });
    const good = distill([mk("email")], baseline).roles.email.autocompleteRate;
    const off = distill([mk("off")], baseline).roles.email.autocompleteRate;
    const wrong = distill([mk("username")], baseline).roles.email.autocompleteRate;
    expect(good).toBeGreaterThan(off);
    expect(off).toBe(wrong);
    expect(off).toBeLessThan(baseline.roles.email.autocompleteRate);
  });
  it("skipped_samples_ignored", () => {
    const out = distill([sample({ status: "skipped: robots", forms: undefined }), sample({ status: "error: timeout" })], baseline);
    expect(out.samples).toBe(0);
  });
  it("lang_weights_sum_to_1", () => {
    const out = distill([sample(), sample({ lang: "fr" }), sample({ lang: undefined })], baseline);
    const sum = out.langs.reduce((a, [, w]) => a + w, 0);
    expect(sum).toBeCloseTo(1, 6);
    const none = distill([], baseline);
    expect(none.langs.reduce((a, [, w]) => a + w, 0)).toBeCloseTo(1, 6);
  });
});

describe("sampleFiles", () => {
  it("skips the crawler's done markers and non-json files", () => {
    expect(sampleFiles(["b.example.0.json", "b.example.done.json", "a.example.1.json", "notes.txt"])).toEqual(["a.example.1.json", "b.example.0.json"]);
  });
});

describe("distill v2", () => {
  const field = (role: string, label?: string) => ({ tag: "input", type: role === "password" ? "password" : "text", name: role, hasPattern: false,
    required: true, visibility: "visible" as const, role: role as never, ...(label ? { label } : {}) });
  const identifierPage = (lang = "en") => sample({ lang, extractor: 2, forms: [{ step: "identifier", buttons: ["Next"], fields: [field("email", "Email")] }] });
  const recorded = (): Sample => sample({
    source: "recorded", extractor: 2, lang: "und", forms: undefined,
    steps: [
      [{ step: "identifier", buttons: [], fields: [field("username", "User")] }],
      [{ step: "password", buttons: [], fields: [field("password", "Pass")] }],
      [{ step: "code", buttons: [], fields: [field("otp", "Code")] }],
    ],
  });

  it("is_version_2_with_steps_frameworks_traits", () => {
    const out = distill([identifierPage(), sample({ framework: "react" })], baseline);
    expect(out.version).toBe(2);
    expect(out.steps.length).toBeGreaterThan(0);
    expect(out.steps.reduce((a, [, w]) => a + w, 0)).toBeCloseTo(1, 6);
    for (const [seq] of out.steps) expect(seq.length).toBeGreaterThanOrEqual(1);
    expect(out.frameworks.map(([f]) => f)).toContain("react");
    expect(out.frameworks.reduce((a, [, w]) => a + w, 0)).toBeCloseTo(1, 6);
    for (const t of ["iframe_same_origin", "iframe_cross_site", "shadow_open", "honeypot", "no_autocomplete", "decoy_form"]) {
      expect(out.traits[t as keyof typeof out.traits]).toBeGreaterThan(0);
    }
  });

  it("identifier_only_page_implies_a_password_step", () => {
    const none = distill([], baseline);
    const out = distill([identifierPage(), identifierPage()], baseline);
    const w = (p: typeof out) => p.steps.find(([s]) => JSON.stringify(s) === JSON.stringify([["email"], ["password"]]))?.[1] ?? 0;
    expect(w(out)).toBeGreaterThan(w(none));
  });

  it("private samples are ignored without --with-private", () => {
    const none = distill([], baseline);
    expect(distill([recorded()], baseline).steps).toEqual(none.steps);
    expect(distill([recorded()], baseline).samples).toBe(0);
    const withPrivate = distill([recorded()], baseline, { withPrivate: true });
    expect(withPrivate.steps.map(([s]) => JSON.stringify(s))).toContain(JSON.stringify([["username"], ["password"], ["otp"]]));
  });

  it("redacted_labels_are_no_label", () => {
    const s = sample({ extractor: 2, forms: [{ step: "both", buttons: [], fields: [field("username", "&lt;redacted&gt;"), field("password", "<redacted>")] }] });
    const out = distill([s], baseline);
    const all = [...Object.values(out.roles.username.labels).flat(), ...Object.values(out.roles.password.labels).flat()];
    expect(all.some((l) => l.includes("redacted"))).toBe(false);
  });

  it("signup_wording_and_provider_buttons_stay_out_of_login_lexicon", () => {
    const s = sample({ extractor: 2, lang: "en", forms: [{ step: "both", buttons: ["continue with esot", "Continue"], fields: [
      field("password", "create a password"), field("password", "Choose a new password"), field("password", "Your password")] }] });
    const out = distill([s], baseline);
    expect(out.roles.password.labels.en).toContain("Your password");
    expect(out.roles.password.labels.en).not.toContain("create a password");
    expect(out.roles.password.labels.en).not.toContain("Choose a new password");
    expect(out.buttons.next.en).toContain("Continue");
    expect(out.buttons.next.en).not.toContain("continue with esot");
  });

  it("langs_cover_every_corpus_language", () => {
    const out = distill([identifierPage("zh"), identifierPage("en_US"), identifierPage("pt-BR")], baseline);
    expect(out.langs.map(([l]) => l).sort()).toEqual(["en", "pt", "zh"]);
  });
});

describe("corpusFiles", () => {
  it("reads samples, top1000, commoncrawl, and private only with --with-private", async () => {
    const { mkdtempSync, mkdirSync, writeFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");
    const { corpusFiles } = await import("../../lab/corpus/distill.ts");
    const root = mkdtempSync(join(tmpdir(), "distill-"));
    const dirs = { samples: join(root, "samples"), top: join(root, "samples", "top1000"), cc: join(root, "samples", "commoncrawl"), priv: join(root, "private") };
    for (const d of Object.values(dirs)) mkdirSync(d, { recursive: true });
    for (const [d, n] of [[dirs.samples, "a.json"], [dirs.top, "b.0.json"], [dirs.top, "b.done.json"], [dirs.cc, "c.0.json"],
      [dirs.priv, "d.json"]] as const) writeFileSync(join(d, n), "{}");
    const base = (xs: string[]) => xs.map((x) => x.slice(root.length + 1)).sort();
    expect(base(corpusFiles({ samples: dirs.samples, private: dirs.priv }, false)))
      .toEqual(["samples/a.json", "samples/commoncrawl/c.0.json", "samples/top1000/b.0.json"]);
    expect(base(corpusFiles({ samples: dirs.samples, private: dirs.priv }, true)))
      .toEqual(["private/d.json", "samples/a.json", "samples/commoncrawl/c.0.json", "samples/top1000/b.0.json"]);
  });

  it("never reads lab/out: the committed patterns.json rebuilds from a clean checkout", async () => {
    const { corpusDirs, corpusFiles } = await import("../../lab/corpus/distill.ts");
    const files = corpusFiles(corpusDirs(), true);
    expect(files.some((f) => f.includes("/samples/commoncrawl/"))).toBe(true);
    for (const f of files) expect(f.replace(/\\/g, "/")).not.toMatch(/\/lab\/out\//);
    expect(JSON.stringify(corpusDirs())).not.toMatch(/\/out\b/);
  });
});

describe("label sanity", () => {
  const fld = (role: string, label: string) => ({ tag: "input", type: "text", name: role, hasPattern: false, required: false,
    visibility: "visible" as const, role: role as never, label });
  const crawled = (fields: ReturnType<typeof fld>[], buttons: string[] = []): Sample =>
    sample({ extractor: 2, lang: "en", forms: [{ step: "other", buttons, fields }] });
  const BAD: [string, string][] = [
    ["new_password", "search"], ["new_password", "cpf"], ["new_password", "at least 8 characters"],
    ["postal_code", "bitte lösen sie folgende aufgabe: *"], ["tel", "chat with chatgpt"],
    ["email", "*"], ["email", "join our newsletter"], ["email", "free software supporter:"], ["email", "confirm email"],
    ["username", "can't register? learn more."], ["username", "create a username"],
    ["organization", "*what is your organization's monthly compute spend on ai?"],
  ];

  it("drops every mislabel seen in the top 1000", () => {
    const out = distill([crawled(BAD.map(([r, l]) => fld(r, l)))], baseline);
    for (const [role, label] of BAD) {
      const all = Object.values(out.roles[role as keyof typeof out.roles].labels).flat();
      expect(all, `${role}: ${label}`).not.toContain(label);
    }
  });

  it("drops skip, without and accept buttons", () => {
    const noise = ["continue without accepting", "skip to next", "accept and continue", "agree & continue", "next page", "next items"];
    const out = distill([crawled([], [...noise, "Next"])], baseline);
    const all = Object.values(out.buttons).flatMap((m) => Object.values(m).flat());
    for (const b of noise) expect(all).not.toContain(b);
    expect(out.buttons.next.en).toContain("Next");
  });

  it("keeps sound labels", () => {
    const good: [string, string][] = [["email", "work email"], ["username", "login id"], ["new_password", "choose a password"],
      ["postal_code", "zip code"], ["tel", "mobile number"], ["organization", "company"], ["given_name", "first name"]];
    const out = distill([crawled(good.map(([r, l]) => fld(r, l)))], baseline);
    for (const [role, label] of good) {
      expect(out.roles[role as keyof typeof out.roles].labels.en!.map((x) => x.toLowerCase()), label).toContain(label);
    }
  });

  it("hand-picked samples are not held to the crawl's role agreement", () => {
    const out = distill([sample({ forms: [{ step: "both", buttons: [], fields: [fld("username", "Nome utente"), fld("password", "Parola chiave")] }] })], baseline);
    expect(out.roles.password.labels.it).toContain("Parola chiave");
  });
});
