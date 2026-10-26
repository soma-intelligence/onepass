// Distiller of the corpus: merge of baseline and samples, stable output.
import { describe, expect, it } from "vitest";
import { distill } from "../../lab/corpus/distill.ts";
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
    expect(out.roles.username.labels.fr).toEqual(baseline.roles.username.labels.fr!.slice().sort());
    expect(out.roles.username.labels.it).toContain("nome utente");
    expect(out.roles.username.tokens).toContain("utente");
    expect(out.buttons.signin.it).toContain("accedi");
    expect(out.structure.sso.google).toBeGreaterThan(0);
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
