import { describe, expect, it } from "vitest";
import { build, fieldOf } from "../../lab/corpus/build";
import type { FieldFeatures, PageFeatures } from "../../src/content/detect/features";
import type { Sample } from "../../lab/corpus/types";

const field = (over: Partial<FieldFeatures> = {}): FieldFeatures => ({
  index: 0, tag: "input", type: "text", hasPattern: false, required: false, depth: 3, siblings: 0,
  visibility: "visible", width: 200, height: 30, formButtons: [], neighbourLabels: [], ...over,
});
const base: Sample = { source_url: "https://example.com/login", host: "example.com", category: "login", captured_at: "t", extractor: 2, source: "rendered", status: "ok" };

describe("corpus build from shared features", () => {
  it("fills the v2 fields", () => {
    const f = fieldOf(field({ label: "email", placeholder: "you", ariaLabel: "mail", before: "sign in", after: "forgot", index: 2, depth: 5, siblings: 1 }));
    expect(f).toMatchObject({ label: "email", placeholder: "you", ariaLabel: "mail", before: "sign in", after: "forgot", index: 2, depth: 5, siblings: 1 });
  });

  it("a redacted neighbour or attribute never becomes a feature", () => {
    const f = fieldOf(field({ label: "email", before: "write to bob@example.com", after: "call 0612345678", placeholder: "bob@example.com", ariaLabel: "id 123456" }));
    expect(f.before).toBeUndefined();
    expect(f.after).toBeUndefined();
    expect(f.placeholder).toBeUndefined();
    expect(f.ariaLabel).toBeUndefined();
    expect(JSON.stringify(f)).not.toMatch(/redacted/);
  });

  it("neighbour text stays at 40 characters", () => {
    expect(fieldOf(field({ before: "a ".repeat(50).trim() })).before!.length).toBeLessThanOrEqual(40);
  });

  it("carries framework, same-site iframes and sanitized origins", () => {
    const page: PageFeatures = {
      forms: [{ fields: [field({ label: "password", type: "password" })], buttons: ["Sign in"] }], framework: "react",
      iframes: [{ origin: "https://accounts.example.com", sameSite: false }, { origin: "https://pay.stripe.com", sameSite: true }],
      shadowFields: 0, truncated: false,
    };
    const s = build(base, page, { lang: "en-US", providerTexts: ["Continue with Google"] }, []);
    expect(s).toMatchObject({ framework: "react", extractor: 2, source: "rendered", lang: "en", providerButtons: ["google"] });
    expect(s.iframes).toEqual([{ origin: "https://accounts.example.com", sameSite: true }, { origin: "https://pay.stripe.com", sameSite: false }]);
    expect(s.forms![0]).toMatchObject({ step: "password", buttons: ["Sign in"] });
  });
});
