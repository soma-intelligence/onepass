// Sample format version 2: extractor 1 samples stay valid, v2 fields are optional or additive.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { Sample, SampleField } from "../../lab/corpus/types.ts";

describe("sample types", () => {
  it("extractor 1 samples still parse as Sample", () => {
    const s: Sample = JSON.parse(readFileSync("lab/corpus/samples/github.com.json", "utf8"));
    expect(s.extractor).toBe(1);
    expect(s.source ?? "rendered").toBe("rendered");
  });
  it("accepts a version 2 sample", () => {
    const f: SampleField = {
      tag: "input", hasPattern: false, required: true, visibility: "visible", role: "password",
      placeholder: "Password", ariaLabel: "Password", before: "Email", after: "Forgot?", index: 1, depth: 3, siblings: 2,
    };
    const s: Sample = {
      source_url: "https://example.test/", host: "example.test", category: "login", captured_at: "2026-10-27T00:00:00Z",
      extractor: 2, source: "recorded", status: "ok", framework: "react",
      forms: [{ step: "both", fields: [f], buttons: ["Sign in"] }],
      steps: [[{ step: "identifier", fields: [], buttons: [] }]],
    };
    expect(s.extractor).toBe(2);
  });
});

describe("forms roles", () => {
  it("a field spec takes a forms role, a person, a block and a rendering; Role keeps the 21 model classes", async () => {
    const { MODEL_ROLES } = await import("../../src/shared/model-labels.ts");
    const { isModelRole } = await import("../../lab/dataset/rows.ts");
    const f: import("../../lab/gen/model.ts").FieldSpec = {
      role: "passport_expiry", name: "pax[1][exp_m]", id: "pax-1-exp-m", label: "Mois", type: "select", person: 1,
      block: "passenger", render: { date: { kind: "part", part: "month", group: "Date d'expiration", select: true, months: "name" } },
    };
    expect(isModelRole(f.role)).toBe(false);
    expect(MODEL_ROLES.every((r) => isModelRole(r))).toBe(true);
    expect(MODEL_ROLES).toHaveLength(21);
  });
});
