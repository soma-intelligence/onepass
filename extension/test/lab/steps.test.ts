// Step sequences of multi_step sites: weighted draw from patterns.json, at
// least two steps, only roles a step form renders, completed when a step is missing.
import { describe, expect, it } from "vitest";
import patternsJson from "../../lab/corpus/patterns.json";
import type { Patterns } from "../../lab/corpus/types.ts";
import { STEP_ROLES } from "../../lab/gen/render-forms.ts";
import { Rng } from "../../lab/gen/rng.ts";
import { pickSteps } from "../../lab/gen/steps.ts";

const FIXED = patternsJson as unknown as Patterns;
const ID = ["username", "email"];

describe("pickSteps", () => {
  it("at_least_two_steps_with_identifier_and_password", () => {
    const r = new Rng("steps");
    for (let i = 0; i < 300; i++) {
      const seq = pickSteps(r, FIXED, "en");
      expect(seq.length).toBeGreaterThanOrEqual(2);
      const flat = seq.flat();
      expect(flat.some((x) => ID.includes(x))).toBe(true);
      expect(flat).toContain("password");
      for (const step of seq) {
        expect(step.length).toBeGreaterThan(0);
        for (const role of step) expect(STEP_ROLES).toContain(role);
      }
    }
  });

  it("deterministic", () => {
    const a = Array.from({ length: 20 }, (_, k) => pickSteps(new Rng(`d${k}`), FIXED, "fr"));
    const b = Array.from({ length: 20 }, (_, k) => pickSteps(new Rng(`d${k}`), FIXED, "fr"));
    expect(a).toEqual(b);
  });

  it("completes_a_missing_identifier_or_password", () => {
    const only = (seq: Patterns["steps"][number][0]): Patterns => ({ ...FIXED, steps: [[seq, 1]] });
    expect(pickSteps(new Rng("p"), only([["password"]]), "en")).toEqual([["email"], ["password"]]);
    expect(pickSteps(new Rng("p"), only([["username"]]), "en")).toEqual([["username"], ["password"]]);
    expect(pickSteps(new Rng("p"), only([["otp"]]), "en")).toEqual([["email"], ["password"], ["otp"]]);
    expect(pickSteps(new Rng("p"), only([["email", "password"]]), "en")).toEqual([["email"], ["password"]]);
    // Roles a step form does not render are dropped, then the sequence is completed.
    expect(pickSteps(new Rng("p"), only([["given_name"], ["password"]]), "en")).toEqual([["email"], ["password"]]);
  });

  it("follows_the_weights", () => {
    const p: Patterns = { ...FIXED, steps: [[[["username"], ["password"]], 0.9], [[["email"], ["password"], ["otp"]], 0.1]] };
    const r = new Rng("w");
    let otp = 0;
    for (let i = 0; i < 1000; i++) if (pickSteps(r, p, "en").flat().includes("otp")) otp++;
    expect(otp).toBeGreaterThan(50);
    expect(otp).toBeLessThan(150);
  });
});
