// Seeded PRNG of the autofill lab: determinism, independence of forks, bounds.
import { describe, expect, it } from "vitest";
import { Rng } from "../../lab/gen/rng.ts";

describe("Rng", () => {
  it("same_seed_same_sequence", () => {
    const a = new Rng("a");
    const b = new Rng("a");
    for (let i = 0; i < 100; i++) expect(a.next()).toBe(b.next());
  });

  it("different_seed_differs", () => {
    const a = new Rng("a");
    const b = new Rng("b");
    const xs = Array.from({ length: 10 }, () => a.next());
    const ys = Array.from({ length: 10 }, () => b.next());
    expect(xs).not.toEqual(ys);
  });

  it("fork_is_independent_of_draws", () => {
    const fresh = new Rng("s").fork("x").next();
    const parent = new Rng("s");
    for (let i = 0; i < 10; i++) parent.next();
    expect(parent.fork("x").next()).toBe(fresh);
  });

  it("int_bounds", () => {
    const r = new Rng("ints");
    const seen = new Set<number>();
    for (let i = 0; i < 10000; i++) {
      const v = r.int(1, 6);
      expect(v).toBeGreaterThanOrEqual(1);
      expect(v).toBeLessThanOrEqual(6);
      seen.add(v);
    }
    expect([...seen].sort((x, y) => x - y)).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it("pinned_first_values", () => {
    const r = new Rng("lab");
    expect([r.next(), r.next(), r.next()]).toEqual([0.03776918654330075, 0.12196121574379504, 0.9503673983272165]);
  });

  it("weighted_zero_weight_never_picked", () => {
    const r = new Rng("w");
    for (let i = 0; i < 1000; i++) {
      expect(r.weighted([["no", 0], ["yes", 1], ["also", 2]] as const)).not.toBe("no");
    }
  });
});
