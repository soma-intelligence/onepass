import { describe, expect, it } from "vitest";
import { splitOf } from "../../lab/dataset/split.ts";

describe("splitOf", () => {
  it("gives the same origin the same split", () => {
    for (const o of ["example.com", "synthetic:ds/site:3", "shop.example.co.uk"]) {
      expect(splitOf(o, "s")).toBe(splitOf(o, "s"));
    }
  });

  it("splits 10,000 origins within one point of 80/10/10", () => {
    const n = 10_000;
    const count = { train: 0, val: 0, test: 0 };
    for (let i = 0; i < n; i++) count[splitOf(`origin-${i}.example`, "seed")]++;
    expect(Math.abs(count.train / n - 0.8)).toBeLessThan(0.01);
    expect(Math.abs(count.val / n - 0.1)).toBeLessThan(0.01);
    expect(Math.abs(count.test / n - 0.1)).toBeLessThan(0.01);
  });

  it("depends on the seed", () => {
    let differs = 0;
    for (let i = 0; i < 200; i++) if (splitOf(`o${i}`, "a") !== splitOf(`o${i}`, "b")) differs++;
    expect(differs).toBeGreaterThan(0);
  });
});
