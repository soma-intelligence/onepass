import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { DESIGN_TOKENS } from "../../src/shared/design-tokens";

describe("design tokens mirror", () => {
  it("mirrors theme.css", () => {
    expect(() => execFileSync("node", ["scripts/gen-design-tokens.mjs", "--check"], { stdio: "pipe" })).not.toThrow();
  });

  it("has the glyph tokens in both themes", () => {
    expect(DESIGN_TOKENS.dark["glyph-focus"]).toBeDefined();
    expect(DESIGN_TOKENS.light["glyph-focus"]).toBeDefined();
    expect(DESIGN_TOKENS.dark["glyph-rest"]).toBeDefined();
    expect(DESIGN_TOKENS.light["glyph-rest"]).not.toBe(DESIGN_TOKENS.dark["glyph-rest"]);
  });
});
