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

  it("has a lighter frame shadow in the light theme", () => {
    expect(DESIGN_TOKENS.light["frame-shadow"]).toBe("0 0 0 .5px rgba(0,0,0,.12), 0 12px 32px rgba(0,0,0,.16)");
    expect(DESIGN_TOKENS.dark["frame-shadow"]).toBe("0 0 0 .5px rgba(0,0,0,.18), 0 16px 40px rgba(0,0,0,.28)");
  });
});
