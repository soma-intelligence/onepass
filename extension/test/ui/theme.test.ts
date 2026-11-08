import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const css = readFileSync(resolve(process.cwd(), "src/ui/theme.css"), "utf8");

/** Body of the first `{ ... }` block that follows `header`, braces balanced. */
function block(header: string, from = 0): string {
  const at = css.indexOf(header, from);
  expect(at, `missing ${header}`).toBeGreaterThanOrEqual(0);
  const open = css.indexOf("{", at);
  let depth = 0;
  for (let i = open; i < css.length; i++) {
    if (css[i] === "{") depth++;
    if (css[i] === "}" && --depth === 0) return css.slice(open + 1, i);
  }
  throw new Error(`unbalanced ${header}`);
}

const root = block(":root {");
const contrast = block("@media (prefers-contrast: more), (prefers-reduced-transparency: reduce)");
const light = block("@media (prefers-color-scheme: light)");

describe("theme tokens mirroring DesignKit", () => {
  it("declares the washes in :root", () => {
    expect(root).toContain("--wash-accent: linear-gradient(180deg, color-mix(in srgb, var(--accent), white 10%), var(--accent))");
    expect(root).toMatch(/--wash-alert-danger: linear-gradient\(180deg, color-mix\(in srgb, var\(--danger\), white 8%\), color-mix\(in srgb, var\(--danger\), black 6%\)\)/);
    expect(root).toContain("--wash-scale: linear-gradient(90deg, var(--danger) 0%, var(--warn) 40%, #FFD60A 60%, var(--ok) 80%)");
    expect(root).toMatch(/--wash-identity:[^;]*var\(--identity[^;]*22%/);
  });

  it("lightens the identity wash to 14% in the light block", () => {
    expect(light).toMatch(/--wash-identity:[^;]*var\(--identity[^;]*14%/);
  });

  it("declares spacing and radius tokens", () => {
    const space: Record<string, string> = { xxs: "2px", xs: "4px", s: "8px", m: "12px", l: "16px", xl: "24px", xxl: "32px" };
    for (const [name, px] of Object.entries(space)) expect(root).toContain(`--space-${name}: ${px};`);
    expect(root).toContain("--r-chip: 8px;");
    expect(root).toContain("--r-control: 12px;");
    expect(root).toContain("--r-card: 18px;");
    expect(root).toContain("--r-sheet: 26px;");
    expect(root).toContain("--r-s: var(--r-chip);");
    expect(root).toContain("--r-m: var(--r-control);");
    expect(root).toContain("--r-l: var(--r-control);");
  });

  it("flattens every wash under increased contrast and reduced transparency", () => {
    const declared = [...root.matchAll(/(--wash-[a-z-]+):/g)].map((m) => m[1]);
    expect(declared.sort()).toEqual(["--wash-accent", "--wash-alert-danger", "--wash-identity", "--wash-scale"]);
    for (const name of declared) expect(contrast, name).toContain(`${name}:`);
    expect(contrast).toContain("--wash-accent: var(--accent);");
    expect(contrast).toContain("--wash-alert-danger: var(--danger);");
    expect(contrast).toContain("--wash-scale: none;");
    expect(contrast).toContain("--wash-identity: transparent;");
    expect(contrast).not.toContain("gradient(");
    // The light block also sets --wash-identity: the flat fallback must come after it to win.
    expect(css.indexOf("@media (prefers-contrast: more)")).toBeGreaterThan(css.indexOf("@media (prefers-color-scheme: light)"));
  });

  it("keeps meaningless gradients out of the sheet", () => {
    const stray = css.split("\n").filter((l) => /linear-gradient\(/.test(l) && !/--wash-/.test(l));
    expect(stray).toEqual([]);
    // Any radial or conic gradient, whatever its form. The only ones allowed are the hard-stop
    // concave corners of the overflow tab, a shape and not a wash.
    const shaped = css.split("\n").filter((l) => /(radial|conic)-gradient\(/.test(l) && !/^\.ov-others::(before|after) /.test(l));
    expect(shaped).toEqual([]);
  });
});
