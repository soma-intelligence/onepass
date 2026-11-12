// Guard of the design foundation (spec 2026-11-11 fill UI, section 1): the fill surfaces take every
// size and colour from the tokens. theme.css (its `:root` and theme media blocks) and the generated
// shared/design-tokens.ts are the only places a hex colour or an off-scale px value may live.
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Layout sizes that are not on the spacing scale: the frame widths and heights frames.ts exports
 * (FRAME_WIDTHS, FRAME_HEIGHT, SHEET_*, FRAME_MIN_HEIGHT, the ghost's 120 px minimum).
 */
const LAYOUT_PX: ReadonlySet<number> = new Set([340, 360, 380, 420, 430, 440, 480, 520, 560, 600, 160, 44, 120]);
/** The spacing and radius scale, the type scale and the glyph's hit area. */
const SCALE_PX: ReadonlySet<number> = new Set([0, 1, 2, 4, 8, 12, 16, 24, 32, 11, 13, 15, 17, 18, 22, 26]);
const TYPE_PX: ReadonlySet<number> = new Set([11, 12, 13, 15, 17]);

const ROOT = resolve(process.cwd(), "src");
const UI = join(ROOT, "ui");
const LOCALES = ["en", "fr", "es", "it"] as const;
const DEAD_KEYS = ["save.saveLogin", "save.newItem", "save.update1"] as const;

/** `css` without the blocks that follow `header` each time it appears (braces balanced). */
function dropBlocks(css: string, header: string): string {
  let out = css;
  for (let at = out.indexOf(header); at >= 0; at = out.indexOf(header)) {
    const open = out.indexOf("{", at);
    let depth = 0;
    let end = open;
    for (; end < out.length; end++) {
      if (out[end] === "{") depth++;
      if (out[end] === "}" && --depth === 0) break;
    }
    out = out.slice(0, at) + out.slice(end + 1);
  }
  return out;
}

/** The rule bodies of theme.css: no comments, no `:root` token block, no theme media block. */
function themeRules(): string {
  let css = readFileSync(join(UI, "theme.css"), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
  css = dropBlocks(css, "@media (prefers-color-scheme: light)");
  css = dropBlocks(css, "@media (prefers-contrast: more)");
  css = dropBlocks(css, ":root {");
  return css;
}

/** Every guarded source, by its path under src. */
function sources(): [string, string][] {
  const out: [string, string][] = [];
  for (const f of readdirSync(UI).sort()) {
    if (f.endsWith(".ts") || f.endsWith(".html")) out.push([`ui/${f}`, readFileSync(join(UI, f), "utf8")]);
  }
  out.push(["content/frames.ts", readFileSync(join(ROOT, "content/frames.ts"), "utf8")]);
  out.push(["ui/theme.css (rules)", themeRules()]);
  return out;
}

describe("token guard", () => {
  it("has no hex colour outside the token blocks", () => {
    const found: string[] = [];
    for (const [name, text] of sources()) {
      for (const m of text.matchAll(/#[0-9a-fA-F]{3,8}\b/g)) found.push(`${name}: ${m[0]}`);
    }
    expect(found).toEqual([]);
  });

  it("uses only scale sizes", () => {
    const off: string[] = [];
    const fonts: string[] = [];
    for (const [name, text] of sources()) {
      for (const m of text.matchAll(/(\d+(\.\d+)?)px/g)) {
        const v = Number(m[1]);
        if (!SCALE_PX.has(v) && !LAYOUT_PX.has(v)) off.push(`${name}: ${m[0]}`);
      }
      // A literal font size, in a declaration or a `font` shorthand.
      for (const m of text.matchAll(/font(?:-size)?\s*:[^;{}]*?(\d+(\.\d+)?)px/g)) {
        if (!TYPE_PX.has(Number(m[1]))) fonts.push(`${name}: ${m[0]}`);
      }
    }
    expect(off).toEqual([]);
    expect(fonts).toEqual([]);
  });

  it("passkey page has no inline style", () => {
    expect(readFileSync(join(UI, "passkey.html"), "utf8")).not.toMatch(/<style/i);
  });

  it("drops the dead save keys", () => {
    for (const lang of LOCALES) {
      const table = JSON.parse(readFileSync(join(ROOT, `shared/l10n/${lang}.json`), "utf8")) as Record<string, unknown>;
      for (const key of DEAD_KEYS) expect(table[key], `${lang}: ${key}`).toBeUndefined();
    }
  });
});
