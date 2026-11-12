// Illustrated category icons, after the Mac app's CategoryArtwork: a small
// raised object (darker band under it, flat face, light top edge) drawn in a
// 100 x 100 box. Original drawings in the app's palette; shapes are constants
// of this file, the only data used is one monogram letter set as text.
import { DESIGN_TOKENS } from "../shared/design-tokens";
import { t } from "../shared/i18n";

const SVG_NS = "http://www.w3.org/2000/svg";

export type ArtKind = "login" | "password" | "card" | "identity" | "note" | "generic";

type Shape =
  | ["rect", number, number, number, number, number, string, number?]
  | ["circle", number, number, number, string, number?]
  | ["path", string, string, number?];

/**
 * A colour the pages draw the same in both themes (art, brand marks, vaults): theme.css holds it,
 * shared/design-tokens.ts mirrors it for SVG fills.
 */
export function fixedColor(name: string): string {
  const v = DESIGN_TOKENS.dark[name];
  if (v === undefined) throw new Error(`no design token ${name}`);
  return v;
}

// Palette of the app (Tailwind-like tones) and their shaded bands (mixed 32 % toward ink, as the
// app does), from theme.css.
const WHITE = fixedColor("art-white");
const TEAL = fixedColor("art-teal");
const TEAL_BAND = fixedColor("art-teal-band");
const TEAL_HOLE = fixedColor("art-teal-hole");
const DEEP_TEAL = fixedColor("art-deep-teal");
const DEEP_TEAL_BAND = fixedColor("art-deep-teal-band");
const BLUE = fixedColor("art-blue");
const BLUE_BAND = fixedColor("art-blue-band");
const BLUE_STRIPE = fixedColor("art-blue-stripe");
const GOLD = fixedColor("art-gold");
const GOLD_BAND = fixedColor("art-gold-band");
const GREEN = fixedColor("art-green");
const GREEN_BAND = fixedColor("art-green-band");
const GREEN_TINT = fixedColor("art-green-tint");
const YELLOW = fixedColor("art-yellow");
const YELLOW_BAND = fixedColor("art-yellow-band");
const YELLOW_RULE = fixedColor("art-yellow-rule");
const RED_RULE = fixedColor("art-red-rule");
const SLATE = fixedColor("art-slate");
const SLATE_BAND = fixedColor("art-slate-band");
const STEEL = fixedColor("art-steel");
const STEEL_BAND = fixedColor("art-steel-band");
const STEEL_LINE = fixedColor("art-steel-line");
const CHARCOAL = fixedColor("art-charcoal");
const PAPER = fixedColor("art-paper");
const PAPER_BAND = fixedColor("art-paper-band");

/** A raised slab: band offset below, face, gloss line on the top edge. */
function slab(x: number, y: number, w: number, h: number, r: number, face: string, band: string, depth = 4): Shape[] {
  return [
    ["rect", x, y + depth, w, h, r, band],
    ["rect", x, y, w, h, r, face],
    ["rect", x + r * 0.6, y + 1.2, Math.max(0, w - r * 1.2), 1.6, 0.8, WHITE, 0.4],
  ];
}

const ART: Readonly<Record<ArtKind, Shape[]>> = {
  login: [
    ...slab(12, 12, 76, 74, 22, TEAL, TEAL_BAND),
    ["circle", 50, 42, 12, TEAL_HOLE],
    ["path", "M46 46h8l3 24H43z", TEAL_HOLE],
    ["rect", 43, 68, 14, 2.5, 1, WHITE, 0.35],
  ],
  password: [
    ...slab(8, 28, 84, 42, 16, DEEP_TEAL, DEEP_TEAL_BAND),
    ["circle", 24, 49, 4.5, WHITE],
    ["circle", 37, 49, 4.5, WHITE],
    ["circle", 50, 49, 4.5, WHITE],
    ["circle", 63, 49, 4.5, WHITE],
    ["rect", 76, 39, 3.5, 20, 1.5, WHITE, 0.85],
  ],
  card: [
    ...slab(7, 22, 86, 56, 9, BLUE, BLUE_BAND),
    ["rect", 7, 33, 86, 11, 0, BLUE_STRIPE],
    ["rect", 16, 52.5, 16, 12, 3, GOLD_BAND],
    ["rect", 16, 51, 16, 12, 3, GOLD],
    ["rect", 40, 55, 9, 4, 1.5, WHITE, 0.85],
    ["rect", 52.5, 55, 9, 4, 1.5, WHITE, 0.85],
    ["rect", 65, 55, 9, 4, 1.5, WHITE, 0.85],
    ["rect", 77.5, 55, 9, 4, 1.5, WHITE, 0.85],
    ["rect", 16, 68, 30, 3.5, 1.5, WHITE, 0.55],
  ],
  identity: [
    ...slab(20, 17, 60, 72, 12, GREEN, GREEN_BAND),
    ["circle", 50, 44, 16, WHITE],
    ["circle", 50, 40, 6, GREEN_TINT],
    ["path", "M38 54c2-8 22-8 24 0a16 16 0 0 1-24 0z", GREEN_TINT],
    ["rect", 31, 66, 38, 5, 2.5, WHITE, 0.9],
    ["path", "M34 80c3-5 6-5 9-2s6 3 9-1 6-4 9-1", "none"],
    ...slab(38, 8, 24, 16, 4, STEEL, STEEL_BAND, 2),
    ["rect", 43, 13.5, 14, 4, 2, CHARCOAL, 0.8],
  ],
  note: [
    ...slab(17, 14, 66, 75, 6, YELLOW, YELLOW_BAND),
    ["rect", 24, 36, 52, 2, 1, YELLOW_RULE, 0.55],
    ["rect", 24, 46, 52, 2, 1, YELLOW_RULE, 0.55],
    ["rect", 24, 56, 52, 2, 1, YELLOW_RULE, 0.55],
    ["rect", 24, 66, 52, 2, 1, YELLOW_RULE, 0.55],
    ["rect", 24, 76, 52, 2, 1, YELLOW_RULE, 0.55],
    ["rect", 31, 22, 1.6, 64, 0.8, RED_RULE, 0.55],
    ...slab(13, 8, 74, 15, 4, SLATE, SLATE_BAND, 2.5),
  ],
  generic: [
    ...slab(16, 8, 58, 80, 6, PAPER, PAPER_BAND),
    ["path", "M54.3 8H74v20H54.3z", STEEL_LINE],
    ["rect", 24, 34, 30, 4, 2, STEEL_LINE],
    ["rect", 24, 44, 40, 4, 2, STEEL_LINE],
    ["rect", 24, 54, 34, 4, 2, STEEL_LINE],
    ["rect", 24, 64, 22, 4, 2, STEEL_LINE],
  ],
};

/** Accessible name of a category ("Login", "Carte bancaire"). */
export function artLabel(kind: ArtKind): string {
  switch (kind) {
    case "login":
      return "Login";
    case "password":
      return t("term.password");
    case "card":
      return t("art.creditCard");
    case "identity":
      return t("art.identity");
    case "note":
      return t("art.secureNote");
    default:
      return t("term.item");
  }
}

/**
 * The category icon at `size` px. For logins, `monogram` (one letter) is set
 * on the teal tile in place of the keyhole, as the app does.
 */
export function art(kind: ArtKind, size: number, monogram?: string): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("viewBox", "0 0 100 100");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("class", `art art-${kind}`);
  const letter = kind === "login" ? [...(monogram ?? "").trim()][0]?.toUpperCase() : undefined;
  let shapes = ART[kind];
  if (letter) shapes = shapes.slice(0, 3);
  // Small sizes drop the fine details, like the app below 24 pt.
  const detailed = size >= 24;
  for (const s of shapes) {
    let el: SVGElement;
    if (s[0] === "rect") {
      const [, x, y, w, hh, r, fill, op] = s;
      if (!detailed && hh < 3) continue;
      el = document.createElementNS(SVG_NS, "rect");
      el.setAttribute("x", String(x));
      el.setAttribute("y", String(y));
      el.setAttribute("width", String(w));
      el.setAttribute("height", String(hh));
      el.setAttribute("rx", String(r));
      el.setAttribute("fill", fill);
      if (op !== undefined) el.setAttribute("fill-opacity", String(op));
    } else if (s[0] === "circle") {
      const [, cx, cy, r, fill, op] = s;
      el = document.createElementNS(SVG_NS, "circle");
      el.setAttribute("cx", String(cx));
      el.setAttribute("cy", String(cy));
      el.setAttribute("r", String(r));
      el.setAttribute("fill", fill);
      if (op !== undefined) el.setAttribute("fill-opacity", String(op));
    } else {
      const [, d, fill, op] = s;
      if (fill === "none" && !detailed) continue;
      el = document.createElementNS(SVG_NS, "path");
      el.setAttribute("d", d);
      if (fill === "none") {
        el.setAttribute("fill", "none");
        el.setAttribute("stroke", WHITE);
        el.setAttribute("stroke-opacity", "0.75");
        el.setAttribute("stroke-width", "2.2");
        el.setAttribute("stroke-linecap", "round");
      } else {
        el.setAttribute("fill", fill);
        if (op !== undefined) el.setAttribute("fill-opacity", String(op));
      }
    }
    svg.appendChild(el);
  }
  if (letter) {
    const shadow = document.createElementNS(SVG_NS, "text");
    const text = document.createElementNS(SVG_NS, "text");
    for (const [t, dy, fill] of [
      [shadow, 2, TEAL_HOLE],
      [text, 0, WHITE],
    ] as const) {
      t.setAttribute("x", "50");
      t.setAttribute("y", String(49 + dy));
      t.setAttribute("text-anchor", "middle");
      t.setAttribute("dominant-baseline", "central");
      t.setAttribute("font-size", "44");
      t.setAttribute("font-weight", "700");
      t.setAttribute("font-family", 'ui-rounded, "SF Pro Rounded", -apple-system, BlinkMacSystemFont, sans-serif');
      t.setAttribute("fill", fill);
      if (t === shadow) t.setAttribute("fill-opacity", "0.55");
      t.textContent = letter;
      svg.appendChild(t);
    }
  }
  return svg;
}
