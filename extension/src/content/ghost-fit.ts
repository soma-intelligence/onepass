// Whether the ghost (spec 3.2) can lie over a new-password field, or the menu with its preview row
// opens instead (spec 3.4). The rules run in the spec's order and the first that holds names the
// reason. On a fit, the field's text metrics as the ghost page needs them (`GhostMetrics`): sizes,
// alignment and font, never a value of the field.
import type { GhostMetrics } from "../shared/messages";
import { DESIGN_TOKENS } from "../shared/design-tokens";
import { readLayout } from "./frames";

/** Narrower than this, a field gets the menu (spec 3.4). */
export const MIN_GHOST_WIDTH = 120;

/** A px token of theme.css (the same in both themes); 0 when missing. */
function tokenPx(name: string): number {
  const n = parseFloat(DESIGN_TOKENS.light[name] ?? "");
  return Number.isFinite(n) && n > 0 ? n : 0;
}

/**
 * The width the ghost page draws beside the grey text, taken from the tokens it uses: the pill at
 * its widest (`.ghost-pill` is capped at --ghost-pill-max) and the gap of `.ghost` (--space-xs).
 */
const GHOST_PILL_ROOM = tokenPx("ghost-pill-max") + tokenPx("space-xs");
/** The least width the grey text needs to be read (--ghost-text-min). */
const GHOST_TEXT_MIN = tokenPx("ghost-text-min");

export type GhostFallback = "narrow" | "touch" | "transform" | "indent" | "covered" | "cross_origin" | "sheet";

export type GhostFit = { ok: true; metrics: GhostMetrics } | { ok: false; reason: GhostFallback };

/** The largest font family list the worker takes (router.ts MAX_FONT_FAMILY). */
const MAX_FONT_FAMILY = 256;

const TRANSLATIONS = /^(translate|translateX|translateY|translateZ|translate3d)$/i;

/** True when a computed `transform` value moves the box without turning, scaling or skewing it. */
function translationOnly(value: string): boolean {
  const v = value.trim();
  if (v === "" || v === "none") return true;
  const fns = [...v.matchAll(/([a-zA-Z0-9]+)\(([^)]*)\)/g)];
  if (fns.length === 0) return false;
  for (const [, name, args] of fns) {
    if (TRANSLATIONS.test(name!)) continue;
    const n = args!.split(",").map((x) => parseFloat(x));
    if (n.some((x) => !Number.isFinite(x))) return false;
    // matrix(a, b, c, d, tx, ty): the identity but for the last two.
    if (name === "matrix" && n.length === 6 && n[0] === 1 && n[1] === 0 && n[2] === 0 && n[3] === 1) continue;
    // matrix3d: the identity but for the translation (m41, m42, m43).
    if (name === "matrix3d" && n.length === 16 && n.every((x, i) => i >= 12 && i <= 14 ? true : x === (i % 5 === 0 ? 1 : 0))) continue;
    return false;
  }
  return true;
}

function style(view: Window, el: Element): CSSStyleDeclaration | null {
  try {
    return view.getComputedStyle(el);
  } catch {
    return null;
  }
}

/** The parent element, or across a shadow boundary the shadow root's host; null at the document. */
function parentOf(el: Element): Element | null {
  if (el.parentElement) return el.parentElement;
  const root = el.getRootNode();
  return root instanceof ShadowRoot ? root.host : null;
}

/**
 * The field or one of its ancestors is turned, scaled or skewed (the individual `rotate` and `scale`
 * too). The walk crosses shadow roots: a scaled host moves its shadow tree's field as well.
 */
function transformed(field: Element, view: Window): boolean {
  for (let el: Element | null = field; el; el = parentOf(el)) {
    const cs = style(view, el);
    if (!cs) continue;
    if (!translationOnly(cs.getPropertyValue("transform") || cs.transform || "none")) return true;
    const rotate = cs.getPropertyValue("rotate").trim();
    if (rotate !== "" && rotate !== "none" && parseFloat(rotate) !== 0) return true;
    const scale = cs.getPropertyValue("scale").trim();
    if (scale !== "" && scale !== "none" && !scale.split(/\s+/).every((x) => parseFloat(x) === 1)) return true;
  }
  return false;
}

/** The field sits in a child frame of another origin (reading the top frame's origin throws or differs). */
function crossOrigin(view: Window): boolean {
  try {
    const top = view.top;
    if (!top || top === view) return false;
    return top.location.origin !== view.location.origin;
  } catch {
    return true;
  }
}

function px(v: string, fallback = 0): number {
  const n = parseFloat(v);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function alignOf(cs: CSSStyleDeclaration): GhostMetrics["textAlign"] {
  const rtl = cs.direction === "rtl";
  switch (cs.textAlign) {
    case "right":
      return "right";
    case "center":
    case "-webkit-center":
      return "center";
    case "end":
      return rtl ? "left" : "right";
    case "start":
      return rtl ? "right" : "left";
    case "left":
      return "left";
    default:
      return rtl ? "right" : "left";
  }
}

const unquote = (s: string) => s.trim().replace(/^["']|["']$/g, "").toLowerCase();

/**
 * The field's family list when its first face is not a web font of the page (the ghost's own
 * document cannot load it); null: the ghost's own face.
 */
function familyOf(cs: CSSStyleDeclaration, doc: Document): string | null {
  const list = cs.fontFamily.trim();
  if (list === "") return null;
  const first = unquote(list.split(",")[0] ?? "");
  try {
    const fonts = (doc as Document & { fonts?: Iterable<{ family: string }> }).fonts;
    if (fonts) for (const f of fonts) if (unquote(f.family) === first) return null;
  } catch {
    return null;
  }
  if (list.length <= MAX_FONT_FAMILY) return list;
  // Too long a list: whole families from the front.
  let out = "";
  for (const fam of list.split(",")) {
    const next = out === "" ? fam.trim() : `${out}, ${fam.trim()}`;
    if (next.length > MAX_FONT_FAMILY) break;
    out = next;
  }
  return out === "" ? null : out;
}

/**
 * Spec 3.4, in order: under MIN_GHOST_WIDTH wide, or too little room for the grey text beside the
 * pill (the field's width less its insets, the pill and the gap, under --ghost-text-min); a touch layout (fix round 1 ruling: the frame
 * opens its pill to the pointer on `pointermove`, which a finger never sends, so a tap would land on
 * the field: touch screens get the menu); a transform other than a translation on the field or an
 * ancestor, across shadow roots; a non-zero `text-indent`; partly covered (`occluded`, the occlusion
 * check of occlusion.ts); in a cross-origin child frame; the narrow touch layout (the bottom sheet:
 * a touch layout too, so "touch" takes it first; kept last for the spec's list).
 *
 * `paddingLeft` and `paddingRight` include the field's borders: the ghost covers the border box,
 * so the grey text starts where the caret does.
 */
export function fitGhost(field: HTMLInputElement, view: Window, occluded: (el: Element) => boolean): GhostFit {
  const r = field.getBoundingClientRect();
  if (!(r.width >= MIN_GHOST_WIDTH)) return { ok: false, reason: "narrow" };
  const cs = style(view, field);
  const insetLeft = cs ? px(cs.paddingLeft) + px(cs.borderLeftWidth) : 0;
  const insetRight = cs ? px(cs.paddingRight) + px(cs.borderRightWidth) : 0;
  // Past the minimum width, the pill can still cover the text (lab pass6 site 93, 125 px).
  if (r.width - insetLeft - insetRight - GHOST_PILL_ROOM < GHOST_TEXT_MIN) return { ok: false, reason: "narrow" };
  const layout = readLayout(view);
  if (layout.touch) return { ok: false, reason: "touch" };
  if (transformed(field, view)) return { ok: false, reason: "transform" };
  if (!cs) return { ok: false, reason: "transform" };
  const indent = parseFloat(cs.textIndent);
  if (Number.isFinite(indent) && indent !== 0) return { ok: false, reason: "indent" };
  if (occluded(field)) return { ok: false, reason: "covered" };
  if (crossOrigin(view)) return { ok: false, reason: "cross_origin" };
  if (layout.sheet) return { ok: false, reason: "sheet" };
  const fontSize = px(cs.fontSize, 13);
  const lh = parseFloat(cs.lineHeight);
  return {
    ok: true,
    metrics: {
      fontSize,
      // "normal": the usual 1.2 of the font size.
      lineHeight: Number.isFinite(lh) && lh > 0 ? lh : Math.round(fontSize * 1.2 * 100) / 100,
      paddingLeft: insetLeft,
      paddingRight: insetRight,
      textAlign: alignOf(cs),
      fontFamily: familyOf(cs, field.ownerDocument),
      box: { x: r.left, y: r.top, width: r.width, height: r.height },
    },
  };
}
