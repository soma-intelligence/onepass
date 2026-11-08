// Visibility rules of spec 8.2. Layout goes through a `Geometry` function so
// tests can stub it (jsdom has no layout engine).

import { composedParent, hostOf, MAX_SHADOW_DEPTH } from "./shadow";

export interface Rect {
  left: number;
  top: number;
  width: number;
  height: number;
}

export interface Layout {
  /** Viewport-relative rectangle (as `getBoundingClientRect`). */
  rect: Rect;
  /** Page scroll offset, to turn `rect` into document coordinates. */
  scroll: { x: number; y: number };
  /** Width of the scrollable document. */
  scrollWidth: number;
}

export type Geometry = (el: Element) => Layout;

/** Minimum rendered width and height, in CSS pixels. */
export const MIN_SIZE_PX = 4;
/**
 * How far outside the document (left, above, or right) an element may sit
 * before it is ignored. No limit downward: long pages are legitimate.
 */
export const MAX_OFFSCREEN_PX = 2000;
/** Cumulative opacity below which an element is ignored. */
export const MIN_OPACITY = 0.1;
/** Most ancestors inspected for clipping and styles (hostile deep trees). */
export const MAX_ANCESTORS = 64;

export const domGeometry: Geometry = (el) => {
  const r = el.getBoundingClientRect();
  const doc = el.ownerDocument;
  const view = doc.defaultView;
  return {
    rect: { left: r.left, top: r.top, width: r.width, height: r.height },
    scroll: { x: view?.scrollX ?? 0, y: view?.scrollY ?? 0 },
    scrollWidth: doc.documentElement?.scrollWidth ?? 0,
  };
};

const ARIA_HIDDEN = '[aria-hidden="true" i]';

function styleOf(el: Element): CSSStyleDeclaration | null {
  return el.ownerDocument.defaultView?.getComputedStyle(el) ?? null;
}

/** `clip-path: inset(100%)` (or more) or `clip: rect(0 0 0 0)` style hiding. */
function isClippedAway(s: CSSStyleDeclaration): boolean {
  const clipPath = s.getPropertyValue("clip-path").replace(/\s+/g, "");
  const inset = /^inset\((\d+(?:\.\d+)?)%/.exec(clipPath);
  if (inset && Number(inset[1]) >= 50) return true;
  const clip = s.getPropertyValue("clip").replace(/\s+/g, "");
  if (/^rect\(/.test(clip)) {
    const nums = clip.match(/-?\d+(\.\d+)?/g)?.map(Number) ?? [];
    const [top = 0, right = 0, bottom = 0, left = 0] = nums;
    if (right - left < MIN_SIZE_PX || bottom - top < MIN_SIZE_PX) return true;
  }
  return false;
}

/** Overflow values, including the per-axis ones when the engine reports them. */
function overflows(s: CSSStyleDeclaration): string[] {
  return [s.overflow, s.getPropertyValue("overflow-x"), s.getPropertyValue("overflow-y")]
    .flatMap((v) => v.split(/\s+/))
    .filter((v) => v !== "");
}

function intersect(a: Rect, b: Rect): Rect {
  const left = Math.max(a.left, b.left);
  const top = Math.max(a.top, b.top);
  const right = Math.min(a.left + a.width, b.left + b.width);
  const bottom = Math.min(a.top + a.height, b.top + b.height);
  return { left, top, width: Math.max(0, right - left), height: Math.max(0, bottom - top) };
}

const tooSmall = (r: Rect) => r.width < MIN_SIZE_PX || r.height < MIN_SIZE_PX;

/**
 * Rendered and perceivable: not display:none (self or ancestor), not
 * visibility:hidden, cumulative opacity >= 0.1, not clipped away
 * (clip-path, clip, or an overflow-clipping ancestor), at least 4x4 px, not
 * more than 2000 px left of, above, or right of the document, not aria-hidden
 * (self or ancestor). Applies to any element (buttons, list entries, fields).
 */
export function isRendered(el: Element, geometry: Geometry = domGeometry): boolean {
  // Ancestors are read across shadow boundaries: a field in a shadow root is
  // hidden by its host's ancestors too.
  for (let t: Element | null = el, i = 0; t && i <= MAX_SHADOW_DEPTH; t = hostOf(t), i++) {
    if (t.closest(ARIA_HIDDEN)) return false;
  }
  const own = styleOf(el);
  // `visibility` is inherited, so the element's own computed value covers ancestors.
  if (own && (own.visibility === "hidden" || own.visibility === "collapse")) return false;

  const layout = geometry(el);
  let visible = layout.rect;
  if (tooSmall(visible)) return false;

  const doc = el.ownerDocument;
  let opacity = 1;
  let n: Element | null = el;
  for (let i = 0; n && i < MAX_ANCESTORS; n = composedParent(n), i++) {
    const s = styleOf(n);
    if (!s) continue;
    if (s.display === "none") return false;
    if (isClippedAway(s)) return false;
    const o = Number.parseFloat(s.opacity);
    if (Number.isFinite(o)) opacity *= o;
    if (opacity < MIN_OPACITY) return false;
    // The page scroller itself never clips its content.
    if (n === el || n === doc.body || n === doc.documentElement) continue;
    const ov = overflows(s);
    if (ov.some((v) => v === "hidden" || v === "clip")) {
      visible = intersect(visible, geometry(n).rect);
      if (tooSmall(visible)) return false;
    } else if (ov.some((v) => v === "auto" || v === "scroll")) {
      // A scroll container may legitimately scroll a field out of view; only
      // a collapsed one hides it.
      if (tooSmall(geometry(n).rect)) return false;
    }
  }

  const { rect, scroll, scrollWidth } = layout;
  const docLeft = rect.left + scroll.x;
  const docTop = rect.top + scroll.y;
  if (docLeft + rect.width < -MAX_OFFSCREEN_PX) return false;
  if (docTop + rect.height < -MAX_OFFSCREEN_PX) return false;
  if (docLeft > scrollWidth + MAX_OFFSCREEN_PX) return false;
  return true;
}

/** Fillable field check: rendered, enabled, writable, not type=hidden. */
export function isVisible(el: Element, geometry: Geometry = domGeometry): boolean {
  if (el instanceof HTMLInputElement && el.type === "hidden") return false;
  if ((el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) && el.readOnly) return false;
  if (el.matches(":disabled")) return false;
  return isRendered(el, geometry);
}

// ---- identity documents and personal data (security review M4) ----

/**
 * Thresholds of `isPerceivable`, stricter than `isRendered`'s (4x4 px, opacity 0.1, no limit
 * downward), so a form cannot hide extra fields the user would never notice being filled:
 * - at least 10x10 px of the field inside the viewport: a field the user can see and click
 *   (the smallest native checkbox or radio is about 13 px);
 * - cumulative opacity at least 0.5: a field faded to near nothing is not one the user reads;
 * - the hit test at the center of that visible part finds the field itself (or its label, or our
 *   own icon), not an element laid over it.
 */
export const PERCEIVABLE_MIN_PX = 10;
export const PERCEIVABLE_MIN_OPACITY = 0.5;

/** The topmost element at a viewport point, seen from `el`'s document or shadow root; undefined without hit testing. */
export type FieldHitTest = (el: Element, x: number, y: number) => Element | null | undefined;

/** `elementFromPoint` of the field's own root (a shadow root answers with its own elements). */
export const domFieldHitTest: FieldHitTest = (el, x, y) => {
  const root = el.getRootNode() as Partial<DocumentOrShadowRoot>;
  return typeof root.elementFromPoint === "function" ? root.elementFromPoint(x, y) : undefined;
};

export interface PerceivableOptions {
  hitTest?: FieldHitTest;
  /** Our own host (its icon sits on the field). */
  isOwn?: (el: Element) => boolean;
}

/** Cumulative opacity of `el` and its ancestors (across shadow roots), bounded. */
function cumulativeOpacity(el: Element): number {
  let opacity = 1;
  let n: Element | null = el;
  for (let i = 0; n && i < MAX_ANCESTORS; n = composedParent(n), i++) {
    const s = styleOf(n);
    const o = s ? Number.parseFloat(s.opacity) : Number.NaN;
    if (Number.isFinite(o)) opacity *= o;
  }
  return opacity;
}

/**
 * For identity documents (passport, licence, loyalty) and personal data: a fillable field
 * (`isVisible`) that the user can perceive right now, by the PERCEIVABLE_* thresholds: in the
 * viewport, large enough, opaque enough, and not covered.
 */
export function isPerceivable(el: Element, geometry: Geometry = domGeometry, opts: PerceivableOptions = {}): boolean {
  if (!isVisible(el, geometry)) return false;
  const view = el.ownerDocument.defaultView;
  const vw = view?.innerWidth ?? 0;
  const vh = view?.innerHeight ?? 0;
  const seen = intersect(geometry(el).rect, { left: 0, top: 0, width: vw, height: vh });
  if (seen.width < PERCEIVABLE_MIN_PX || seen.height < PERCEIVABLE_MIN_PX) return false;
  if (cumulativeOpacity(el) < PERCEIVABLE_MIN_OPACITY) return false;
  const hit = (opts.hitTest ?? domFieldHitTest)(el, seen.left + seen.width / 2, seen.top + seen.height / 2);
  // No hit testing in this engine: the other rules only.
  if (hit === undefined) return true;
  if (hit === null) return false;
  if (hit === el || el.contains(hit) || opts.isOwn?.(hit) === true) return true;
  const labels = (el as Partial<HTMLInputElement>).labels;
  return labels ? Array.from(labels).some((l) => l === hit || l.contains(hit)) : false;
}

