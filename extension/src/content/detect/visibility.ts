// Visibility rules of spec 8.2. Layout goes through a `Geometry` function so
// tests can stub it (jsdom has no layout engine).

export interface Rect {
  left: number;
  top: number;
  width: number;
  height: number;
}

export interface Layout {
  rect: Rect;
  viewport: { width: number; height: number };
}

export type Geometry = (el: Element) => Layout;

/** Minimum rendered width and height, in CSS pixels. */
export const MIN_SIZE_PX = 4;
/** How far outside the viewport an element may sit before it is ignored. */
export const MAX_OFFSCREEN_PX = 2000;
/** Cumulative opacity below which an element is ignored. */
export const MIN_OPACITY = 0.1;

export const domGeometry: Geometry = (el) => {
  const r = el.getBoundingClientRect();
  const view = el.ownerDocument.defaultView;
  return {
    rect: { left: r.left, top: r.top, width: r.width, height: r.height },
    viewport: { width: view?.innerWidth ?? 0, height: view?.innerHeight ?? 0 },
  };
};

function styleOf(el: Element): CSSStyleDeclaration | null {
  return el.ownerDocument.defaultView?.getComputedStyle(el) ?? null;
}

/**
 * Rendered and perceivable: not display:none (self or ancestor), not
 * visibility:hidden, cumulative opacity >= 0.1, at least 4x4 px, not more than
 * 2000 px outside the viewport, not aria-hidden (self or ancestor).
 * Applies to any element (buttons, list entries, fields).
 */
export function isRendered(el: Element, geometry: Geometry = domGeometry): boolean {
  if (el.closest('[aria-hidden="true"]')) return false;
  const own = styleOf(el);
  // `visibility` is inherited, so the element's own computed value covers ancestors.
  if (own && (own.visibility === "hidden" || own.visibility === "collapse")) return false;
  let opacity = 1;
  for (let n: Element | null = el; n; n = n.parentElement) {
    const s = styleOf(n);
    if (!s) continue;
    if (s.display === "none") return false;
    const o = Number.parseFloat(s.opacity);
    if (Number.isFinite(o)) opacity *= o;
    if (opacity < MIN_OPACITY) return false;
  }
  const { rect, viewport } = geometry(el);
  if (rect.width < MIN_SIZE_PX || rect.height < MIN_SIZE_PX) return false;
  if (rect.left + rect.width < -MAX_OFFSCREEN_PX) return false;
  if (rect.top + rect.height < -MAX_OFFSCREEN_PX) return false;
  if (rect.left > viewport.width + MAX_OFFSCREEN_PX) return false;
  if (rect.top > viewport.height + MAX_OFFSCREEN_PX) return false;
  return true;
}

/** Fillable field check: rendered, enabled, writable, not type=hidden. */
export function isVisible(el: Element, geometry: Geometry = domGeometry): boolean {
  if (el instanceof HTMLInputElement) {
    if (el.type === "hidden" || el.readOnly) return false;
  }
  if (el.matches(":disabled")) return false;
  return isRendered(el, geometry);
}
