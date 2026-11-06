// Other password managers' in-page UI (founder, 2026-11-03): their save
// prompt or notification in the top right corner, their in-field buttons.
// OnePass never sits under them nor covers them: the save card stacks below
// theirs (or to its left when there is no room below), our field icon moves
// left of theirs.
//
// Read only, geometry only: elements the extensions inject at the top of the
// document (children of <html> and <body>, one level into an open shadow
// root), recognized by a known tag or attribute of a manager, or, for the
// corner, by their shape: a fixed box of popup size, high z-index. Nothing
// here reads a value or touches the element. Browser chrome (Chrome's save
// bubble, Safari's Keychain sheet) is outside the page and needs nothing.
import type { Rect } from "./detect/visibility";

/** Tags and attributes of the managers' injected UI (1Password, Bitwarden, Dashlane, LastPass, Proton Pass, ...). */
export const KNOWN_TAG = /^(com-1password|onepassword-|bit-|bitwarden|protonpass|dashlane|nordpass|keeper|lastpass|lp-|roboform|enpass|zoho)/i;
export const KNOWN_ID = /(1password|bitwarden|bit-notification|bit-inline|dashlane|lastpass|protonpass|nordpass|keeper|roboform|enpass)/i;
const KNOWN_ATTRS = ["data-dashlanecreated", "data-lastpass-root", "data-lastpass-icon-root", "data-protonpass-role", "data-bitwarden-watching", "data-1p-ignore-host"];

/** The corner zone a save card may share: this far from the right edge and the top. */
export const CORNER_W = 560;
export const CORNER_H = 480;
/** A generic box counts in the corner up to this size (larger: the page's own header or a modal). */
const MAX_W = 480;
const MAX_H = 640;
const MIN_Z = 1000;

export interface OccupantOptions {
  /** Our own host: never an occupant. */
  isOwn: (n: Node) => boolean;
}

function known(el: Element): boolean {
  if (KNOWN_TAG.test(el.localName)) return true;
  if (el.id !== "" && KNOWN_ID.test(el.id)) return true;
  return KNOWN_ATTRS.some((a) => el.hasAttribute(a));
}

function rectOf(el: Element): Rect | null {
  const r = el.getBoundingClientRect();
  if (!(r.width > 1 && r.height > 1)) return null;
  return { left: r.left, top: r.top, width: r.width, height: r.height };
}

function visibleBox(el: Element, view: Window): boolean {
  const cs = view.getComputedStyle(el);
  if (cs.display === "none" || cs.visibility === "hidden" || parseFloat(cs.opacity) === 0) return false;
  return true;
}

/** Top-of-document elements an extension may have injected: children of <html>, of <body>, and one level into open shadow roots. */
function injected(doc: Document, opts: OccupantOptions): Element[] {
  const out: Element[] = [];
  const add = (parent: Element | null) => {
    if (!parent) return;
    for (const el of Array.from(parent.children)) {
      if (opts.isOwn(el) || el.localName === "head" || el.localName === "body" || el.localName === "script" || el.localName === "style") continue;
      out.push(el);
    }
  };
  add(doc.documentElement);
  add(doc.body);
  return out;
}

/** The boxes of an element and of what its open shadow root holds (a 0x0 host with fixed children, as ours). */
function boxes(el: Element): { el: Element; rect: Rect }[] {
  const out: { el: Element; rect: Rect }[] = [];
  const r = rectOf(el);
  if (r) out.push({ el, rect: r });
  const sr = (el as Element & { shadowRoot: ShadowRoot | null }).shadowRoot;
  if (sr) {
    for (const c of Array.from(sr.children)) {
      const cr = rectOf(c);
      if (cr) out.push({ el: c, rect: cr });
      for (const g of Array.from(c.children)) {
        const gr = rectOf(g);
        if (gr) out.push({ el: g, rect: gr });
      }
    }
  }
  return out;
}

function zIndex(el: Element, view: Window): number {
  const z = parseInt(view.getComputedStyle(el).zIndex, 10);
  return Number.isFinite(z) ? z : 0;
}

/**
 * Other managers' boxes in the top right corner of the viewport: known UI
 * anywhere there, or a generic fixed box of popup size and high z-index.
 */
export function cornerOccupants(doc: Document, opts: OccupantOptions): Rect[] {
  const view = doc.defaultView;
  if (!view) return [];
  const w = view.innerWidth;
  const out: Rect[] = [];
  for (const el of injected(doc, opts)) {
    const isKnown = known(el);
    for (const b of boxes(el)) {
      const r = b.rect;
      if (r.left + r.width < w - CORNER_W || r.top > CORNER_H || r.top + r.height < 0) continue;
      if (!visibleBox(b.el, view)) continue;
      if (!isKnown) {
        const pos = view.getComputedStyle(b.el).position;
        if (pos !== "fixed" && pos !== "absolute") continue;
        if (r.width > MAX_W || r.height > MAX_H) continue;
        if (Math.max(zIndex(b.el, view), zIndex(el, view)) < MIN_Z) continue;
      }
      out.push(r);
    }
  }
  return out;
}

/** Known managers' boxes that overlap `zone` (their in-field buttons near our icon). */
export function knownOccupantsIn(doc: Document, zone: Rect, opts: OccupantOptions): Rect[] {
  const view = doc.defaultView;
  if (!view) return [];
  const out: Rect[] = [];
  for (const el of injected(doc, opts)) {
    if (!known(el)) continue;
    for (const b of boxes(el)) {
      if (overlaps(b.rect, zone, 0) && visibleBox(b.el, view)) out.push(b.rect);
    }
  }
  return out;
}

export function overlaps(a: Rect, b: Rect, gap: number): boolean {
  return a.left < b.left + b.width + gap && b.left < a.left + a.width + gap && a.top < b.top + b.height + gap && b.top < a.top + a.height + gap;
}

/**
 * Where a `width` x `height` card goes at the top right without touching any
 * of `taken`: moved below what it would overlap, or, when the viewport has no
 * room below, to the left of it. `edge`: distance to the viewport edges.
 */
export function stackInCorner(
  start: { left: number; top: number },
  size: { width: number; height: number },
  taken: readonly Rect[],
  viewport: { w: number; h: number },
  gap: number,
  edge: number,
): { left: number; top: number } {
  let { left, top } = start;
  // At most one move per occupant (a fixed point; never loops).
  for (let i = 0; i <= taken.length; i++) {
    const me: Rect = { left, top, width: size.width, height: size.height };
    const hit = taken.filter((r) => overlaps(me, r, gap));
    if (hit.length === 0) break;
    const bottom = Math.max(...hit.map((r) => r.top + r.height));
    if (bottom + gap + size.height <= viewport.h - edge) {
      top = bottom + gap;
    } else {
      top = start.top;
      left = Math.min(...hit.map((r) => r.left)) - gap - size.width;
      if (left < edge) {
        // No room anywhere: back to the corner, under nothing (we are in the top layer).
        return start;
      }
    }
  }
  return { left, top };
}
