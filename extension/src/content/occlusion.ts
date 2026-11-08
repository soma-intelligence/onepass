// Cheap occlusion checks for our in-page UI (spec 8.3, anti-clickjacking), run by the content
// script on every browser.
//
// Our host is the last child of `<html>` at the highest z-index, so no ordinary page element paints
// over it. What can: the top layer (an open popover, a modal dialog, a fullscreen element), and the
// root element's own opacity, filter, mask or clip-path (they apply to every descendant of `<html>`,
// our host included, but not to the top layer, where a decoy then shows at full strength). A cover
// with `pointer-events: none` is invisible to hit testing (`elementFromPoint` skips it), so the top
// layer and the root's styles are checked by themselves; the hit test catches the rest (a cover
// that takes the pointer, an element the page slipped above us before the observer put the host
// back).
//
// Limit: a popover inside a closed shadow root the browser does not let us read (no
// `openOrClosedShadowRoot`: Firefox, Safari) is not seen. Chromium has IntersectionObserver v2,
// which sees every cover; the callers use it there as well.

/** Selectors of top-layer elements: an open popover, a modal dialog. */
const TOP_LAYER_SELECTORS = [":popover-open", ":modal"] as const;

/** Where top-layer elements may sit: the document, and the shadow roots we can read. */
export type Scopes = () => Iterable<ParentNode>;

/** A box in viewport coordinates. */
export interface Box {
  left: number;
  top: number;
  width: number;
  height: number;
}

const overlaps = (a: Box, b: Box): boolean =>
  a.left < b.left + b.width && b.left < a.left + a.width && a.top < b.top + b.height && b.top < a.top + a.height;

/**
 * True when something is in the top layer (it paints above any z-index): a fullscreen element, an
 * open popover or a modal dialog in the document or one of `scopes`. With `near`, only such an
 * element whose bounding box overlaps `near` counts (a toast or chat bubble in another corner
 * covers nothing there). A selector the engine does not know means nothing of that kind can be
 * open.
 */
export function topLayerOpen(doc: Document, scopes?: Scopes, near?: Box): boolean {
  const counts = (el: Element | null | undefined): boolean => {
    if (!el) return false;
    if (!near) return true;
    let r: Box;
    try {
      r = el.getBoundingClientRect();
    } catch {
      return true;
    }
    return overlaps(r, near);
  };
  if (counts(doc.fullscreenElement)) return true;
  const all: ParentNode[] = [doc];
  if (scopes) for (const s of scopes()) all.push(s);
  for (const scope of all) {
    for (const sel of TOP_LAYER_SELECTORS) {
      let found: Element[];
      try {
        found = Array.from(scope.querySelectorAll(sel));
      } catch {
        // Unknown pseudo-class in this engine: no such element can be open.
        continue;
      }
      if (found.some(counts)) return true;
    }
  }
  return false;
}

/**
 * True when the root element's own style dims or hides every descendant, ours included: opacity
 * below 1, a filter, a mask or a clip-path. Same rule as IntersectionObserver v2 `isVisible` for an
 * ancestor (any non-neutral value fails), so a page cannot fade the real page out and leave a
 * decoy in the top layer.
 */
export function rootHidden(doc: Document): boolean {
  const html = doc.documentElement;
  const view = doc.defaultView;
  if (!html || !view) return false;
  let s: CSSStyleDeclaration;
  try {
    s = view.getComputedStyle(html);
  } catch {
    return false;
  }
  const o = Number.parseFloat(s.opacity);
  if (Number.isFinite(o) && o < 1) return true;
  const set = (v: string) => v !== "" && v !== "none";
  return (
    set(s.getPropertyValue("filter")) ||
    set(s.getPropertyValue("mask-image")) ||
    set(s.getPropertyValue("-webkit-mask-image")) ||
    set(s.getPropertyValue("clip-path"))
  );
}

/** The topmost element at a viewport point, as hit testing sees it; undefined where the engine has no hit test. */
export type HitTest = (x: number, y: number) => Element | null | undefined;

/** `document.elementFromPoint` where the engine has it (jsdom does not). */
export function domHitTest(doc: Document): HitTest {
  return (x, y) => (typeof doc.elementFromPoint === "function" ? doc.elementFromPoint(x, y) : undefined);
}

/**
 * False when hit testing at (x, y) finds an element other than our own host (the shadow root is
 * closed, so anything inside it comes back as the host). A point outside the viewport (null) or an
 * engine without hit testing (undefined) tells nothing: true.
 */
export function hostOnTop(hit: HitTest, isOwnHost: (el: Element) => boolean, x: number, y: number): boolean {
  if (!Number.isFinite(x) || !Number.isFinite(y)) return true;
  const el = hit(x, y);
  if (el === null || el === undefined) return true;
  return isOwnHost(el);
}
