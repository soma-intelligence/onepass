// Touch or mouse, for the in-page UI and its frames (fix batch B, IPAD-01). One rule, read by the
// content script (icons, sheet or popover) and by the frame pages (finger-sized rows), so the two
// never disagree.

/** The pointer media queries a change of layout is watched on. */
export const POINTER_QUERIES = ["(pointer: coarse)", "(any-pointer: coarse)", "(any-pointer: fine)"] as const;

function matches(view: Window, query: string): boolean {
  try {
    return view.matchMedia?.(query).matches === true;
  } catch {
    return false;
  }
}

/** An Apple touch device: an iPhone, or an iPad (whose Safari says "Macintosh" and has touch points). */
function appleTouch(view: Window): boolean {
  const nav = view.navigator as (Navigator & { maxTouchPoints?: number }) | undefined;
  if (!nav || !((nav.maxTouchPoints ?? 0) > 1)) return false;
  return /iPhone|iPad|iPod|Mac/.test(nav.platform ?? "");
}

/**
 * A finger may be used: the primary pointer is coarse, or, on an iPhone or iPad only, any pointer
 * is (an iPad with a trackpad keeps its touch screen). A touch laptop whose primary pointer is the
 * mouse (Windows, ChromeOS) and a Mac keep the desktop layout.
 */
export function touchDevice(view: Window | null | undefined): boolean {
  if (!view) return false;
  return matches(view, "(pointer: coarse)") || (matches(view, "(any-pointer: coarse)") && appleTouch(view));
}
