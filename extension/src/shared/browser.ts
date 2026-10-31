// The only module allowed to touch the `chrome` / `browser` globals.
// Safari and Firefox expose `browser`; Chromium exposes `chrome`.
const g = globalThis as unknown as { browser?: typeof chrome; chrome?: typeof chrome };

export const ext: typeof chrome = (g.browser ?? g.chrome) as typeof chrome;

/**
 * `chrome.dom.openOrClosedShadowRoot` (Chromium content scripts only): the
 * shadow root of a page element, open or closed. Null where the browser does
 * not have it (Firefox and Safari builds): closed roots then stay out of reach.
 */
export const openOrClosedShadowRoot: ((el: Element) => ShadowRoot | null) | null = (() => {
  const dom = (g.chrome ?? g.browser)?.dom as { openOrClosedShadowRoot?: (el: HTMLElement) => ShadowRoot | null } | undefined;
  const fn = dom?.openOrClosedShadowRoot;
  if (typeof fn !== "function") return null;
  return (el: Element) => (el instanceof HTMLElement ? fn.call(dom, el) : el.shadowRoot);
})();
