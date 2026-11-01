// The only module allowed to touch the `chrome` / `browser` globals.
// Safari and Firefox expose `browser`; Chromium exposes `chrome`.
const g = globalThis as unknown as { browser?: typeof chrome; chrome?: typeof chrome };

export const ext: typeof chrome = (g.browser ?? g.chrome) as typeof chrome;

/** Elements `attachShadow` accepts besides custom elements (DOM standard). */
const SHADOW_HOSTS: ReadonlySet<string> = new Set([
  "article",
  "aside",
  "blockquote",
  "body",
  "div",
  "footer",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "header",
  "main",
  "nav",
  "p",
  "section",
  "span",
]);

/**
 * `chrome.dom.openOrClosedShadowRoot` (Chromium content scripts; Firefox has
 * it as well): the shadow root of a page element, open or closed. Null where
 * the browser does not have it (Safari): closed roots then stay out of reach.
 */
export const openOrClosedShadowRoot: ((el: Element) => ShadowRoot | null) | null = (() => {
  const dom = (g.chrome ?? g.browser)?.dom as { openOrClosedShadowRoot?: (el: HTMLElement) => ShadowRoot | null } | undefined;
  const fn = dom?.openOrClosedShadowRoot;
  if (typeof fn !== "function") return null;
  return (el: Element) => {
    if (el.shadowRoot) return el.shadowRoot;
    // Only these elements can host a root (DOM `attachShadow`): the API is
    // not called for the others, on a walk of up to 3000 elements.
    if (!(el instanceof HTMLElement) || !(el.localName.includes("-") || SHADOW_HOSTS.has(el.localName))) return null;
    return fn.call(dom, el);
  };
})();
