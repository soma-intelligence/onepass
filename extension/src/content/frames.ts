// The in-page shell (spec 8.3): one `<onepass-root>` host appended to
// `document.documentElement`, with a CLOSED shadow root holding the field
// icons and the extension frames (menu, overlay, save). The page cannot reach
// the shadow root (`host.shadowRoot` is null) and the frames are of another
// origin, so it can read neither the menu nor the overlay (S1). References to
// the root and to the frames live in closures only, never on window/document.
import type { FrameKind } from "../shared/messages";
import { type Geometry, type Rect } from "./detect/visibility";

/** Highest z-index a page can use. */
export const Z_MAX = "2147483647";
/** Width of every extension frame (spec 8.3 "360 px de large"). */
export const FRAME_WIDTH = 360;
/** Fixed frame heights: extension pages scroll inside when they need more. */
export const FRAME_HEIGHT: Readonly<Record<FrameKind, number>> = { menu: 320, overlay: 440, save: 520 };
/** Gap between the anchor field and the menu, and from the viewport edges. */
const GAP = 4;
const EDGE = 12;
const ACCENT = "#5856D6";

const PAGE_OF: Readonly<Record<FrameKind, string>> = { menu: "menu.html", overlay: "overlay.html", save: "save.html" };
const EXTENSION_SCHEMES: ReadonlySet<string> = new Set(["chrome-extension:", "moz-extension:", "safari-web-extension:"]);
const TOKEN_HASH = /^#[A-Za-z0-9_-]{22}$/;

const STYLE = `
:host {
  all: initial !important;
  display: block !important;
  position: fixed !important;
  top: 0 !important;
  left: 0 !important;
  width: 0 !important;
  height: 0 !important;
  margin: 0 !important;
  padding: 0 !important;
  border: 0 !important;
  overflow: visible !important;
  z-index: ${Z_MAX} !important;
  pointer-events: none !important;
  visibility: visible !important;
  opacity: 1 !important;
  transform: none !important;
  filter: none !important;
  contain: none !important;
}
.layer { all: initial; position: fixed; top: 0; left: 0; width: 0; height: 0; pointer-events: none; }
.icon {
  all: initial;
  position: fixed;
  box-sizing: border-box;
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background: ${ACCENT};
  color: #FFFFFF;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  pointer-events: auto;
  box-shadow: 0 1px 2px rgba(0,0,0,.18);
}
.icon[hidden] { display: none; }
.icon svg { display: block; width: 11px; height: 11px; }
.ring {
  all: initial;
  position: fixed;
  box-sizing: border-box;
  border-radius: 8px;
  box-shadow: 0 0 0 3px ${ACCENT}88;
  pointer-events: none;
}
.ring[hidden] { display: none; }
iframe {
  all: initial;
  position: fixed;
  box-sizing: border-box;
  border: 0;
  border-radius: 12px;
  background: transparent;
  color-scheme: normal;
  pointer-events: auto;
  box-shadow: 0 14px 36px rgba(0,0,0,.24);
}
`;

export interface Shell {
  /** Shadow root; only for this content script's own modules and tests. */
  readonly root: ShadowRoot;
  /** Container of icons, highlight ring and frames. */
  readonly layer: HTMLElement;
  /** True for the host element (events retargeted out of the shadow root). */
  isHost(node: EventTarget | null): boolean;
  /** Puts the host back if the page removed it. */
  ensureAttached(): void;
  destroy(): void;
}

export function createShell(doc: Document): Shell {
  const host = doc.createElement("onepass-root");
  // Inline as well: some pages style unknown elements globally.
  host.setAttribute("style", `all: initial !important; position: fixed !important; z-index: ${Z_MAX} !important;`);
  const root = host.attachShadow({ mode: "closed" });
  const style = doc.createElement("style");
  style.textContent = STYLE;
  const layer = doc.createElement("div");
  layer.className = "layer";
  root.append(style, layer);
  const attach = () => {
    const html = doc.documentElement;
    if (html && (host.parentNode !== html || host !== html.lastElementChild)) html.appendChild(host);
  };
  attach();
  return {
    root,
    layer,
    isHost: (node) => node === host,
    ensureAttached: () => {
      if (!host.isConnected) attach();
    },
    destroy: () => host.remove(),
  };
}

/**
 * True when `url` may be loaded as the `kind` frame: an extension scheme, the
 * page of that kind, a token fragment, nothing else; and either under our own
 * `runtime.getURL("")` base or vouched for by the service worker (Chromium
 * `use_dynamic_url` serves the pages from a per-session URL that `getURL` in a
 * content script may not report). A page never supplies these URLs.
 */
export function checkFrameUrl(url: string, kind: FrameKind, base: string, vouched: boolean): string | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (!EXTENSION_SCHEMES.has(u.protocol)) return null;
  if (u.username !== "" || u.password !== "" || u.search !== "") return null;
  if (u.pathname !== `/${PAGE_OF[kind]}` || !TOKEN_HASH.test(u.hash)) return null;
  if (u.href.startsWith(base) || vouched) return u.href;
  return null;
}

export interface FramesOptions {
  shell: Shell;
  doc: Document;
  geometry: Geometry;
}

export interface Frames {
  /** Shows (or replaces) the `kind` frame at an already checked extension URL. */
  showFrame(kind: FrameKind, url: string, anchor?: Element | null): void;
  removeFrame(kind: FrameKind): void;
  has(kind: FrameKind): boolean;
  /** Follows anchors after a scroll or resize. */
  reposition(): void;
  /** Rings the element (chain step), or clears the ring. */
  highlight(el: Element | null): void;
}

export function createFrames(opts: FramesOptions): Frames {
  const { shell, doc, geometry } = opts;
  const frames = new Map<FrameKind, { iframe: HTMLIFrameElement; anchor: Element | null }>();
  let ring: { box: HTMLElement; el: Element } | null = null;

  const viewport = () => {
    const view = doc.defaultView;
    return { w: view?.innerWidth ?? 1024, h: view?.innerHeight ?? 768 };
  };

  const place = (kind: FrameKind, iframe: HTMLIFrameElement, anchor: Element | null) => {
    const { w } = viewport();
    const width = Math.min(FRAME_WIDTH, Math.max(0, w - 2 * EDGE));
    let left = w - width - EDGE;
    let top = EDGE;
    if (kind === "menu" && anchor) {
      const r: Rect = geometry(anchor).rect;
      left = Math.max(EDGE, Math.min(r.left, w - width - EDGE));
      top = r.top + r.height + GAP;
    }
    const s = iframe.style;
    s.setProperty("left", `${Math.round(left)}px`);
    s.setProperty("top", `${Math.round(top)}px`);
    s.setProperty("width", `${width}px`);
    s.setProperty("height", `${FRAME_HEIGHT[kind]}px`);
  };

  const placeRing = () => {
    if (!ring) return;
    const r = geometry(ring.el).rect;
    const s = ring.box.style;
    ring.box.hidden = !ring.el.isConnected || r.width === 0;
    s.setProperty("left", `${Math.round(r.left)}px`);
    s.setProperty("top", `${Math.round(r.top)}px`);
    s.setProperty("width", `${Math.round(r.width)}px`);
    s.setProperty("height", `${Math.round(r.height)}px`);
  };

  return {
    showFrame(kind, url, anchor = null) {
      shell.ensureAttached();
      frames.get(kind)?.iframe.remove();
      const iframe = doc.createElement("iframe");
      // Extension pages need scripts: no `sandbox`. Nothing delegated.
      iframe.setAttribute("allow", "");
      iframe.setAttribute("referrerpolicy", "no-referrer");
      iframe.setAttribute("scrolling", "no");
      iframe.setAttribute("title", "OnePass");
      iframe.setAttribute("src", url);
      place(kind, iframe, anchor);
      shell.layer.appendChild(iframe);
      frames.set(kind, { iframe, anchor });
    },
    removeFrame(kind) {
      frames.get(kind)?.iframe.remove();
      frames.delete(kind);
    },
    has: (kind) => frames.has(kind),
    reposition() {
      for (const [kind, f] of frames) {
        if (f.anchor && !f.anchor.isConnected) {
          f.iframe.remove();
          frames.delete(kind);
          continue;
        }
        place(kind, f.iframe, f.anchor);
      }
      placeRing();
    },
    highlight(el) {
      ring?.box.remove();
      ring = null;
      if (!el) return;
      const box = doc.createElement("div");
      box.className = "ring";
      shell.layer.appendChild(box);
      ring = { box, el };
      placeRing();
    },
  };
}
