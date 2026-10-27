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
  border-radius: 6px;
  background: ${ACCENT};
  color: #FFFFFF;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  pointer-events: auto;
  box-shadow: 0 1px 2px rgba(0,0,0,.22), inset 0 1px 0 rgba(255,255,255,.22);
  transition: transform .12s ease, background-color .12s ease;
}
.icon:hover { background: #6765E2; transform: scale(1.08); }
.icon:active { transform: scale(.94); }
.icon[hidden] { display: none; }
.icon svg { display: block; width: 12px; height: 12px; }
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
  border-radius: 14px;
  background: transparent;
  color-scheme: normal;
  pointer-events: auto;
  box-shadow: 0 0 0 .5px rgba(0,0,0,.18), 0 16px 40px rgba(0,0,0,.28);
}
`;

export interface Shell {
  /** Shadow root; only for this content script's own modules and tests. */
  readonly root: ShadowRoot;
  /** Container of icons, highlight ring and frames. */
  readonly layer: HTMLElement;
  /** True for the host element (events retargeted out of the shadow root). */
  isHost(node: EventTarget | null): boolean;
  /**
   * Puts the host back as the last child of `<html>` if the page removed,
   * re-parented or covered it with a later sibling. True when it moved.
   */
  ensureAttached(): boolean;
  /** Registers a callback run after the host was moved back. */
  onReattach(cb: () => void): void;
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
  const reattached: (() => void)[] = [];
  const attach = (): boolean => {
    const html = doc.documentElement;
    if (!html || (host.parentNode === html && host === html.lastElementChild)) return false;
    html.appendChild(host);
    return true;
  };
  attach();
  return {
    root,
    layer,
    isHost: (node) => node === host,
    ensureAttached: () => {
      const moved = attach();
      if (moved) for (const cb of reattached) cb();
      return moved;
    },
    onReattach: (cb) => void reattached.push(cb),
    destroy: () => host.remove(),
  };
}

/**
 * The checked URL when `url` may be loaded as the `kind` frame, else null:
 * the scheme of our own `runtime.getURL("")` base, the page of that kind, a
 * token fragment, nothing else; and our own extension host. Only on Chromium
 * (`chrome-extension:`), where `use_dynamic_url` serves the pages from a
 * per-session host that `getURL` in a content script may not report, another
 * host is accepted, and only when `vouched`: the URL is exactly the one the
 * service worker returned for this frame. A page never supplies these URLs.
 */
export function checkFrameUrl(url: string, kind: FrameKind, base: string, vouched: boolean): string | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  let own: URL;
  try {
    own = new URL(base);
  } catch {
    return null;
  }
  if (!EXTENSION_SCHEMES.has(u.protocol) || u.protocol !== own.protocol) return null;
  if (u.username !== "" || u.password !== "" || u.search !== "") return null;
  if (u.pathname !== `/${PAGE_OF[kind]}` || !TOKEN_HASH.test(u.hash)) return null;
  if (u.host === own.host && own.host !== "") return u.href;
  if (u.protocol === "chrome-extension:" && vouched && u.href === url) return u.href;
  return null;
}

export interface FramesOptions {
  shell: Shell;
  doc: Document;
  geometry: Geometry;
}

/** Clicks into a frame are ignored this long after it moved (spec 8.3). */
export const MOVE_GUARD_MS = 300;

export interface Frames {
  /** Shows (or replaces) the `kind` frame at an already checked extension URL. */
  showFrame(kind: FrameKind, url: string, anchor?: Element | null): void;
  removeFrame(kind: FrameKind): void;
  has(kind: FrameKind): boolean;
  /** Follows anchors after a scroll or resize. */
  reposition(): void;
  /** Rings the element (chain step), or clears the ring. */
  highlight(el: Element | null): void;
  destroy(): void;
}

export function createFrames(opts: FramesOptions): Frames {
  const { shell, doc, geometry } = opts;
  const frames = new Map<FrameKind, { iframe: HTMLIFrameElement; anchor: Element | null }>();
  let ring: { box: HTMLElement; el: Element } | null = null;
  const guards = new Map<HTMLIFrameElement, ReturnType<typeof setTimeout>>();

  /**
   * Anti-clickjacking (spec 8.3): the menu cannot see its own position, so
   * the content script makes a frame ignore pointer input for 300 ms after
   * any change of its position or size, and after the host moved back.
   */
  const guard = (iframe: HTMLIFrameElement) => {
    const prev = guards.get(iframe);
    if (prev !== undefined) clearTimeout(prev);
    iframe.style.setProperty("pointer-events", "none");
    guards.set(
      iframe,
      setTimeout(() => {
        guards.delete(iframe);
        iframe.style.removeProperty("pointer-events");
      }, MOVE_GUARD_MS),
    );
  };
  const drop = (iframe: HTMLIFrameElement) => {
    const t = guards.get(iframe);
    if (t !== undefined) clearTimeout(t);
    guards.delete(iframe);
    iframe.remove();
  };
  shell.onReattach(() => {
    for (const f of frames.values()) guard(f.iframe);
  });

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
    const next = [`${Math.round(left)}px`, `${Math.round(top)}px`, `${width}px`, `${FRAME_HEIGHT[kind]}px`];
    const props = ["left", "top", "width", "height"];
    const changed = props.some((p, i) => s.getPropertyValue(p) !== next[i]);
    props.forEach((p, i) => s.setProperty(p, next[i] as string));
    return changed;
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
      const old = frames.get(kind);
      if (old) drop(old.iframe);
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
      const f = frames.get(kind);
      if (f) drop(f.iframe);
      frames.delete(kind);
    },
    has: (kind) => frames.has(kind),
    reposition() {
      for (const [kind, f] of frames) {
        if (f.anchor && !f.anchor.isConnected) {
          drop(f.iframe);
          frames.delete(kind);
          continue;
        }
        if (place(kind, f.iframe, f.anchor)) guard(f.iframe);
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
    destroy() {
      for (const f of frames.values()) drop(f.iframe);
      frames.clear();
      ring?.box.remove();
      ring = null;
    },
  };
}
