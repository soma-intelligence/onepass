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
/**
 * Largest frame heights: each page asks for its content height (a resize
 * message vouched by the worker) and scrolls inside past these.
 */
export const FRAME_HEIGHT: Readonly<Record<FrameKind, number>> = { menu: 420, overlay: 440, save: 520 };
/** Smallest height a page may ask for. */
export const FRAME_MIN_HEIGHT = 44;
/**
 * A frame stays transparent until its page reported its height, so it never
 * shows at a guessed size and then jumps; past this delay it shows anyway.
 */
export const REVEAL_TIMEOUT_MS = 400;
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
  opacity: 0;
  transform: translateY(-4px) scale(.98);
  transform-origin: top left;
  transition: opacity 160ms cubic-bezier(.23, 1, .32, 1), transform 200ms cubic-bezier(.23, 1, .32, 1);
}
iframe.corner { transform-origin: top right; }
iframe.shown { opacity: 1; transform: none; }
@media (prefers-reduced-motion: reduce) {
  iframe { transform: none; transition: opacity 120ms ease; }
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
  /**
   * Removes the frame. When the focus was inside it (the user was in the
   * menu), it goes back to the field the frame was anchored to.
   */
  removeFrame(kind: FrameKind): void;
  has(kind: FrameKind): boolean;
  /** Sizes the frame to its page's content (clamped), and shows it. */
  resize(kind: FrameKind, height: number): void;
  /** Moves the keyboard focus into the frame (the user pressed a key to enter it). */
  focus(kind: FrameKind): void;
  /** The element the frame is anchored to, if any. */
  anchorOf(kind: FrameKind): Element | null;
  /** Follows anchors after a scroll or resize. */
  reposition(): void;
  /** Rings the element (chain step), or clears the ring. */
  highlight(el: Element | null): void;
  destroy(): void;
}

export function createFrames(opts: FramesOptions): Frames {
  const { shell, doc, geometry } = opts;
  const frames = new Map<FrameKind, { iframe: HTMLIFrameElement; anchor: Element | null; height: number; reveal: ReturnType<typeof setTimeout> | null }>();
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
  const show = (f: { iframe: HTMLIFrameElement; reveal: ReturnType<typeof setTimeout> | null }) => {
    if (f.reveal !== null) clearTimeout(f.reveal);
    f.reveal = null;
    if (f.iframe.classList.contains("shown")) return;
    f.iframe.classList.add("shown");
    // Appearing under the pointer counts as a move.
    guard(f.iframe);
  };
  shell.onReattach(() => {
    for (const f of frames.values()) guard(f.iframe);
  });

  const viewport = () => {
    const view = doc.defaultView;
    return { w: view?.innerWidth ?? 1024, h: view?.innerHeight ?? 768 };
  };

  /**
   * Under the anchor (the menu, or the overlay of a chain started from a
   * field), or above it when the viewport has no room below; else the top
   * right. True when the position, the width or a larger height changed (a
   * smaller height brings nothing new under the pointer).
   */
  const place = (kind: FrameKind, iframe: HTMLIFrameElement, anchor: Element | null, height: number) => {
    const { w, h: vh } = viewport();
    const width = Math.min(FRAME_WIDTH, Math.max(0, w - 2 * EDGE));
    let left = w - width - EDGE;
    let top = EDGE;
    if (anchor && kind !== "save") {
      const r: Rect = geometry(anchor).rect;
      left = Math.max(EDGE, Math.min(r.left, w - width - EDGE));
      top = r.top + r.height + GAP;
      const above = r.top - GAP - height;
      if (top + height > vh - EDGE && above >= EDGE) top = above;
    }
    iframe.classList.toggle("corner", !(anchor && kind !== "save"));
    const s = iframe.style;
    const prevHeight = parseFloat(s.getPropertyValue("height")) || 0;
    const next = [`${Math.round(left)}px`, `${Math.round(top)}px`, `${width}px`, `${height}px`];
    const props = ["left", "top", "width", "height"];
    const changed = props.slice(0, 3).some((p, i) => s.getPropertyValue(p) !== next[i]) || height > prevHeight;
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
      const height = FRAME_HEIGHT[kind];
      place(kind, iframe, anchor, height);
      shell.layer.appendChild(iframe);
      const f = { iframe, anchor, height, reveal: null as ReturnType<typeof setTimeout> | null };
      f.reveal = setTimeout(() => show(f), REVEAL_TIMEOUT_MS);
      frames.set(kind, f);
    },
    removeFrame(kind) {
      const f = frames.get(kind);
      if (!f) return;
      const focused = shell.root.activeElement === f.iframe;
      if (f.reveal !== null) clearTimeout(f.reveal);
      drop(f.iframe);
      frames.delete(kind);
      if (focused && f.anchor?.isConnected && typeof (f.anchor as HTMLElement).focus === "function") {
        (f.anchor as HTMLElement).focus({ preventScroll: true });
      }
    },
    has: (kind) => frames.has(kind),
    resize(kind, height) {
      const f = frames.get(kind);
      if (!f || !Number.isFinite(height)) return;
      f.height = Math.round(Math.min(FRAME_HEIGHT[kind], Math.max(FRAME_MIN_HEIGHT, height)));
      const moved = place(kind, f.iframe, f.anchor, f.height);
      if (f.iframe.classList.contains("shown")) {
        if (moved) guard(f.iframe);
      } else {
        show(f);
      }
    },
    focus(kind) {
      frames.get(kind)?.iframe.focus({ preventScroll: true });
    },
    anchorOf: (kind) => frames.get(kind)?.anchor ?? null,
    reposition() {
      for (const [kind, f] of frames) {
        if (f.anchor && !f.anchor.isConnected) {
          if (kind === "menu") {
            if (f.reveal !== null) clearTimeout(f.reveal);
            drop(f.iframe);
            frames.delete(kind);
            continue;
          }
          // The progress outlives the field it started from: to the top right.
          f.anchor = null;
        }
        if (place(kind, f.iframe, f.anchor, f.height)) guard(f.iframe);
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
      for (const f of frames.values()) {
        if (f.reveal !== null) clearTimeout(f.reveal);
        drop(f.iframe);
      }
      frames.clear();
      ring?.box.remove();
      ring = null;
    },
  };
}
