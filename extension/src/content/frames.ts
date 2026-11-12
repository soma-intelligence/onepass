// The in-page shell (spec 8.3): one `<onepass-root>` host appended to
// `document.documentElement`, with a CLOSED shadow root holding the field
// icons and the extension frames (menu, overlay, save). The page cannot reach
// the shadow root (`host.shadowRoot` is null) and the frames are of another
// origin, so it can read neither the menu nor the overlay (S1). References to
// the root and to the frames live in closures only, never on window/document.
import { DESIGN_TOKENS } from "../shared/design-tokens";
import { POINTER_QUERIES, touchDevice } from "../shared/layout";
import type { FrameKind } from "../shared/messages";
import { type Geometry, type Rect } from "./detect/visibility";
import { type HitTest, hostOnTop, rootHidden, type Scopes, topLayerOpen } from "./occlusion";
import { stackInCorner } from "./occupants";

/** Highest z-index a page can use. */
export const Z_MAX = "2147483647";
/** Width of the save prompt (spec 8.3 "360 px de large"). */
export const FRAME_WIDTH = 360;
/**
 * Width per frame: the menu's inset list is 380 px; the one-click card is a
 * transparent frame holding the capsule, its detached close button and the
 * room their shadows need.
 */
export const FRAME_WIDTHS: Readonly<Record<FrameKind, number>> = { menu: 380, overlay: 430, save: 340 };
/**
 * Largest frame heights: each page asks for its content height (a resize
 * message vouched by the worker) and scrolls inside past these.
 */
export const FRAME_HEIGHT: Readonly<Record<FrameKind, number>> = { menu: 420, overlay: 440, save: 520 };
/** On a narrow touch screen the menu is a bottom sheet, up to this tall (the unlock sheet fits). */
export const SHEET_HEIGHT = 560;
/** The bottom sheet only below this window width (iPhone, Slide Over, narrow Split View); wider, the menu follows its field. */
export const SHEET_MAX_VIEWPORT = 600;
/** Widest bottom sheet, centered (a 599 px window does not get a sheet from edge to edge). */
export const SHEET_MAX_WIDTH = 480;
/** Under this much room below its field, the sheet goes above the field instead (it never covers it). */
export const SHEET_MIN_HEIGHT = 160;
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
/** Between our save card and another manager's prompt. */
const CARD_GAP = 8;
/** Side of the in-field glyph's hit area, and on a touch screen (icon.ts places it by these). */
export const ICON_SIZE = 22;
export const TOUCH_ICON_SIZE = 28;
/**
 * The design tokens of theme.css, as concrete values: the shadow root cannot read the extension
 * stylesheet, and the `var()` aliases of theme.css mean nothing in it.
 */
const DARK = DESIGN_TOKENS.dark;
const LIGHT = DESIGN_TOKENS.light;

/** The design tokens of a glyph theme. */
export type GlyphTheme = "light" | "dark";

/** Relative luminance (WCAG) of an sRGB colour, channels 0 to 255. */
function luminance(r: number, g: number, b: number): number {
  const lin = (c: number) => {
    const v = c / 255;
    return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

/** Channels and alpha of a computed `rgb()` or `rgba()` colour; null for anything else. */
function rgba(color: string): [number, number, number, number] | null {
  if (!/^rgba?\(/.test(color)) return null;
  const n = color.match(/[\d.]+%?/g);
  if (!n || n.length < 3) return null;
  const alpha = n[3] === undefined ? 1 : n[3].endsWith("%") ? parseFloat(n[3]) / 100 : parseFloat(n[3]);
  return [parseFloat(n[0]!), parseFloat(n[1]!), parseFloat(n[2]!), alpha];
}

/** Below this alpha a background is a wash over what is under it, which decides instead. */
const OPAQUE_ENOUGH = 0.5;

/**
 * Which tokens the glyph of `field` takes (spec 2026-11-11 fill UI, section 2): the luminance of
 * the first computed background that is mostly opaque (alpha 0.5 or more), from the field up to
 * the root element, so a dark field on a light page still gets a visible glyph. A translucent
 * wash (a dark input with rgba(255,255,255,.06) on a dark page) or a colour this parser cannot
 * read (oklch(), color()) is walked past. Nothing found: the system appearance.
 */
export function glyphTheme(field: HTMLElement, view: Window): GlyphTheme {
  const root = field.ownerDocument.documentElement;
  for (let el: Element | null = field; el; el = el === root ? null : el.parentElement) {
    let bg = "";
    try {
      bg = view.getComputedStyle(el).backgroundColor;
    } catch {
      bg = "";
    }
    const c = rgba(bg);
    if (!c || c[3] < OPAQUE_ENOUGH) continue;
    return luminance(c[0], c[1], c[2]) > 0.5 ? "light" : "dark";
  }
  let dark = false;
  try {
    dark = view.matchMedia("(prefers-color-scheme: dark)").matches;
  } catch {
    dark = false;
  }
  return dark ? "dark" : "light";
}

/** Colour and background of a glyph at rest or in the focused field, from the design tokens. */
export function glyphPaint(theme: GlyphTheme, focus: boolean): { color: string; background: string } {
  const tk = theme === "dark" ? DARK : LIGHT;
  return focus
    ? { color: tk["glyph-focus"] ?? "", background: tk["glyph-focus-bg"] ?? "" }
    : { color: tk["glyph-rest"] ?? "", background: "transparent" };
}

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
/* The field glyph: the grey Lattice mark, no tile; in the focused field, indigo on a soft accent
   background. Its colours are set inline from the tokens of the field's theme (icon.ts). */
.icon {
  all: initial;
  position: fixed;
  box-sizing: border-box;
  width: ${ICON_SIZE}px;
  height: ${ICON_SIZE}px;
  border-radius: ${DARK["r-chip"]};
  background: transparent;
  color: ${LIGHT["glyph-rest"]};
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  pointer-events: auto;
  transition: transform .12s ease, color .12s ease, background-color .12s ease;
}
.icon:hover { transform: scale(1.08); }
/* Pressed: a darker mark by colour only. A filter, a downscale or an opacity change makes
   IntersectionObserver v2, the icon's click guard on Chromium, report the icon as not visible, and
   a long press then loses its click. !important: paint() sets the resting colours inline. */
.icon[data-theme="light"]:active { color: ${LIGHT["glyph-press"]} !important; background-color: ${LIGHT["glyph-focus-bg"]} !important; }
.icon[data-theme="dark"]:active { color: ${DARK["glyph-press"]} !important; background-color: ${DARK["glyph-focus-bg"]} !important; }
.icon[hidden] { display: none; }
/* Touch screens: a finger-sized icon, and the label above the focused field's icon. */
.icon.touch { width: ${TOUCH_ICON_SIZE}px; height: ${TOUCH_ICON_SIZE}px; }
.icon.touch svg { width: 18px; height: 18px; }
.tip {
  all: initial;
  position: fixed;
  transform: translateX(-50%);
  padding: ${DARK["space-xs"]} ${DARK["space-s"]};
  border-radius: ${DARK["r-chip"]};
  background: ${DARK["frame-tip"]};
  color: ${DARK["frame-tip-ink"]};
  font: 600 12px/1.3 -apple-system, system-ui, sans-serif;
  white-space: nowrap;
  pointer-events: none;
  box-shadow: ${DARK["frame-shadow-quiet"]};
}
.tip[hidden] { display: none; }
.icon svg { display: block; width: 16px; height: 16px; }
.ring {
  all: initial;
  position: fixed;
  box-sizing: border-box;
  border-radius: ${DARK["r-chip"]};
  box-shadow: 0 0 0 ${DARK["space-xs"]} ${DARK["accent-ring"]};
  pointer-events: none;
}
.ring[hidden] { display: none; }
iframe {
  all: initial;
  position: fixed;
  box-sizing: border-box;
  border: 0;
  border-radius: ${DARK["r-card"]};
  background: transparent;
  /* The frames follow the system appearance. "normal" would take the page's
     declared scheme: a page that declares only "light" turned the menu light
     on a dark Mac, and, the overlay's own document being dark, made Chromium
     paint an opaque white backdrop under it (a white line along its edge). */
  color-scheme: light dark;
  pointer-events: auto;
  box-shadow: ${DARK["frame-shadow"]};
  opacity: 0;
  transform: translateY(-${DARK["space-xs"]}) scale(.98);
  transform-origin: top left;
  transition: opacity 160ms cubic-bezier(.23, 1, .32, 1), transform 200ms cubic-bezier(.23, 1, .32, 1);
}
iframe.corner { transform-origin: top right; }
/* The save card: quiet, a light shadow, no movement beyond a fade. */
iframe.quiet { border-radius: ${DARK["r-control"]}; box-shadow: ${DARK["frame-shadow-quiet"]}; transform: none; transition: opacity 140ms ease; }
/* The one-click card draws its own shape and shadow inside a transparent frame. */
iframe.bare { border-radius: 0; box-shadow: none; }
iframe.top-center { transform-origin: top center; transform: translateY(-${DARK["space-m"]}) scale(.96); transition: opacity 180ms cubic-bezier(.23, 1, .32, 1), transform 380ms cubic-bezier(.34, 1.56, .64, 1), border-radius 200ms ease; }
iframe.top-center.shown { transform: none; }
iframe.shown { opacity: 1; transform: none; }
/* Narrow touch screens: the menu rises from the bottom edge as a sheet. */
iframe.sheet { border-radius: ${DARK["r-card"]} ${DARK["r-card"]} 0 0; transform-origin: bottom center; transform: translateY(${DARK["space-xl"]}); box-shadow: ${DARK["frame-shadow-sheet"]}; }
iframe.sheet.shown { transform: none; }
@media (prefers-color-scheme: light) {
  .ring { box-shadow: 0 0 0 ${LIGHT["space-xs"]} ${LIGHT["accent-ring"]}; }
  iframe { box-shadow: ${LIGHT["frame-shadow"]}; }
  iframe.quiet { box-shadow: ${LIGHT["frame-shadow-quiet"]}; }
  iframe.sheet { box-shadow: ${LIGHT["frame-shadow-sheet"]}; }
  iframe.bare { box-shadow: none; }
}
@media (prefers-reduced-motion: reduce) {
  iframe { transform: none; transition: opacity 120ms ease; }
}
`;

export interface Shell {
  /** Shadow root; only for this content script's own modules and tests. */
  readonly root: ShadowRoot;
  /** Container of icons, highlight ring and frames. */
  readonly layer: HTMLElement;
  /**
   * Where `top: 0; left: 0` of the fixed layer sits in client coordinates
   * (`getBoundingClientRect`). Zero on desktop. iOS 27 Safari with the keyboard
   * up and the page scrolled: client coordinates follow the visual viewport while
   * `position: fixed` follows the layout viewport, which then starts above the
   * screen (top = -visualViewport.offsetTop). A box placed at a field's client
   * position must subtract this.
   */
  origin(): { left: number; top: number };
  /**
   * How far the fixed layer sits from where the browser alone puts it: its origin, less what the
   * visual viewport explains (iOS, above). Zero in every honest page. Anything else means the
   * page moved our host on the screen (a transform on `<html>` with the inverse on `<body>`):
   * the frames are placed in the layer's own coordinates, so they slid with it, unseen.
   */
  shift(): { left: number; top: number };
  /**
   * Watches `shift()` (every SHIFT_POLL_MS while anyone watches). `cb(off, moved)`: `moved` when
   * it changed since the last look, `off` while it is not zero. Called on a change and on every
   * look while off. Returns the function that stops this watch.
   */
  watchShift(cb: (off: boolean, moved: boolean) => void): () => void;
  /** The parent of the host as it is now (the root element, unless the page moved it). */
  parent(): Element | null;
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

/** How often the layer's place on the screen is looked at while a frame or an icon is shown (a rendering frame). */
export const SHIFT_POLL_MS = 16;
/** Sub-pixel layout noise is no shift. */
const SHIFT_TOLERANCE_PX = 1;

export function createShell(doc: Document): Shell {
  const host = doc.createElement("onepass-root");
  // Inline as well: some pages style unknown elements globally.
  host.setAttribute("style", `all: initial !important; position: fixed !important; z-index: ${Z_MAX} !important; overflow: visible !important; margin: 0 !important; padding: 0 !important; border: 0 !important; background: transparent !important;`);
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
  const origin = () => {
    const r = layer.getBoundingClientRect();
    return { left: Number.isFinite(r.left) ? r.left : 0, top: Number.isFinite(r.top) ? r.top : 0 };
  };
  const shift = () => {
    const o = origin();
    const vv = doc.defaultView?.visualViewport;
    const n = (x: unknown) => (typeof x === "number" && Number.isFinite(x) ? x : 0);
    // Either the layer is at the viewport's corner, or it follows the visual viewport (iOS).
    const panned = { left: o.left + n(vv?.offsetLeft), top: o.top + n(vv?.offsetTop) };
    const pick = Math.hypot(o.left, o.top) <= Math.hypot(panned.left, panned.top) ? o : panned;
    const px = (x: number) => (Math.abs(x) <= SHIFT_TOLERANCE_PX ? 0 : Math.round(x));
    return { left: px(pick.left), top: px(pick.top) };
  };
  const watchers = new Set<(off: boolean, moved: boolean) => void>();
  let watch: ReturnType<typeof setInterval> | null = null;
  let lastShift = "0,0";
  const looked = () => {
    const s = shift();
    const key = `${s.left},${s.top}`;
    const moved = key !== lastShift;
    lastShift = key;
    const off = key !== "0,0";
    if (moved || off) for (const cb of [...watchers]) cb(off, moved);
  };
  // Dev builds only: what the watch costs (its looks and their total time in ms), read from the
  // content script's world by a bench. Measured 2026-11-11 on the heaviest lab pages: 5 to 12
  // microseconds a look, under 1 ms per second, 0.07 % of a frame at most.
  const cost = __DEV__ ? { looks: 0, ms: 0 } : null;
  if (cost) (globalThis as { __onepassShiftCost?: unknown }).__onepassShiftCost = cost;
  const look = cost
    ? () => {
        const t0 = performance.now();
        looked();
        cost.looks++;
        cost.ms += performance.now() - t0;
      }
    : looked;
  const stopWatch = () => {
    if (watch !== null) clearInterval(watch);
    watch = null;
  };
  return {
    root,
    layer,
    isHost: (node) => node === host,
    origin,
    shift,
    watchShift: (cb) => {
      watchers.add(cb);
      if (watch === null) {
        const s = shift();
        lastShift = `${s.left},${s.top}`;
        watch = setInterval(look, SHIFT_POLL_MS);
      }
      return () => {
        watchers.delete(cb);
        if (watchers.size === 0) stopWatch();
      };
    },
    parent: () => host.parentElement,
    ensureAttached: () => {
      const moved = attach();
      if (moved) for (const cb of reattached) cb();
      return moved;
    },
    onReattach: (cb) => void reattached.push(cb),
    destroy: () => {
      watchers.clear();
      stopWatch();
      host.remove();
    },
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
  /**
   * The layout right now, read at every placement (it changes with a trackpad, a rotation, Slide
   * Over). From `readLayout` by default.
   */
  layout?: () => Layout;
  /** Other password managers' boxes in the top right corner (occupants.ts): the save card stacks beside them. */
  occupants?: () => Rect[];
  /**
   * Browsers without IntersectionObserver v2 (Firefox, Safari): the frames cannot see a cover
   * themselves, so the content script watches for one (`watchCovers`) and makes a covered frame
   * inert. Off where the frames have IOv2 (Chromium keeps its own behaviour).
   */
  covers?: { hitTest: HitTest; scopes?: Scopes };
}

/**
 * How the in-page UI is laid out. `touch`: a finger may be used (`touchDevice`: the primary
 * pointer is coarse, or an iPhone or iPad has any coarse pointer, an iPad with a trackpad still
 * having its touch screen), so icons and rows are finger-sized. `sheet`: a touch screen narrower than SHEET_MAX_VIEWPORT, where the menu is a
 * bottom sheet; wider (iPad), it is the popover anchored to its field, as on a desktop. A mouse
 * only (Mac, desktop Chromium): neither, the desktop layout.
 */
export interface Layout {
  touch: boolean;
  sheet: boolean;
}

const DESKTOP: Layout = { touch: false, sheet: false };

/** The layout of `view` right now (the frame pages mark themselves with the same `touchDevice`). */
export function readLayout(view: Window | null | undefined): Layout {
  if (!view) return DESKTOP;
  const touch = touchDevice(view);
  return { touch, sheet: touch && (view.innerWidth ?? Infinity) < SHEET_MAX_VIEWPORT };
}

/** A live layout: read once, then again when a pointer media query or the window width changes. */
export interface LayoutWatch {
  current(): Layout;
  /** `cb` runs after the layout changed (a trackpad came or went, a rotation, Slide Over). */
  onChange(cb: () => void): void;
  destroy(): void;
}

export function watchLayout(view: Window | null | undefined): LayoutWatch {
  let now = readLayout(view);
  const subs: (() => void)[] = [];
  const offs: (() => void)[] = [];
  const check = () => {
    const next = readLayout(view);
    if (next.touch === now.touch && next.sheet === now.sheet) return;
    now = next;
    for (const cb of subs) cb();
  };
  if (view) {
    for (const q of POINTER_QUERIES) {
      try {
        const mq = view.matchMedia?.(q);
        if (mq && typeof mq.addEventListener === "function") {
          mq.addEventListener("change", check);
          offs.push(() => mq.removeEventListener("change", check));
        }
      } catch {
        // No media queries: the resize check still runs.
      }
    }
    view.addEventListener("resize", check, { passive: true });
    offs.push(() => view.removeEventListener("resize", check));
  }
  return {
    current: () => now,
    onChange: (cb) => void subs.push(cb),
    destroy: () => {
      for (const off of offs.splice(0)) off();
      subs.length = 0;
    },
  };
}

/** Clicks into a frame are ignored this long after it moved (spec 8.3). */
export const MOVE_GUARD_MS = 300;
/**
 * Touch: how far a frame may have drifted on the screen between a pan of the visual viewport and
 * its next placement without counting as a move (a third of a row: iOS's own smooth pans move a
 * few pixels a frame; a page jumping the viewport moves more).
 */
export const DRIFT_PX = 16;
/**
 * Without IntersectionObserver v2: how often a shown frame is checked for a cover (the same delay
 * IOv2 is asked for in the frames), on top of the checks run on every top-layer toggle and every
 * placement.
 */
export const COVER_POLL_MS = 100;

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
  /**
   * Without IOv2: the frame is covered right now (checked at once), so it is inert and a key the
   * content script relays to it must not act either. Always false with IOv2 (the frame guards itself).
   */
  covered(kind: FrameKind): boolean;
  destroy(): void;
}

export function createFrames(opts: FramesOptions): Frames {
  const { shell, doc, geometry } = opts;
  const layout = opts.layout ?? (() => readLayout(doc.defaultView));
  const sheet = (kind: FrameKind) => kind === "menu" && layout().sheet;
  const maxHeight = (kind: FrameKind) => (sheet(kind) ? SHEET_HEIGHT : FRAME_HEIGHT[kind]);
  /**
   * Touch: where each frame was last put on the screen, relative to the visual viewport. iOS moves
   * the visual viewport all the time (the keyboard, the page panning under it); a frame that stays
   * at the same place on the screen brings nothing new under the finger.
   */
  const onScreen = new WeakMap<HTMLIFrameElement, { left: number; top: number; width: number; height: number; scale: number }>();
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
        if (blocked.has(iframe)) return;
        iframe.style.removeProperty("pointer-events");
        // Taking the pointer again: a cover the hit test can see blocks it at once, in this same task.
        if (opts.covers && coveredNow(iframe)) block(iframe);
      }, MOVE_GUARD_MS),
    );
  };
  /**
   * The page moved our host on the screen (`Shell.shift`): every frame slid with it, on every
   * browser. That is a move: no pointer for MOVE_GUARD_MS, again at every look while the layer is
   * out of place, so a frame takes a click only once it has been back where it belongs for that long.
   */
  let unwatchShift: (() => void) | null = null;
  const watchShift = () => {
    unwatchShift ??= shell.watchShift(() => {
      for (const f of frames.values()) guard(f.iframe);
    });
  };
  const drop = (iframe: HTMLIFrameElement) => {
    const t = guards.get(iframe);
    if (t !== undefined) clearTimeout(t);
    guards.delete(iframe);
    blocked.delete(iframe);
    iframe.remove();
    if (frames.size <= 1) {
      stopPoll();
      unwatchShift?.();
      unwatchShift = null;
    }
  };

  // ---- covers (no IntersectionObserver v2: Firefox, Safari) ----

  /** Frames made inert because something covers them. */
  const blocked = new Set<HTMLIFrameElement>();
  /**
   * Covered right now: a top-layer element is open, the root element dims the page, or (while the
   * frame takes the pointer) the hit test at its center finds something else than our host.
   */
  const coveredNow = (iframe: HTMLIFrameElement): boolean => {
    const c = opts.covers;
    if (!c) return false;
    if (topLayerOpen(doc, c.scopes) || rootHidden(doc, shell.parent())) return true;
    if (guards.has(iframe) || blocked.has(iframe)) return false;
    const r = iframe.getBoundingClientRect();
    if (!(r.width > 0 && r.height > 0)) return false;
    return !hostOnTop(c.hitTest, (el) => shell.isHost(el), r.left + r.width / 2, r.top + r.height / 2);
  };
  /** Inert (no pointer, no focus, no key) until the cover is gone. */
  const block = (iframe: HTMLIFrameElement) => {
    blocked.add(iframe);
    iframe.style.setProperty("pointer-events", "none");
    iframe.setAttribute("inert", "");
  };
  /** The cover is gone: the frame comes back as if it had just appeared (the move guard). */
  const unblock = (iframe: HTMLIFrameElement) => {
    blocked.delete(iframe);
    iframe.removeAttribute("inert");
    guard(iframe);
  };
  const checkCovers = () => {
    if (!opts.covers) return;
    for (const f of frames.values()) {
      const iframe = f.iframe;
      if (blocked.has(iframe)) {
        // Unblocked only when nothing that the hit test cannot see covers it; the hit test runs
        // again when the move guard ends.
        if (!coveredNow(iframe)) unblock(iframe);
      } else if (coveredNow(iframe)) {
        block(iframe);
      }
    }
  };
  let poll: ReturnType<typeof setInterval> | null = null;
  const startPoll = () => {
    if (!opts.covers || poll !== null) return;
    poll = setInterval(checkCovers, COVER_POLL_MS);
  };
  const stopPoll = () => {
    if (poll === null) return;
    clearInterval(poll);
    poll = null;
  };
  // A popover or a dialog shown or hidden (toggle does not bubble: caught while capturing), and fullscreen.
  const onToggle = () => checkCovers();
  if (opts.covers) {
    doc.addEventListener("toggle", onToggle, true);
    doc.addEventListener("fullscreenchange", onToggle, true);
  }
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
   * The element's box in the fixed layer's coordinates, the ones `left` and `top`
   * of our frames take and the visual viewport's offsets are counted in.
   */
  const fixedRect = (el: Element): Rect => {
    const r = geometry(el).rect;
    const o = shell.origin();
    return { left: r.left - o.left, top: r.top - o.top, width: r.width, height: r.height };
  };
  /**
   * The part of the page the user sees. On iOS the keyboard shrinks the
   * visual viewport and not the layout one, so a sheet placed on innerHeight
   * lands under the keyboard.
   */
  const visible = () => {
    const vv = doc.defaultView?.visualViewport;
    if (!vv || !(vv.height > 0)) {
      const { h } = viewport();
      return { top: 0, left: 0, h, scale: 1 };
    }
    const n = (x: number, d: number) => (Number.isFinite(x) ? x : d);
    return { top: n(vv.offsetTop, 0), left: n(vv.offsetLeft, 0), h: vv.height, scale: n(vv.scale, 1) };
  };

  /** The anchor's box when the user can see it (inside the visible part), else null. */
  const seen = (anchor: Element | null, v: { top: number; h: number }): Rect | null => {
    if (!anchor?.isConnected) return null;
    const r = fixedRect(anchor);
    if (r.width <= 0 || r.height <= 0 || r.top + r.height <= v.top || r.top >= v.top + v.h) return null;
    return r;
  };

  /**
   * Under the anchor (the menu, or the overlay of a chain started from a
   * field), or above it when the viewport has no room below; else the top
   * right. True when the position, the width or a larger height changed (a
   * smaller height brings nothing new under the pointer).
   */
  const place = (kind: FrameKind, iframe: HTMLIFrameElement, anchor: Element | null, height: number) => {
    const { w, h: vh } = viewport();
    const { touch } = layout();
    // A sheet's height, kept after a rotation made it a popover, is the popover's again.
    height = Math.min(height, maxHeight(kind));
    const width = Math.min(FRAME_WIDTHS[kind], Math.max(0, w - 2 * EDGE));
    let left = w - width - EDGE;
    let top = EDGE;
    let width2 = width;
    /** A bottom sheet (rounded top corners, rising from the bottom edge). */
    let asSheet = false;
    if (sheet(kind)) {
      // A bottom sheet, centered and at most SHEET_MAX_WIDTH wide. Its bottom is the top of the
      // keyboard when one is up. It never covers its field (IPAD-02): it stops under the field,
      // or, with too little room there, it goes above the field.
      const v = visible();
      const bottom = v.top + v.h;
      width2 = Math.min(w, SHEET_MAX_WIDTH);
      left = Math.max(0, Math.round((w - width2) / 2));
      let room = Math.max(0, Math.floor(v.h));
      asSheet = true;
      const r = seen(anchor, v);
      if (r) {
        const below = Math.floor(bottom - (r.top + r.height + GAP));
        const above = Math.floor(r.top - GAP - v.top);
        if (below >= Math.min(height, SHEET_MIN_HEIGHT) || below >= above) {
          room = Math.max(0, Math.min(room, below));
        } else {
          // The field sits low (just above the keyboard): the menu goes above it.
          asSheet = false;
          height = Math.max(FRAME_MIN_HEIGHT, Math.min(height, above));
          top = r.top - GAP - height;
        }
      }
      if (asSheet) {
        // Never a sheet of no height (a field filling the visible part): the smallest one.
        height = Math.max(FRAME_MIN_HEIGHT, Math.min(height, room));
        top = Math.max(0, bottom - height);
      }
    } else if (kind === "overlay") {
      // The one-click offer and its progress sit centered at the top of what the user sees
      // (touch: the visual viewport, as the save card; the keyboard may have scrolled it).
      left = Math.max(EDGE, Math.round((w - width) / 2));
      if (touch) top = Math.max(0, Math.round(visible().top)) + EDGE;
    } else if (anchor && kind !== "save") {
      const r = fixedRect(anchor);
      left = Math.max(EDGE, Math.min(r.left, w - width - EDGE));
      top = r.top + r.height + GAP;
      if (touch) {
        // iPad: the popover follows its field inside what the user sees (the keyboard hides the
        // bottom of the layout viewport), below it or above it, the larger side when neither
        // fits; it never covers the field.
        const v = visible();
        const below = Math.floor(v.top + v.h - EDGE - top);
        const above = Math.floor(r.top - GAP - (v.top + EDGE));
        if (height > below) {
          if (height <= above) top = r.top - GAP - height;
          else if (above > below) {
            height = Math.max(FRAME_MIN_HEIGHT, above);
            top = r.top - GAP - height;
          } else height = Math.max(FRAME_MIN_HEIGHT, below);
        }
      } else {
        const above = r.top - GAP - height;
        if (top + height > vh - EDGE && above >= EDGE) top = above;
      }
    } else if (kind === "save" && touch) {
      // Touch (iPhone, iPad): centered at the top of what the user sees. Safari's own bars and
      // the keyboard leave the visual viewport, never the layout one; no other manager's box
      // stacks in a corner there.
      const v = visible();
      left = Math.max(EDGE, Math.round((w - width) / 2));
      top = Math.max(0, Math.round(v.top)) + EDGE;
    } else if (kind === "save" && opts.occupants) {
      // Another manager's prompt in the corner: below it, or to its left.
      const taken = opts.occupants();
      if (taken.length > 0) ({ left, top } = stackInCorner({ left, top }, { width, height }, taken, { w, h: vh }, CARD_GAP, EDGE));
    }
    iframe.classList.toggle("quiet", kind === "save");
    iframe.classList.toggle("top-center", kind === "overlay");
    iframe.classList.toggle("bare", kind === "overlay");
    iframe.classList.toggle("sheet", asSheet);
    iframe.classList.toggle("corner", !sheet(kind) && kind !== "overlay" && !(anchor && kind !== "save"));
    const s = iframe.style;
    const prevHeight = parseFloat(s.getPropertyValue("height")) || 0;
    const prevLeft = parseFloat(s.getPropertyValue("left")) || 0;
    const prevTop = parseFloat(s.getPropertyValue("top")) || 0;
    const next = [`${Math.round(left)}px`, `${Math.round(top)}px`, `${width2}px`, `${height}px`];
    const props = ["left", "top", "width", "height"];
    let changed = props.slice(0, 3).some((p, i) => s.getPropertyValue(p) !== next[i]) || height > prevHeight;
    props.forEach((p, i) => s.setProperty(p, next[i] as string));
    if (touch) {
      // IOSSAF-09: on a touch screen, a move is a move on the screen. The frame keeps its place
      // relative to the visual viewport (iOS panned the page under the keyboard): no new guard. A
      // change of the visual viewport's size (keyboard, toolbar) or zoom that moves the frame on
      // the screen still re-arms it: a page can blur its field to slide the sheet under a finger.
      // So does a drift: the frame is fixed to the layout viewport, so between a pan and this
      // placement it was off its place on the screen; past DRIFT_PX (a page jumping the visual
      // viewport, not iOS's own smooth pan) that counts as a move.
      const v = visible();
      const at = { left: Math.round(left) - Math.round(v.left), top: Math.round(top) - Math.round(v.top), width: width2, height, scale: v.scale };
      const was = onScreen.get(iframe);
      onScreen.set(iframe, at);
      if (was) {
        const driftX = Math.abs(prevLeft - Math.round(v.left) - was.left);
        const driftY = Math.abs(prevTop - Math.round(v.top) - was.top);
        changed =
          was.left !== at.left ||
          was.top !== at.top ||
          was.width !== at.width ||
          at.height > was.height ||
          was.scale !== at.scale ||
          driftX > DRIFT_PX ||
          driftY > DRIFT_PX;
      }
    } else {
      // A mouse layout again: the next touch placement starts afresh (and guards).
      onScreen.delete(iframe);
    }
    return changed;
  };

  const placeRing = () => {
    if (!ring) return;
    const r = fixedRect(ring.el);
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
      // Named for assistive technologies only: a `title` shows as a tooltip over the frame.
      iframe.setAttribute("aria-label", "OnePass");
      iframe.setAttribute("src", url);
      const height = maxHeight(kind);
      place(kind, iframe, anchor, height);
      shell.layer.appendChild(iframe);
      const f = { iframe, anchor, height, reveal: null as ReturnType<typeof setTimeout> | null };
      f.reveal = setTimeout(() => show(f), REVEAL_TIMEOUT_MS);
      frames.set(kind, f);
      watchShift();
      // Shown while the layer is out of place: no pointer from the start.
      const at = shell.shift();
      if (at.left !== 0 || at.top !== 0) guard(iframe);
      if (opts.covers) {
        // Shown over a cover already there: inert from the start.
        if (coveredNow(iframe)) block(iframe);
        startPoll();
      }
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
      f.height = Math.round(Math.min(maxHeight(kind), Math.max(FRAME_MIN_HEIGHT, height)));
      const moved = place(kind, f.iframe, f.anchor, f.height);
      if (f.iframe.classList.contains("shown")) {
        if (moved) guard(f.iframe);
      } else {
        show(f);
      }
    },
    focus(kind) {
      const f = frames.get(kind);
      if (!f || blocked.has(f.iframe)) return;
      f.iframe.focus({ preventScroll: true });
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
      checkCovers();
      placeRing();
    },
    covered(kind) {
      const f = frames.get(kind);
      if (!f || !opts.covers) return false;
      checkCovers();
      return blocked.has(f.iframe);
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
      stopPoll();
      if (opts.covers) {
        doc.removeEventListener("toggle", onToggle, true);
        doc.removeEventListener("fullscreenchange", onToggle, true);
      }
      ring?.box.remove();
      ring = null;
    },
  };
}
