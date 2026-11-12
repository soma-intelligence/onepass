// In-field icon (spec 8.3, restyled by spec 2026-11-11 fill UI section 2): the grey Lattice mark
// with no tile, in a 22 px hit area at the right edge of each fillable field, inside the closed
// shadow root; indigo on a soft accent background in the focused field, in the light or dark
// tokens the field's own background calls for (glyphTheme). A click runs smart fill (the
// menu when the plan cannot choose) only when the browser vouches for it
// (`isTrusted`): a page cannot start a fill nor open the menu with a
// synthetic click (S2).
//
// Anti-clickjacking: one click may fill and sign in, so the icon follows the
// frames' rules (ClickGuard). A click counts only CLICK_GUARD_MS after the icon
// was shown or moved (or the host put back), only while IntersectionObserver v2
// (Chromium) does not report it covered, and only when no top-layer element
// (popover, modal dialog, fullscreen) is open over the icon, the root element does not dim
// the page, and the topmost element at the click point is our own host
// (occlusion.ts). A page that covers the icon with a decoy gets nothing.
import { ClickGuard, type ObserveVisibility, observeVisibility } from "../shared/click-guard";
import { t } from "../shared/i18n";
import type { FieldRole, FormInfo, PageAnalysis } from "../shared/messages";
import type { RefRegistry } from "./detect/refs";
import type { Geometry, Rect } from "./detect/visibility";
import { glyphPaint, glyphTheme, type GlyphTheme, ICON_SIZE, type Layout, readLayout, type Shell, TOUCH_ICON_SIZE } from "./frames";
import { domHitTest, type HitTest, hostOnTop, rootHidden, type Scopes, topLayerOpen } from "./occlusion";

/** Roles that carry an icon. */
export const ICON_ROLES: ReadonlySet<FieldRole> = new Set<FieldRole>([
  "username",
  "email",
  "current_password",
  "new_password",
  "otp",
  "cc_number",
  "given_name",
  "full_name",
]);

/**
 * Roles that carry an icon only on a form none of whose fields has an ICON_ROLES role, and then on
 * the first of them only (IOSSAF-11, MS-07): an address step that starts at the street or the
 * postal code, a checkout whose number sits in the payment provider's frame. One icon per form, so
 * the page does not fill up with icons.
 */
export const SECONDARY_ICON_ROLES: ReadonlySet<FieldRole> = new Set<FieldRole>(["address_line1", "postal_code", "tel", "cc_name", "cc_exp"]);

export { ICON_SIZE, TOUCH_ICON_SIZE };
/** Inset from the field's right edge. */
const ICON_INSET = 6;
/** Below this width the icon sits just outside the field (OTP cells). */
const NARROW_FIELD = 64;

const SVG_NS = "http://www.w3.org/2000/svg";

/** A field with an icon: what the menu request needs. */
export interface IconTarget {
  el: Element;
  fieldRef: string;
  form: FormInfo;
}

export interface IconsOptions {
  shell: Shell;
  doc: Document;
  refs: RefRegistry;
  geometry: Geometry;
  isTrusted: (e: Event) => boolean;
  onOpen: (t: IconTarget) => void;
  /** Called when a field's box changes (ResizeObserver). */
  onLayout: () => void;
  /**
   * Other password managers' boxes over `zone` (their in-field buttons,
   * occupants.ts): our icon moves left of them instead of sitting under.
   */
  avoid?: (zone: Rect) => Rect[];
  /**
   * The layout right now (frames.ts). Touch (iPhone, iPad, with or without a trackpad): a larger
   * icon for a finger, and a "OnePass" label beside the icon of the focused field (spec
   * 2026-11-03-ios-safari-autofill 5). Read at every placement; `readLayout` by default.
   */
  layout?: () => Layout;
  /** Clock of the click guard; `performance.now` by default. */
  now?: () => number;
  /** Topmost element at a point; `document.elementFromPoint` by default. */
  hitTest?: HitTest;
  /** Shadow roots we can read, where a top-layer element may sit too. */
  scopes?: Scopes;
  /** IntersectionObserver v2 visibility of an icon (Chromium); the real observer by default. */
  observe?: ObserveVisibility;
}

export interface Icons {
  attachIcons(analysis: PageAnalysis): void;
  reposition(): void;
  /** The icon target for a field element, if it has one. */
  targetOf(el: EventTarget | null): IconTarget | undefined;
  /** Every icon target, in the order the fields were reported. */
  all(): IconTarget[];
  destroy(): void;
}

function glyph(doc: Document): SVGElement {
  // The OnePass mark: the Lattice (2 x 3 dots and a bar), in the glyph's colour.
  const svg = doc.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 100 100");
  svg.setAttribute("fill", "currentColor");
  svg.setAttribute("aria-hidden", "true");
  for (const cx of ["23.5", "49.5"]) {
    for (const cy of ["24", "50", "76"]) {
      const dot = doc.createElementNS(SVG_NS, "circle");
      dot.setAttribute("cx", cx);
      dot.setAttribute("cy", cy);
      dot.setAttribute("r", "9");
      dot.setAttribute("fill-opacity", "0.55");
      svg.appendChild(dot);
    }
  }
  const bar = doc.createElementNS(SVG_NS, "rect");
  bar.setAttribute("x", "67.5");
  bar.setAttribute("y", "15");
  bar.setAttribute("width", "18");
  bar.setAttribute("height", "70");
  bar.setAttribute("rx", "9");
  svg.appendChild(bar);
  return svg;
}

export function createIcons(opts: IconsOptions): Icons {
  const { shell, doc, refs, geometry, isTrusted, onOpen } = opts;
  const now = opts.now ?? (() => (typeof performance !== "undefined" ? performance.now() : Date.now()));
  const hit = opts.hitTest ?? domHitTest(doc);
  const observe = opts.observe ?? observeVisibility;
  let destroyed = false;
  const layout = opts.layout ?? (() => readLayout(doc.defaultView));
  /** Touch or not, as of the last placement (a trackpad may come or go). */
  let touch = layout().touch;
  let size = touch ? TOUCH_ICON_SIZE : ICON_SIZE;
  // The label beside the focused field's icon (touch screens only), made when first needed.
  let tip: HTMLElement | null = null;
  const tipBox = (): HTMLElement => {
    if (tip) return tip;
    tip = doc.createElement("div");
    tip.className = "tip";
    tip.hidden = true;
    tip.textContent = t("icon.tooltip");
    shell.layer.appendChild(tip);
    return tip;
  };
  let focused: Element | null = null;
  const placeTip = () => {
    if (!touch) {
      if (tip) tip.hidden = true;
      return;
    }
    const box = tipBox();
    const entry = focused ? byField.get(focused) : undefined;
    if (!entry || entry.icon.hidden) {
      box.hidden = true;
      return;
    }
    const left = parseFloat(entry.icon.style.getPropertyValue("left"));
    const top = parseFloat(entry.icon.style.getPropertyValue("top"));
    box.hidden = false;
    box.style.setProperty("left", `${Math.round(left + size / 2)}px`);
    box.style.setProperty("top", `${Math.round(top - 30)}px`);
  };
  /** Colours the glyph of `entry` for its field's theme, grey at rest, indigo in the focused field. */
  const paint = (entry: Entry) => {
    const focus = focused !== null && byField.get(focused) === entry;
    const { color, background } = glyphPaint(entry.theme, focus);
    entry.icon.dataset.state = focus ? "focus" : "rest";
    entry.icon.dataset.theme = entry.theme;
    entry.icon.style.setProperty("color", color);
    entry.icon.style.setProperty("background-color", background);
  };
  /** The theme of a field's glyph, read again from the field's computed background. */
  const themeOf = (el: Element): GlyphTheme =>
    el instanceof HTMLElement && doc.defaultView ? glyphTheme(el, doc.defaultView) : "light";
  const onFocusIn = (e: Event) => {
    const was = focused ? byField.get(focused) : undefined;
    focused = e.target instanceof Element && byField.has(e.target) ? e.target : null;
    const now = focused ? byField.get(focused) : undefined;
    if (was && was !== now) paint(was);
    if (now) {
      // A field may change its background on focus.
      now.theme = themeOf(now.target.el);
      paint(now);
    }
    placeTip();
  };
  const onFocusOut = () => {
    const was = focused ? byField.get(focused) : undefined;
    focused = null;
    if (was) paint(was);
    placeTip();
  };
  doc.addEventListener("focusin", onFocusIn, true);
  doc.addEventListener("focusout", onFocusOut, true);
  /** Follows a change of layout: every icon's size, the label. */
  const relayout = () => {
    const next = layout().touch;
    if (next === touch) return;
    touch = next;
    size = touch ? TOUCH_ICON_SIZE : ICON_SIZE;
    for (const e of byField.values()) e.icon.classList.toggle("touch", touch);
  };
  interface Entry {
    icon: HTMLElement;
    target: IconTarget;
    anchor: Element;
    guard: ClickGuard;
    unobserve: (() => void) | void;
    /** Where the icon is on the screen (`placeAt`), null while hidden. */
    screen: string | null;
    /** Tokens of the glyph, from the field's background. */
    theme: GlyphTheme;
  }
  const byField = new Map<Element, Entry>();
  // The host moved back (the page removed or covered it): every icon appeared anew.
  shell.onReattach(() => {
    if (destroyed) return;
    for (const e of byField.values()) e.guard.reset();
  });
  /**
   * While an icon shows, the layer's place on the screen is watched (`Shell.shift`): a host slid
   * away and back puts the icons under the pointer anew, so every click guard starts again.
   */
  let unwatchShift: (() => void) | null = null;
  const watchShift = () => {
    if (byField.size === 0) {
      unwatchShift?.();
      unwatchShift = null;
    } else {
      unwatchShift ??= shell.watchShift((_off, moved) => {
        if (moved) for (const e of byField.values()) e.guard.reset();
      });
    }
  };
  const RO = (doc.defaultView as (Window & { ResizeObserver?: typeof ResizeObserver }) | null)?.ResizeObserver;
  const resize = RO ? new RO(() => opts.onLayout()) : null;

  /** Whether a click on an icon may act: the guard's delay and visibility, then the cover checks. */
  const accepts = (entry: Entry, e: MouseEvent): boolean => {
    if (!entry.guard.accepts(e)) return false;
    // Only a top-layer element over the icon refuses it (one elsewhere on the page covers nothing here).
    let box: DOMRect | null = null;
    try {
      box = entry.icon.getBoundingClientRect();
    } catch {
      box = null;
    }
    const near = box && box.width > 0 && box.height > 0 ? box : undefined;
    if (topLayerOpen(doc, opts.scopes, near) || rootHidden(doc, shell.parent())) return false;
    // The page moved our host on the screen: the icon is not on its field, a click on it is not meant.
    const at = shell.shift();
    if (at.left !== 0 || at.top !== 0) {
      entry.guard.reset();
      return false;
    }
    return hostOnTop(hit, (el) => shell.isHost(el), e.clientX, e.clientY);
  };

  const makeIcon = (getEntry: () => Entry | undefined): HTMLElement => {
    const icon = doc.createElement("div");
    icon.className = touch ? "icon touch" : "icon";
    icon.setAttribute("role", "button");
    icon.setAttribute("aria-label", t("icon.openOnepassMenu"));
    icon.appendChild(glyph(doc));
    // Keep the focus in the field.
    icon.addEventListener("mousedown", (e) => e.preventDefault());
    icon.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (!isTrusted(e)) return;
      const entry = getEntry();
      if (!entry || !accepts(entry, e)) return;
      const t = entry.target;
      if (t.el.isConnected) onOpen(t);
    });
    return icon;
  };

  /**
   * Places the icon on its field; showing it, or moving it on the screen, re-arms its click guard.
   * The screen position is the client one (iOS: the visual viewport's), so a pan that keeps the
   * field where it is on the screen is no move.
   */
  const place = (entry: Entry) => {
    const was = entry.icon.hidden ? null : entry.screen;
    entry.screen = placeAt(entry.icon, entry.anchor);
    if (entry.screen !== null && was === null) {
      // Shown anew: the field's background is read again (not on every scroll).
      entry.theme = themeOf(entry.target.el);
      paint(entry);
    }
    if (entry.screen !== null && entry.screen !== was) entry.guard.reset();
  };

  /** Puts the icon in place; its client position and size (a key), or null when hidden. */
  const placeAt = (icon: HTMLElement, anchor: Element): string | null => {
    const r = geometry(anchor).rect;
    const view = doc.defaultView;
    const vw = view?.innerWidth ?? Infinity;
    const vh = view?.innerHeight ?? Infinity;
    const off =
      !anchor.isConnected || r.width < 4 || r.height < 4 || r.top + r.height < 0 || r.left + r.width < 0 || r.top > vh || r.left > vw;
    icon.hidden = off;
    if (off) return null;
    let left = r.width < NARROW_FIELD ? r.left + r.width + ICON_INSET : r.left + r.width - size - ICON_INSET;
    const top = r.top + (r.height - size) / 2;
    if (opts.avoid) {
      // Their icon in the same field: ours goes just left of it (never under, never over).
      const theirs = opts.avoid({ left: r.left, top: r.top, width: r.width + size + 2 * ICON_INSET, height: r.height });
      for (let i = 0; i < theirs.length; i++) {
        const me = { left, top, width: size, height: size };
        const hit = theirs.filter((o) => o.left < me.left + me.width + 2 && me.left < o.left + o.width + 2 && o.top < me.top + me.height && me.top < o.top + o.height);
        if (hit.length === 0) break;
        left = Math.min(...hit.map((o) => o.left)) - size - 4;
      }
    }
    // Client coordinates to the fixed layer's (iOS with the keyboard up: not the same).
    const o = shell.origin();
    icon.style.setProperty("left", `${Math.round(left - o.left)}px`);
    icon.style.setProperty("top", `${Math.round(top - o.top)}px`);
    icon.style.setProperty("width", `${size}px`);
    icon.style.setProperty("height", `${size}px`);
    return `${Math.round(left)} ${Math.round(top)} ${size}`;
  };

  return {
    attachIcons(analysis) {
      shell.ensureAttached();
      relayout();
      const wanted = new Map<Element, { target: IconTarget; anchor: Element }>();
      for (const form of analysis.forms) {
        let any = false;
        for (const f of form.fields) {
          if (!ICON_ROLES.has(f.role) || (f.person ?? 0) > 0) continue;
          const el = refs.get(f.ref);
          if (!el) continue;
          any = true;
          if (wanted.has(el)) continue;
          // A split code: the icon follows its last cell.
          const last = f.parts ? refs.get(f.parts[f.parts.length - 1] ?? "") : null;
          wanted.set(el, { target: { el, fieldRef: f.ref, form }, anchor: last ?? el });
        }
        if (any) continue;
        // No main field: the first address, phone or card detail field carries the form's icon.
        for (const f of form.fields) {
          if (!SECONDARY_ICON_ROLES.has(f.role)) continue;
          const el = refs.get(f.ref);
          if (!el) continue;
          if (!wanted.has(el)) wanted.set(el, { target: { el, fieldRef: f.ref, form }, anchor: el });
          break;
        }
      }
      for (const [el, entry] of byField) {
        if (wanted.has(el)) continue;
        entry.icon.remove();
        entry.unobserve?.();
        resize?.unobserve(entry.anchor);
        byField.delete(el);
      }
      for (const [el, w] of wanted) {
        const known = byField.get(el);
        if (known) {
          known.target = w.target;
          if (known.anchor !== w.anchor) {
            resize?.unobserve(known.anchor);
            resize?.observe(w.anchor);
            known.anchor = w.anchor;
          }
          place(known);
          continue;
        }
        const entry: Entry = {
          icon: makeIcon(() => byField.get(el)),
          target: w.target,
          anchor: w.anchor,
          guard: new ClickGuard({ now, trusted: isTrusted }),
          unobserve: undefined,
          screen: null,
          theme: themeOf(w.target.el),
        };
        if (doc.activeElement === el) focused = el;
        byField.set(el, entry);
        shell.layer.appendChild(entry.icon);
        entry.unobserve = observe(entry.icon, (v) => entry.guard.setVisibility(v));
        resize?.observe(w.anchor);
        place(entry);
      }
      watchShift();
    },
    reposition() {
      relayout();
      for (const e of byField.values()) place(e);
      placeTip();
    },
    targetOf(el) {
      if (!(el instanceof Element)) return undefined;
      return byField.get(el)?.target;
    },
    all() {
      return [...byField.values()].map((e) => e.target);
    },
    destroy() {
      destroyed = true;
      doc.removeEventListener("focusin", onFocusIn, true);
      doc.removeEventListener("focusout", onFocusOut, true);
      tip?.remove();
      resize?.disconnect();
      for (const e of byField.values()) {
        e.icon.remove();
        e.unobserve?.();
      }
      byField.clear();
      watchShift();
    },
  };
}
