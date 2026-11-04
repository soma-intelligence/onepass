// In-field icon (spec 8.3): a 20 px indigo tile with the Lattice mark at the right edge of each
// fillable field, inside the closed shadow root. A click runs smart fill (the
// menu when the plan cannot choose) only when the browser vouches for it
// (`isTrusted`): a page cannot start a fill nor open the menu with a
// synthetic click (S2).
import { t } from "../shared/i18n";
import type { FieldRole, FormInfo, PageAnalysis } from "../shared/messages";
import type { RefRegistry } from "./detect/refs";
import type { Geometry, Rect } from "./detect/visibility";
import { type Layout, readLayout, type Shell } from "./frames";

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

export const ICON_SIZE = 20;
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
}

/** Icon side on a touch screen. */
export const TOUCH_ICON_SIZE = 28;

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
  // The OnePass mark: the white Lattice on the indigo tile (as in the app).
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
  const onFocusIn = (e: Event) => {
    focused = e.target instanceof Element && byField.has(e.target) ? e.target : null;
    placeTip();
  };
  const onFocusOut = () => {
    focused = null;
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
  const byField = new Map<Element, { icon: HTMLElement; target: IconTarget; anchor: Element }>();
  const RO = (doc.defaultView as (Window & { ResizeObserver?: typeof ResizeObserver }) | null)?.ResizeObserver;
  const resize = RO ? new RO(() => opts.onLayout()) : null;

  const makeIcon = (getTarget: () => IconTarget | undefined): HTMLElement => {
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
      const t = getTarget();
      if (t && t.el.isConnected) onOpen(t);
    });
    return icon;
  };

  const place = (icon: HTMLElement, anchor: Element) => {
    const r = geometry(anchor).rect;
    const view = doc.defaultView;
    const vw = view?.innerWidth ?? Infinity;
    const vh = view?.innerHeight ?? Infinity;
    const off =
      !anchor.isConnected || r.width < 4 || r.height < 4 || r.top + r.height < 0 || r.left + r.width < 0 || r.top > vh || r.left > vw;
    icon.hidden = off;
    if (off) return;
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
    icon.style.setProperty("left", `${Math.round(left)}px`);
    icon.style.setProperty("top", `${Math.round(top)}px`);
  };

  return {
    attachIcons(analysis) {
      shell.ensureAttached();
      relayout();
      const wanted = new Map<Element, { target: IconTarget; anchor: Element }>();
      for (const form of analysis.forms) {
        let any = false;
        for (const f of form.fields) {
          if (!ICON_ROLES.has(f.role)) continue;
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
          place(known.icon, known.anchor);
          continue;
        }
        const entry = { icon: null as unknown as HTMLElement, target: w.target, anchor: w.anchor };
        entry.icon = makeIcon(() => byField.get(el)?.target);
        byField.set(el, entry);
        shell.layer.appendChild(entry.icon);
        resize?.observe(w.anchor);
        place(entry.icon, entry.anchor);
      }
    },
    reposition() {
      relayout();
      for (const e of byField.values()) place(e.icon, e.anchor);
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
      doc.removeEventListener("focusin", onFocusIn, true);
      doc.removeEventListener("focusout", onFocusOut, true);
      tip?.remove();
      resize?.disconnect();
      for (const e of byField.values()) e.icon.remove();
      byField.clear();
    },
  };
}
