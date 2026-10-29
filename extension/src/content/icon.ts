// In-field icon (spec 8.3): a 20 px indigo tile with the Lattice mark at the right edge of each
// fillable field, inside the closed shadow root. A click runs smart fill (the
// menu when the plan cannot choose) only when the browser vouches for it
// (`isTrusted`): a page cannot start a fill nor open the menu with a
// synthetic click (S2).
import { tr } from "../shared/i18n";
import type { FieldRole, FormInfo, PageAnalysis } from "../shared/messages";
import type { RefRegistry } from "./detect/refs";
import type { Geometry } from "./detect/visibility";
import type { Shell } from "./frames";

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
  const byField = new Map<Element, { icon: HTMLElement; target: IconTarget; anchor: Element }>();
  const RO = (doc.defaultView as (Window & { ResizeObserver?: typeof ResizeObserver }) | null)?.ResizeObserver;
  const resize = RO ? new RO(() => opts.onLayout()) : null;

  const makeIcon = (getTarget: () => IconTarget | undefined): HTMLElement => {
    const icon = doc.createElement("div");
    icon.className = "icon";
    icon.setAttribute("role", "button");
    icon.setAttribute("aria-label", tr("Ouvrir le menu OnePass", "Open the OnePass menu"));
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
    const left = r.width < NARROW_FIELD ? r.left + r.width + ICON_INSET : r.left + r.width - ICON_SIZE - ICON_INSET;
    const top = r.top + (r.height - ICON_SIZE) / 2;
    icon.style.setProperty("left", `${Math.round(left)}px`);
    icon.style.setProperty("top", `${Math.round(top)}px`);
  };

  return {
    attachIcons(analysis) {
      shell.ensureAttached();
      const wanted = new Map<Element, { target: IconTarget; anchor: Element }>();
      for (const form of analysis.forms) {
        for (const f of form.fields) {
          if (!ICON_ROLES.has(f.role)) continue;
          const el = refs.get(f.ref);
          if (!el || wanted.has(el)) continue;
          // A split code: the icon follows its last cell.
          const last = f.parts ? refs.get(f.parts[f.parts.length - 1] ?? "") : null;
          wanted.set(el, { target: { el, fieldRef: f.ref, form }, anchor: last ?? el });
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
      for (const e of byField.values()) place(e.icon, e.anchor);
    },
    targetOf(el) {
      if (!(el instanceof Element)) return undefined;
      return byField.get(el)?.target;
    },
    all() {
      return [...byField.values()].map((e) => e.target);
    },
    destroy() {
      resize?.disconnect();
      for (const e of byField.values()) e.icon.remove();
      byField.clear();
    },
  };
}
