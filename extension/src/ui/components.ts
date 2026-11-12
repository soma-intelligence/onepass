// Building blocks of the extension pages (menu, overlay, save, popup).
//
// Rules for every page:
// - DOM is built with createElement and textContent only: no HTML string is
//   ever parsed, so data from the host or the page cannot become markup;
// - a page talks to the service worker only (runtime messages, with the
//   token from its own `location.hash`); it never reads `window.parent` and
//   never listens to `message` events;
// - every reply is validated (parse.ts) before anything is rendered.
import type { ProviderId, UiToBg } from "../shared/messages";
import { t, tn } from "../shared/i18n";
import { POINTER_QUERIES, touchDevice } from "../shared/layout";
import { PROVIDERS } from "../shared/providers";
import { UNLOCK_WAIT_MS } from "../shared/unlock";
import { type ArtKind, art, fixedColor } from "./art";
import type { ObserveVisibility } from "../shared/click-guard";

// ---- DOM ----

export type Child = Node | string | null | undefined | false;

export interface Props {
  class?: string;
  /** Attributes, set with setAttribute (never event handler attributes). */
  attrs?: Record<string, string | undefined>;
  on?: { [K in keyof HTMLElementEventMap]?: (e: HTMLElementEventMap[K]) => void };
}

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Props | null = null,
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (props?.class) el.className = props.class;
  for (const [k, v] of Object.entries(props?.attrs ?? {})) {
    if (v === undefined) continue;
    if (/^on/i.test(k)) throw new Error("event handler attributes are not allowed");
    el.setAttribute(k, v);
  }
  for (const [type, fn] of Object.entries(props?.on ?? {})) {
    el.addEventListener(type, fn as EventListener);
  }
  append(el, ...children);
  return el;
}

export function append(el: Node, ...children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
}

/** Replace all children of `el`. */
export function mount(el: Element, ...children: Child[]): void {
  el.replaceChildren();
  append(el, ...children);
}

const SVG_NS = "http://www.w3.org/2000/svg";

/** Static icon paths (constants of this file, never data). */
const ICONS = {
  key: ["M8.3 9.7L15 3M12.5 5.5l1.8 1.8", "C6 12 3.2"],
  plus: ["M6 1.5v9M1.5 6h9"],
  close: ["M2.5 2.5l7 7M9.5 2.5l-7 7"],
  search: ["M9.2 9.2l3 3", "C6 6 4.2"],
  star: ["M8 1.5l1.6 4.2 4.4.3-3.4 2.8 1.1 4.3L8 10.7l-3.7 2.4 1.1-4.3L2 6l4.4-.3z"],
  shield: ["M8 1.5l5.5 2v4.2c0 3.3-2.3 5.7-5.5 6.8-3.2-1.1-5.5-3.5-5.5-6.8V3.5z", "M5.6 8l1.7 1.7 3.2-3.4"],
  more: ["C2.8 7 1.2", "C7 7 1.2", "C11.2 7 1.2"],
  refresh: ["M13 8a5 5 0 11-1.6-3.7", "M13 2.5v3h-3"],
  history: ["M2.5 8a5.5 5.5 0 101.6-3.9", "M2.5 2.5v2.6h2.6", "M8 5v3l2 1.5"],
  check: ["M2.5 6.2l2.4 2.3 4.6-5"],
  chevron: ["M4.5 3l3 3-3 3"],
  edit: ["M9.5 2.2l2.3 2.3-7 7H2.5V9.2z"],
  lock: ["M4 5.5V4a2 2 0 014 0v1.5", "R2.5 5.5 7 5"],
  copy: ["R5 5 8.5 8.5", "M3 10.5H2.5a1 1 0 01-1-1v-7a1 1 0 011-1h7a1 1 0 011 1V3"],
  // The OnePass mark: two columns of dots and one bar (render.mjs geometry).
  lattice: [
    "C23.5 24 9", "C23.5 50 9", "C23.5 76 9", "C49.5 24 9", "C49.5 50 9", "C49.5 76 9",
    "M67.5 24a9 9 0 0118 0v52a9 9 0 01-18 0z",
  ],
  alert: ["M7 1.8l5.6 9.7H1.4z", "M7 5.6v2.6", "M7 10h.01"],
  // Face ID: four corners, eyes, nose and smile (unlock sheet).
  faceid: [
    "M1.5 5V3.2a1.7 1.7 0 011.7-1.7H5", "M11 1.5h1.8a1.7 1.7 0 011.7 1.7V5",
    "M14.5 11v1.8a1.7 1.7 0 01-1.7 1.7H11", "M5 14.5H3.2a1.7 1.7 0 01-1.7-1.7V11",
    "M5.5 5.5v1.2", "M10.5 5.5v1.2", "M8 5.5v3.2H7.2", "M5.6 10.8c1.3 1.1 3.5 1.1 4.8 0",
  ],
  // Touch ID: three arcs.
  touchid: ["M3.5 9a4.5 4.5 0 019 0v1", "M5.5 9a2.5 2.5 0 015 0v3", "M8 9v4.5", "M2.5 6a6.5 6.5 0 0111 0"],
  // Provider marks, drawn here as plain monochrome strokes in the UI's own
  // line style (never the providers' artwork or colours).
  p_google: ["M12.2 4.5A5.5 5.5 0 1 0 13.5 8H8.5"],
  p_apple: [
    "M8 5.4c-.9-.8-3.4-1-4.2 1.3-.8 2.3.6 5.5 2.1 6.1.8.3 1.3-.2 2.1-.2s1.3.5 2.1.2c1.5-.6 2.9-3.8 2.1-6.1C11.4 4.4 8.9 4.6 8 5.4z",
    "M8 5.2c0-1.3.7-2.4 2-2.7",
  ],
  p_microsoft: ["R3 3 4.3 4.3", "R8.7 3 4.3 4.3", "R3 8.7 4.3 4.3", "R8.7 8.7 4.3 4.3"],
  p_github: ["M3.6 9.2a4.4 4.4 0 0 0 8.8 0c0-1.2-.4-2.2-1-3l.4-2.9-2.4 1.3a4.6 4.6 0 0 0-2.8 0L4.2 3.3l.4 2.9c-.6.8-1 1.8-1 3z"],
  p_facebook: ["M10 2.8H8.8c-1.3 0-2 .8-2 2.1V13.2", "M5.2 7.2h4.6"],
  p_x: ["M3.5 3.5l9 9", "M12.5 3.5l-9 9"],
  p_linkedin: ["M4.6 7v5.5", "M4.6 4.4v.01", "M7.6 12.5V7", "M7.6 9.6c0-1.5 1-2.6 2.4-2.6s2.1 1 2.1 2.5v3"],
  p_discord: [
    "M4.2 4.6c1-.5 2.2-.8 3.8-.8s2.8.3 3.8.8c1 1.6 1.6 3.6 1.5 6-1 .8-2 1.3-3 1.5l-.6-1.2H6.3l-.6 1.2c-1-.2-2-.7-3-1.5-.1-2.4.5-4.4 1.5-6z",
    "C6.2 8.5 .7",
    "C9.8 8.5 .7",
  ],
  p_slack: ["M6.4 2.5l-1.2 11", "M11 2.5l-1.2 11", "M2.8 6h11", "M2.2 10.2h11"],
} as const;

export type IconName = keyof typeof ICONS;

const VIEWBOX: Partial<Record<IconName, string>> = {
  key: "0 0 18 18",
  plus: "0 0 12 12",
  close: "0 0 12 12",
  search: "0 0 14 14",
  more: "0 0 14 14",
  check: "0 0 12 12",
  chevron: "0 0 12 12",
  edit: "0 0 14 14",
  lock: "0 0 12 12",
  copy: "0 0 15 15",
  lattice: "0 0 100 100",
  alert: "0 0 14 14",
};

export function icon(name: IconName, size = 14): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("viewBox", VIEWBOX[name] ?? "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("class", `glyph glyph-${name}`);
  const filled = name === "more" || name === "lattice";
  svg.setAttribute("fill", filled ? "currentColor" : "none");
  if (!filled) {
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.6");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
  }
  for (const d of ICONS[name]) {
    let el: SVGElement;
    if (d.startsWith("C")) {
      const [cx, cy, r] = d.slice(1).split(" ");
      el = document.createElementNS(SVG_NS, "circle");
      el.setAttribute("cx", cx ?? "0");
      el.setAttribute("cy", cy ?? "0");
      el.setAttribute("r", r ?? "0");
      // The mark's dots sit behind its bar.
      if (name === "lattice") el.setAttribute("fill-opacity", "0.55");
    } else if (d.startsWith("R")) {
      const [x, y, w, hh] = d.slice(1).split(" ");
      el = document.createElementNS(SVG_NS, "rect");
      el.setAttribute("x", x ?? "0");
      el.setAttribute("y", y ?? "0");
      el.setAttribute("width", w ?? "0");
      el.setAttribute("height", hh ?? "0");
      el.setAttribute("rx", "1");
    } else {
      el = document.createElementNS(SVG_NS, "path");
      el.setAttribute("d", d);
    }
    svg.appendChild(el);
  }
  return svg;
}

const COLOR_RE = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;
export const FALLBACK_COLOR = fixedColor("tile-fallback");

/** A hex color from the host, or a neutral one. */
export function safeColor(c: string): string {
  return COLOR_RE.test(c) ? c : FALLBACK_COLOR;
}

const TILE_PX = { s: 30, m: 34, l: 48 } as const;

/**
 * Item icon: the illustrated category art of the app. Logins carry the
 * host's monogram letter on the teal tile. The host sends no site icon over
 * the bridge, so there is no favicon (and no third-party icon service).
 */
export function tile(letter: string, _color: string, size: "s" | "m" | "l" | number = "m", kind: ArtKind = "login"): SVGSVGElement {
  const px = typeof size === "number" ? size : TILE_PX[size];
  return art(kind, px, kind === "login" ? letter : undefined);
}

/** Category of a summary: a login without a password but with a linked provider has no secret of its own. */
export function artKindOf(s: { kind: "login" | "card" | "identity"; has_password: boolean; methods: readonly unknown[] }): ArtKind {
  if (s.kind === "card") return "card";
  if (s.kind === "identity") return "identity";
  return "login";
}

/** Icon of a summary, at `size`. */
export function itemArt(
  s: { kind: "login" | "card" | "identity"; has_password: boolean; methods: readonly unknown[]; icon_letter: string },
  size: "s" | "m" | "l" | number = "m",
): SVGSVGElement {
  const kind = artKindOf(s);
  return tile(s.icon_letter, "", size, kind);
}

/**
 * The site's own icon (its /favicon.ico over HTTPS, already in the browser's cache in most
 * cases), the given tile when the site has none. No third-party icon service, no referrer.
 */
export function siteIcon(url: string | null | undefined, fallback: Element, px = 34): Element {
  let origin: string | null = null;
  try {
    const u = url ? new URL(url) : null;
    origin = u && u.protocol === "https:" ? u.origin : null;
  } catch {
    origin = null;
  }
  if (!origin) return fallback;
  const img = h("img", {
    class: "site-icon",
    attrs: { src: `${origin}/favicon.ico`, alt: "", referrerpolicy: "no-referrer", decoding: "async", "aria-hidden": "true", width: String(px), height: String(px) },
  }) as HTMLImageElement;
  img.style.width = img.style.height = `${px}px`;
  img.addEventListener("error", () => img.replaceWith(fallback), { once: true });
  return img;
}

/**
 * The site's icon on a neutral tile, as the apps show it (SiteIconTreatment: a
 * coloured mark on a plain tile): the site's own /favicon.ico over HTTPS, the
 * same source as the pill; when the site has none, the tile keeps the item's
 * initial in the secondary text colour (never a coloured letter tile).
 */
export function siteTile(url: string | null | undefined, letter: string, px: number, round = false): HTMLSpanElement {
  const tileEl = h("span", { class: `site-tile${round ? " round" : ""}`, attrs: { "aria-hidden": "true" } });
  tileEl.style.width = tileEl.style.height = `${px}px`;
  tileEl.style.fontSize = `${Math.round(px * 0.44)}px`;
  const initial = () => {
    tileEl.classList.add("letter");
    tileEl.replaceChildren(h("span", { class: "site-letter" }, (letter.trim().charAt(0) || "•").toUpperCase()));
  };
  let origin: string | null = null;
  try {
    const u = url ? new URL(url) : null;
    origin = u && u.protocol === "https:" ? u.origin : null;
  } catch {
    origin = null;
  }
  if (!origin) {
    initial();
    return tileEl;
  }
  const side = Math.round(px * 0.56);
  const img = h("img", {
    class: "site-img",
    attrs: { src: `${origin}/favicon.ico`, alt: "", referrerpolicy: "no-referrer", decoding: "async", width: String(side), height: String(side) },
  }) as HTMLImageElement;
  img.style.width = img.style.height = `${side}px`;
  img.addEventListener("error", initial, { once: true });
  tileEl.append(img);
  return tileEl;
}

/** A way to sign in on a site: its tile, with the provider's glyph on a disc at the corner. */
export function wayTile(url: string | null | undefined, letter: string, provider: ProviderId | undefined, px: number, round = false): HTMLSpanElement {
  return h(
    "span",
    { class: "way-art", attrs: { "aria-hidden": "true" } },
    siteTile(url, letter, px, round),
    provider ? h("span", { class: "way-badge" }, providerGlyph(provider, 10)) : null,
  );
}

// ---- provider marks ----

/** The providers' official marks, in their own colours (sign-in branding guidelines). */
const BRAND_MARKS: Partial<Record<ProviderId, { view: string; paths: readonly (readonly [string, string])[] }>> = {
  google: {
    view: "0 0 48 48",
    paths: [
      [fixedColor("brand-google-red"), "M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"],
      [fixedColor("brand-google-blue"), "M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"],
      [fixedColor("brand-google-yellow"), "M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"],
      [fixedColor("brand-google-green"), "M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"],
    ],
  },
  microsoft: {
    view: "0 0 23 23",
    paths: [
      [fixedColor("brand-microsoft-red"), "M1 1h10v10H1z"],
      [fixedColor("brand-microsoft-green"), "M12 1h10v10H12z"],
      [fixedColor("brand-microsoft-blue"), "M1 12h10v10H1z"],
      [fixedColor("brand-microsoft-yellow"), "M12 12h10v10H12z"],
    ],
  },
  apple: {
    view: "0 0 24 24",
    paths: [
      [
        fixedColor("brand-apple"),
        "M16.37 1.43c0 1.14-.49 2.27-1.18 3.08-.74.9-1.99 1.57-2.99 1.57-.12 0-.23-.02-.3-.03-.01-.06-.04-.22-.04-.39 0-1.15.57-2.27 1.21-2.98.8-.94 2.14-1.64 3.25-1.68.03.13.05.28.05.43zm4.56 15.71c-.03.07-.46 1.58-1.52 3.12-.94 1.34-1.94 2.71-3.43 2.71-1.52 0-1.9-.88-3.63-.88-1.7 0-2.3.91-3.67.91-1.38 0-2.33-1.26-3.43-2.8-1.29-1.82-2.32-4.63-2.32-7.28 0-4.28 2.8-6.55 5.55-6.55 1.45 0 2.68.95 3.6.95.87 0 2.22-1.01 3.9-1.01.61 0 2.89.06 4.37 2.19-.13.09-2.38 1.37-2.38 4.19 0 3.26 2.85 4.42 2.96 4.45z",
      ],
    ],
  },
  github: {
    view: "0 0 16 16",
    paths: [
      [
        fixedColor("brand-github"),
        "M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z",
      ],
    ],
  },
  facebook: {
    view: "0 0 24 24",
    paths: [
      [fixedColor("brand-facebook"), "M24 12a12 12 0 1 0-13.88 11.85v-8.38H7.08V12h3.04V9.36c0-3 1.79-4.67 4.53-4.67 1.31 0 2.68.24 2.68.24v2.95h-1.51c-1.49 0-1.95.92-1.95 1.87V12h3.32l-.53 3.47h-2.79v8.38A12 12 0 0 0 24 12z"],
      [fixedColor("brand-facebook-f"), "M16.67 15.47 17.2 12h-3.32V9.75c0-.95.46-1.87 1.95-1.87h1.51V4.93s-1.37-.24-2.68-.24c-2.74 0-4.53 1.66-4.53 4.67V12H7.08v3.47h3.04v8.38a12.1 12.1 0 0 0 3.76 0v-8.38z"],
    ],
  },
};

/**
 * The provider's official mark, in colour, on a small white disc. Providers
 * without a vector mark here keep the neutral glyph on the same disc.
 */
export function brandBadge(id: ProviderId, px = 16): HTMLSpanElement {
  const disc = h("span", { class: `brand-badge brand-${id}`, attrs: { "aria-hidden": "true" } });
  disc.style.width = disc.style.height = `${px}px`;
  const mark = BRAND_MARKS[id];
  const inner = Math.round(px * 0.62);
  if (!mark) {
    disc.append(providerGlyph(id, inner));
    return disc;
  }
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", mark.view);
  svg.setAttribute("width", String(inner));
  svg.setAttribute("height", String(inner));
  svg.setAttribute("class", `brand-mark mark-${id}`);
  for (const [fill, d] of mark.paths) {
    const p = document.createElementNS(SVG_NS, "path");
    p.setAttribute("fill", fill);
    p.setAttribute("d", d);
    svg.append(p);
  }
  disc.append(svg);
  return disc;
}

/** The site's tile with the provider's official mark at its corner (a "Sign in with" login). */
export function brandTile(url: string | null | undefined, letter: string, provider: ProviderId | undefined, px: number, round = false): HTMLSpanElement {
  return h(
    "span",
    { class: "brand-art", attrs: { "aria-hidden": "true" } },
    siteTile(url, letter, px, round),
    provider ? brandBadge(provider, Math.round(px * 0.44)) : null,
  );
}

const VAULT_COLORS = [1, 2, 3, 4, 5, 6].map((n) => fixedColor(`vault-${n}`));

/** A stable colour for a vault, from its id. */
export function vaultColor(id: string): string {
  let n = 0;
  for (const c of id) n = (n * 31 + c.charCodeAt(0)) >>> 0;
  return VAULT_COLORS[n % VAULT_COLORS.length]!;
}

/**
 * What the host adds to a row's second line: the account the item belongs to (sent only when
 * several accounts answer) and "associated site" for a login offered through one. Muted text,
 * each after a middle dot; nothing when the host sent neither.
 */
export function accountNotes(x: { account?: string; associated?: true }): HTMLSpanElement[] {
  const out: HTMLSpanElement[] = [];
  if (x.account !== undefined && x.account !== "") out.push(h("span", { class: "meta row-account" }, ` · ${x.account}`));
  if (x.associated === true) out.push(h("span", { class: "meta row-assoc" }, ` · ${t("ui.associatedSite")}`));
  return out;
}

/** The vault as a small coloured chip: a dot and its name. */
export function vaultChip(v: { id: string; name: string }): HTMLSpanElement {
  const chip = h("span", { class: "vault-chip" }, h("span", { class: "vault-dot", attrs: { "aria-hidden": "true" } }), v.name);
  chip.style.setProperty("--vault", vaultColor(v.id));
  return chip;
}

/** The OnePass mark: indigo tile with the white Lattice. */
export function mark(size: "s" | "m" | "l" = "m"): HTMLSpanElement {
  const px = size === "s" ? 12 : size === "m" ? 17 : 34;
  return h("span", { class: `mark mark-${size}`, attrs: { "aria-hidden": "true" } }, icon("lattice", px));
}

/** Text only for assistive technologies. */
export function srOnly(text: string): HTMLSpanElement {
  return h("span", { class: "sr-only" }, text);
}

/** Provider name as written in the UI ("Google", "GitHub"). */
export function providerLabel(id: ProviderId): string {
  return PROVIDERS.find((p) => p.id === id)?.name ?? id;
}

/** "Autre compte Google", or "Autres comptes Google" when there are several. */
export function otherAccounts(name: string, n: number): string {
  return tn("ui.otherAccounts", n, { name });
}

/** The provider's mark as a neutral monochrome glyph (currentColor). */
export function providerGlyph(id: ProviderId, size = 12): SVGSVGElement {
  const svg = icon(`p_${id}` as IconName, size);
  svg.setAttribute("stroke-width", "1.5");
  return svg;
}

/**
 * Icon of a way to sign in: the item's art, with the provider's glyph on a
 * small disc at its corner when it signs in through a provider.
 */
export function wayArt(
  it: { kind: "login" | "card" | "identity"; has_password: boolean; methods: readonly unknown[]; icon_letter: string },
  provider: ProviderId | undefined,
  size: "s" | "m" = "s",
): HTMLSpanElement {
  return h(
    "span",
    { class: `way-art way-art-${size}`, attrs: { "aria-hidden": "true" } },
    itemArt(it, size),
    provider ? h("span", { class: "way-badge" }, providerGlyph(provider, 10)) : null,
  );
}

// ---- frame size ----

export type ObserveSize = (el: Element, cb: () => void) => void;

/** ResizeObserver where the browser has it (not jsdom). */
export const observeSize: ObserveSize = (el, cb) => {
  const RO = (globalThis as { ResizeObserver?: typeof ResizeObserver }).ResizeObserver;
  if (!RO) return;
  new RO(() => cb()).observe(el);
};

/**
 * Reports the natural height of `el` (its content, whatever the frame's
 * current size) each time it changes, once per frame of rendering. The
 * content script sizes the frame to it, between its own bounds.
 */
export function autosize(el: HTMLElement, report: (height: number) => void, observe: ObserveSize = observeSize): () => void {
  let last = -1;
  let queued = false;
  const measure = () => {
    queued = false;
    const height = Math.ceil(el.scrollHeight);
    if (height <= 0 || height === last) return;
    last = height;
    report(height);
  };
  const raf = (globalThis as { requestAnimationFrame?: (cb: () => void) => number }).requestAnimationFrame;
  const queue = () => {
    if (queued) return;
    queued = true;
    if (raf) raf(measure);
    else measure();
  };
  observe(el, queue);
  return queue;
}

export function hostOf(origin: string): string {
  try {
    return new URL(origin).hostname;
  } catch {
    return origin;
  }
}

// ---- messaging ----

/** Sends one message to the service worker and resolves with its raw reply. */
export type Send = (m: UiToBg) => Promise<unknown>;

export type Result<T> = { ok: true; value: T } | { ok: false; code: string };

/** Stable codes the pages know a sentence for (spec 10, plus background codes). */
const KNOWN_CODES: ReadonlySet<string> = new Set([
  "version",
  "bad_mac",
  "bad_frame",
  "locked",
  "not_found",
  "origin_mismatch",
  "insecure_origin",
  "cross_site_frame",
  "not_allowed",
  "reprompt_required",
  "rate_limited",
  "invalid",
  "internal",
  "unpaired",
  "host_missing",
  "timeout",
  "refused",
  "expired",
  "no_form",
  "site_refused",
]);

/** One request; the reply is validated by `parse` (null: malformed). */
export async function call<T>(send: Send, msg: UiToBg, parse: (v: unknown) => T | null): Promise<Result<T>> {
  let reply: unknown;
  try {
    reply = await send(msg);
  } catch {
    return { ok: false, code: "internal" };
  }
  if (typeof reply !== "object" || reply === null) return { ok: false, code: "internal" };
  const r = reply as Record<string, unknown>;
  if ("err" in r) {
    const code = typeof r.err === "string" && KNOWN_CODES.has(r.err) ? r.err : "internal";
    return { ok: false, code };
  }
  if (!("ok" in r)) return { ok: false, code: "internal" };
  const value = parse(r.ok);
  return value === null ? { ok: false, code: "internal" } : { ok: true, value };
}

/** Sentence (French or English) for a stable code; never a host message. */
export function errorText(code: string): string {
  switch (code) {
    case "version":
      return t("ui.extensionAndOnepassApp");
    case "bad_mac":
    case "bad_frame":
      return t("ui.exchangeWithOnepassApp");
    case "locked":
      return t("ui.onepassLocked");
    case "not_found":
      return t("ui.itemNotFound");
    case "origin_mismatch":
      return t("ui.pageChangedFillCancelled");
    case "insecure_origin":
      return t("ui.insecurePageHttpFill");
    case "cross_site_frame":
      return t("ui.frameFromAnotherSite");
    case "not_allowed":
      return t("ui.actionNotAllowedHere");
    case "reprompt_required":
      return t("ui.confirmItemInOnepass");
    case "rate_limited":
      return t("ui.tooManyRequestsTry");
    case "invalid":
      return t("ui.requestRefused");
    case "unpaired":
      return t("ui.onepassNotPaired");
    case "host_missing":
      return t("ui.onepassAppNotFound");
    case "timeout":
      return t("ui.onepassAppNotResponding");
    case "refused":
      return t("ui.pairingRefusedInOnepass");
    case "expired":
      return t("ui.codeExpiredStartPairing");
    case "no_form":
      return t("ui.noFormToFill");
    case "site_refused":
      return t("ui.siteRefusesGeneratedPassword");
    default:
      return t("ui.onepassInternalError");
  }
}

const TOKEN_HASH = /^#([A-Za-z0-9_-]{22})$/;

/** The frame token from `location.hash`, or null. */
export function tokenFromHash(hash: string): string | null {
  return TOKEN_HASH.exec(hash)?.[1] ?? null;
}

// ---- anti-clickjacking ----

export {
  CLICK_GUARD_MS,
  ClickGuard,
  type GuardOptions,
  hasVisibilityV2,
  type ObserveVisibility,
  observeVisibility,
  type Visibility,
} from "../shared/click-guard";

// ---- touch ----

/**
 * Marks the frame page `touch` (class on `<html>`) by the content script's own rule, kept live:
 * finger-sized rows exactly when the content script lays the frame out for a finger (IPAD-01). The
 * CSS also keeps `(pointer: coarse)` for pages that do not call this.
 */
export function markTouch(doc: Document): void {
  const view = doc.defaultView;
  const apply = () => doc.documentElement.classList.toggle("touch", touchDevice(view));
  apply();
  for (const q of POINTER_QUERIES) {
    try {
      view?.matchMedia?.(q).addEventListener?.("change", apply);
    } catch {
      // No media queries: the first mark stays.
    }
  }
}

// ---- timers ----

/** After an unlock was asked in the app: one check a second, for the shared deadline (90 s). */
export const UNLOCK_POLL_MS = 1000;
export const UNLOCK_WAIT_TRIES = Math.round(UNLOCK_WAIT_MS / UNLOCK_POLL_MS);

export interface Timers {
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(id: unknown): void;
  setInterval(fn: () => void, ms: number): unknown;
  clearInterval(id: unknown): void;
}

export const realTimers: Timers = {
  setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimeout: (id) => globalThis.clearTimeout(id as ReturnType<typeof setTimeout>),
  setInterval: (fn, ms) => globalThis.setInterval(fn, ms),
  clearInterval: (id) => globalThis.clearInterval(id as ReturnType<typeof setInterval>),
};

/** Common dependencies of the in-page frames. */
export interface FrameDeps {
  send: Send;
  /** `location.hash` of the page. */
  hash: string;
  now?: () => number;
  trusted?: (e: Event) => boolean;
  observe?: ObserveVisibility;
  timers?: Timers;
  /** Size observer of the frame content (tests drive it). */
  observeSize?: ObserveSize;
  /** UI preferences of this browser profile (`storage.local`); none in tests unless given. */
  prefs?: Prefs;
}

/** A small key-value store for UI preferences (no secret ever goes there). */
export interface Prefs {
  get(key: string): Promise<unknown>;
  set(key: string, value: unknown): Promise<void>;
}

/** Common page frame: a status line for errors. */
export function messageBlock(title: string, detail?: string, action?: HTMLElement): HTMLElement {
  return h(
    "div",
    { class: "message", attrs: { role: "status" } },
    h("p", { class: "message-title" }, title),
    detail ? h("p", { class: "message-detail" }, detail) : null,
    action ?? null,
  );
}
