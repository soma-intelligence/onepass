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
import { PROVIDERS } from "../shared/providers";

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
};

export function icon(name: IconName, size = 14): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("viewBox", VIEWBOX[name] ?? "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("class", `glyph glyph-${name}`);
  const filled = name === "more";
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
export const FALLBACK_COLOR = "#5B6472";

/** A hex color from the host, or a neutral one. */
export function safeColor(c: string): string {
  return COLOR_RE.test(c) ? c : FALLBACK_COLOR;
}

/** Item tile: one or two letters on the item color. */
export function tile(letter: string, color: string, size: "s" | "m" | "l" = "m"): HTMLSpanElement {
  const el = h("span", { class: `tile tile-${size}`, attrs: { "aria-hidden": "true" } }, [...letter].slice(0, 2).join("").toUpperCase());
  el.style.background = safeColor(color);
  return el;
}

/** The OnePass mark (accent dot). */
export function mark(size: "s" | "m" = "m"): HTMLSpanElement {
  return h("span", { class: `mark mark-${size}`, attrs: { "aria-hidden": "true" } });
}

/** Text only for assistive technologies. */
export function srOnly(text: string): HTMLSpanElement {
  return h("span", { class: "sr-only" }, text);
}

/** Provider name as written in the UI ("Google", "GitHub"). */
export function providerLabel(id: ProviderId): string {
  return PROVIDERS.find((p) => p.id === id)?.name ?? id;
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

/** French sentence for a stable code; never a host message. */
export function errorText(code: string): string {
  switch (code) {
    case "version":
      return "L'extension et l'app OnePass ne sont pas à la même version.";
    case "bad_mac":
    case "bad_frame":
      return "Échange avec l'app OnePass refusé. Réessaie.";
    case "locked":
      return "OnePass est verrouillé";
    case "not_found":
      return "Élément introuvable.";
    case "origin_mismatch":
      return "La page a changé : remplissage annulé.";
    case "insecure_origin":
      return "Page non sécurisée (HTTP) : remplissage refusé.";
    case "cross_site_frame":
      return "Cadre d'un autre site : remplissage refusé.";
    case "not_allowed":
      return "Action non permise ici.";
    case "reprompt_required":
      return "Confirme dans l'app OnePass pour cet élément.";
    case "rate_limited":
      return "Trop de demandes. Réessaie dans une minute.";
    case "invalid":
      return "Demande refusée.";
    case "unpaired":
      return "OnePass n'est pas appairé.";
    case "host_missing":
      return "App OnePass introuvable";
    case "timeout":
      return "L'app OnePass ne répond pas.";
    case "refused":
      return "Appairage refusé dans l'app OnePass.";
    case "expired":
      return "Le code a expiré. Recommence l'appairage.";
    case "no_form":
      return "Aucun formulaire à remplir sur cette page.";
    default:
      return "Erreur interne de OnePass.";
  }
}

const TOKEN_HASH = /^#([A-Za-z0-9_-]{22})$/;

/** The frame token from `location.hash`, or null. */
export function tokenFromHash(hash: string): string | null {
  return TOKEN_HASH.exec(hash)?.[1] ?? null;
}

// ---- anti-clickjacking ----

/** Clicks are ignored this long after content appears (spec 8.3). */
export const CLICK_GUARD_MS = 300;

export interface Visibility {
  intersecting: boolean;
  /** IntersectionObserver v2 `isVisible`; undefined where unsupported. */
  visible?: boolean;
}

export type ObserveVisibility = (el: Element, cb: (v: Visibility) => void) => void;

/** IntersectionObserver with v2 `trackVisibility` where the browser has it. */
export const observeVisibility: ObserveVisibility = (el, cb) => {
  const IO = (globalThis as { IntersectionObserver?: typeof IntersectionObserver }).IntersectionObserver;
  if (!IO) return;
  try {
    const opts = { threshold: [0, 1], trackVisibility: true, delay: 100 } as IntersectionObserverInit;
    const io = new IO((entries) => {
      for (const e of entries) {
        const v: Visibility = { intersecting: e.isIntersecting };
        const iv = (e as { isVisible?: unknown }).isVisible;
        if (typeof iv === "boolean") v.visible = iv;
        cb(v);
      }
    }, opts);
    io.observe(el);
  } catch {
    // No observer: the time guard still applies.
  }
};

export interface GuardOptions {
  now: () => number;
  /** Whether an event comes from the user (`isTrusted` in production). */
  trusted?: (e: Event) => boolean;
}

/**
 * Accepts an activation only 300 ms after the content was (re)shown, from a
 * trusted event, and, where IntersectionObserver v2 reports it, while the
 * frame is declared visible (not covered, not transformed, opaque).
 */
export class ClickGuard {
  private shownAt: number;
  private visible: boolean | undefined;
  private readonly trusted: (e: Event) => boolean;

  constructor(private readonly opts: GuardOptions) {
    this.shownAt = opts.now();
    this.trusted = opts.trusted ?? ((e) => e.isTrusted);
  }

  /** Content changed under the pointer: restart the delay. */
  reset(): void {
    this.shownAt = this.opts.now();
  }

  setVisibility(v: Visibility): void {
    if (v.visible !== undefined) this.visible = v.visible;
  }

  accepts(e: Event): boolean {
    if (!this.trusted(e)) return false;
    if (this.opts.now() - this.shownAt < CLICK_GUARD_MS) return false;
    return this.visible !== false;
  }

  /** Wraps a click handler with the guard. */
  wrap(fn: (e: MouseEvent) => void): (e: MouseEvent) => void {
    return (e) => {
      if (!this.accepts(e)) {
        e.preventDefault();
        return;
      }
      fn(e);
    };
  }
}

// ---- timers ----

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
