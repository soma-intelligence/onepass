// Anti-clickjacking guard shared by the extension frames (menu, overlay, save, passkey) and the
// in-page field icon of the content script. Kept free of UI imports so the content script can use
// it without pulling the page building blocks into its bundle.

/** Clicks are ignored this long after content appears (spec 8.3). */
export const CLICK_GUARD_MS = 300;
/** A held-back tap shows pressed at least this long. */
const HELD_MIN_MS = 120;

export interface Visibility {
  intersecting: boolean;
  /** IntersectionObserver v2 `isVisible`; undefined where unsupported. */
  visible?: boolean;
}

/** Starts observing `el`; the returned function (when there is one) stops it. */
export type ObserveVisibility = (el: Element, cb: (v: Visibility) => void) => (() => void) | void;

/**
 * Whether this browser reports IntersectionObserver v2 `isVisible` (Chromium). Elsewhere (Firefox,
 * Safari) occlusion is only checked by the content script's own cheaper rules.
 */
export function hasVisibilityV2(): boolean {
  const E = (globalThis as { IntersectionObserverEntry?: { prototype: object } }).IntersectionObserverEntry;
  return E !== undefined && "isVisible" in E.prototype;
}

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
    return () => io.disconnect();
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
  private intersecting: boolean | undefined;
  private readonly trusted: (e: Event) => boolean;

  constructor(private readonly opts: GuardOptions) {
    this.shownAt = opts.now();
    this.trusted = opts.trusted ?? ((e) => e.isTrusted);
  }

  /** Content changed under the pointer: restart the delay. */
  reset(): void {
    this.shownAt = this.opts.now();
  }

  /**
   * Becoming visible (v2 `isVisible`) or entering the viewport re-arms the
   * delay: a page cannot keep the frame hidden and reveal it under a click.
   */
  setVisibility(v: Visibility): void {
    if (v.intersecting && this.intersecting === false) this.reset();
    this.intersecting = v.intersecting;
    if (v.visible === undefined) return;
    if (v.visible && this.visible === false) this.reset();
    this.visible = v.visible;
  }

  accepts(e: Event): boolean {
    if (!this.trusted(e)) return false;
    return this.ready();
  }

  /**
   * Past the delay and not declared hidden: a key relayed by the content
   * script (trusted there) may act. Same time and visibility rules as a click.
   */
  ready(): boolean {
    if (this.opts.now() - this.shownAt < CLICK_GUARD_MS) return false;
    return this.visible !== false;
  }

  /** Wraps a click handler with the guard. */
  wrap(fn: (e: MouseEvent) => void): (e: MouseEvent) => void {
    return (e) => {
      if (!this.accepts(e)) {
        e.preventDefault();
        // A real tap held back by the delay only (IOSSAF-09): the control shows it was pressed
        // until the delay is over, so the user taps again rather than wonder. Nothing runs.
        if (this.trusted(e)) this.showHeld(e.currentTarget);
        return;
      }
      fn(e);
    };
  }

  private readonly held = new WeakMap<Element, ReturnType<typeof setTimeout>>();

  private showHeld(target: EventTarget | null): void {
    if (!(target instanceof Element)) return;
    const left = Math.max(0, CLICK_GUARD_MS - (this.opts.now() - this.shownAt));
    const prev = this.held.get(target);
    if (prev !== undefined) globalThis.clearTimeout(prev);
    target.classList.add("held");
    this.held.set(
      target,
      globalThis.setTimeout(() => {
        this.held.delete(target);
        target.classList.remove("held");
      }, Math.max(left, HELD_MIN_MS)),
    );
  }
}
