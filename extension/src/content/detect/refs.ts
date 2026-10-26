import { newToken } from "../../shared/tokens";

/**
 * Maps page elements to opaque refs. Refs are random 128-bit tokens, never
 * derived from page attributes, so a page cannot predict or forge them.
 * Elements are held weakly: the registry never keeps a removed node alive.
 */
export class RefRegistry {
  private readonly byElement = new WeakMap<Element, string>();
  private readonly byRef = new Map<string, WeakRef<Element>>();

  refFor(el: Element): string {
    const known = this.byElement.get(el);
    if (known !== undefined) return known;
    const ref = newToken();
    this.byElement.set(el, ref);
    this.byRef.set(ref, new WeakRef(el));
    return ref;
  }

  /** The element for `ref`, or null if unknown, collected or detached. */
  get(ref: string): Element | null {
    const el = this.byRef.get(ref)?.deref();
    if (el === undefined) {
      this.byRef.delete(ref);
      return null;
    }
    if (!el.isConnected) return null;
    return el;
  }

  /** Drops entries whose element was garbage collected or detached. */
  prune(): void {
    for (const [ref, weak] of this.byRef) {
      const el = weak.deref();
      if (el === undefined || !el.isConnected) this.byRef.delete(ref);
    }
  }
}
