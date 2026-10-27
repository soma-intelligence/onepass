import type { FormInfo, PageAnalysis } from "../../shared/messages";
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

/** Most forms remembered by `FormLineage` (oldest dropped first). */
const LINEAGE_MAX = 256;

/**
 * Identity of a form across re-renders. Single-page apps often replace a
 * form with a fresh copy (same markup, new nodes) while it is being filled:
 * every ref of the old copy is then dead. A form is identified by what the
 * page renders (tag, `id`, `name`, kind, field roles in order), recorded at
 * each analysis; a dead form ref resolves to the one connected form of the
 * current analysis with the same identity, never to a lookalike when two
 * forms share it.
 */
export class FormLineage {
  private readonly keys = new Map<string, string>();

  constructor(private readonly refs: RefRegistry) {}

  private keyOf(f: FormInfo): string | null {
    const el = this.refs.get(f.ref);
    if (!el) return null;
    const fields = f.fields.map((x) => `${x.role}:${x.parts?.length ?? 0}`);
    // Attributes, not properties: a field named "id" shadows `form.id`.
    return JSON.stringify([el.localName, el.getAttribute("id") ?? "", el.getAttribute("name") ?? "", f.kind, fields]);
  }

  /** Remembers the identity of each form of an analysis. */
  record(a: PageAnalysis): void {
    for (const f of a.forms) {
      const k = this.keyOf(f);
      if (k === null) continue;
      this.keys.delete(f.ref);
      this.keys.set(f.ref, k);
    }
    while (this.keys.size > LINEAGE_MAX) {
      const oldest = this.keys.keys().next().value;
      if (oldest === undefined) break;
      this.keys.delete(oldest);
    }
  }

  /** The form `ref` is now in `a`: itself if still there, else its unique successor. */
  resolve(ref: string, a: PageAnalysis): FormInfo | null {
    const same = a.forms.find((f) => f.ref === ref);
    if (same) return same;
    const k = this.keys.get(ref);
    if (k === undefined) return null;
    const next = a.forms.filter((f) => this.keyOf(f) === k);
    return next.length === 1 ? (next[0] ?? null) : null;
  }
}
