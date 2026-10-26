// Page observer (spec 8.2): pages that build their forms after load are
// analysed again 150 ms after a mutation burst starts; the analysis is
// reported only when its signature changes. Runs in every frame: routing by
// `frameId` is the service worker's job.
import type { PageAnalysis } from "../shared/messages";

export const OBSERVER_DELAY_MS = 150;

/** Attributes whose change can show, hide or retype a field. */
const ATTRIBUTES = ["type", "style", "class", "hidden", "disabled", "readonly", "autocomplete", "aria-hidden"];

export interface ObserverOptions {
  doc: Document;
  analyze: () => PageAnalysis;
  /** Called with each analysis whose signature differs from the previous one. */
  onChange: (a: PageAnalysis) => void;
  /** Called on every mutation batch (cheap upkeep, e.g. re-attaching the host). */
  onMutation?: () => void;
  /** Mutations caused by our own nodes are ignored. */
  isOwn: (node: Node) => boolean;
}

export interface PageObserver {
  start(): void;
  stop(): void;
  /** Analyses now (no delay); reports if changed. Returns the analysis. */
  refresh(): PageAnalysis;
  latest(): PageAnalysis | null;
}

/**
 * Stable signature of an analysis: everything the worker consumes (form
 * kinds, field roles and refs, buttons, flags, URL).
 */
export function signature(a: PageAnalysis): string {
  return JSON.stringify([
    a.url,
    a.captcha,
    a.push,
    a.forms.map((f) => [f.ref, f.kind, f.submitRef ?? null, f.fields.map((x) => [x.ref, x.role, x.parts ?? null])]),
    a.providerButtons.map((b) => [b.provider, b.ref]),
    a.accountChooser.map((b) => [b.email, b.ref]),
  ]);
}

export function createObserver(opts: ObserverOptions): PageObserver {
  const { doc } = opts;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let current: PageAnalysis | null = null;
  let sig = "";
  let mo: MutationObserver | null = null;

  const refresh = (): PageAnalysis => {
    const a = opts.analyze();
    current = a;
    const s = signature(a);
    if (s !== sig) {
      sig = s;
      opts.onChange(a);
    }
    return a;
  };

  const relevant = (records: MutationRecord[]) =>
    records.some((r) => {
      if (opts.isOwn(r.target)) return false;
      if (r.type !== "childList") return true;
      const nodes = [...Array.from(r.addedNodes), ...Array.from(r.removedNodes)];
      return nodes.length === 0 || nodes.some((n) => !opts.isOwn(n));
    });

  return {
    start() {
      refresh();
      const MO = doc.defaultView?.MutationObserver ?? globalThis.MutationObserver;
      mo = new MO((records) => {
        opts.onMutation?.();
        if (timer !== null || !relevant(records)) return;
        // Fixed delay from the first mutation of a burst: a page that mutates
        // continuously still gets analysed every 150 ms.
        timer = setTimeout(() => {
          timer = null;
          refresh();
        }, OBSERVER_DELAY_MS);
      });
      mo.observe(doc, { subtree: true, childList: true, attributes: true, attributeFilter: ATTRIBUTES });
    },
    stop() {
      mo?.disconnect();
      mo = null;
      if (timer !== null) clearTimeout(timer);
      timer = null;
    },
    refresh,
    latest: () => current,
  };
}
