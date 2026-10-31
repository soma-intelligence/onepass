// Content script side of the dev-only recorder: remembers which fields OnePass
// filled (by role) and which the user edited (a trusted input or change event,
// never the value), and reports a step on each submission.
import type { FieldRole } from "../shared/messages";
import { type FilledRole, MSG_STEP, recordSubmit } from "./recorder";

export interface RecorderHooks {
  /** OnePass wrote `role` into `el`. */
  noteFilled(el: Element, role: FieldRole): void;
  /** A form (or container) was submitted by the user. */
  step(container: Element): void;
  stop(): void;
}

const DEDUPE_MS = 1000;
const MAX_SEEN = 200;

export function createRecorderContent(o: {
  doc: Document;
  send: (m: unknown) => Promise<unknown>;
  isTrusted: (e: Event) => boolean;
}): RecorderHooks {
  const filled = new WeakMap<Element, FilledRole>();
  // Latest value seen in each field this script saw OnePass fill or the user edit.
  // Memory only (never stored or sent): used to redact page text that echoes a
  // value, on a later step too. Bounded; the oldest entries go first.
  const seen = new Map<Element, string>();
  const remember = (el: Element) => {
    const v = (el as HTMLInputElement).value;
    if (typeof v !== "string" || v === "") return;
    seen.delete(el);
    seen.set(el, v);
    if (seen.size > MAX_SEEN) seen.delete(seen.keys().next().value as Element);
  };
  const lastAt = new WeakMap<Element, number>();
  const onEdit = (e: Event) => {
    if (!o.isTrusted(e) || !(e.target instanceof Element)) return;
    filled.set(e.target, "user");
    remember(e.target);
  };
  o.doc.addEventListener("input", onEdit, true);
  o.doc.addEventListener("change", onEdit, true);
  return {
    noteFilled(el, role) {
      filled.set(el, role);
      remember(el);
    },
    step(container) {
      const now = Date.now();
      const prev = lastAt.get(container);
      // A click on the submit button and the submit event it causes are one step.
      if (prev !== undefined && now - prev < DEDUPE_MS) return;
      lastAt.set(container, now);
      void o.send({ type: MSG_STEP, step: recordSubmit(container, filled, seen.values()) }).catch(() => undefined);
    },
    stop() {
      o.doc.removeEventListener("input", onEdit, true);
      o.doc.removeEventListener("change", onEdit, true);
    },
  };
}

export default createRecorderContent;
