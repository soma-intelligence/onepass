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

export function createRecorderContent(o: {
  doc: Document;
  send: (m: unknown) => Promise<unknown>;
  isTrusted: (e: Event) => boolean;
}): RecorderHooks {
  const filled = new WeakMap<Element, FilledRole>();
  const lastAt = new WeakMap<Element, number>();
  const onEdit = (e: Event) => {
    if (o.isTrusted(e) && e.target instanceof Element) filled.set(e.target, "user");
  };
  o.doc.addEventListener("input", onEdit, true);
  o.doc.addEventListener("change", onEdit, true);
  return {
    noteFilled: (el, role) => void filled.set(el, role),
    step(container) {
      const now = Date.now();
      const prev = lastAt.get(container);
      // A click on the submit button and the submit event it causes are one step.
      if (prev !== undefined && now - prev < DEDUPE_MS) return;
      lastAt.set(container, now);
      void o.send({ type: MSG_STEP, step: recordSubmit(container, filled) }).catch(() => undefined);
    },
    stop() {
      o.doc.removeEventListener("input", onEdit, true);
      o.doc.removeEventListener("change", onEdit, true);
    },
  };
}

export default createRecorderContent;
