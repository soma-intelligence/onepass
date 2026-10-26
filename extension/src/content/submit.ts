// Submission watcher (spec 8.5) and the click / submit actions of the chain.
//
// A submission of a login, signup or change-password form is seen through:
// - a trusted `submit` event;
// - a trusted click on the form's submit control (or any submit-type button);
// - a trusted Enter keydown in one of its fields;
// - single-page apps: a trusted click on any other button of the form, after
//   which the password field disappears within 2 s.
// The identifier and password are read when the gesture happens (the page
// often clears the fields right after) and sent once per submission:
// identical reports within 2 s are dropped.
import type { CsToBg, FormInfo, FormKind, PageAnalysis } from "../shared/messages";
import type { RefRegistry } from "./detect/refs";
import { type Geometry, isRendered } from "./detect/visibility";
import { nativeValue } from "./filler";

export const DEDUPE_MS = 2000;
export const SPA_WINDOW_MS = 2000;
const SPA_POLL_MS = 250;

const CREDENTIAL_KINDS: ReadonlySet<FormKind> = new Set<FormKind>(["login", "signup", "change_password"]);
const BUTTONS =
  'button, input[type="submit" i], input[type="image" i], input[type="button" i], [role="button"], a:not([href]), a[href^="#"]';

export interface Credentials {
  formRef: string;
  username: string;
  password: string;
  isNew: boolean;
}

export interface SubmitOptions {
  doc: Document;
  refs: RefRegistry;
  geometry: Geometry;
  isTrusted: (e: Event) => boolean;
  /** Latest analysis sent to the worker. */
  latest: () => PageAnalysis | null;
  /** A fresh analysis (for chain actions). */
  analyze: () => PageAnalysis;
  onCredentials: (c: Extract<CsToBg, { type: "submitted_credentials" }>) => void;
}

export interface SubmitWatcher {
  start(): void;
  stop(): void;
  /** Chain: clicks a rendered element by ref. */
  clickRef(ref: string): boolean;
  /** Chain: submits a form (its button, then `requestSubmit`, then Enter). */
  submitForm(formRef: string): boolean;
}

function isSubmitType(el: Element): boolean {
  if (el instanceof HTMLButtonElement) return el.type === "submit";
  return el instanceof HTMLInputElement && (el.type === "submit" || el.type === "image");
}

export function createSubmitWatcher(opts: SubmitOptions): SubmitWatcher {
  const { doc, refs, geometry, isTrusted } = opts;
  let last: { key: string; at: number } | null = null;
  const timers = new Set<ReturnType<typeof setTimeout>>();
  const view = doc.defaultView;

  const ownerForm = (el: Element): HTMLFormElement | null =>
    el instanceof HTMLInputElement || el instanceof HTMLButtonElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement
      ? el.form
      : el.closest("form");

  /** The credential form that `el` belongs to (field, button, or the form itself). */
  const formOf = (el: Element): FormInfo | null => {
    const a = opts.latest();
    if (!a) return null;
    for (const f of a.forms) {
      if (!CREDENTIAL_KINDS.has(f.kind)) continue;
      const container = refs.get(f.ref);
      if (!container) continue;
      if (el === container) return f;
      if (f.fields.some((x) => refs.get(x.ref) === el)) return f;
      const owner = ownerForm(el);
      if (container instanceof HTMLFormElement ? owner === container : owner === null && container.contains(el)) return f;
    }
    return null;
  };

  const passwordField = (f: FormInfo): Element | null => {
    const role = f.kind === "login" ? "current_password" : "new_password";
    const fi = f.fields.find((x) => x.role === role);
    return fi ? refs.get(fi.ref) : null;
  };

  const read = (f: FormInfo): Credentials | null => {
    const pw = passwordField(f);
    const password = pw ? nativeValue(pw) : "";
    if (password === "") return null;
    let username = "";
    for (const role of ["username", "email"] as const) {
      for (const fi of f.fields) {
        if (fi.role !== role || username !== "") continue;
        const el = refs.get(fi.ref);
        if (el) username = nativeValue(el).trim();
      }
    }
    return { formRef: f.ref, username, password, isNew: f.kind !== "login" };
  };

  const report = (c: Credentials | null) => {
    if (!c) return;
    const key = `${c.formRef}\u0000${c.username}\u0000${c.password}`;
    const now = Date.now();
    if (last && last.key === key && now - last.at < DEDUPE_MS) return;
    last = { key, at: now };
    opts.onCredentials({ type: "submitted_credentials", ...c });
  };

  /** SPA: report the snapshot if the password field goes away within 2 s. */
  const watchDisappearance = (f: FormInfo, snapshot: Credentials) => {
    const pw = passwordField(f);
    if (!pw) return;
    const deadline = Date.now() + SPA_WINDOW_MS;
    const tick = () => {
      if (!pw.isConnected || !isRendered(pw, geometry)) {
        report(snapshot);
        return;
      }
      if (Date.now() >= deadline) return;
      const t = setTimeout(() => {
        timers.delete(t);
        tick();
      }, SPA_POLL_MS);
      timers.add(t);
    };
    const t = setTimeout(() => {
      timers.delete(t);
      tick();
    }, SPA_POLL_MS);
    timers.add(t);
  };

  const onSubmit = (e: Event) => {
    if (!isTrusted(e) || !(e.target instanceof Element)) return;
    const f = formOf(e.target);
    if (f) report(read(f));
  };

  const onClick = (e: Event) => {
    if (!isTrusted(e) || !(e.target instanceof Element)) return;
    const button = e.target.closest(BUTTONS);
    if (!button) return;
    const f = formOf(button);
    if (!f) return;
    const snapshot = read(f);
    if (!snapshot) return;
    if ((f.submitRef !== undefined && refs.get(f.submitRef) === button) || isSubmitType(button)) report(snapshot);
    else watchDisappearance(f, snapshot);
  };

  const onKey = (e: Event) => {
    if (!isTrusted(e) || !(e instanceof KeyboardEvent) || e.key !== "Enter" || e.isComposing) return;
    if (!(e.target instanceof HTMLInputElement)) return;
    const f = formOf(e.target);
    if (f) report(read(f));
  };

  const target: EventTarget = view ?? doc;

  return {
    start() {
      target.addEventListener("submit", onSubmit, true);
      target.addEventListener("click", onClick, true);
      target.addEventListener("keydown", onKey, true);
    },
    stop() {
      target.removeEventListener("submit", onSubmit, true);
      target.removeEventListener("click", onClick, true);
      target.removeEventListener("keydown", onKey, true);
      for (const t of timers) clearTimeout(t);
      timers.clear();
    },
    clickRef(ref) {
      const el = refs.get(ref);
      if (!(el instanceof HTMLElement) || !isRendered(el, geometry)) return false;
      el.click();
      return true;
    },
    submitForm(formRef) {
      const container = refs.get(formRef);
      const f = opts.analyze().forms.find((x) => x.ref === formRef);
      if (!container || !f) return false;
      const button = f.submitRef !== undefined ? refs.get(f.submitRef) : null;
      if (button instanceof HTMLElement && isRendered(button, geometry)) {
        button.click();
        return true;
      }
      if (container instanceof HTMLFormElement) {
        try {
          container.requestSubmit();
          return true;
        } catch {
          // Invalid form: fall through to Enter.
        }
      }
      const lastField = [...f.fields].reverse().map((x) => refs.get(x.parts?.at(-1) ?? x.ref)).find((el) => el instanceof HTMLElement);
      if (!(lastField instanceof HTMLElement)) return false;
      for (const type of ["keydown", "keypress", "keyup"]) {
        lastField.dispatchEvent(new KeyboardEvent(type, { key: "Enter", code: "Enter", keyCode: 13, which: 13, bubbles: true, cancelable: true }));
      }
      return true;
    },
  };
}
