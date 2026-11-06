// Submission watcher (spec 8.5) and the click / submit actions of the chain.
//
// A submission of a login, signup or change-password form is seen through:
// - a trusted `submit` event;
// - a trusted click on the form's submit control (or any submit-type button);
// - a trusted Enter keydown in one of its fields;
// - single-page apps: a trusted click on any other button of the form, after
//   which the password field disappears within 10 s (a real server round
//   trip often takes more than a second or two).
// A lone identifier step (identifier first, password on the next page) is
// reported the same way, without a password (`submitted_identifier`): the
// worker then knows whose password the next step sends.
// The identifier and password are read when the gesture happens (the page
// often clears the fields right after) and sent once per submission:
// identical reports within 2 s are dropped.
//
// A `submit` event is trusted even when a page script called
// `requestSubmit()` or `button.click()`: it is reported only after a trusted
// click or keydown inside that same form within the last 5 s, and, where the
// browser has it, under user activation (`navigator.userActivation.isActive`).
// User activation alone is page-wide: after any click elsewhere, a page could
// submit a credential form filled with values of its choosing. Otherwise a
// page could make OnePass report credentials of its choosing at will (save
// prompt spoofing, probing for stored credentials).
//
// A card, identity or address form sent the same ways (submit event after a
// gesture in it, its submit control, Enter) is reported as `submitted_form`:
// the values of its card or identity roles, never a security code, so the
// worker can offer to save a card or address typed by hand (MS-04).
//
// Forms in shadow roots (spec D1, D2): the caller's `listen` also listens on
// every watched root, so a gesture is read from its real target (a `submit`
// never leaves its root); a button's own shadow root is crossed to its host.
import {
  CARD_SUBMIT_ROLES,
  type CsToBg,
  type FormInfo,
  type FormKind,
  IDENTITY_SUBMIT_ROLES,
  type PageAnalysis,
  type SavedFormKind,
  type SubmittedValues,
} from "../shared/messages";
import { buttonClass } from "./context";
import { BUTTON_SELECTOR } from "./detect/forms";
import type { RefRegistry } from "./detect/refs";
import { composedClosest, composedContains } from "./detect/shadow";
import { type Geometry, isRendered } from "./detect/visibility";
import { nativeValue } from "./filler";

export const DEDUPE_MS = 2000;
export const SPA_WINDOW_MS = 10_000;
const SPA_POLL_MS = 250;
/** A `submit` event counts only after a trusted gesture in that form this recent. */
export const GESTURE_MS = 5000;

const CREDENTIAL_KINDS: ReadonlySet<FormKind> = new Set<FormKind>(["login", "signup", "change_password"]);
/** Forms whose values may be offered for saving, and as what. */
const SAVED_KINDS: ReadonlyMap<FormKind, SavedFormKind> = new Map<FormKind, SavedFormKind>([
  ["card", "card"],
  ["identity", "identity"],
  ["address", "identity"],
]);
const SAVED_FORM_KINDS: ReadonlySet<FormKind> = new Set<FormKind>(SAVED_KINDS.keys());
const GESTURE_KINDS: ReadonlySet<FormKind> = new Set<FormKind>([...CREDENTIAL_KINDS, ...SAVED_KINDS.keys()]);
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
  /** Where form `ref` is in `a`: itself, or the copy a re-render put in its place. */
  resolve: (ref: string, a: PageAnalysis) => FormInfo | null;
  onCredentials: (c: Extract<CsToBg, { type: "submitted_credentials" }>) => void;
  /** A card, identity or address form was sent by the user. */
  onForm?: (c: Extract<CsToBg, { type: "submitted_form" }>) => void;
  /** A lone identifier step was sent. */
  onIdentifier?: (c: Extract<CsToBg, { type: "submitted_identifier" }>) => void;
  /** A trusted submission of any form (or, without a form, of the page): the container. Tooling only. */
  onStep?: (container: Element) => void;
  /**
   * Adds a listener (and returns its removal); defaults to `target` alone.
   * The content script passes its tree listeners: the document and every
   * watched shadow root.
   */
  listen?: (target: EventTarget, type: string, fn: (e: Event) => void, options: AddEventListenerOptions) => () => void;
}

export interface SubmitWatcher {
  start(): void;
  stop(): void;
  /** Chain: clicks a rendered element by ref. */
  clickRef(ref: string): boolean;
  /** One-click signup: clicks the button of `ref` only if it is rendered and still reads as a passkey button. */
  clickPasskey(ref: string): boolean;
  /**
   * Chain and plan: submits a form (its button, then `requestSubmit`, then
   * Enter). `planned` (a plan's submit): only that very form, never a copy a
   * re-render put in its place, and never when one of its buttons reads as
   * pay or create now.
   */
  submitForm(formRef: string, planned?: boolean): boolean;
}

function isSubmitType(el: Element): boolean {
  if (el instanceof HTMLButtonElement) return el.type === "submit";
  return el instanceof HTMLInputElement && (el.type === "submit" || el.type === "image");
}

/** The form's chosen submit control, or any rendered button of it, reads as pay or create. */
function payOrCreate(container: Element, button: Element | null, geometry: Geometry): boolean {
  const all = new Set<Element>(Array.from(container.querySelectorAll(BUTTON_SELECTOR)));
  if (button) all.add(button);
  if (container instanceof HTMLFormElement) for (const el of Array.from(container.elements)) if (el.matches(BUTTON_SELECTOR)) all.add(el);
  for (const b of all) {
    if (!(b instanceof HTMLElement) || (b !== button && !isRendered(b, geometry))) continue;
    const c = buttonClass(b);
    if (c === "pay" || c === "create") return true;
    // The control that would send the form makes a passkey: an account, not a sign-in.
    if (c === "passkey" && b === button) return true;
  }
  return false;
}

export function createSubmitWatcher(opts: SubmitOptions): SubmitWatcher {
  const { doc, refs, geometry, isTrusted } = opts;
  // Dedupe key: form, identifier and password LENGTH only; cleared after 2 s
  // so no password outlives the submission in this script's memory.
  let last: string | null = null;
  let lastTimer: ReturnType<typeof setTimeout> | null = null;
  let gesture: { formRef: string; at: number } | null = null;
  const timers = new Set<ReturnType<typeof setTimeout>>();
  const view = doc.defaultView;

  const ownerForm = (el: Element): HTMLFormElement | null =>
    el instanceof HTMLInputElement || el instanceof HTMLButtonElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement
      ? el.form
      : (composedClosest(el, "form") as HTMLFormElement | null);

  /** The credential form (or, with `kinds`, a form of those kinds) that `el` belongs to (field, button, or the form itself). */
  const formOf = (el: Element, kinds: ReadonlySet<FormKind> = CREDENTIAL_KINDS): FormInfo | null => {
    const a = opts.latest();
    if (!a) return null;
    for (const f of a.forms) {
      if (!kinds.has(f.kind)) continue;
      const container = refs.get(f.ref);
      if (!container) continue;
      if (el === container) return f;
      if (f.fields.some((x) => refs.get(x.ref) === el)) return f;
      const owner = ownerForm(el);
      if (container instanceof HTMLFormElement ? owner === container : owner === null && composedContains(container, el)) return f;
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

  /** A sign-in step that asks for the identifier alone: its value, else null. */
  const readIdentifier = (f: FormInfo): string | null => {
    if (f.kind !== "login") return null;
    if (f.fields.some((x) => x.role === "current_password" || x.role === "new_password")) return null;
    for (const role of ["username", "email"] as const) {
      for (const fi of f.fields) {
        if (fi.role !== role) continue;
        const el = refs.get(fi.ref);
        const v = el ? nativeValue(el).trim() : "";
        if (v !== "") return v;
      }
    }
    return null;
  };
  let lastIdentifier: string | null = null;
  const reportIdentifier = (f: FormInfo) => {
    const username = readIdentifier(f);
    if (username === null) return;
    const key = `${f.ref}\u0000${username}`;
    if (lastIdentifier === key) return;
    lastIdentifier = key;
    opts.onIdentifier?.({ type: "submitted_identifier", formRef: f.ref, username });
  };
  /** The identifier field of a lone identifier step. */
  const identifierField = (f: FormInfo): Element | null => {
    const fi = f.fields.find((x) => x.role === "username" || x.role === "email");
    return fi ? refs.get(fi.ref) : null;
  };

  /** The card or identity values of a sent form; null when there is nothing to offer. */
  const readForm = (f: FormInfo): Extract<CsToBg, { type: "submitted_form" }> | null => {
    const kind = SAVED_KINDS.get(f.kind);
    if (!kind) return null;
    const roles: readonly string[] = kind === "card" ? CARD_SUBMIT_ROLES : IDENTITY_SUBMIT_ROLES;
    const values: Record<string, string> = {};
    for (const fi of f.fields) {
      if (!roles.includes(fi.role) || values[fi.role] !== undefined || (fi.person ?? 0) > 0) continue;
      const cells = (fi.parts ?? [fi.ref]).map((r) => refs.get(r)).filter((el): el is Element => el !== null && el !== undefined);
      const v = cells.map((el) => nativeValue(el)).join("").trim();
      if (v !== "") values[fi.role] = v.slice(0, 256);
    }
    if (kind === "card" && values.cc_number === undefined) return null;
    if (Object.keys(values).length === 0) return null;
    return { type: "submitted_form", formRef: f.ref, kind, values: values as SubmittedValues };
  };
  let lastForm: string | null = null;
  const reportForm = (f: FormInfo | null) => {
    if (!f || !opts.onForm) return;
    const m = readForm(f);
    if (!m) return;
    // Same dedupe as a sign-in: the form and its value lengths only, cleared after 2 s.
    const key = `${f.ref}\u0000${Object.entries(m.values).map(([k, v]) => `${k}:${v.length}`).join(",")}`;
    if (lastForm === key) return;
    lastForm = key;
    const t = setTimeout(() => {
      timers.delete(t);
      if (lastForm === key) lastForm = null;
    }, DEDUPE_MS);
    timers.add(t);
    opts.onForm(m);
  };

  const report = (c: Credentials | null) => {
    if (!c) return;
    const key = `${c.formRef}\u0000${c.username}\u0000${c.password.length}`;
    if (last === key) return;
    last = key;
    if (lastTimer !== null) {
      clearTimeout(lastTimer);
      timers.delete(lastTimer);
    }
    const t = setTimeout(() => {
      timers.delete(t);
      if (lastTimer === t) {
        last = null;
        lastTimer = null;
      }
    }, DEDUPE_MS);
    lastTimer = t;
    timers.add(t);
    opts.onCredentials({ type: "submitted_credentials", ...c });
  };

  /** SPA: `then` once `el` goes away within the window. */
  const watchDisappearance = (el: Element | null, then: () => void) => {
    const pw = el;
    if (!pw) return;
    const deadline = Date.now() + SPA_WINDOW_MS;
    const tick = () => {
      if (!pw.isConnected || !isRendered(pw, geometry)) {
        then();
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

  /** A recent trusted gesture in `f` itself, plus user activation where the browser has it. */
  const activated = (f: FormInfo): boolean => {
    if (gesture === null || gesture.formRef !== f.ref || Date.now() - gesture.at > GESTURE_MS) return false;
    const ua = (view?.navigator as (Navigator & { userActivation?: { isActive: boolean } }) | undefined)?.userActivation;
    return !(ua && typeof ua.isActive === "boolean") || ua.isActive;
  };

  /** Remembers a trusted click or keydown inside a credential, card or identity form. */
  const noteGesture = (target: Element) => {
    const f = formOf(target, GESTURE_KINDS);
    if (f) gesture = { formRef: f.ref, at: Date.now() };
  };

  /** The form a gesture belongs to, or the document element for a page without forms. */
  const stepContainer = (el: Element): Element => ownerForm(el) ?? composedClosest(el, "form") ?? doc.documentElement;

  const onSubmit = (e: Event) => {
    if (!isTrusted(e) || !(e.target instanceof Element)) return;
    if (e.target instanceof HTMLFormElement) opts.onStep?.(e.target);
    const f = formOf(e.target);
    if (!f) {
      const saved = formOf(e.target, SAVED_FORM_KINDS);
      if (saved && activated(saved)) reportForm(saved);
      return;
    }
    if (!activated(f)) return;
    report(read(f));
    reportIdentifier(f);
  };

  const onClick = (e: Event) => {
    if (!isTrusted(e) || !(e.target instanceof Element)) return;
    noteGesture(e.target);
    const button = composedClosest(e.target, BUTTONS);
    if (!button) return;
    if (isSubmitType(button)) opts.onStep?.(stepContainer(button));
    const f = formOf(button);
    if (!f) {
      const saved = formOf(button, SAVED_FORM_KINDS);
      if (saved && ((saved.submitRef !== undefined && refs.get(saved.submitRef) === button) || isSubmitType(button))) reportForm(saved);
      return;
    }
    const sends = (f.submitRef !== undefined && refs.get(f.submitRef) === button) || isSubmitType(button);
    const snapshot = read(f);
    if (!snapshot) {
      if (readIdentifier(f) === null) return;
      if (sends) reportIdentifier(f);
      else watchDisappearance(identifierField(f), () => reportIdentifier(f));
      return;
    }
    if (sends) report(snapshot);
    else watchDisappearance(passwordField(f), () => report(snapshot));
  };

  const onKey = (e: Event) => {
    if (!isTrusted(e) || !(e instanceof KeyboardEvent)) return;
    if (e.target instanceof Element) noteGesture(e.target);
    if (e.key !== "Enter" || e.isComposing) return;
    if (!(e.target instanceof HTMLInputElement)) return;
    opts.onStep?.(stepContainer(e.target));
    const f = formOf(e.target);
    if (!f) {
      reportForm(formOf(e.target, SAVED_FORM_KINDS));
      return;
    }
    report(read(f));
    reportIdentifier(f);
  };

  const target: EventTarget = view ?? doc;
  const listen =
    opts.listen ??
    ((t: EventTarget, type: string, fn: (e: Event) => void, o: AddEventListenerOptions) => {
      t.addEventListener(type, fn, o);
      return () => t.removeEventListener(type, fn, o);
    });
  const removals: (() => void)[] = [];

  return {
    start() {
      if (removals.length > 0) return;
      removals.push(
        listen(target, "submit", onSubmit, { capture: true }),
        listen(target, "click", onClick, { capture: true }),
        listen(target, "keydown", onKey, { capture: true }),
      );
    },
    stop() {
      for (const r of removals.splice(0)) r();
      for (const t of timers) clearTimeout(t);
      timers.clear();
      last = null;
      lastTimer = null;
      lastIdentifier = null;
      lastForm = null;
      gesture = null;
    },
    clickRef(ref) {
      const el = refs.get(ref);
      if (!(el instanceof HTMLElement) || !isRendered(el, geometry)) return false;
      el.click();
      return true;
    },
    clickPasskey(ref) {
      const el = refs.get(ref);
      // Relabelled since the plan (or never one): refused, nothing clicked.
      if (!(el instanceof HTMLElement) || !isRendered(el, geometry) || buttonClass(el) !== "passkey") return false;
      el.click();
      return true;
    },
    submitForm(formRef, planned = false) {
      // A form the page re-rendered since the chain saw it: its copy (not for a plan).
      const f = opts.resolve(formRef, opts.analyze());
      const container = f ? refs.get(f.ref) : null;
      if (!container || !f) return false;
      if (planned && f.ref !== formRef) return false;
      const button = f.submitRef !== undefined ? refs.get(f.submitRef) : null;
      // The page may have relabelled a button since the plan: read them again, at click time.
      if (planned && payOrCreate(container, button, geometry)) return false;
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
