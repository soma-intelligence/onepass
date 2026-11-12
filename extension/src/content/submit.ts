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
//
// A sign-in that keeps its form on screen (spec 5.3): UNCERTAIN_MS after a
// reported sign-in whose form is still in the document, `submit_outcome` says
// whether the URL changed (path or hash), the password field was emptied or
// removed, and a `role="alert"` or `aria-invalid="true"` is in the form; once
// per submission, never a value. The top document also reports `page_alert`
// once when a `role="alert"` with text shows within UNCERTAIN_MS of the
// script's start (an error or captcha page after a sign-in): the worker only
// ever makes a pending sign-in more cautious with either.
//
// Where a submission goes (security review M3): OnePass never submits a form
// itself (`submitForm`, the chain's and the plan's submit) when the browser
// would send it to another site than the page's: the form's `action`, the
// `formaction` of the control clicked, or of any submit control of the form
// (Enter submits through the form's default button), resolving to another
// registrable domain, to plain HTTP from an HTTPS page, or to a scheme other
// than http(s) and `javascript:`. A scriptless injected `<form action=evil>`
// would otherwise get the site's credentials posted out. The fill itself may
// still happen; the submit reports "not submitted".
import { parseOrigin, sameSite } from "../shared/domain";
import {
  CARD_SUBMIT_ROLES,
  type CsToBg,
  type FormInfo,
  type FormKind,
  IDENTITY_SUBMIT_ROLES,
  type PageAnalysis,
  type SavedFormKind,
  type SubmittedValues,
  UNCERTAIN_MS,
} from "../shared/messages";
import { buttonClass } from "./context";
import { BUTTON_SELECTOR } from "./detect/forms";
import { findPasskeySignIn } from "./detect/passkey-button";
import type { RefRegistry } from "./detect/refs";
import { MAX_SHADOW_DEPTH, MAX_SHADOW_ELEMENTS, composedClosest, composedContains } from "./detect/shadow";
import { type Geometry, isRendered } from "./detect/visibility";
import { nativeValue } from "./filler";

export const DEDUPE_MS = 2000;
export const SPA_WINDOW_MS = 10_000;
const SPA_POLL_MS = 250;
/** A `submit` event counts only after a trusted gesture in that form this recent. */
export const GESTURE_MS = 5000;
const ALERT_SELECTOR = '[role="alert" i]';

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
  /** Spec 5.3: what became of a reported sign-in whose form stayed in the document. */
  onOutcome?: (c: Extract<CsToBg, { type: "submit_outcome" }>) => void;
  /** Spec 5.3: the top document showed a `role="alert"` right after its load. */
  onPageAlert?: () => void;
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
   * A gesture on a sign-in page with no form: clicks the page's one rendered button that reads as
   * a passkey sign-in ("Use passkey", "Sign in with a passkey"). None, several, or one that makes
   * a passkey or an account: nothing clicked.
   */
  clickPasskeySignIn(): boolean;
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

// Read through the prototypes: a form's named controls shadow its own properties
// (`<input name="action">` makes `form.action` that input, DOM clobbering).
const getAttr = Element.prototype.getAttribute;
const formElements = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, "elements")?.get;

/** The controls of `form` (its `elements`, unclobbered). */
function controlsOf(form: HTMLFormElement): Element[] {
  const c = formElements?.call(form) as HTMLFormControlsCollection | undefined;
  return c ? Array.from(c) : [];
}

/**
 * Whether a submission to the URL in attribute `raw` (an `action` or `formaction`) stays on the
 * page's site: same registrable domain, no HTTPS to HTTP downgrade; from a page that is not https
 * (http on a loopback host), the page's exact origin only. Only a missing or exactly empty
 * attribute means the page itself (`page`); any other value, whitespace included, is resolved as the
 * browser does, against the document base URL (`base`, which a `<base href>` sets). `javascript:`
 * posts nothing anywhere. Any other scheme, or an unparsable URL, is refused.
 */
export function submitTargetAllowed(raw: string | null, base: string, page: string): boolean {
  if (raw === null || raw === "") return true;
  let u: URL;
  try {
    u = new URL(raw, base);
  } catch {
    return false;
  }
  if (u.protocol === "javascript:") return true;
  const to = parseOrigin(u.href);
  const from = parseOrigin(page);
  if (!to || !from) return false;
  if (from.https && !to.https) return false;
  // A page that is not https (a local development server): the registrable domain says nothing
  // there, another port is another server. Its exact origin, or nothing.
  if (!from.https) return to.origin === from.origin;
  return sameSite(u.href, page);
}

/**
 * The forms a native submission from `button` (or from `container`, or Enter in `field`) may send,
 * and the URLs it may send them to: every one must stay on the page's site.
 */
function submissionStaysOnSite(doc: Document, container: Element, button: Element | null, field: Element | null): boolean {
  const base = doc.baseURI;
  const page = doc.URL;
  const forms = new Set<HTMLFormElement>();
  if (container instanceof HTMLFormElement) forms.add(container);
  for (const el of [button, field]) {
    const owner = el instanceof HTMLButtonElement || el instanceof HTMLInputElement ? el.form : null;
    if (owner) forms.add(owner);
  }
  const controls = new Set<Element>();
  if (button && isSubmitType(button)) controls.add(button);
  for (const form of forms) {
    if (!submitTargetAllowed(getAttr.call(form, "action"), base, page)) return false;
    for (const c of controlsOf(form)) if (isSubmitType(c)) controls.add(c);
  }
  for (const c of controls) if (!submitTargetAllowed(getAttr.call(c, "formaction"), base, page)) return false;
  return true;
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

  /**
   * `f` as the page is now: the analysis may lag the page by a few hundred ms (a password field a
   * "Next" button just revealed in the same form, typed and sent at once). Read when a submission
   * finds no password in `f`: the copy a fresh analysis has of it, else `f`.
   */
  const fresh = (f: FormInfo): FormInfo => {
    const container = refs.get(f.ref);
    if (!container) return f;
    const passwords = Array.from(container.querySelectorAll('input[type="password" i]')).filter((el) => nativeValue(el) !== "" && isRendered(el, geometry));
    const known = new Set(f.fields.map((x) => refs.get(x.ref)));
    if (passwords.every((el) => known.has(el))) return f;
    const g = opts.resolve(f.ref, opts.analyze());
    return g && CREDENTIAL_KINDS.has(g.kind) ? g : f;
  };
  /** The credentials of `f`, read again from a fresh analysis when the one known has no password. */
  const readNow = (f: FormInfo): { f: FormInfo; c: Credentials | null } => {
    const c = read(f);
    if (c) return { f, c };
    const g = fresh(f);
    return g === f ? { f, c: null } : { f: g, c: read(g) };
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

  /** Path and hash of the page now (spec 5.3: the URL changed). */
  const where = (): string => {
    try {
      const u = new URL(doc.URL);
      return `${u.pathname}${u.hash}`;
    } catch {
      return doc.URL;
    }
  };
  /** Elements matching `selector` in `root` and in the open shadow roots nested in it (bounded walk). */
  const deepMatches = (root: Element | Document, selector: string): Element[] => {
    const out: Element[] = [];
    let budget = MAX_SHADOW_ELEMENTS;
    const queue: { r: Element | Document | ShadowRoot; depth: number }[] = [{ r: root, depth: 0 }];
    for (let k = 0; k < queue.length && budget > 0; k++) {
      const { r, depth } = queue[k]!;
      out.push(...Array.from(r.querySelectorAll(selector)));
      if (depth >= MAX_SHADOW_DEPTH) continue;
      const walker = doc.createTreeWalker(r, NodeFilter.SHOW_ELEMENT);
      for (let n: Node | null = walker.currentNode; n !== null && budget > 0; n = walker.nextNode()) {
        budget--;
        const sr = n instanceof Element ? n.shadowRoot : null;
        if (sr) queue.push({ r: sr, depth: depth + 1 });
      }
    }
    return out;
  };
  /** A rendered `role="alert"` with text among `els`. */
  const shownAlert = (els: Element[]): boolean => els.some((el) => (el.textContent ?? "").trim() !== "" && isRendered(el, geometry));
  /** A rendered `role="alert"` with text in `root` (light DOM: the page-wide watch stays cheap). */
  const alertIn = (root: ParentNode): boolean => shownAlert(Array.from(root.querySelectorAll(ALERT_SELECTOR)));
  let outcomeTimer: ReturnType<typeof setTimeout> | null = null;
  /** Spec 5.3: UNCERTAIN_MS after the report of `f`, the form still there: what changed. */
  const watchOutcome = (f: FormInfo) => {
    if (!opts.onOutcome) return;
    if (outcomeTimer !== null) {
      clearTimeout(outcomeTimer);
      timers.delete(outcomeTimer);
    }
    const from = where();
    const container = refs.get(f.ref);
    const pw = passwordField(f);
    const t = setTimeout(() => {
      timers.delete(t);
      if (outcomeTimer === t) outcomeTimer = null;
      if (!container?.isConnected) return;
      const passwordCleared = !pw || !pw.isConnected || !composedContains(container, pw) || nativeValue(pw) === "";
      // In the form, nested open shadow roots included.
      const alert = deepMatches(container, '[aria-invalid="true" i]').length > 0 || shownAlert(deepMatches(container, ALERT_SELECTOR));
      opts.onOutcome?.({ type: "submit_outcome", formRef: f.ref, urlChanged: where() !== from, passwordCleared, alert });
    }, UNCERTAIN_MS);
    outcomeTimer = t;
    timers.add(t);
  };

  const report = (c: Credentials | null, f?: FormInfo) => {
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
    if (f) watchOutcome(f);
  };

  /** Spec 5.3: the top document reports a `role="alert"` shown within UNCERTAIN_MS of the start. */
  let alertWatch: MutationObserver | null = null;
  const watchPageAlert = () => {
    if (!opts.onPageAlert || !view || view.top !== view) return;
    let sent = false;
    const look = () => {
      if (sent || !alertIn(doc)) return;
      sent = true;
      stopAlertWatch();
      opts.onPageAlert?.();
    };
    look();
    if (sent || typeof MutationObserver === "undefined") return;
    alertWatch = new MutationObserver(look);
    alertWatch.observe(doc, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ["role", "style", "class", "hidden"] });
    const t = setTimeout(() => {
      timers.delete(t);
      stopAlertWatch();
    }, UNCERTAIN_MS);
    timers.add(t);
  };
  const stopAlertWatch = () => {
    alertWatch?.disconnect();
    alertWatch = null;
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
    const now = readNow(f);
    report(now.c, now.f);
    if (!now.c) reportIdentifier(now.f);
  };

  const onClick = (e: Event) => {
    if (!isTrusted(e) || !(e.target instanceof Element)) return;
    noteGesture(e.target);
    const button = composedClosest(e.target, BUTTONS);
    if (!button) return;
    if (isSubmitType(button)) opts.onStep?.(stepContainer(button));
    const known = formOf(button);
    if (!known) {
      const saved = formOf(button, SAVED_FORM_KINDS);
      if (saved && ((saved.submitRef !== undefined && refs.get(saved.submitRef) === button) || isSubmitType(button))) reportForm(saved);
      return;
    }
    const sends = (known.submitRef !== undefined && refs.get(known.submitRef) === button) || isSubmitType(button);
    // The form as the page is now (a password field just revealed in it).
    const { f, c: snapshot } = readNow(known);
    if (!snapshot) {
      if (readIdentifier(f) === null) return;
      if (sends) reportIdentifier(f);
      else watchDisappearance(identifierField(f), () => reportIdentifier(f));
      return;
    }
    if (sends) report(snapshot, f);
    else watchDisappearance(passwordField(f), () => report(snapshot, f));
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
    const now = readNow(f);
    report(now.c, now.f);
    if (!now.c) reportIdentifier(now.f);
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
      watchPageAlert();
    },
    stop() {
      for (const r of removals.splice(0)) r();
      stopAlertWatch();
      outcomeTimer = null;
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
    clickPasskeySignIn() {
      const one = findPasskeySignIn(doc, geometry);
      if (!one) return false;
      one.click();
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
      const lastField = [...f.fields].reverse().map((x) => refs.get(x.parts?.at(-1) ?? x.ref)).find((el) => el instanceof HTMLElement) ?? null;
      // Read at submit time too: the browser would post to another site (M3). Not submitted.
      if (!submissionStaysOnSite(doc, container, button instanceof HTMLElement ? button : null, lastField)) return false;
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
      if (!(lastField instanceof HTMLElement)) return false;
      for (const type of ["keydown", "keypress", "keyup"]) {
        lastField.dispatchEvent(new KeyboardEvent(type, { key: "Enter", code: "Enter", keyCode: 13, which: 13, bubbles: true, cancelable: true }));
      }
      return true;
    },
  };
}
