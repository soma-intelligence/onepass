// Perception for the fill planner (smart fill): turns a page analysis into a
// `PageContext` that carries roles, opaque refs and flags, never a value. The
// only thing derived from what the user typed is the salted hash of a typed
// username, made in `hashTypedUsername` and attached by the caller.
//
// `origins` are given by the caller. On the wire the background owns them
// (it derives them from the message sender), so what is built here is only
// a consistent draft: a top frame is its own top.
import type {
  ButtonClass,
  ButtonContext,
  FieldContext,
  FieldRole,
  FormContext,
  IntentHints,
  PageAnalysis,
  PageContext,
  PageFrameKind,
  Prefilled,
} from "../shared/messages";
import {
  PAGE_CONTEXT_MAX_BUTTONS,
  PAGE_CONTEXT_MAX_FIELDS,
  PAGE_CONTEXT_MAX_FORMS,
} from "../shared/messages";
import { controlType, type FieldElement, isFieldCandidate, scoreField } from "./detect/fields";
import {
  BUTTON_SELECTOR,
  controlForm,
  isNavigatingLink,
  isSubmitType,
} from "./detect/forms";
import {
  AUTOCOMPLETE_SCORE,
  CHECKOUT_WORDS,
  CREATE_WORDS,
  NEWSLETTER_WORDS,
  NEXT_WORDS,
  normalizeText,
  PAY_WORDS,
  RESET_WORDS,
  SCORE_CEILING,
  SEARCH_WORDS,
  SIGN_IN_WORDS,
  SIGNUP_WORDS,
  TYPE_ONLY_CONFIDENCE,
  TYPE_WEIGHTS,
} from "./detect/lexicon";
import { buttonLabel } from "./detect/provider";
import type { RefRegistry } from "./detect/refs";
import { ownText } from "./detect/text";
import { domGeometry, type Geometry, isRendered, isVisible } from "./detect/visibility";
import { filledByUs, nativeValue } from "./filler";

export interface FrameOrigins {
  origin: string;
  topOrigin: string;
  frame: PageFrameKind;
}

/** Confidence of a split one-time code: a run of 4 to 8 one-character cells is a strong signal on its own. */
const SPLIT_OTP_CONFIDENCE = 0.8;
/** Headings read per form. */
const MAX_FORM_HEADINGS = 5;

/**
 * `score` of a field as 0..1. `typeWeight` is what the control type alone
 * contributed to that score (`TYPE_WEIGHTS[type][role]`). `AUTOCOMPLETE_SCORE`
 * or more is 1. When nothing but the type backs the role (a bare
 * `type=password`) confidence stops at `TYPE_ONLY_CONFIDENCE`; otherwise
 * `SCORE_CEILING` of score is 1.
 */
export function confidenceOf(score: number, typeWeight = 0): number {
  if (Number.isNaN(score)) return 0;
  if (score >= AUTOCOMPLETE_SCORE) return 1;
  const raw = Math.min(1, Math.max(0, score / SCORE_CEILING));
  return score - typeWeight <= 0 ? Math.min(TYPE_ONLY_CONFIDENCE, raw) : raw;
}

/** What a button does, read from its label and type. */
export function buttonClass(el: HTMLElement): ButtonClass {
  const label = normalizeText(buttonLabel(el));
  if (PAY_WORDS.test(label)) return "pay";
  if (CREATE_WORDS.test(label)) return "create";
  if (NEXT_WORDS.test(label) && !SIGN_IN_WORDS.test(label)) return "next";
  if (isSubmitType(el) || SIGN_IN_WORDS.test(label)) return "submit";
  return "other";
}

/** Lowercase hex to its bytes as plain numbers (the wire form of Rust's `[u8; 32]`). */
function hexToBytes(hex: string): number[] {
  const out: number[] = [];
  for (let i = 0; i + 1 < hex.length; i += 2) out.push(Number.parseInt(hex.slice(i, i + 2), 16));
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * SHA-256 over the session salt, then the username trimmed and lowercased,
 * as lowercase hex (`username_hash` in onepass-bridge). `salt` is the hex the
 * bridge's `fill_salt` returns. Undefined for an empty username.
 */
export async function hashTypedUsername(salt: string, value: string): Promise<string | undefined> {
  if (!/^[0-9a-f]{64}$/i.test(salt)) return undefined;
  // Rust `char::is_whitespace`: White_Space, which excludes U+FEFF.
  const name = value.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "").toLowerCase();
  if (name === "") return undefined;
  const saltBytes = Uint8Array.from(hexToBytes(salt));
  const nameBytes = new TextEncoder().encode(name);
  const input = new Uint8Array(saltBytes.length + nameBytes.length);
  input.set(saltBytes, 0);
  input.set(nameBytes, saltBytes.length);
  const digest = await crypto.subtle.digest("SHA-256", input);
  return bytesToHex(new Uint8Array(digest));
}

/** `ctx` with the hash of `value` as `typed_username_hash` (null when `value` is empty). */
export async function withTypedUsernameHash(ctx: PageContext, salt: string, value: string | undefined): Promise<PageContext> {
  const hex = value === undefined ? undefined : await hashTypedUsername(salt, value);
  return { ...ctx, typed_username_hash: hex === undefined ? null : hexToBytes(hex) };
}

function isChecked(el: Element): boolean {
  return el instanceof HTMLInputElement && (el.type === "checkbox" || el.type === "radio") && el.checked;
}

/** A select holds a value only when moved off the option the page selected (or the first one). */
function selectMoved(el: HTMLSelectElement): boolean {
  if (el.multiple) return el.selectedIndex >= 0 && nativeValue(el) !== "";
  const opts = Array.from(el.options);
  const def = Math.max(0, opts.findIndex((o) => o.defaultSelected));
  return el.selectedIndex !== def && nativeValue(el) !== "";
}

function holdsValue(el: Element): boolean {
  if (el instanceof HTMLSelectElement) return selectMoved(el);
  return isChecked(el) || nativeValue(el) !== "";
}

/** `empty`, `typed` or `ours` over all the cells of a field. */
function prefilledOf(els: Element[]): Prefilled {
  const filled = els.filter(holdsValue);
  if (filled.length === 0) return "empty";
  return filled.every(filledByUs) ? "ours" : "typed";
}

function cellsOf(refs: RefRegistry, ref: string, parts: string[] | undefined): Element[] {
  const out: Element[] = [];
  for (const r of parts && parts.length > 0 ? parts : [ref]) {
    const el = refs.get(r);
    if (el !== null) out.push(el);
  }
  return out;
}

/** The text of a form that tells what it is for: its own attributes, headings and buttons. Never a value. */
function formWords(container: Element, buttons: Element[]): string {
  const attrs = ["aria-label", "id", "name", "action", "role"].map((a) => container.getAttribute(a) ?? "");
  const headings = Array.from(container.querySelectorAll("h1, h2, h3, h4, legend"))
    .slice(0, MAX_FORM_HEADINGS)
    .map((h) => ownText(h, 100));
  return [...attrs, ...headings, ...buttons.map(buttonLabel)].map(normalizeText).join(" ");
}

/** Title, first heading and path of the page: read as form words only when the page holds one form. */
function pageWords(doc: Document, url: string): string {
  let path = "";
  try {
    path = new URL(url).pathname;
  } catch {
    path = "";
  }
  const h1 = doc.querySelector("h1");
  return [doc.title, h1 ? ownText(h1, 100) : "", path].map(normalizeText).join(" ");
}

const NEWSLETTER_ROLES: ReadonlySet<FieldRole> = new Set(["email", "given_name", "family_name", "full_name", "remember_me"]);

function isSearchForm(container: Element, words: string): boolean {
  if (container.getAttribute("role")?.toLowerCase() === "search") return true;
  if (container.querySelector('input[type="search" i], [role="searchbox"]') !== null) return true;
  return SEARCH_WORDS.test(words);
}

function hintsFor(
  kind: IntentHints["kind"],
  roles: FieldRole[],
  container: Element,
  buttons: Element[],
  extraWords: string,
): IntentHints {
  const words = formWords(container, buttons);
  const all = `${words} ${extraWords}`;
  const secret = roles.some((r) => r === "current_password" || r === "new_password" || r === "confirm_password" || r === "otp");
  const newsletterOnly = roles.length > 0 && roles.every((r) => NEWSLETTER_ROLES.has(r)) && NEWSLETTER_WORDS.test(words);
  return {
    kind,
    signup_words: SIGNUP_WORDS.test(all),
    reset_words: RESET_WORDS.test(all),
    checkout_words: CHECKOUT_WORDS.test(all),
    ignore: !secret && (isSearchForm(container, words) || newsletterOnly),
  };
}

/**
 * Buttons of one group (form, or the container of fields outside any form),
 * at most `PAGE_CONTEXT_MAX_BUTTONS`: the submit first, then the pay and
 * create buttons, then the rest, each in document order, so the cap never
 * drops the button a plan sends or one that must hold its submit.
 */
function groupButtons(doc: Document, container: Element, submit: Element | null, geometry: Geometry): HTMLElement[] {
  const form = container instanceof HTMLFormElement ? container : null;
  const candidates = Array.from(container.querySelectorAll(BUTTON_SELECTOR));
  // Buttons that belong to the form from outside: `form="id"`, and the one the detector chose.
  if (form !== null && form.id !== "") {
    for (const b of Array.from(doc.querySelectorAll("[form]"))) {
      // Compared as text, no selector built from the id (nothing to escape).
      if (b.getAttribute("form") === form.id && b.matches(BUTTON_SELECTOR) && !candidates.includes(b)) candidates.push(b);
    }
  }
  if (submit !== null && !candidates.includes(submit)) candidates.push(submit);
  const kept = candidates
    .filter(
      (b): b is HTMLElement =>
        b instanceof HTMLElement &&
        (b === submit || controlForm(b) === form) &&
        !isNavigatingLink(b) &&
        !b.matches(":disabled") &&
        isRendered(b, geometry),
    )
    .sort((a, b) => (a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : a === b ? 0 : 1));
  const rank = (b: HTMLElement): number => {
    if (b === submit) return 0;
    const c = buttonClass(b);
    return c === "pay" || c === "create" ? 1 : 2;
  };
  // Stable sort: document order within each rank.
  return kept.sort((a, b) => rank(a) - rank(b)).slice(0, PAGE_CONTEXT_MAX_BUTTONS);
}

const CARD_ROLES: ReadonlySet<FieldRole> = new Set(["cc_name", "cc_number", "cc_exp", "cc_exp_month", "cc_exp_year"]);

function fieldContexts(form: PageAnalysis["forms"][number], refs: RefRegistry, geometry: Geometry): FieldContext[] {
  const out: FieldContext[] = [];
  // As `resolveSecurityCodes`: an ambiguous security code is a card code only next to another card field.
  const cardForm = form.fields.some((f) => CARD_ROLES.has(f.role));
  for (const f of form.fields) {
    if (out.length >= PAGE_CONTEXT_MAX_FIELDS) break;
    const cells = cellsOf(refs, f.ref, f.parts);
    const first = refs.get(f.ref);
    if (first === null || !isFieldCandidate(first)) continue;
    const split = f.parts !== undefined && f.parts.length > 0;
    const el = first as FieldElement;
    const typeWeight = (f.role === "unknown" ? undefined : TYPE_WEIGHTS[controlType(el)]?.[f.role]) ?? 0;
    const confidence = split ? SPLIT_OTP_CONFIDENCE : confidenceOf(scoreField(el, cardForm)[f.role], typeWeight);
    out.push({
      field_ref: f.ref,
      role: f.role,
      confidence,
      visible: isVisible(first, geometry),
      prefilled: prefilledOf(cells),
    });
  }
  return out;
}

/**
 * The page as the planner sees it: at most 32 forms (the first ones, in
 * document order), 64 fields and 32 buttons each. A ref whose element is gone
 * is dropped. No value of any field is read into the result, only whether the
 * field is empty, typed or filled by OnePass.
 */
export function buildPageContext(
  doc: Document,
  refs: RefRegistry,
  analysis: PageAnalysis,
  origins: FrameOrigins,
  geometry: Geometry = domGeometry,
): PageContext {
  const forms: FormContext[] = [];
  const words = pageWords(doc, analysis.url);
  for (const info of analysis.forms.slice(0, PAGE_CONTEXT_MAX_FORMS)) {
    const container = refs.get(info.ref);
    if (container === null) continue;
    // Page words: any form of a one-form page, and every sign-in or sign-up form (its heading is often outside it).
    const extra = analysis.forms.length === 1 || info.kind === "login" || info.kind === "signup" ? words : "";
    const fields = fieldContexts(info, refs, geometry);
    const buttons = groupButtons(doc, container, info.submitRef === undefined ? null : refs.get(info.submitRef), geometry);
    forms.push({
      form_ref: info.ref,
      intent_hints: hintsFor(info.kind, fields.flatMap((f) => (f.role === null ? [] : [f.role])), container, buttons, extra),
      step_index: null,
      fields,
      buttons: buttons.map((b): ButtonContext => ({ button_ref: refs.refFor(b), class: buttonClass(b) })),
    });
  }
  return {
    origin: origins.origin,
    // A top frame is its own top, whatever the caller passed.
    top_origin: origins.frame === "top" ? origins.origin : origins.topOrigin,
    frame_kind: origins.frame,
    forms,
    typed_username_hash: null,
  };
}

/**
 * Page-set values count as typed (a page can pre-fill a field, and then steers
 * which of its own logins ranks first): accepted, it is the same origin.
 *
 * The username the user typed in the page's first form, to hash with
 * `withTypedUsernameHash`. Stays in the content script: it is never put in a
 * context or a message. Fields OnePass filled are not the user's typing.
 */
export function findTypedUsername(analysis: PageAnalysis, refs: RefRegistry): string | undefined {
  for (const form of analysis.forms.slice(0, PAGE_CONTEXT_MAX_FORMS)) {
    for (const f of form.fields) {
      if (f.role !== "username" && f.role !== "email") continue;
      const el = refs.get(f.ref);
      if (el === null || !holdsValue(el) || filledByUs(el)) continue;
      const v = nativeValue(el);
      if (v.trim() !== "") return v;
    }
  }
  return undefined;
}
