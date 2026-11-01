// What a page says about its new password fields (spec 4.1): the
// `passwordrules` attributes, `minlength` / `maxlength`, the written hints
// near the field, and its `pattern` (tested in the worker, spec 6.3). Page
// text is untrusted: every piece is bounded here, and again in the worker.
// No value typed in the page is ever read: only attributes and the text of
// non-control elements.
import type { WirePasswordContext } from "../shared/messages";

/** The bridge's bounds on `rules` (more, or longer, and `generate` fails). */
export const MAX_RULES = 8;
export const MAX_RULE_BYTES = 1024;
export const MAX_HINT_PIECE = 200;
export const MAX_HINT = 600;
export const MAX_PATTERN = 512;
/** Following siblings read for hints, from the field and from its label wrapper. */
const SIBLINGS = 3;

const encoder = new TextEncoder();
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/** `s` with every lone surrogate replaced: the host's JSON parser refuses them. */
export function wellFormed(s: string): string {
  return s.replace(LONE_SURROGATE, "\uFFFD");
}

/** `s` cut to at most `max` UTF-16 units, never in the middle of a pair. */
export function cut(s: string, max: number): string {
  if (s.length <= max) return s;
  const head = s.slice(0, max);
  return /[\uD800-\uDBFF]$/.test(head) ? head.slice(0, -1) : head;
}

/** `rules` without empty strings, repeats, or strings the bridge would refuse; the first 8. */
export function boundRules(rules: readonly unknown[]): string[] {
  const out: string[] = [];
  for (const raw of rules) {
    if (out.length >= MAX_RULES) break;
    if (typeof raw !== "string") continue;
    const r = wellFormed(raw);
    if (r.trim() === "" || out.includes(r)) continue;
    if (encoder.encode(r).length > MAX_RULE_BYTES) continue;
    out.push(r);
  }
  return out;
}

/** Whitespace collapsed, trimmed, cut to `max` chars. */
function piece(text: string | null | undefined, max: number): string {
  return cut(wellFormed(text ?? "").replace(/\s+/g, " ").trim(), max);
}

/** A form control's text would be its options (a select) or nothing: skipped. */
function isControl(el: Element): boolean {
  return el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement || el instanceof HTMLButtonElement;
}

const SKIPPED: ReadonlySet<string> = new Set(["SCRIPT", "STYLE", "TEMPLATE", "NOSCRIPT"]);

/** Visible-ish text of `el` (its text nodes, never a control's value). */
function textOf(el: Element): string {
  if (isControl(el) || SKIPPED.has(el.tagName)) return "";
  return el.textContent ?? "";
}

/** Elements `aria-describedby` of `field` names, in its order, from the field's own tree (document or shadow root). */
function describedBy(field: Element): Element[] {
  const ids = (field.getAttribute("aria-describedby") ?? "").split(/\s+/).filter((x) => x !== "");
  const root = field.getRootNode() as Document | ShadowRoot;
  const out: Element[] = [];
  for (const id of ids.slice(0, 16)) {
    const el = typeof root.getElementById === "function" ? root.getElementById(id) : null;
    if (el && el !== field) out.push(el);
  }
  return out;
}

/** Another field's name or block (a label with its control, an element holding a control): not a hint. */
function namesAField(el: Element): boolean {
  if (el instanceof HTMLLabelElement && el.control !== null) return true;
  return el.querySelector("input, select, textarea") !== null;
}

/** The hint siblings among the three elements after `el`, inside `form`. */
function following(el: Element, form: Element): Element[] {
  const out: Element[] = [];
  let s = el.nextElementSibling;
  for (let i = 0; s && i < SIBLINGS; i++, s = s.nextElementSibling) {
    if (form.contains(s) && !namesAField(s)) out.push(s);
  }
  return out;
}

/** The hint text of `fields` (spec 4.1): `aria-describedby` first, then nearby siblings; each piece 200 chars, all 600. */
function hintText(fields: readonly Element[], form: Element): string | undefined {
  const seenEls = new Set<Element>();
  const seenText = new Set<string>();
  const parts: string[] = [];
  const add = (el: Element) => {
    if (seenEls.has(el)) return;
    seenEls.add(el);
    const t = piece(textOf(el), MAX_HINT_PIECE);
    if (t === "" || seenText.has(t)) return;
    seenText.add(t);
    parts.push(t);
  };
  for (const f of fields) for (const el of describedBy(f)) add(el);
  for (const f of fields) {
    for (const el of following(f, form)) add(el);
    // A field wrapped in its label: the hint follows the label.
    const wrapper = f.parentElement?.closest("label");
    if (wrapper && wrapper !== form && form.contains(wrapper)) for (const el of following(wrapper, form)) add(el);
  }
  const all = parts.join(" ");
  if (all === "") return undefined;
  return cut(all, MAX_HINT);
}

/** A positive length attribute of the DOM (`minLength` / `maxLength` are -1 when absent). */
function positive(n: number): number | null {
  return Number.isInteger(n) && n > 0 ? n : null;
}

/**
 * The page's rules for the new password fields `fields` of `form` (the
 * fields detection gave the `new_password` and `confirm_password` roles; the
 * form's password inputs when left out): every `passwordrules`, the largest
 * `minlength`, the smallest `maxlength`, the hints, and the `pattern` of the
 * first field with one (null when it is over 512 chars).
 */
export function collectPasswordContext(
  form: HTMLFormElement | Element,
  fields?: readonly Element[],
): { context: WirePasswordContext; pattern: string | null } {
  const list = fields ?? Array.from(form.querySelectorAll("input[type=password]"));
  const rules: string[] = [];
  let min: number | null = null;
  let max: number | null = null;
  let pattern: string | null | undefined;
  for (const f of list) {
    const r = f.getAttribute("passwordrules");
    if (r !== null) rules.push(r);
    if (f instanceof HTMLInputElement) {
      const lo = positive(f.minLength);
      if (lo !== null) min = min === null ? lo : Math.max(min, lo);
      const hi = positive(f.maxLength);
      if (hi !== null) max = max === null ? hi : Math.min(max, hi);
    }
    const p = f.getAttribute("pattern");
    if (pattern === undefined && p !== null && p !== "") pattern = p.length > MAX_PATTERN ? null : p;
  }
  const context: WirePasswordContext = { rules: boundRules(rules) };
  if (min !== null) context.min_length = min;
  if (max !== null) context.max_length = max;
  const hint = hintText(list, form);
  if (hint !== undefined) context.hint_text = hint;
  return { context, pattern: pattern ?? null };
}
