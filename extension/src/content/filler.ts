// Form filler (spec 8.4 step 4). Writes values, keyed by role, into the
// classified fields of ONE form, as typing would: native `value` setter of the
// prototype (so framework-level instance trackers see a change), then `input`
// and `change`, with `focus`/`blur` around the write.
//
// Only fields of the target form that are still connected, still visible and
// still of the classified role are written: the form is analysed again at
// fill time, so a field the page hid or moved since the last analysis is
// skipped. Nothing else is ever written.
import type { FieldInfo, FieldRole, PageAnalysis } from "../shared/messages";
import { type FieldElement, isFieldCandidate } from "./detect/fields";
import { normalizeText } from "./detect/lexicon";
import type { RefRegistry } from "./detect/refs";
import { type Geometry, isVisible } from "./detect/visibility";

// Captured once, at content script start. The content script runs in an
// isolated world: page scripts cannot replace these.
const inputValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
const textAreaValue = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value");
const selectValue = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value");

/** Reads a control's value through the prototype getter. */
export function nativeValue(el: Element): string {
  const d =
    el instanceof HTMLInputElement
      ? inputValue
      : el instanceof HTMLTextAreaElement
        ? textAreaValue
        : el instanceof HTMLSelectElement
          ? selectValue
          : undefined;
  const v: unknown = d?.get?.call(el);
  return typeof v === "string" ? v : "";
}

function setNative(el: FieldElement, v: string): void {
  const d = el instanceof HTMLInputElement ? inputValue : el instanceof HTMLTextAreaElement ? textAreaValue : selectValue;
  d?.set?.call(el, v);
}

/** Month names (English, French), index 0 is January. Accent-free. */
const MONTHS: readonly (readonly string[])[] = [
  ["january", "janvier", "jan", "janv"],
  ["february", "fevrier", "feb", "fev", "fevr"],
  ["march", "mars", "mar"],
  ["april", "avril", "apr", "avr"],
  ["may", "mai"],
  ["june", "juin", "jun"],
  ["july", "juillet", "jul", "juil"],
  ["august", "aout", "aug"],
  ["september", "septembre", "sep", "sept"],
  ["october", "octobre", "oct"],
  ["november", "novembre", "nov"],
  ["december", "decembre", "dec"],
];

const leadingInt = (s: string): number => {
  const m = /^\s*(\d{1,4})\b/.exec(s);
  return m ? Number(m[1]) : Number.NaN;
};

function monthOf(s: string): number {
  const n = leadingInt(s);
  if (n >= 1 && n <= 12) return n;
  const t = normalizeText(s);
  const word = /^[a-z]+/.exec(t)?.[0] ?? "";
  const i = MONTHS.findIndex((names) => names.includes(word));
  return i < 0 ? Number.NaN : i + 1;
}

function yearOf(s: string): number {
  const n = leadingInt(s);
  if (!Number.isFinite(n)) return Number.NaN;
  return n < 100 ? 2000 + n : n;
}

/** Index of the option matching `v` for `role`, or -1. */
export function matchOption(sel: HTMLSelectElement, v: string, role: FieldRole): number {
  const opts = Array.from(sel.options);
  const want = v.trim().toLowerCase();
  let i = opts.findIndex((o) => o.value.trim().toLowerCase() === want);
  if (i >= 0) return i;
  i = opts.findIndex((o) => (o.textContent ?? "").trim().toLowerCase() === want);
  if (i >= 0) return i;
  if (role === "cc_exp_month") {
    const m = monthOf(v);
    if (!Number.isFinite(m)) return -1;
    i = opts.findIndex((o) => monthOf(o.value) === m);
    return i >= 0 ? i : opts.findIndex((o) => monthOf(o.textContent ?? "") === m);
  }
  if (role === "cc_exp_year") {
    const y = yearOf(v);
    if (!Number.isFinite(y)) return -1;
    i = opts.findIndex((o) => yearOf(o.value) === y);
    return i >= 0 ? i : opts.findIndex((o) => yearOf(o.textContent ?? "") === y);
  }
  const norm = normalizeText(v);
  return opts.findIndex((o) => normalizeText(o.textContent ?? "") === norm);
}

function fire(el: Element, type: string): void {
  const init = { bubbles: true, composed: true };
  const ev = type === "input" && typeof InputEvent === "function" ? new InputEvent(type, { ...init, inputType: "insertText" }) : new Event(type, init);
  el.dispatchEvent(ev);
}

/** Writes `v` into one control, as a user would. False when nothing matched. */
function write(el: FieldElement, v: string, role: FieldRole): boolean {
  let value = v;
  if (el instanceof HTMLSelectElement) {
    const i = matchOption(el, v, role);
    const opt = i >= 0 ? el.options[i] : undefined;
    if (!opt) return false;
    value = opt.value;
  }
  if (el instanceof HTMLElement) el.focus({ preventScroll: true });
  setNative(el, value);
  fire(el, "input");
  fire(el, "change");
  if (el instanceof HTMLElement) el.blur();
  return true;
}

export interface FillerOptions {
  refs: RefRegistry;
  geometry: Geometry;
  /** A fresh analysis of the document (same ref registry). */
  analyze: () => PageAnalysis;
}

export interface Filler {
  /** Fills the fields of `formRef`; returns how many controls were written. */
  fillForm(formRef: string, values: Partial<Record<FieldRole, string>>): number;
}

export function createFiller(opts: FillerOptions): Filler {
  const { refs, geometry } = opts;

  const usable = (ref: string, container: Element): FieldElement | null => {
    const el = refs.get(ref);
    if (!el || !el.isConnected || !isFieldCandidate(el)) return null;
    const owner = el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement || el instanceof HTMLSelectElement ? el.form : null;
    if (owner !== container && !(owner === null && container.contains(el))) return null;
    return isVisible(el, geometry) ? el : null;
  };

  const fillField = (f: FieldInfo, v: string, container: Element): number => {
    if (f.parts && f.parts.length > 0) {
      // Split code: one character per cell, in order.
      const chars = Array.from(v);
      let n = 0;
      f.parts.forEach((ref, i) => {
        const c = chars[i];
        const el = usable(ref, container);
        if (c !== undefined && el && write(el, c, f.role)) n++;
      });
      return n;
    }
    const el = usable(f.ref, container);
    return el && write(el, v, f.role) ? 1 : 0;
  };

  return {
    fillForm(formRef, values) {
      const container = refs.get(formRef);
      if (!container) return 0;
      const form = opts.analyze().forms.find((f) => f.ref === formRef);
      if (!form) return 0;
      let n = 0;
      for (const f of form.fields) {
        const v = values[f.role];
        if (typeof v !== "string" || v === "") continue;
        n += fillField(f, v, container);
      }
      return n;
    },
  };
}
