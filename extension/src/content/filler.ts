// Form filler (spec 8.4 step 4). Writes values, keyed by role, into the
// classified fields of ONE form, as typing would: native `value` setter of the
// prototype (so framework-level instance trackers see a change), then `input`
// and `change`, with `focus`/`blur` around the write.
//
// Only fields of the target form that are still connected, still visible and
// still of the classified role are written: the form is analysed again at
// fill time, so a field the page hid or moved since the last analysis is
// skipped. Nothing else is ever written.
//
// Re-rendered forms (spec B2): a ref that died during the fill (the page
// replaced the form or the field) is resolved again in a fresh analysis, to
// the copy of the same form (`FormLineage`) and the field of the same role
// and rank. A written field replaced by an empty copy is filled once more.
import type { FieldInfo, FieldRole, FormInfo, PageAnalysis } from "../shared/messages";
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

/**
 * What each control held right after OnePass wrote it. Lives in this closure
 * only (a page cannot read or forge it); `filledByUs` compares it with the
 * control's value now, so a field the user edited since is theirs again.
 */
const written = new WeakMap<Element, string>();

/** True when `el` still holds exactly what OnePass wrote into it. */
export function filledByUs(el: Element): boolean {
  const v = written.get(el);
  return v !== undefined && v !== "" && v === nativeValue(el);
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
  written.set(el, nativeValue(el));
  return true;
}

export interface FillerOptions {
  refs: RefRegistry;
  geometry: Geometry;
  /** A fresh analysis of the document (same ref registry). */
  analyze: () => PageAnalysis;
  /** Where form `ref` is in `a`: itself, or the copy a re-render put in its place. */
  resolve: (ref: string, a: PageAnalysis) => FormInfo | null;
}

export interface Filler {
  /** Fills the fields of `formRef`; returns how many controls were written. */
  fillForm(formRef: string, values: Partial<Record<FieldRole, string>>): number;
}

/** A field of the target form: its role and rank among the fields of that role. */
interface Slot {
  role: FieldRole;
  nth: number;
}

interface Written {
  slot: Slot;
  part: number | undefined;
  el: FieldElement;
  value: string;
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

  const fieldAt = (form: FormInfo, slot: Slot): FieldInfo | undefined => form.fields.filter((x) => x.role === slot.role)[slot.nth];

  /**
   * The focus where the user left it: each write focuses and blurs its
   * field (as typing would), then the field that had the focus (the one the
   * menu was opened from, say) gets it back.
   */
  const keepFocus = <T>(fn: () => T): T => {
    const had = typeof document !== "undefined" ? document.activeElement : null;
    try {
      return fn();
    } finally {
      if (had instanceof HTMLInputElement && had.isConnected && document.activeElement !== had) had.focus({ preventScroll: true });
    }
  };

  return {
    fillForm(formRef, values) {
      return keepFocus(() => fillOnce(formRef, values));
    },
  };

  function fillOnce(formRef: string, values: Partial<Record<FieldRole, string>>): number {
    {
      const first = opts.resolve(formRef, opts.analyze());
      if (!first) return 0;
      let form: FormInfo = first;

      // Spec B2: a page may re-render the form while it is filled (on the
      // first `input`, say). A dead ref is then looked up again in a fresh
      // analysis: the same form (its re-rendered copy), the same role.
      const lookup = (slot: Slot, part: number | undefined): { el: FieldElement | null; dead: boolean } => {
        const container = refs.get(form.ref);
        const fi = fieldAt(form, slot);
        if (!container || !fi) return { el: null, dead: true };
        const ref = part === undefined ? fi.ref : fi.parts?.[part];
        if (ref === undefined) return { el: null, dead: false };
        if (!refs.get(ref)) return { el: null, dead: true };
        return { el: usable(ref, container), dead: false };
      };
      const target = (slot: Slot, part: number | undefined): FieldElement | null => {
        const r = lookup(slot, part);
        if (!r.dead) return r.el;
        const again = opts.resolve(form.ref, opts.analyze());
        if (!again) return null;
        form = again;
        return lookup(slot, part).el;
      };

      const written: Written[] = [];
      const put = (slot: Slot, part: number | undefined, value: string): boolean => {
        const el = target(slot, part);
        if (!el || !write(el, value, slot.role)) return false;
        written.push({ slot, part, el, value });
        return true;
      };

      const seen = new Map<FieldRole, number>();
      const slots: { slot: Slot; field: FieldInfo }[] = [];
      for (const f of form.fields) {
        const nth = seen.get(f.role) ?? 0;
        seen.set(f.role, nth + 1);
        slots.push({ slot: { role: f.role, nth }, field: f });
      }
      let n = 0;
      for (const { slot, field } of slots) {
        const v = values[slot.role];
        if (typeof v !== "string" || v === "") continue;
        if (field.parts && field.parts.length > 0) {
          // Split code: one character per cell, in order.
          const chars = Array.from(v);
          for (let i = 0; i < field.parts.length; i++) {
            const c = chars[i];
            if (c !== undefined && put(slot, i, c)) n++;
          }
        } else if (put(slot, undefined, v)) {
          n++;
        }
      }

      // A written control the page replaced by an empty copy gets its value
      // again, once: a page that re-renders on every input is not chased.
      for (const w of written.splice(0)) {
        if (w.el.isConnected) continue;
        const el = target(w.slot, w.part);
        if (el && nativeValue(el) === "") write(el, w.value, w.slot.role);
      }
      return n;
    }
  }
}
