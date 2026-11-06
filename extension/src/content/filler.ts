// Form filler (spec 8.4 step 4). Writes values, keyed by role, into the
// classified fields of ONE form, as typing would: native `value` setter of the
// prototype (so framework-level instance trackers see a change), then `input`
// and `change`, with `focus`/`blur` around the write.
//
// Only fields of the target form that are still connected, still visible and
// still of the classified role are written: the form is analysed again at
// fill time, so a field the page hid or moved since the last analysis is
// skipped. Nothing else is ever written, with one exception: the hidden
// native select that backs a visible country or region combobox OnePass just
// filled gets the same choice (spec 2026-10-31, section 4).
//
// Re-rendered forms (spec B2): a ref that died during the fill (the page
// replaced the form or the field) is resolved again in a fresh analysis, to
// the copy of the same form (`FormLineage`) and the field of the same role
// and rank. A written field replaced by an empty copy is filled once more.
//
// Country and region (spec 2026-10-31): options are matched through ISO
// codes and names (`geo/`), a tie picks nothing, the region is filled after
// the country and, when the country changed, once the page reloaded its list
// (bounded wait); ARIA comboboxes are typed into and their option pressed.
import type { FieldInfo, FieldRole, FillHints, FormInfo, PageAnalysis } from "../shared/messages";
import { backingSelect, isCombobox, optionLike, optionsOf, press } from "./combobox";
import { pickChoice } from "./choice";
import { dateOption, datePart, dateText, leadingInt, monthOf } from "./date";
import { type FieldElement, isFieldCandidate } from "./detect/fields";
import { normalizeText } from "./detect/lexicon";
import type { RefRegistry } from "./detect/refs";
import { type Geometry, isVisible } from "./detect/visibility";
import { countryName, nameLangs, resolveCountry, resolveCountryValue } from "./geo/countries";
import { demonym, demonymCountry } from "./geo/demonyms";
import { type OptionLike, pickCountry, pickNationality, pickRegion, postalFallback, regionWanted } from "./geo/options";
import { parentRegion, REGIONS, regionText } from "./geo/regions";
import { OBSERVER_DELAY_MS } from "./observer";
import { settle } from "./settle";

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

function yearOf(s: string): number {
  const n = leadingInt(s);
  if (!Number.isFinite(n)) return Number.NaN;
  return n < 100 ? 2000 + n : n;
}

/** What country and region matching knows besides the value. */
export interface GeoContext {
  /** Languages of country names: the page's, then French and English. */
  langs: readonly string[];
  /** Alpha-2 country of the item, else of the form's country field. */
  country: string | null;
  /** The item's postal code: a region deduced from it when the item has none. */
  postal?: string | null;
  /** The page's language as it declares it (`en-US`): the written order of a birth date. */
  lang?: string | null;
  /** The identity's sex (`f`, `m`, `x`): a nationality's gender, a civility from the sex. */
  sex?: string | undefined;
  /** A civility list with no vault civility picks the one of the sex (spec section 7). */
  civilityFromSex?: boolean;
}

export type { FillHints };

/** Civility and sex: chosen by their tables (choice.ts). */
const CHOICE_ROLES: ReadonlySet<FieldRole> = new Set(["honorific_prefix", "sex"]);
/** Countries of a document: the country path (pickCountry), never the region nor the postal code. */
const ISSUING_ROLES: ReadonlySet<FieldRole> = new Set(["passport_issuing_country", "license_issuing_country"]);

const DEFAULT_GEO: GeoContext = { langs: nameLangs(null), country: null };

const optionsOfSelect = (sel: HTMLSelectElement): OptionLike[] =>
  Array.from(sel.options).map((o) => ({ value: o.value, text: (o.textContent ?? "").replace(/\s+/g, " ").trim() }));

/** Index of the option matching `v` for `role`, or -1. */
export function matchOption(sel: HTMLSelectElement, v: string, role: FieldRole, geo: GeoContext = DEFAULT_GEO): number {
  if (role === "country" || ISSUING_ROLES.has(role)) return pickCountry(optionsOfSelect(sel), v, geo.langs);
  if (role === "nationality") return pickNationality(optionsOfSelect(sel), v, geo.langs);
  if (CHOICE_ROLES.has(role)) return pickChoice(optionsOfSelect(sel), role, { value: v, sex: role === "sex" || geo.civilityFromSex ? geo.sex : undefined });
  if (role === "region") {
    const country = geo.country ?? null;
    const os = optionsOfSelect(sel);
    const i = pickRegion(os, regionWanted(v, country, geo.postal ?? null), country, v);
    if (i >= 0 || v.trim() === "") return i;
    // A region the list does not have (a region, the list has departments).
    const r = postalFallback(v, country, geo.postal ?? null);
    return r ? pickRegion(os, [r], country) : -1;
  }
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

/** What to type into a region combobox: the names of the region, then of its parent, then the item's text. */
/** What a list offers now (its options' values and labels): a reload changes it. */
function optionsSignature(sel: HTMLSelectElement): string {
  return Array.from(sel.options, (o) => `${o.value}\u0000${o.text}`).join("\u0001");
}

function typedRegion(wanted: readonly string[], raw: string): string[] {
  if (wanted.length !== 1) return [raw];
  const code = wanted[0]!;
  const r = REGIONS.find((x) => x.code === code);
  const parent = parentRegion(code);
  const p = parent ? REGIONS.find((x) => x.code === parent) : undefined;
  return [...(r?.names ?? []), ...(p?.names.slice(0, 1) ?? []), raw];
}

/** Roles whose value is a date `YYYY-MM-DD` (spec section 6). */
const DATE_ROLES: ReadonlySet<FieldRole> = new Set([
  "bday",
  "passport_issue_date",
  "passport_expiry",
  "license_issue_date",
  "license_expiry",
]);

const autocompleteTokens = (el: Element) => (el.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/);

/** A country or region value as a person writes it in a free text field. */
function textValue(el: FieldElement, v: string, role: FieldRole, geo: GeoContext): string {
  if (role === "region") return regionText(v);
  if (role === "country" && autocompleteTokens(el).includes("country-name")) {
    const cc = resolveCountry(v, geo.langs);
    if (cc) return countryName(cc, geo.langs[0] ?? "en");
  }
  const lang = geo.langs[0] ?? "en";
  if (ISSUING_ROLES.has(role)) {
    // A person writes the country's name.
    const cc = resolveCountry(v, geo.langs);
    return cc ? countryName(cc, lang) : v;
  }
  if (role === "nationality") {
    // The demonym in the page's language, of the identity's gender; else the country's name.
    const cc = resolveCountry(v, geo.langs) ?? demonymCountry(v);
    if (!cc) return v;
    return demonym(cc, lang, geo.sex === "f") ?? countryName(cc, lang);
  }
  return v;
}

/** What a radio button says: its labels, else its ARIA label, else its value. */
function radioLabel(b: HTMLInputElement): string {
  const own = Array.from(b.labels ?? [], (l) => (l.textContent ?? "").replace(/\s+/g, " ").trim()).filter((t) => t !== "");
  if (own.length > 0) return own.join(" ");
  return (b.getAttribute("aria-label") ?? b.value).trim();
}

/** Writes `v` into one control, as a user would. False when nothing matched. */
function write(el: FieldElement, v: string, role: FieldRole, geo: GeoContext = DEFAULT_GEO): boolean {
  let value = v;
  if (DATE_ROLES.has(role)) {
    // The date input, the part, or the written format the field wants (date.ts).
    if (el instanceof HTMLSelectElement) {
      const i = dateOption(el, v);
      const opt = i >= 0 ? el.options[i] : undefined;
      if (!opt) return false;
      value = opt.value;
    } else {
      const text = dateText(el, v, geo.lang ?? null);
      if (text === null) return false;
      value = text;
    }
  } else if (el instanceof HTMLSelectElement) {
    const i = matchOption(el, v, role, geo);
    const opt = i >= 0 ? el.options[i] : undefined;
    if (!opt) return false;
    // A person leaves a country or region list that already shows the
    // value alone: no change event, so the page reloads nothing.
    if ((role === "country" || role === "region") && el.selectedIndex === i) return true;
    value = opt.value;
  } else if (role === "country" || role === "region" || role === "nationality" || ISSUING_ROLES.has(role)) {
    value = textValue(el, v, role, geo);
    if (value === "") return false;
  } else if (CHOICE_ROLES.has(role)) {
    // A civility typed as the vault writes it; a sex is never typed (its words differ by page).
    if (role === "sex" || v === "") return false;
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
  /** Called with each control written and the role it received (never the value). */
  onFill?: (el: Element, role: FieldRole) => void;
  /**
   * The focused element, inside the page's shadow roots (`deepActiveElement`);
   * defaults to `document.activeElement`, which is the host when the focus is
   * in a root.
   */
  activeElement?: () => Element | null;
  /** Language of the page (`<html lang>`), for country names. */
  lang?: () => string | null;
  /** Bound of each wait for the page (region list reload, combobox options). Default 2000 ms. */
  settleMs?: number;
}

export interface FillResult {
  /** Controls written at once. */
  now: number;
  /** Roles written at once. */
  filled: FieldRole[];
  /** True when writes are still to come (region list reload, combobox pick). */
  pending: boolean;
  /** Every role this fill wrote, once its later writes are over (bounded by `settleMs` per wait). */
  done: Promise<FieldRole[]>;
  /** The roles written until now. */
  soFar(): FieldRole[];
}

export interface Filler {
  /**
   * Fills the fields of `formRef`. A combobox counts only once an option
   * was picked, a region that waits for its list once it is written: both
   * come later, in `done`.
   */
  fill(formRef: string, values: Partial<Record<FieldRole, string>>, hints?: FillHints): FillResult;
  /** `fill(...).now`: how many controls were written at once. */
  fillForm(formRef: string, values: Partial<Record<FieldRole, string>>, hints?: FillHints): number;
  /** Resolves when every later write (region wait, combobox pick) is over. */
  settled(): Promise<void>;
}

export const SETTLE_MS = 2000;
/** At most this many names are typed into a combobox, each try waits at least MIN_TRY_MS. */
const MAX_TYPED = 4;
const MIN_TRY_MS = 300;

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
    const radio = el instanceof HTMLInputElement && el.type === "radio";
    if (!el || !el.isConnected || !(isFieldCandidate(el) || radio)) return null;
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
  const active = opts.activeElement ?? (() => (typeof document !== "undefined" ? document.activeElement : null));
  const keepFocus = <T>(fn: () => T): T => {
    const had = active();
    try {
      return fn();
    } finally {
      if (had instanceof HTMLInputElement && had.isConnected && active() !== had) had.focus({ preventScroll: true });
    }
  };

  const settleMs = opts.settleMs ?? SETTLE_MS;
  const pageLang = opts.lang ?? (() => (typeof document !== "undefined" ? document.documentElement.lang : null));
  const visible = (el: Element) => isVisible(el, geometry);

  // Later writes run one after the other, in fill order.
  let chain: Promise<unknown> = Promise.resolve();
  const later = (task: () => Promise<unknown>): void => {
    chain = chain.then(task).catch(() => undefined);
  };

  /**
   * A combobox: types each of `typed` in turn (a menu filtered by "Bayern"
   * never shows "Bavaria"), waits for its list, presses the option `match`
   * picks; the hidden select behind it gets the same choice (`matchSelect`).
   * False when no option matched within the bound (shared by the tries).
   */
  const pickInCombobox = async (
    input: HTMLInputElement,
    role: FieldRole,
    tally: FieldRole[],
    typed: readonly string[],
    match: (o: OptionLike[]) => number,
    matchSelect: (sel: HTMLSelectElement) => number,
  ): Promise<boolean> => {
    if (!input.isConnected || !visible(input)) return false;
    const had = active();
    const before = nativeValue(input);
    const root = input.getRootNode();
    const tries = typed.filter((t, i) => t !== "" && typed.indexOf(t) === i).slice(0, MAX_TYPED);
    const bound = Math.max(MIN_TRY_MS, Math.floor(settleMs / Math.max(1, tries.length)));
    let option: HTMLElement | null = null;
    let last = "";
    for (const text of tries) {
      if (!input.isConnected) break;
      input.focus({ preventScroll: true });
      setNative(input, text);
      fire(input, "input");
      last = text;
      let picked: HTMLElement | null = null;
      await settle(
        // In a shadow root, its list may be portaled into the document (aria-controls names it there).
        root instanceof ShadowRoot ? [root, input.ownerDocument] : input.ownerDocument,
        () => {
          const os = optionsOf(input).filter(visible);
          const i = os.length > 0 ? match(os.map(optionLike)) : -1;
          picked = i >= 0 ? os[i]! : null;
          return picked !== null;
        },
        bound,
      );
      option = picked as HTMLElement | null;
      if (option?.isConnected) break;
      option = null;
    }
    if (!option) {
      // Nothing to pick: the typed text goes, as a person would erase it.
      if (input.isConnected && last !== "" && nativeValue(input) === last) {
        setNative(input, before);
        fire(input, "input");
      }
      if (input.isConnected) input.blur();
      return false;
    }
    press(option);
    // Spec section 4: the hidden native select behind this very widget.
    const backing = backingSelect(input, visible);
    if (backing && !visible(backing)) {
      const i = matchSelect(backing);
      const opt = i >= 0 ? backing.options[i] : undefined;
      if (opt) {
        setNative(backing, opt.value);
        fire(backing, "input");
        fire(backing, "change");
        written.set(backing, nativeValue(backing));
      }
    }
    if (input.isConnected) {
      written.set(input, nativeValue(input));
      opts.onFill?.(input, role);
      tally.push(role);
      input.blur();
    }
    if (had instanceof HTMLElement && had !== input && had.isConnected) had.focus({ preventScroll: true });
    return true;
  };

  // Tasks queued while waiting are waited for too.
  const settled = async (): Promise<void> => {
    let seen: Promise<unknown>;
    do {
      seen = chain;
      await seen;
    } while (seen !== chain);
  };

  const fill = (formRef: string, values: Partial<Record<FieldRole, string>>, hints: FillHints = {}): FillResult => {
    const tally: FieldRole[] = [];
    const before = chain;
    const now = keepFocus(() => fillOnce(formRef, values, tally, hints));
    const unique = () => [...new Set(tally)];
    const filled = unique();
    const pending = chain !== before;
    return { now, filled, pending, done: pending ? settled().then(unique) : Promise.resolve(filled), soFar: unique };
  };

  return { fill, fillForm: (formRef, values, hints) => fill(formRef, values, hints).now, settled };

  function fillOnce(formRef: string, values: Partial<Record<FieldRole, string>>, tally: FieldRole[], hints: FillHints): number {
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

      const lang = pageLang();
      const langs = nameLangs(lang);
      const itemCountry = typeof values.country === "string" && values.country !== "" ? resolveCountry(values.country, langs) : null;
      const postal = typeof values.postal_code === "string" && values.postal_code !== "" ? values.postal_code : null;
      /** The country of the item, else the one the form's country field holds now. */
      const countryNow = (): string | null => {
        if (itemCountry) return itemCountry;
        const f = form.fields.find((x) => x.role === "country");
        const el = f ? refs.get(f.ref) : undefined;
        if (el instanceof HTMLSelectElement) {
          const o = el.selectedOptions[0];
          return o && o.value !== "" ? (resolveCountry(o.textContent ?? "", langs) ?? resolveCountryValue(o.value, langs)) : null;
        }
        return el instanceof HTMLInputElement ? resolveCountry(nativeValue(el), langs) : null;
      };
      const sex = typeof hints.sex === "string" && hints.sex !== "" ? hints.sex : undefined;
      const civilityFromSex = hints.civility_from_sex === true;
      const geoNow = (): GeoContext => ({ langs, country: countryNow(), postal, lang, sex, civilityFromSex });

      const written: Written[] = [];
      /**
       * Checks the radio of a civility or sex group that means `v` (spec section 7), with click,
       * input and change as a person's click. A group the user (or the page) already checked is
       * left alone; a tie or no match: nothing.
       */
      const pickRadio = (slot: Slot, count: number, v: string): boolean => {
        const buttons: HTMLInputElement[] = [];
        for (let i = 0; i < count; i++) {
          const el = target(slot, i);
          if (el instanceof HTMLInputElement && el.type === "radio") buttons.push(el);
        }
        if (buttons.length < 2 || buttons.some((b) => b.checked)) return false;
        const choices = buttons.map((b) => ({ value: b.value, text: radioLabel(b) }));
        const i = pickChoice(choices, slot.role, { value: v, sex: slot.role === "sex" || civilityFromSex ? sex : undefined });
        const b = i >= 0 ? buttons[i] : undefined;
        if (!b) return false;
        b.focus({ preventScroll: true });
        b.click();
        if (!b.checked) {
          // A page that cancelled the click: a person's click would not check it either.
          b.blur();
          return false;
        }
        b.blur();
        // The control's own events already ran with the click (input, change).
        opts.onFill?.(b, slot.role);
        tally.push(slot.role);
        return true;
      };
      const put = (slot: Slot, part: number | undefined, value: string): boolean => {
        const el = target(slot, part);
        if (!el || !write(el, value, slot.role, geoNow())) return false;
        opts.onFill?.(el, slot.role);
        tally.push(slot.role);
        written.push({ slot, part, el, value });
        return true;
      };

      const seen = new Map<FieldRole, number>();
      const slots: { slot: Slot; field: FieldInfo }[] = [];
      for (const f of form.fields) {
        const nth = seen.get(f.role) ?? 0;
        seen.set(f.role, nth + 1);
        // Passengers 2 and later are other people: never written (ruling R3). The birth country
        // is never written either (ruling R5).
        if ((f.person ?? 0) > 0 || f.role === "birth_country") continue;
        slots.push({ slot: { role: f.role, nth }, field: f });
      }
      let n = 0;
      // The region after the country: its list often depends on it.
      const regionSlots = slots.filter((x) => x.slot.role === "region");
      let countryChanged = false;
      let countryPending = false;
      for (const { slot, field } of slots) {
        if (slot.role === "region") continue;
        // A civility the vault does not hold comes from the sex, when the civility was asked.
        const fromSex = slot.role === "honorific_prefix" && civilityFromSex && sex !== undefined;
        // A work phone field gets the work phone, else today's phone (ruling R7).
        const own = slot.role === "tel" && field.work === true ? (hints.work_tel ?? values.tel) : values[slot.role];
        const v = own ?? (fromSex ? "" : undefined);
        if (typeof v !== "string" || (v === "" && !fromSex)) continue;
        if (slot.role === "country") {
          const el = target(slot, undefined);
          if (el && isCombobox(el)) {
            const cc = itemCountry;
            const typed = cc ? [...langs.map((l) => countryName(cc, l)), v] : [v];
            later(() => pickInCombobox(el, slot.role, tally, typed, (o) => pickCountry(o, v, langs), (s) => matchOption(s, v, "country", geoNow())));
            countryPending = true;
            continue;
          }
          const before = el ? nativeValue(el) : "";
          if (put(slot, undefined, v)) {
            n++;
            if (el && nativeValue(el) !== before) countryChanged = true;
          }
          continue;
        }
        if (field.parts && field.parts.length > 0 && DATE_ROLES.has(slot.role)) {
          // A date in parts: each control takes its own part of the date (date.ts); a control no
          // sign designates as a day, a month or a year stays empty (ruling R9).
          for (let i = 0; i < field.parts.length; i++) {
            const el = target(slot, i);
            if (el && datePart(el) !== null && put(slot, i, v)) n++;
          }
        } else if (field.parts && field.parts.length > 0) {
          // A radio group: the button whose label means the value (choice.ts), never one character per button.
          if (CHOICE_ROLES.has(slot.role)) {
            if (pickRadio(slot, field.parts.length, v)) n++;
            continue;
          }
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

      const region = typeof values.region === "string" ? values.region : "";
      if (region !== "" || postal !== null) {
        // A region field may also appear only once the country is chosen.
        const todo: Slot[] = regionSlots.length > 0 ? regionSlots.map((x) => x.slot) : countryChanged || countryPending ? [{ role: "region", nth: 0 }] : [];
        const formRef0 = form.ref;
        /** One try at the region in `el`: "written", "picking" (its combobox, counted once picked) or false. */
        const regionInto = (el: FieldElement, slot: Slot, fresh: boolean): "written" | "picking" | false => {
          const geo = geoNow();
          if (isCombobox(el)) {
            const wanted = regionWanted(region, geo.country, postal);
            if (wanted.length === 0 && region === "") return false;
            const typed = typedRegion(wanted, region);
            later(() => pickInCombobox(el, "region", tally, typed, (o) => pickRegion(o, wanted, geo.country, region), (s) => matchOption(s, region, "region", geo)));
            return "picking";
          }
          // A region deduced from the postal code goes into a list only.
          if (region === "" && !(el instanceof HTMLSelectElement)) return false;
          if (!write(el, region, "region", geo)) return false;
          opts.onFill?.(el, "region");
          tally.push("region");
          if (!fresh) written.push({ slot, part: undefined, el, value: region });
          return "written";
        };
        /**
         * The tries of a wait for the region (a list the page reloads, a
         * field it shows). A live field is tried again only once its options
         * changed, without analysing the page; a dead or missing one is looked
         * for in a fresh analysis, at most once per OBSERVER_DELAY_MS (and at
         * the last try): a page that mutates all the time is not analysed on
         * every batch.
         */
        const regionWait = (slot: Slot) => {
          let lookedAt = Date.now();
          let tried: string | null = null;
          return (final: boolean): boolean => {
            let r = lookup(slot, undefined);
            if (r.dead) {
              const now = Date.now();
              if (!final && now - lookedAt < OBSERVER_DELAY_MS) return false;
              lookedAt = now;
              const again = opts.resolve(form.ref, opts.analyze()) ?? opts.resolve(formRef0, opts.analyze());
              if (!again) return false;
              form = again;
              r = lookup(slot, undefined);
              tried = null;
            }
            const el = r.el;
            if (!el) return false;
            if (el instanceof HTMLSelectElement) {
              const sig = optionsSignature(el);
              if (sig === tried) return false;
              tried = sig;
            }
            return regionInto(el, slot, true) !== false;
          };
        };
        for (const slot of todo) {
          let r: "written" | "picking" | false = false;
          if (!countryPending) {
            const el = target(slot, undefined);
            r = el ? regionInto(el, slot, false) : false;
          }
          if (r === "written") n++;
          if (r !== false) continue;
          if (!countryChanged && !countryPending) continue;
          // Wait for the page to reload the list (or show the field).
          later(async () => {
            const container = refs.get(form.ref);
            const root = container?.getRootNode() ?? document;
            await settle(root, regionWait(slot), settleMs);
          });
        }
      }

      // A written control the page replaced by an empty copy gets its value
      // again, once: a page that re-renders on every input is not chased.
      for (const w of written.splice(0)) {
        if (w.el.isConnected) continue;
        const el = target(w.slot, w.part);
        if (el && nativeValue(el) === "") write(el, w.value, w.slot.role, geoNow());
      }
      return n;
    }
  }
}
