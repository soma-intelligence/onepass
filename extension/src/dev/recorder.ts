// Dev-only form flow recorder (lab corpus source "recorded"). Built only when
// ONEPASS_LAB_RECORDER=1; a release build never imports this file.
//
// It keeps the STRUCTURE of each form step the user fills (the shared
// extractor's features: attributes, labels, geometry) and never a value: no
// typed text, no value attribute, no length, no "does it match" flag. `filled`
// only says which role OnePass wrote into a field, or "user" for a field the
// user edited. Steps are stored under the host alone.
import { extractFeatures, type FieldFeatures, type PageFeatures, type Visibility } from "../content/detect/features.ts";
import type { FieldRole } from "../shared/messages.ts";
import { sanitizeNeighbour, sanitizeText, sanitizeToken } from "../shared/sanitize.ts";

export const RECORDER_KEY = "onepass-lab-recorder";
export const MAX_STEPS = 2000;
/** Serialized size above which the oldest steps go (storage.local has ~10 MB without unlimitedStorage). */
export const MAX_BYTES = 4_000_000;
/** Values shorter than this are not used to redact page text (they would match everything). */
export const MIN_ECHO = 3;
export const MSG_STEP = "lab-recorder-step";
export const MSG_EXPORT = "lab-recorder-export";

export type FilledRole = FieldRole | "user";

export interface RecordedStep {
  host: string;
  at: number;
  form: PageFeatures["forms"][number];
  /** Field index in `form.fields` to the role OnePass filled, or "user". */
  filled: Record<number, FilledRole>;
}

const FIELD_SEL = "input, select, textarea";
const SKIP_TYPES = ["hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file"];
const EDITABLE = '[contenteditable]:not([contenteditable="false" i])';

const eligible = (el: Element): boolean => !(el instanceof (el.ownerDocument.defaultView ?? window).HTMLInputElement && SKIP_TYPES.includes(el.type));

/** Fields (in extractor order) of the group the extractor builds for `container`. */
function groupFields(doc: Document, container: Element): Element[] {
  if (container instanceof (doc.defaultView ?? window).HTMLFormElement) {
    return Array.from(container.querySelectorAll(FIELD_SEL)).filter(eligible);
  }
  return Array.from(doc.querySelectorAll(FIELD_SEL)).filter((e) => !e.closest("form") && eligible(e));
}

/** Position of `container`'s group among the forms the extractor returns, or -1. */
function groupIndex(doc: Document, container: Element, features: PageFeatures): number {
  if (container instanceof (doc.defaultView ?? window).HTMLFormElement) {
    let n = 0;
    for (const f of Array.from(doc.querySelectorAll("form"))) {
      const has = Array.from(f.querySelectorAll(FIELD_SEL)).some(eligible);
      if (f === container) return has ? n : -1;
      if (has) n++;
    }
    return -1;
  }
  const orphans = groupFields(doc, container).length > 0;
  return orphans ? features.forms.length - 1 : -1;
}

function scrub(f: FieldFeatures, dropText: boolean): FieldFeatures {
  const { lab: _lab, ...rest } = f;
  if (!dropText) return rest;
  // Text the user can type is part of the page text: keep none of it as a label or neighbour.
  const { label: _l, before: _b, after: _a, ...kept } = rest;
  return { ...kept, neighbourLabels: [] };
}

const fold = (t: string): string => t.normalize("NFKC").toLowerCase().replace(/\s+/g, " ").trim();

/** Normalized values currently in any field of the document, plus `known` (held in memory by the caller). */
function echoValues(doc: Document, known: Iterable<string>): string[] {
  const out = new Set<string>();
  const add = (v: unknown) => {
    if (typeof v !== "string") return;
    const t = fold(v);
    if (t.length >= MIN_ECHO) out.add(t);
  };
  for (const el of Array.from(doc.querySelectorAll(FIELD_SEL))) {
    if (el instanceof (doc.defaultView ?? window).HTMLSelectElement) {
      for (const o of Array.from(el.selectedOptions)) {
        add(o.value);
        add(o.textContent);
      }
    } else {
      add((el as HTMLInputElement | HTMLTextAreaElement).value);
    }
  }
  for (const v of known) add(v);
  return [...out];
}

/** True when `t` ends with the first `n` (or starts with the last `n`) characters of `v`, for some MIN_ECHO <= n < |v|. */
function cutShort(t: string, v: string): boolean {
  for (let n = Math.min(v.length - 1, t.length); n >= MIN_ECHO; n--) {
    if (t.endsWith(v.slice(0, n)) || t.startsWith(v.slice(v.length - n))) return true;
  }
  return false;
}

/**
 * True when the page text holds one of the values, whole or cut at either end: the extractor
 * caps texts (neighbours at 40, buttons at 60, labels at 120) and the sanitizer at 60, so a value
 * echoed at a boundary may only be there in part.
 */
const echoes = (t: string | undefined, values: readonly string[]): boolean => {
  if (t === undefined) return false;
  const f = fold(t);
  return values.some((v) => f.includes(v) || cutShort(f, v));
};

/**
 * Cleans every string of a field: anything that echoes a value is dropped, checked on the full
 * text first (the sanitizer cuts at 60 or 40 characters, which could leave a value cut short),
 * then the sanitizer, then the same check on what it kept.
 */
function clean(f: FieldFeatures, values: readonly string[]): FieldFeatures {
  const bad = (t: string | undefined): boolean => t === undefined || t === "<redacted>" || echoes(t, values);
  const text = (s: string | undefined, fn: (x: string | undefined) => string | undefined = sanitizeText): string | undefined => {
    if (echoes(s, values)) return undefined;
    const t = fn(s);
    return bad(t) ? undefined : t;
  };
  const list = (a: string[]): string[] => a.map((x) => text(x)).filter((x): x is string => x !== undefined);
  const tok = (s: string | undefined): string | undefined => {
    if (echoes(s, values)) return undefined;
    const t = sanitizeToken(s);
    return bad(t) ? undefined : t;
  };
  const out: FieldFeatures = { ...f, formButtons: list(f.formButtons), neighbourLabels: list(f.neighbourLabels) };
  const set = (k: "label" | "placeholder" | "ariaLabel" | "before" | "after" | "pageTitle", v: string | undefined) => {
    if (v === undefined) delete out[k];
    else out[k] = v;
  };
  set("label", text(f.label));
  set("placeholder", text(f.placeholder));
  set("ariaLabel", text(f.ariaLabel));
  set("before", text(f.before, sanitizeNeighbour));
  set("after", text(f.after, sanitizeNeighbour));
  set("pageTitle", text(f.pageTitle));
  for (const k of ["name", "id", "autocomplete", "inputmode"] as const) {
    const v = tok(f[k]);
    if (v === undefined) delete out[k];
    else out[k] = v;
  }
  return out;
}

/**
 * The structure of the form step `form` (a <form>, or any container for a page
 * without one), and which of its fields OnePass or the user filled.
 */
export function recordSubmit(
  form: HTMLFormElement | Element,
  filled: { get(el: Element): FilledRole | undefined },
  known: Iterable<string> = [],
): RecordedStep {
  const doc = form.ownerDocument;
  const features = extractFeatures(doc);
  const at = groupIndex(doc, form, features);
  const group = at >= 0 ? features.forms[at] : undefined;
  const els = at >= 0 ? groupFields(doc, form) : [];
  const editable = Array.from(doc.querySelectorAll(EDITABLE)).some((e) => (e.textContent ?? "").trim() !== "");
  const values = echoValues(doc, known);
  const fields = (group?.fields ?? []).map((f) => clean(scrub(f, editable), values));
  const map: Record<number, FilledRole> = {};
  fields.forEach((f, i) => {
    const el = els[i];
    const v = el ? filled.get(el) : undefined;
    if (v !== undefined) map[f.index] = v;
  });
  return {
    host: doc.defaultView?.location?.hostname ?? "",
    at: Date.now(),
    form: {
      fields,
      buttons: (group?.buttons ?? [])
        .filter((b) => !echoes(b, values))
        .map((b) => sanitizeText(b))
        .filter((b): b is string => b !== undefined && b !== "<redacted>" && !echoes(b, values)),
    },
    filled: map,
  };
}

// ---- untrusted input: rebuild from validated fields only ----

const VISIBILITY: ReadonlySet<string> = new Set<Visibility>(["visible", "display_none", "offscreen", "opacity", "zero_size"]);
const HOST_RE = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/;
const ROLE_RE = /^[a-z][a-z0-9_]{0,31}$/;

const obj = (v: unknown): Record<string, unknown> | null => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const optStr = (v: unknown, max: number): string | undefined | null => (v === undefined ? undefined : typeof v === "string" && v.length <= max ? v : null);
const strList = (v: unknown, maxItems: number, maxLen: number): string[] | null => {
  if (!Array.isArray(v) || v.length > maxItems) return null;
  return v.every((x) => typeof x === "string" && x.length <= maxLen) ? (v as string[]) : null;
};

function field(v: unknown): FieldFeatures | null {
  const o = obj(v);
  if (!o) return null;
  const strs = {} as Record<string, string | undefined>;
  for (const k of ["type", "name", "id", "autocomplete", "inputmode", "label", "placeholder", "ariaLabel", "before", "after", "pageTitle"]) {
    const s = optStr(o[k], k === "type" ? 32 : 240);
    if (s === null) return null;
    strs[k] = s;
  }
  const maxlength = o.maxlength === undefined ? undefined : num(o.maxlength);
  const nums = ["index", "depth", "siblings", "width", "height"].map((k) => num(o[k]));
  const formButtons = strList(o.formButtons, 12, 120);
  const neighbourLabels = strList(o.neighbourLabels, 4, 240);
  if (typeof o.tag !== "string" || o.tag.length > 16 || maxlength === null || nums.includes(null)) return null;
  if (typeof o.hasPattern !== "boolean" || typeof o.required !== "boolean" || typeof o.visibility !== "string" || !VISIBILITY.has(o.visibility)) return null;
  if (!formButtons || !neighbourLabels) return null;
  const out: FieldFeatures = {
    index: nums[0]!, tag: o.tag, hasPattern: o.hasPattern, required: o.required, depth: nums[1]!, siblings: nums[2]!,
    visibility: o.visibility as Visibility, width: nums[3]!, height: nums[4]!, formButtons, neighbourLabels,
  };
  for (const [k, s] of Object.entries(strs)) if (s !== undefined) (out as unknown as Record<string, unknown>)[k] = s;
  if (maxlength !== undefined) out.maxlength = maxlength;
  return out;
}

/** A step from an untrusted sender, rebuilt key by key; the host is the caller's. Null when malformed. */
export function normalizeStep(v: unknown, host: string): RecordedStep | null {
  const o = obj(v);
  const form = obj(o?.form);
  const filled = obj(o?.filled);
  if (!o || !form || !filled || !HOST_RE.test(host)) return null;
  const at = num(o.at);
  const buttons = strList(form.buttons, 12, 120);
  if (at === null || !buttons || !Array.isArray(form.fields) || form.fields.length > 300) return null;
  const fields: FieldFeatures[] = [];
  for (const f of form.fields) {
    const x = field(f);
    if (!x) return null;
    fields.push(x);
  }
  const map: Record<number, FilledRole> = {};
  for (const [k, r] of Object.entries(filled)) {
    if (!/^\d{1,3}$/.test(k) || typeof r !== "string" || !(r === "user" || ROLE_RE.test(r))) return null;
    map[Number(k)] = r as FilledRole;
  }
  return { host, at, form: { fields, buttons }, filled: map };
}

// ---- storage: one key, newest MAX_STEPS ----

export interface StepStorage {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

export async function readSteps(st: StepStorage): Promise<RecordedStep[]> {
  const raw = (await st.get(RECORDER_KEY))[RECORDER_KEY];
  if (!Array.isArray(raw)) return [];
  const out: RecordedStep[] = [];
  for (const x of raw) {
    const host = obj(x)?.host;
    const s = typeof host === "string" ? normalizeStep(x, host) : null;
    if (s) out.push(s);
  }
  return out;
}

const queues = new WeakMap<object, Promise<unknown>>();

const size = (v: unknown): number => new TextEncoder().encode(JSON.stringify(v)).length;

/**
 * Appends a step (read, push, drop the oldest past the step cap and the byte
 * cap, write), one at a time per storage. A write the browser refuses (quota)
 * drops the oldest half and is retried once.
 */
export function appendStep(st: StepStorage, step: RecordedStep, maxBytes = MAX_BYTES): Promise<void> {
  const run = async () => {
    let all = [...(await readSteps(st)), step].slice(-MAX_STEPS);
    while (all.length > 1 && size(all) > maxBytes) all = all.slice(Math.ceil(all.length / 10));
    try {
      await st.set({ [RECORDER_KEY]: all });
    } catch {
      all = all.slice(Math.ceil(all.length / 2));
      await st.set({ [RECORDER_KEY]: all });
    }
  };
  const next = (queues.get(st) ?? Promise.resolve()).then(run, run);
  queues.set(st, next.catch(() => undefined));
  return next;
}
