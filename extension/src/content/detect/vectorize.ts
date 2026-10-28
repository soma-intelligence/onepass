// Shared field vectorizer. The model is trained in Python (ml/onepass_ml/vectorize.py, an exact port)
// and runs here, so both sides must turn a field into the same vector and the same text.
// extension/test/vectors/vectorize.json holds the cases both sides assert.
//
// Reads only FieldFeatures. Never `lab`, and (ruling R16) never width, height or pageTitle: real
// samples do not carry them. The training target is not a feature and is not visible here.
//
// Vector layout (VECTOR_DIM = 4096):
//   [0, HASH_DIM)            hashed token counts, HASH_DIM = VECTOR_DIM - NUM_INDICATORS
//   [HASH_DIM, VECTOR_DIM)   numeric indicators, in the order and sizes of INDICATORS
// A token adds 1 at cyrb128(`${namespace}:${token}`)[0] % HASH_DIM (word 0 of the 4 words).
// All values are small integers or k/16 fractions, exact in float32.
//
// Text handling: normalizeText, then capped to TEXT_CAP code points. Tokens are maximal runs of
// code points whose Unicode general category is L*, M* or N* (JS \p{L}\p{M}\p{N}, Python
// unicodedata category first letter in "LMN"). Inside a run, Han, Hiragana, Katakana and Hangul
// code points (CJK_RANGES) form segments that become overlapping character bigrams (a lone code
// point stays a unigram); other segments are one token. Both sides use their own Unicode tables
// (Node ICU vs Python 3.12 unicodedata 15.0): code points assigned after Unicode 15.0 may differ.

import { normalizeText, type FieldFeatures } from "./features";
import { cyrb128 } from "../../shared/hash";

export const VECTOR_DIM = 4096;
export const TEXT_CAP = 256;

export const TYPES = [
  "text", "email", "password", "tel", "number", "url", "search", "date", "datetime-local", "month",
  "week", "time", "color", "range", "select", "textarea", "other",
] as const;
export const KNOWN_AUTOCOMPLETE = [
  "name", "honorific-prefix", "given-name", "additional-name", "family-name", "honorific-suffix",
  "nickname", "username", "new-password", "current-password", "one-time-code", "organization-title",
  "organization", "street-address", "address-line1", "address-line2", "address-line3",
  "address-level1", "address-level2", "address-level3", "address-level4", "country", "country-name",
  "postal-code", "cc-name", "cc-given-name", "cc-additional-name", "cc-family-name", "cc-number",
  "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc", "cc-type", "transaction-currency",
  "transaction-amount", "language", "bday", "bday-day", "bday-month", "bday-year", "sex", "url",
  "photo", "email", "tel", "tel-country-code", "tel-national", "tel-area-code", "tel-local",
  "tel-extension", "impp", "webauthn",
] as const;
export const VISIBILITIES = ["visible", "display_none", "offscreen", "opacity", "zero_size"] as const;
/** Upper bounds (inclusive) of the maxlength buckets; bucket 0 = no maxlength, last = above all bounds. */
export const MAXLENGTH_BOUNDS = [2, 4, 8, 16, 64] as const;
/** Index 0 = attribute absent, last = any value not in the list. */
export const INPUTMODES = ["", "text", "numeric", "tel", "email", "url", "search", "decimal"] as const;

const MAXLEN_SIZE = MAXLENGTH_BOUNDS.length + 2;
const INPUTMODE_SIZE = INPUTMODES.length + 1;

/** Indicator blocks in order. `offset` is absolute in the vector. */
export const INDICATORS: readonly { name: string; offset: number; size: number }[] = (() => {
  const blocks: [string, number][] = [
    ["type", TYPES.length], ["known_autocomplete", 1], ["visibility", VISIBILITIES.length],
    ["maxlength", MAXLEN_SIZE], ["depth", 1], ["index", 1], ["siblings", 1], ["has_pattern", 1],
    ["required", 1], ["inputmode", INPUTMODE_SIZE],
  ];
  const total = blocks.reduce((s, [, n]) => s + n, 0);
  let at = VECTOR_DIM - total;
  return blocks.map(([name, size]) => {
    const b = { name, offset: at, size };
    at += size;
    return b;
  });
})();
export const NUM_INDICATORS = INDICATORS.reduce((s, b) => s + b.size, 0);
export const HASH_DIM = VECTOR_DIM - NUM_INDICATORS;

const KNOWN_AC = new Set<string>(KNOWN_AUTOCOMPLETE);
const WORD_CHAR = /^[\p{L}\p{M}\p{N}]$/u;
const CJK_RANGES: readonly (readonly [number, number])[] = [
  [0x3040, 0x309f], [0x30a0, 0x30ff], [0x31f0, 0x31ff], [0x3400, 0x4dbf], [0x4e00, 0x9fff],
  [0xac00, 0xd7af], [0xf900, 0xfaff], [0x20000, 0x2a6df], [0x2a700, 0x2ebef], [0x30000, 0x323af],
];
const isCjk = (c: string): boolean => {
  const cp = c.codePointAt(0)!;
  return CJK_RANGES.some(([a, b]) => cp >= a && cp <= b);
};

/** normalizeText, then the first TEXT_CAP code points, trailing space removed. */
function clean(s: string | null | undefined): string {
  if (s == null) return "";
  const cps = Array.from(normalizeText(s));
  return (cps.length > TEXT_CAP ? cps.slice(0, TEXT_CAP).join("") : cps.join("")).replace(/ +$/, "");
}

/** Tokens of a text (see the file header). Normalizes and caps its input. */
export function tokenize(s: string | null | undefined): string[] {
  const out: string[] = [];
  let run: string[] = [];
  const flushSegment = (seg: string[], cjk: boolean): void => {
    if (!seg.length) return;
    if (!cjk) out.push(seg.join(""));
    else if (seg.length === 1) out.push(seg[0]!);
    else for (let i = 0; i + 1 < seg.length; i++) out.push(seg[i]! + seg[i + 1]!);
  };
  const flushRun = (): void => {
    let seg: string[] = [];
    let segCjk = false;
    for (const c of run) {
      const k = isCjk(c);
      if (seg.length && k !== segCjk) { flushSegment(seg, segCjk); seg = []; }
      segCjk = k;
      seg.push(c);
    }
    flushSegment(seg, segCjk);
    run = [];
  };
  for (const c of Array.from(clean(s))) {
    if (WORD_CHAR.test(c)) run.push(c);
    else flushRun();
  }
  flushRun();
  return out;
}

const effectiveType = (f: FieldFeatures): string => clean(f.tag) === "select" ? "select" : clean(f.type ?? f.tag);

export function vectorize(f: FieldFeatures): Float32Array {
  const v = new Float32Array(VECTOR_DIM);
  const add = (ns: string, tok: string): void => {
    v[(cyrb128(`${ns}:${tok}`)[0] as number) % HASH_DIM]! += 1;
  };
  const addAll = (ns: string, s: string | null | undefined): void => { for (const t of tokenize(s)) add(ns, t); };

  const type = effectiveType(f);
  if (type) add("type", type);
  const tag = clean(f.tag);
  if (tag) add("tag", tag);
  for (const [ns, s] of [["name", f.name], ["id", f.id]] as const) {
    addAll(ns, s);
    const whole = clean(s);
    if (whole) add(`${ns}_full`, whole);
  }
  const acTokens = clean(f.autocomplete).split(" ").filter(Boolean);
  for (const t of acTokens) add("ac", t);
  addAll("label", f.label);
  addAll("ph", f.placeholder);
  addAll("aria", f.ariaLabel);
  addAll("before", f.before);
  addAll("after", f.after);
  for (const s of f.neighbourLabels ?? []) addAll("near", s);
  for (const s of f.formButtons ?? []) addAll("btn", s);

  const at = (name: string): number => INDICATORS.find((b) => b.name === name)!.offset;
  const typeIdx = (TYPES as readonly string[]).indexOf(type);
  v[at("type") + (typeIdx >= 0 ? typeIdx : TYPES.length - 1)] = 1;
  if (acTokens.some((t) => KNOWN_AC.has(t))) v[at("known_autocomplete")] = 1;
  const vis = (VISIBILITIES as readonly string[]).indexOf(f.visibility);
  if (vis >= 0) v[at("visibility") + vis] = 1;
  const ml = f.maxlength;
  let mb = 0;
  if (ml != null && ml > 0) {
    mb = MAXLENGTH_BOUNDS.findIndex((b) => ml <= b);
    mb = mb < 0 ? MAXLENGTH_BOUNDS.length + 1 : mb + 1;
  }
  v[at("maxlength") + mb] = 1;
  v[at("depth")] = Math.min(Math.max(f.depth, 0), 16) / 16;
  v[at("index")] = Math.min(Math.max(f.index, 0), 15) / 16;
  v[at("siblings")] = Math.min(Math.max(f.siblings, 0), 15) / 16;
  if (f.hasPattern) v[at("has_pattern")] = 1;
  if (f.required) v[at("required")] = 1;
  const im = clean(f.inputmode);
  const imIdx = (INPUTMODES as readonly string[]).indexOf(im);
  v[at("inputmode") + (imIdx >= 0 ? imIdx : INPUTMODES.length)] = 1;
  return v;
}

/** Text for the encoder. Same fields as the vector, minus the numeric indicators. */
export function serialize(f: FieldFeatures): string {
  const list = (xs: string[] | undefined): string => (xs ?? []).map(clean).join("; ");
  return [
    `type=${effectiveType(f)}`, `ac=${clean(f.autocomplete)}`, `label=${clean(f.label)}`,
    `ph=${clean(f.placeholder)}`, `aria=${clean(f.ariaLabel)}`, `before=${clean(f.before)}`,
    `after=${clean(f.after)}`, `near=${list(f.neighbourLabels)}`, `buttons=${list(f.formButtons)}`,
  ].join(" | ");
}
