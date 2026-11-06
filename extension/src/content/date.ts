// Birth dates as the page wants them (one-click signup, spec 5). The vault
// gives `YYYY-MM-DD` (onepass-bridge `identity_values`); the classifier gives
// one role, `bday`, to the whole date and to each part of a split one. Here,
// the field itself says which: a date input, one part (by `autocomplete`, its
// names and label, or a list's options), or a written format (placeholder,
// `pattern`, else the page's language). A part nothing designates is not
// written: nothing invented goes into the page.
import { normalizeText } from "./detect/lexicon";

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

export const leadingInt = (s: string): number => {
  const m = /^\s*(\d{1,4})\b/.exec(s);
  return m ? Number(m[1]) : Number.NaN;
};

/** 1..12 from a number or an English or French month name, else NaN. */
export function monthOf(s: string): number {
  const n = leadingInt(s);
  if (n >= 1 && n <= 12) return n;
  const t = normalizeText(s);
  const word = /^[a-z]+/.exec(t)?.[0] ?? "";
  const i = MONTHS.findIndex((names) => names.includes(word));
  return i < 0 ? Number.NaN : i + 1;
}

export type DatePart = "day" | "month" | "year";

interface Ymd {
  y: number;
  m: number;
  d: number;
}

function parseIso(iso: string): Ymd | null {
  const r = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso.trim());
  if (!r) return null;
  const y = Number(r[1]);
  const m = Number(r[2]);
  const d = Number(r[3]);
  return m >= 1 && m <= 12 && d >= 1 && d <= 31 ? { y, m, d } : null;
}

const pad = (n: number, width: number) => String(n).padStart(width, "0");

/** The words of a field that name it: its names, placeholder, label. Never its value. */
function hintText(el: Element): string {
  const parts = ["name", "id", "placeholder", "aria-label", "title"].map((a) => el.getAttribute(a) ?? "");
  const labels = (el as HTMLInputElement).labels;
  if (labels) for (const l of Array.from(labels)) parts.push(l.textContent ?? "");
  // "birthDay", "birthday": the whole date, never its day.
  return normalizeText(parts.join(" ")).replace(/\bbirth ?day\b/g, " ");
}

const PART_WORDS: readonly [DatePart, RegExp][] = [
  ["year", /\b(year|yyyy|yy|annee|aaaa|jahr|jjjj|ano|anno)\b/],
  ["month", /\b(month|mm|mois|monat|mes|mese)\b/],
  ["day", /\b(day|dd|jour|jj|tag|tt|dia|giorno)\b/],
];

/** The list's options read as one part of a date, or null. */
function partFromOptions(sel: HTMLSelectElement): DatePart | null {
  const opts = Array.from(sel.options).map((o) => ({ v: o.value, t: (o.textContent ?? "").trim() }));
  const nums = opts.map((o) => leadingInt(o.v !== "" ? o.v : o.t)).filter((n) => Number.isFinite(n));
  const years = nums.filter((n) => n >= 1900 && n <= 2100).length;
  if (years >= 10) return "year";
  const named = opts.filter((o) => Number.isNaN(leadingInt(o.t)) && Number.isFinite(monthOf(o.t))).length;
  if (named >= 12) return "month";
  const small = nums.filter((n) => n >= 1 && n <= 31);
  if (small.length >= 28 && Math.max(...small) >= 28) return "day";
  if (small.length === 12 && Math.max(...small) === 12) return "month";
  return null;
}

/** Which part of a date `el` takes, or null for the whole date. */
export function birthdayPart(el: Element): DatePart | null {
  const ac = (el.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/);
  if (ac.includes("bday-day")) return "day";
  if (ac.includes("bday-month")) return "month";
  if (ac.includes("bday-year")) return "year";
  if (ac.includes("bday")) return null;
  const words = hintText(el);
  // A written format ("JJ/MM/AAAA") names every part: the whole date.
  if (formatOf(el.getAttribute("placeholder") ?? "") === null) {
    const hits = PART_WORDS.filter(([, re]) => re.test(words)).map(([p]) => p);
    if (hits.length === 1) return hits[0] ?? null;
  }
  return el instanceof HTMLSelectElement ? partFromOptions(el) : null;
}

/** A written date format ("JJ/MM/AAAA", "MM/DD/YYYY", "TT.MM.JJJJ"), as its three tokens and separator. */
function formatOf(s: string): { tokens: string[]; sep: string } | null {
  const r = /([DJTMYA]{1,4})([/.\- ])([DJTMYA]{1,4})\2([DJTMYA]{1,4})/i.exec(s.trim());
  if (!r) return null;
  const tokens = [r[1], r[3], r[4]].map((x) => (x ?? "").toUpperCase());
  const kinds = tokens.map(tokenPart);
  if (new Set(kinds).size !== 3) return null;
  return { tokens, sep: r[2] ?? "/" };
}

/** A token of a written format: 3 or more letters, or Y and A, is the year; M the month; else the day. */
function tokenPart(t: string): DatePart {
  if (t.length >= 3 || t.startsWith("Y") || t.startsWith("A")) return "year";
  if (t.startsWith("M")) return "month";
  return "day";
}

function partText(date: Ymd, part: DatePart, width: number): string {
  if (part === "year") return width === 2 ? pad(date.y % 100, 2) : pad(date.y, 4);
  return pad(part === "month" ? date.m : date.d, width);
}

/**
 * What a text or date input takes for the birth date `iso` (`YYYY-MM-DD`),
 * or null when `iso` is not one. `lang`: the page's language (`en-US` and
 * `en` write the month first; any other, the day first).
 */
export function birthdayText(el: Element, iso: string, lang: string | null): string | null {
  const date = parseIso(iso);
  if (!date) return null;
  if (el instanceof HTMLInputElement && el.type === "date") return `${pad(date.y, 4)}-${pad(date.m, 2)}-${pad(date.d, 2)}`;
  const part = birthdayPart(el);
  if (part) return partText(date, part, part === "year" ? 4 : 2);
  const f = formatOf(el.getAttribute("placeholder") ?? "") ?? formatOf(el.getAttribute("aria-label") ?? "");
  if (f) return f.tokens.map((t) => partText(date, tokenPart(t), tokenPart(t) === "year" ? (t.length === 2 ? 2 : 4) : t.length)).join(f.sep);
  const l = (lang ?? "").toLowerCase();
  const monthFirst = l === "en" || l === "en-us";
  return monthFirst ? `${pad(date.m, 2)}/${pad(date.d, 2)}/${date.y}` : `${pad(date.d, 2)}/${pad(date.m, 2)}/${date.y}`;
}

/** Index of the option of `sel` for its part of the birth date `iso`, or -1. */
export function birthdayOption(sel: HTMLSelectElement, iso: string): number {
  const date = parseIso(iso);
  const part = birthdayPart(sel);
  if (!date || !part) return -1;
  const opts = Array.from(sel.options);
  const want = part === "year" ? date.y : part === "month" ? date.m : date.d;
  const read = part === "month" ? monthOf : leadingInt;
  const i = opts.findIndex((o) => o.value !== "" && read(o.value) === want);
  return i >= 0 ? i : opts.findIndex((o) => read(o.textContent ?? "") === want);
}
