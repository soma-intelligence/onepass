// Dates as the page wants them: birth dates (one-click signup, spec 5) and,
// since the forms coverage (spec section 6), the issue and expiry dates of a
// passport or a driver license. The vault gives `YYYY-MM-DD` (onepass-bridge);
// the classifier gives one role to the whole date and to each part of a
// split one. Here, the field itself says which: a date input, one part (by
// `autocomplete`, its names and label, or a list's options), or a written
// format (placeholder, label, else the page's language). A part nothing
// designates is not written: nothing invented goes into the page.
import { normalizeText } from "./detect/lexicon";

/**
 * Month names and their abbreviations in French, English, German, Spanish, Italian, Portuguese
 * and Dutch, accent-free as `normalizeText` writes them ("März" is "marz", "Jän" is "jan"); index 0
 * is January.
 */
const MONTHS: readonly (readonly string[])[] = [
  ["january", "janvier", "jan", "janv", "januar", "janner", "enero", "ene", "gennaio", "gen", "janeiro", "januari"],
  ["february", "fevrier", "feb", "fev", "fevr", "februar", "febrero", "febbraio", "fevereiro", "februari"],
  ["march", "mars", "mar", "marz", "marzo", "marco", "maart", "mrt"],
  ["april", "avril", "apr", "avr", "abril", "abr", "aprile"],
  ["may", "mai", "mayo", "maggio", "mag", "maio", "mei"],
  ["june", "juin", "jun", "juni", "junio", "giugno", "giu", "junho"],
  ["july", "juillet", "jul", "juil", "juli", "julio", "luglio", "lug", "julho"],
  ["august", "aout", "aug", "agosto", "ago", "augustus"],
  ["september", "septembre", "sep", "sept", "septiembre", "settembre", "set", "setembro"],
  ["october", "octobre", "oct", "oktober", "octubre", "ottobre", "ott", "outubro", "out", "okt"],
  ["november", "novembre", "nov", "noviembre", "novembro"],
  ["december", "decembre", "dec", "dezember", "diciembre", "dic", "dicembre", "dezembro", "dez"],
];

export const leadingInt = (s: string): number => {
  const m = /^\s*(\d{1,4})\b/.exec(s);
  return m ? Number(m[1]) : Number.NaN;
};

/** 1..12 from a number or a month name (seven languages, abbreviations too), else NaN. */
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

function labelTexts(el: Element): string[] {
  const labels = (el as HTMLInputElement).labels;
  return labels ? Array.from(labels, (l) => l.textContent ?? "") : [];
}

/** The words of a field that name it: its names, placeholder, label. Never its value. */
function hintText(el: Element): string {
  const parts = ["name", "id", "placeholder", "aria-label", "title"].map((a) => el.getAttribute(a) ?? "");
  parts.push(...labelTexts(el));
  // "birthDay", "birthday": the whole date, never its day.
  return normalizeText(parts.join(" ")).replace(/\bbirth ?day\b/g, " ");
}

const PART_WORDS: readonly [DatePart, RegExp][] = [
  ["year", /\b(year|yyyy|yy|annee|aaaa|jahr|jjjj|ano|anno|jaar)\b/],
  ["month", /\b(month|mm|mois|monat|mes|mese|maand)\b/],
  ["day", /\b(day|dd|jour|jj|tag|tt|dia|giorno|gg|dag)\b/],
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
export function datePart(el: Element): DatePart | null {
  const ac = (el.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/);
  if (ac.includes("bday-day")) return "day";
  if (ac.includes("bday-month")) return "month";
  if (ac.includes("bday-year")) return "year";
  if (ac.includes("bday")) return null;
  const words = hintText(el);
  // A written format ("JJ/MM/AAAA") names every part: the whole date.
  if (writtenFormat(el) === null) {
    const hits = PART_WORDS.filter(([, re]) => re.test(words)).map(([p]) => p);
    if (hits.length === 1) return hits[0] ?? null;
  }
  return el instanceof HTMLSelectElement ? partFromOptions(el) : null;
}

/**
 * A written date format ("JJ/MM/AAAA", "MM/DD/YYYY", "TT.MM.JJJJ", "gg/mm/aaaa", "dd-mm-jjjj"), as
 * its three tokens and separator. Each token repeats one letter, and the three are a day, a month
 * and a year.
 */
function formatOf(s: string): { tokens: string[]; sep: string } | null {
  const r = /(?:^|[^a-z])([DJTMYAG]{1,4})([/.\- ])([DJTMYAG]{1,4})\2([DJTMYAG]{1,4})(?![a-z])/i.exec(s.trim());
  if (!r) return null;
  const tokens = [r[1], r[3], r[4]].map((x) => (x ?? "").toUpperCase());
  if (!tokens.every((t) => /^(.)\1*$/.test(t))) return null;
  const kinds = tokens.map(tokenPart);
  if (new Set(kinds).size !== 3) return null;
  return { tokens, sep: r[2] ?? "/" };
}

/** The format the field writes: its placeholder, ARIA label or label. */
function writtenFormat(el: Element): { tokens: string[]; sep: string } | null {
  for (const s of [el.getAttribute("placeholder") ?? "", el.getAttribute("aria-label") ?? "", ...labelTexts(el)]) {
    const f = formatOf(s);
    if (f) return f;
  }
  return null;
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

/** Day, month and year order and separator of a page language without a written format. */
function languageOrder(lang: string | null): { order: DatePart[]; sep: string } {
  const l = (lang ?? "").toLowerCase();
  if (l === "en" || l === "en-us") return { order: ["month", "day", "year"], sep: "/" };
  const base = l.split("-")[0];
  if (base === "de") return { order: ["day", "month", "year"], sep: "." };
  if (base === "nl") return { order: ["day", "month", "year"], sep: "-" };
  return { order: ["day", "month", "year"], sep: "/" };
}

/**
 * What a text or date input takes for the date `iso` (`YYYY-MM-DD`), or null when `iso` is not
 * one or the input is a month picker. `lang`: the page's language (`en` and `en-US` write the
 * month first, German with dots, Dutch with dashes, the others day first with slashes).
 */
export function dateText(el: Element, iso: string, lang: string | null): string | null {
  const date = parseIso(iso);
  if (!date) return null;
  if (el instanceof HTMLInputElement && el.type === "month") return null;
  if (el instanceof HTMLInputElement && el.type === "date") return `${pad(date.y, 4)}-${pad(date.m, 2)}-${pad(date.d, 2)}`;
  const part = datePart(el);
  const two = el instanceof HTMLInputElement && el.maxLength === 2;
  if (part) return partText(date, part, part === "year" ? (two ? 2 : 4) : 2);
  const f = writtenFormat(el);
  if (f) return f.tokens.map((t) => partText(date, tokenPart(t), tokenPart(t) === "year" ? (t.length === 2 ? 2 : 4) : t.length)).join(f.sep);
  const { order, sep } = languageOrder(lang);
  return order.map((p) => partText(date, p, p === "year" ? 4 : 2)).join(sep);
}

/** Index of the option of `sel` for its part of the date `iso`, or -1. */
export function dateOption(sel: HTMLSelectElement, iso: string): number {
  const date = parseIso(iso);
  const part = datePart(sel);
  if (!date || !part) return -1;
  const opts = Array.from(sel.options);
  const want = part === "year" ? date.y : part === "month" ? date.m : date.d;
  const read = part === "month" ? monthOf : leadingInt;
  const i = opts.findIndex((o) => o.value !== "" && read(o.value) === want);
  return i >= 0 ? i : opts.findIndex((o) => read(o.textContent ?? "") === want);
}

/** Names of the birth date era (one-click signup), kept for their callers. */
export const birthdayPart = datePart;
export const birthdayText = dateText;
export const birthdayOption = dateOption;
