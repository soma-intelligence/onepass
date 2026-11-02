// Password policies of the lab's signup sites: the draw (seeded), the three
// ways a page states one (attributes, `passwordrules`, a hint sentence in the
// site language) and the check the relying party runs. Pure functions: no DOM,
// no clock, no randomness beyond the Rng handed in.
import type { Lang, PasswordPolicy, Site } from "./model.ts";
import type { Rng } from "./rng.ts";

type Via = PasswordPolicy["via"][number];
type Cls = NonNullable<PasswordPolicy["required"]>[number];

/** Share of signup sites that enforce a policy. */
export const POLICY_RATE = 0.6;
/** Languages a hint sentence is written in; the extension's hint reader understands the first two only. */
export const HINT_LANGS: readonly Lang[] = ["fr", "en", "de", "es"];
export const READABLE_HINT_LANGS: readonly Lang[] = ["fr", "en"];

const VIA_SETS: [Via[], number][] = [
  [["attributes"], 25], [["passwordrules"], 15], [["hints"], 25],
  [["attributes", "hints"], 15], [["passwordrules", "hints"], 10], [["attributes", "passwordrules"], 10],
];
const MINS = [8, 10, 12, 14, 16];
const MAXS = [10, 12, 16, 20, 24, 32, 64];
/** Simple safe patterns: one class or a character class, a single quantifier, no group, no nested quantifier. */
const PATTERN_ALNUM = "[A-Za-z0-9]+";
const PATTERN_NO_SPACE = "\\S+";

/** The policy of one signup site, drawn from `r` (a stream of its own). `lang`: sites outside HINT_LANGS never state it by hints. */
export function drawPolicy(r: Rng, lang: Lang): PasswordPolicy {
  const pool = HINT_LANGS.includes(lang) ? VIA_SETS : VIA_SETS.filter(([v]) => !v.includes("hints"));
  const via = r.weighted(pool);
  // Attributes alone carry lengths and a pattern: nothing else can be required of the password.
  const attributesOnly = via.length === 1 && via[0] === "attributes";
  const required: Cls[] = [];
  if (!attributesOnly) {
    if (r.chance(0.45)) required.push("upper");
    if (r.chance(0.5)) required.push("digit");
    if (r.chance(0.3)) required.push("special");
  }
  let noSpecial = !attributesOnly && !required.includes("special") && r.chance(0.2);
  let min = r.chance(0.7) ? r.pick(MINS) : undefined;
  const floor = Math.max(min ?? 0, 4 + required.length);
  let max = r.chance(0.6) ? r.pick(MAXS.filter((m) => m >= floor)) : undefined;
  let pattern: string | undefined;
  if (via.includes("attributes") && r.chance(0.3)) {
    const alnum = (attributesOnly || noSpecial) && !required.includes("special");
    pattern = alnum ? PATTERN_ALNUM : PATTERN_NO_SPACE;
    if (alnum) noSpecial = true;
  }
  if (min === undefined && max === undefined && required.length === 0 && !noSpecial && pattern === undefined) min = r.pick(MINS);
  const out: PasswordPolicy = { via };
  if (min !== undefined) out.min = min;
  if (max !== undefined) out.max = max;
  if (required.length > 0) out.required = required;
  if (noSpecial) out.noSpecial = true;
  if (pattern !== undefined) out.pattern = pattern;
  return out;
}

// ---- how a page states the policy ----

/** The Apple `passwordrules` string of `p`. */
export function passwordRules(p: PasswordPolicy): string {
  const parts: string[] = [];
  if (p.min !== undefined) parts.push(`minlength: ${p.min}`);
  if (p.max !== undefined) parts.push(`maxlength: ${p.max}`);
  for (const c of p.required ?? []) parts.push(`required: ${c}`);
  // `required` alone also limits the password to the named classes (Apple's reading, and the extension's): say what else is fine.
  if (p.noSpecial) parts.push("allowed: upper, lower, digit");
  else if ((p.required ?? []).length > 0) parts.push("allowed: upper, lower, digit, special");
  return parts.join("; ");
}

/** Attributes of a new-password input (leading space, escaped by `esc`), per the sources of `p.via`. */
export function policyAttrs(p: PasswordPolicy, esc: (s: string) => string): string {
  let out = "";
  if (p.via.includes("attributes")) {
    if (p.min !== undefined) out += ` minlength="${p.min}"`;
    if (p.max !== undefined) out += ` maxlength="${p.max}"`;
    if (p.pattern !== undefined) out += ` pattern="${esc(p.pattern)}"`;
  }
  if (p.via.includes("passwordrules")) {
    const rules = passwordRules(p);
    if (rules !== "") out += ` passwordrules="${esc(rules)}"`;
  }
  return out;
}

interface Words {
  between: (a: number, b: number) => string; atLeast: (n: number) => string; atMost: (n: number) => string;
  contain: string; and: string; noSpecial: string; cls: Record<Cls, string>;
}
const WORDS: Record<string, Words> = {
  en: {
    between: (a, b) => `Between ${a} and ${b} characters`, atLeast: (n) => `At least ${n} characters`, atMost: (n) => `Up to ${n} characters`,
    contain: "Must contain at least", and: "and", noSpecial: "No special characters",
    cls: { upper: "one uppercase letter", digit: "one digit", special: "one special character" },
  },
  fr: {
    between: (a, b) => `Entre ${a} et ${b} caractères`, atLeast: (n) => `Au moins ${n} caractères`, atMost: (n) => `${n} caractères maximum`,
    contain: "Doit contenir au moins", and: "et", noSpecial: "Sans caractère spécial",
    cls: { upper: "une majuscule", digit: "un chiffre", special: "un caractère spécial" },
  },
  de: {
    between: (a, b) => `${a} bis ${b} Zeichen`, atLeast: (n) => `Mindestens ${n} Zeichen`, atMost: (n) => `Höchstens ${n} Zeichen`,
    contain: "Muss mindestens enthalten:", and: "und", noSpecial: "Keine Sonderzeichen",
    cls: { upper: "einen Großbuchstaben", digit: "eine Ziffer", special: "ein Sonderzeichen" },
  },
  es: {
    between: (a, b) => `Entre ${a} y ${b} caracteres`, atLeast: (n) => `Al menos ${n} caracteres`, atMost: (n) => `Máximo ${n} caracteres`,
    contain: "Debe contener al menos", and: "y", noSpecial: "Sin caracteres especiales",
    cls: { upper: "una mayúscula", digit: "un número", special: "un carácter especial" },
  },
};

/** The sentence a page writes for `p` in `lang` (fr, en, de, es); undefined when `p` has no hint source or no part to state. */
export function policyHint(p: PasswordPolicy, lang: Lang): string | undefined {
  if (!p.via.includes("hints")) return undefined;
  const w = WORDS[lang];
  if (!w) return undefined;
  const sentences: string[] = [];
  if (p.min !== undefined && p.max !== undefined) sentences.push(w.between(p.min, p.max));
  else if (p.min !== undefined) sentences.push(w.atLeast(p.min));
  else if (p.max !== undefined) sentences.push(w.atMost(p.max));
  const req = (p.required ?? []).map((c) => w.cls[c]);
  if (req.length > 0) {
    const list = req.length === 1 ? req[0]! : `${req.slice(0, -1).join(", ")} ${w.and} ${req.at(-1)!}`;
    sentences.push(`${w.contain} ${list}`);
  }
  if (p.noSpecial) sentences.push(w.noSpecial);
  return sentences.length > 0 ? `${sentences.join(". ")}.` : undefined;
}

// ---- what the relying party enforces ----

/** First rule of `p` that `pw` breaks (a short name), undefined when it satisfies the policy. */
export function policyViolation(pw: string, p: PasswordPolicy): string | undefined {
  const n = [...pw].length;
  if (p.min !== undefined && n < p.min) return "min";
  if (p.max !== undefined && n > p.max) return "max";
  const has: Record<Cls, boolean> = { upper: /[A-Z]/.test(pw), digit: /\d/.test(pw), special: /[^A-Za-z\d]/.test(pw) };
  for (const c of p.required ?? []) if (!has[c]) return `required_${c}`;
  if (p.noSpecial && has.special) return "no_special";
  if (p.pattern !== undefined && !new RegExp(`^(?:${p.pattern})$`, "v").test(pw)) return "pattern";
  return undefined;
}

/** A policy can be met: lengths in order, room for the required classes (and for the lowercase letter), a pattern compatible with them. */
export function satisfiable(p: PasswordPolicy): boolean {
  const need = 4 + (p.required ?? []).length;
  if (p.min !== undefined && p.max !== undefined && p.min > p.max) return false;
  if (p.max !== undefined && p.max < need) return false;
  if (p.noSpecial && (p.required ?? []).includes("special")) return false;
  return true;
}

/**
 * Policy categories of the report. A part of the policy that only a hint
 * states, in a language the hint reader does not know (not fr, en), is
 * "hint_only_unsupported": the extension cannot know it, and fails there by design.
 * "hints_readable": the same in fr or en. Otherwise the policy is known from `passwordrules` or attributes.
 */
export type PolicyCategory = "none" | "attributes" | "passwordrules" | "hints_readable" | "hint_only_unsupported";

export function policyCategory(site: Pick<Site, "lang" | "passwordPolicy">): PolicyCategory {
  const p = site.passwordPolicy;
  if (!p) return "none";
  const lengthByHint = (p.min !== undefined || p.max !== undefined) && !p.via.includes("attributes") && !p.via.includes("passwordrules");
  const alnumPattern = p.via.includes("attributes") && p.pattern === PATTERN_ALNUM && p.noSpecial === true;
  const classesByHint = ((p.required ?? []).length > 0 || p.noSpecial === true) && !p.via.includes("passwordrules") && !alnumPattern;
  const hintCarries = p.via.includes("hints") && (lengthByHint || classesByHint || p.via.length === 1);
  if (hintCarries) return READABLE_HINT_LANGS.includes(site.lang) ? "hints_readable" : "hint_only_unsupported";
  if (p.via.includes("passwordrules")) return "passwordrules";
  if (p.via.includes("attributes")) return "attributes";
  return "hints_readable";
}
