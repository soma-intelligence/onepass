// Civility and sex choices (forms coverage, spec section 7). A list or a radio
// group asking a civility or a sex is read through tables per role: an "M" is a
// sex in a sex list and "Monsieur" in a civility list. Canonical values stay
// inside the extension (sex `f`, `m`, `x`; civility `mr`, `mrs`, `ms`, `miss`,
// `mx`, `dr`); the page gets the option it shows. Best options of different
// values are a tie: nothing is picked.
import type { FieldRole } from "../shared/messages";
import { fold } from "./geo/fold";
import type { OptionLike } from "./geo/options";

export type Sex = "f" | "m" | "x";
export type Civility = "mr" | "mrs" | "ms" | "miss" | "mx" | "dr";

const SEX: Readonly<Record<Sex, readonly string[]>> = {
  m: ["m", "h", "homme", "masculin", "male", "man", "mannlich", "hombre", "masculino", "maschio", "uomo", "maschile", "mannelijk"],
  f: ["f", "femme", "feminin", "female", "woman", "weiblich", "mujer", "femenino", "femmina", "donna", "femminile", "feminino", "mulher", "vrouw", "vrouwelijk"],
  x: ["x", "autre", "other", "divers", "diverse", "otro", "altro", "outro", "anders", "non binaire", "non binary", "nonbinaire", "nonbinary"],
};

const CIVILITY: Readonly<Record<Civility, readonly string[]>> = {
  mr: ["m", "monsieur", "mr", "mister", "herr", "sr", "senor", "sig", "signor", "signore", "senhor", "dhr", "de heer", "heer"],
  ms: ["ms"],
  mrs: ["mrs", "madame", "mme", "frau", "sra", "senora", "sig ra", "sigra", "signora", "senhora", "mevr", "mevrouw"],
  miss: ["miss", "mlle", "mademoiselle", "srta", "senorita", "signorina", "sig na", "signa", "menina", "mej", "mejuffrouw"],
  mx: ["mx"],
  dr: ["dr", "docteur", "doctor", "doktor", "dott", "dottore", "dra", "dottssa"],
};

function index<K extends string>(t: Readonly<Record<K, readonly string[]>>): Map<string, K> {
  const m = new Map<string, K>();
  for (const k of Object.keys(t) as K[]) for (const w of t[k]) m.set(w, k);
  return m;
}
const SEX_OF = index(SEX);
const CIVILITY_OF = index(CIVILITY);

/** Folded words of an option or a vault value ("Sig.ra" -> "sig ra"; a final dot is punctuation). */
const key = (s: string) => fold(s);

/** Canonical sex of a text (vault value, option label or value), or null. */
export function canonicalSex(s: string): Sex | null {
  return SEX_OF.get(key(s)) ?? null;
}

/** Canonical civility of a text, or null. */
export function canonicalCivility(s: string): Civility | null {
  return CIVILITY_OF.get(key(s)) ?? null;
}

export interface ChoiceWant {
  /** The vault's own text (civility as written, or a sex such as "Féminin" or "f"). */
  value?: string | undefined;
  /** The identity's canonical sex, for a civility the vault does not hold. */
  sex?: string | undefined;
}

const canonOf = (role: FieldRole, s: string): string | null => (role === "sex" ? canonicalSex(s) : canonicalCivility(s));

/** The option's canonical value for `role`: its label first, then its value. */
function optionCanon(role: FieldRole, o: OptionLike): string | null {
  return canonOf(role, o.text) ?? (o.value.trim() === "" ? null : canonOf(role, o.value));
}

/** Index of the single best of `scores` (> 0), -1 on none or a tie of different values. */
function best(opts: readonly OptionLike[], scores: readonly number[]): number {
  let top = 0;
  let at = -1;
  let tie = false;
  scores.forEach((s, i) => {
    if (s <= 0) return;
    if (s > top) {
      top = s;
      at = i;
      tie = false;
    } else if (s === top && fold(opts[i]!.value) !== fold(opts[at]!.value)) {
      tie = true;
    }
  });
  return tie ? -1 : at;
}

/**
 * Index of the option of a civility (`honorific_prefix`) or sex list meaning `want`, or -1.
 * Civility: the vault's own (exact text first, then its canonical value; "Dr" never another);
 * without one, from the sex: `m` Mr, `f` Ms then madame (never Miss nor Mlle), `x` Mx.
 */
export function pickChoice(opts: readonly OptionLike[], role: FieldRole, want: ChoiceWant): number {
  const canon = opts.map((o) => optionCanon(role, o));
  const value = (want.value ?? "").trim();
  const exact = (o: OptionLike) => value !== "" && (fold(o.text) === fold(value) || fold(o.value) === fold(value));
  if (role === "sex") {
    const s = (value !== "" ? canonicalSex(value) : null) ?? (want.sex ? canonicalSex(want.sex) : null);
    if (s === null) return -1;
    return best(opts, opts.map((o, i) => (canon[i] === s ? (exact(o) ? 2 : 1) : 0)));
  }
  if (role !== "honorific_prefix") return -1;
  if (value !== "") {
    const c = canonicalCivility(value);
    if (c === null) return -1;
    return best(opts, opts.map((o, i) => (canon[i] === c ? (exact(o) ? 2 : 1) : 0)));
  }
  const sex = want.sex ? canonicalSex(want.sex) : null;
  const order: readonly Civility[] = sex === "m" ? ["mr"] : sex === "f" ? ["ms", "mrs"] : sex === "x" ? ["mx"] : [];
  for (const c of order) {
    const i = best(opts, canon.map((x) => (x === c ? 1 : 0)));
    if (i >= 0) return i;
    if (canon.includes(c)) return -1;
  }
  return -1;
}
