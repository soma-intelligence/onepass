// Synthetic data of the forms flows of the autofill lab (spec 11.2 of
// docs/superpowers/specs/2026-11-06-forms-coverage-design.md): passports and
// driver licenses in the number format of their country, company ids with
// valid check digits (VAT, SIREN, SIRET, CIF, NIF, KvK, HRB), loyalty numbers,
// and the identity fields a full person carries (civility, birth name, sex,
// birth place, nationality, work fields). Every value comes from the seeded
// Rng; nothing here is real. Dates are clock-free: documents are issued up to
// REFERENCE_YEAR and expire after it.
import { FAMILY, GIVEN, cityOf, phoneOf, type Person } from "./data.ts";
import type { Lang } from "./model.ts";
import type { Rng } from "./rng.ts";

/** The lab's clock-free "now": documents are issued in or before it and expire after it. */
export const REFERENCE_YEAR = 2026;

/** Country of the people (and companies) of a site language. */
export const COUNTRY_OF_LANG: Readonly<Record<string, string>> = {
  fr: "FR", en: "US", de: "DE", es: "ES", it: "IT", pt: "PT", nl: "NL",
};
export const countryOfLang = (lang: Lang): string => COUNTRY_OF_LANG[lang] ?? "US";

const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT = "0123456789";
const draw = (r: Rng, alphabet: string, n: number) => Array.from({ length: n }, () => r.pick([...alphabet])).join("");
const num = (r: Rng, n: number) => String(r.int(1, 9)) + draw(r, DIGIT, n - 1);
const pad2 = (n: number) => String(n).padStart(2, "0");

function luhnOk(s: string): boolean {
  let sum = 0;
  [...s].reverse().forEach((c, i) => {
    const x = i % 2 === 1 ? Number(c) * 2 : Number(c);
    sum += x > 9 ? x - 9 : x;
  });
  return sum % 10 === 0;
}
/** The digit that makes `body` + digit pass Luhn. */
const luhnDigit = (body: string): string => DIGIT.split("").find((d) => luhnOk(body + d))!;

// ---- company ids ----

/** A SIREN: eight digits and a Luhn check digit. */
export function siren(r: Rng): string {
  const body = num(r, 8);
  return body + luhnDigit(body);
}

/** A SIRET of `sirenValue`: the SIREN, a four-digit establishment number and a Luhn check digit over the fourteen. */
export function siret(r: Rng, sirenValue: string): string {
  const body = sirenValue + draw(r, DIGIT, 4);
  return body + luhnDigit(body);
}

/** ISO 7064 MOD 11,10 check digit (German USt-IdNr.). */
function mod1110(body: string): string {
  let product = 10;
  for (const c of body) {
    let sum = (Number(c) + product) % 10;
    if (sum === 0) sum = 10;
    product = (2 * sum) % 11;
  }
  return String((11 - product) % 10);
}

/** A Spanish CIF with a digit control: organisation letter, seven digits, control. */
function cif(r: Rng): string {
  const letter = r.pick(["A", "B", "E", "H"]);
  const body = draw(r, DIGIT, 7);
  let total = 0;
  [...body].forEach((c, i) => {
    const d = Number(c);
    if (i % 2 === 0) total += Math.floor((d * 2) / 10) + ((d * 2) % 10);
    else total += d;
  });
  return `${letter}${body}${(10 - (total % 10)) % 10}`;
}

/** A Portuguese NIPC (company tax number): 5, seven digits, mod 11 check. */
function nipc(r: Rng): string {
  const body = `5${draw(r, DIGIT, 7)}`;
  const sum = [...body].reduce((s, c, i) => s + Number(c) * (9 - i), 0);
  const c = 11 - (sum % 11);
  return body + String(c >= 10 ? 0 : c);
}

/** A Dutch btw base: eight digits whose weighted sum mod 11 (not 10) is the ninth. */
function nlBase(r: Rng): string {
  for (;;) {
    const body = num(r, 8);
    const sum = [...body].reduce((s, c, i) => s + Number(c) * (9 - i), 0) % 11;
    if (sum !== 10) return body + String(sum);
  }
}

/** A UK VAT number body: seven digits and two check digits (weights 8..2, total divisible by 97). */
function gbBody(r: Rng): string {
  const body = num(r, 7);
  const sum = [...body].reduce((s, c, i) => s + Number(c) * (8 - i), 0);
  return body + pad2((97 - (sum % 97)) % 97);
}

/** A VAT number of `country` with a valid key (FR, DE, IT, ES, PT, NL; any other country gets a UK one). */
export function vatNumber(r: Rng, country: string): string {
  switch (country) {
    case "FR": {
      const s = siren(r);
      return `FR${pad2((12 + 3 * (Number(s) % 97)) % 97)}${s}`;
    }
    case "DE": {
      const body = num(r, 8);
      return `DE${body}${mod1110(body)}`;
    }
    case "IT": {
      const body = draw(r, DIGIT, 10);
      return `IT${body}${luhnDigit(body)}`;
    }
    case "ES": return `ES${cif(r)}`;
    case "PT": return `PT${nipc(r)}`;
    case "NL": return `NL${nlBase(r)}B01`;
    default: return `GB${gbBody(r)}`;
  }
}

/**
 * The company registration id of `country` for a company whose VAT number is `vat`: SIRET (FR, from the VAT's
 * SIREN), "HRB <5 digits>" (DE), KvK (NL, eight digits), NIPC (PT), CIF (ES) and codice fiscale (IT), the last
 * three being the VAT number's body; eight digits (company number) elsewhere.
 */
export function companyId(r: Rng, country: string, vat: string): string {
  switch (country) {
    case "FR": return siret(r, vat.slice(4));
    case "DE": return `HRB ${num(r, 5)}`;
    case "NL": return num(r, 8);
    case "PT": case "ES": case "IT": return vat.slice(2);
    default: return num(r, 8);
  }
}

// ---- documents ----

/** A passport number in the format of `country`. */
export function passportNumber(r: Rng, country: string): string {
  const noO = "ABCDEFGHIJKLMNPQRSTUVWXYZ";
  switch (country) {
    case "FR": return `${draw(r, DIGIT, 2)}${draw(r, UPPER, 2)}${draw(r, DIGIT, 5)}`;
    case "DE": return `C${draw(r, "0123456789CFGHJKLMNPRTVWXYZ", 8)}`;
    case "ES": return `${draw(r, UPPER, 3)}${draw(r, DIGIT, 6)}`;
    case "IT": return `${draw(r, UPPER, 2)}${draw(r, DIGIT, 7)}`;
    case "PT": return `${draw(r, UPPER, 1)}${draw(r, DIGIT, 6)}`;
    case "NL": return `${draw(r, noO, 2)}${draw(r, noO + DIGIT, 6)}${draw(r, DIGIT, 1)}`;
    default: return draw(r, DIGIT, 9);
  }
}

/** A driver license number in the format of `country` (FR 12 characters, DE 11, else 8 to 12). */
export function licenseNumber(r: Rng, country: string): string {
  const alnum = UPPER + DIGIT;
  switch (country) {
    case "FR": return `${draw(r, DIGIT, 2)}${draw(r, UPPER, 2)}${draw(r, DIGIT, 8)}`;
    case "DE": return `${draw(r, UPPER, 1)}${draw(r, alnum, 9)}${draw(r, DIGIT, 1)}`;
    default: return `${draw(r, UPPER, 1)}${draw(r, alnum, r.int(6, 10))}${draw(r, DIGIT, 1)}`;
  }
}

/** A loyalty (frequent flyer, rewards) number: 9 to 12 digits. */
export function loyaltyNumber(r: Rng): string {
  return num(r, r.int(9, 12));
}

/** The person a document belongs to. */
export interface Holder { given: string; family: string; birthDate: string; sex: Sex; birthPlace: string; nationality: string }
export type Sex = "Féminin" | "Masculin";

export interface PassportData {
  number: string; issuingCountry: string; issuedOn: string; expiry: string;
  firstNames: string; lastName: string; nationality: string; sex: Sex; birthDate: string; birthPlace: string;
}
export interface LicenseData { number: string; country: string; fullName: string; issuedOn: string; expiry: string; birthDate: string }

/** An issue date (YYYY-MM-DD) in [from, REFERENCE_YEAR] and the expiry `years` later, the day before. */
function validity(r: Rng, from: number, years: number): { issuedOn: string; expiry: string } {
  const y = r.int(from, REFERENCE_YEAR - 1);
  const m = r.int(1, 12);
  const d = r.int(2, 28);
  return { issuedOn: `${y}-${pad2(m)}-${pad2(d)}`, expiry: `${y + years}-${pad2(m)}-${pad2(d - 1)}` };
}

/** The passport of `holder` issued by `country` (valid ten years; about one in five lists a second first name). */
export function passportOf(r: Rng, holder: Holder, country: string): PassportData {
  const number = passportNumber(r, country);
  const { issuedOn, expiry } = validity(r, REFERENCE_YEAR - 9, 10);
  const second = r.chance(0.2) ? ` ${r.pick(GIVEN.filter((g) => g !== holder.given))}` : "";
  return {
    number, issuingCountry: country, issuedOn, expiry, firstNames: `${holder.given}${second}`, lastName: holder.family,
    nationality: holder.nationality, sex: holder.sex, birthDate: holder.birthDate, birthPlace: holder.birthPlace,
  };
}

/** The driver license of `holder` issued by `country` (valid fifteen years). */
export function licenseOf(r: Rng, holder: Holder, country: string): LicenseData {
  const number = licenseNumber(r, country);
  const { issuedOn, expiry } = validity(r, REFERENCE_YEAR - 14, 15);
  return { number, country, fullName: `${holder.given} ${holder.family}`, issuedOn, expiry, birthDate: holder.birthDate };
}

// ---- identity completion ----

/** Civility of each sex as a person of each language writes it in the vault (free text). */
const HONORIFIC: Record<string, Record<Sex, string>> = {
  fr: { Masculin: "M.", Féminin: "Mme" }, en: { Masculin: "Mr", Féminin: "Ms" }, de: { Masculin: "Herr", Féminin: "Frau" },
  es: { Masculin: "Sr.", Féminin: "Sra." }, it: { Masculin: "Sig.", Féminin: "Sig.ra" }, pt: { Masculin: "Sr.", Féminin: "Sra." },
  nl: { Masculin: "Dhr.", Féminin: "Mevr." },
};
const JOB_TITLES = ["Office Manager", "Responsable achats", "Einkaufsleiterin", "Jefe de compras", "Responsabile acquisti",
  "Gestor de compras", "Inkoopmanager", "Travel Coordinator", "Head of Operations"];
const DEPARTMENTS = ["Achats", "Finance", "Einkauf", "Compras", "Acquisti", "Inkoop", "Operations", "Procurement"];

/** What a full person adds to the identity of `person()`: civility, birth, work fields and company ids. */
export interface FormsIdentity {
  honorific: string; sex: Sex; middleName: string; birthName: string; birthPlace: string; nationality: string;
  jobTitle: string; department: string; website: string; workPhone: string; vatNumber: string; companyRegistration: string;
}

/** The identity fields of `who` (a person of `lang`'s country) a forms site's vault holds; `brand` names the website. */
export function formsIdentity(r: Rng, who: Person, lang: Lang, brand: string): FormsIdentity {
  const country = countryOfLang(lang);
  const sex: Sex = r.chance(0.5) ? "Féminin" : "Masculin";
  let workPhone = phoneOf(r, lang);
  while (workPhone === who.phone) workPhone = phoneOf(r, lang);
  const vat = vatNumber(r, country);
  const slug = brand.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "company";
  return {
    honorific: (HONORIFIC[lang] ?? HONORIFIC.en!)[sex],
    sex,
    middleName: r.pick(GIVEN.filter((g) => g !== who.given)),
    birthName: r.pick(FAMILY),
    birthPlace: cityOf(r, lang),
    nationality: country,
    jobTitle: r.pick(JOB_TITLES),
    department: r.pick(DEPARTMENTS),
    website: `https://www.${slug}.example`,
    workPhone,
    vatNumber: vat,
    companyRegistration: companyId(r, country, vat),
  };
}
