// Synthetic documents and company ids of the forms flows (lab/gen/forms-data.ts)
// and the forms lexicon (lab/gen/forms-lexicon.ts). Every check digit is
// verified by an independent checker written here, never by the module's own.
import { describe, expect, it } from "vitest";
import {
  COUNTRY_OF_LANG, REFERENCE_YEAR, companyId, formsIdentity, licenseNumber, licenseOf, loyaltyNumber, passportNumber,
  passportOf, siren, siret, vatNumber,
} from "../../lab/gen/forms-data.ts";
import { FORMS_LABELS, FORMS_LANGS, formsLabels } from "../../lab/gen/forms-lexicon.ts";
import { person } from "../../lab/gen/data.ts";
import type { FormsRole } from "../../lab/gen/model.ts";
import { Rng } from "../../lab/gen/rng.ts";

const digits = (s: string) => [...s].map(Number);

/** Luhn over every digit of `s` (the last one is the check digit). */
function luhn(s: string): boolean {
  if (!/^\d+$/.test(s)) return false;
  let sum = 0;
  digits(s).reverse().forEach((d, i) => {
    const x = i % 2 === 1 ? d * 2 : d;
    sum += x > 9 ? x - 9 : x;
  });
  return sum % 10 === 0;
}

function frVat(v: string): boolean {
  const m = /^FR(\d{2})(\d{9})$/.exec(v);
  if (!m || !luhn(m[2]!)) return false;
  return Number(m[1]) === (12 + 3 * (Number(m[2]) % 97)) % 97;
}

/** ISO 7064 MOD 11,10 (German USt-IdNr.). */
function deVat(v: string): boolean {
  const m = /^DE(\d{9})$/.exec(v);
  if (!m) return false;
  const d = digits(m[1]!);
  let product = 10;
  for (const x of d.slice(0, 8)) {
    let sum = (x + product) % 10;
    if (sum === 0) sum = 10;
    product = (2 * sum) % 11;
  }
  const check = (11 - product) % 10;
  return check === d[8];
}

const itVat = (v: string) => /^IT\d{11}$/.test(v) && luhn(v.slice(2));

/** Spanish CIF with a digit control (organisation letters A, B, E, H). */
function esCif(c: string): boolean {
  const m = /^([ABEH])(\d{7})(\d)$/.exec(c);
  if (!m) return false;
  let total = 0;
  digits(m[2]!).forEach((d, i) => {
    if (i % 2 === 0) {
      const x = d * 2;
      total += Math.floor(x / 10) + (x % 10);
    } else total += d;
  });
  return (10 - (total % 10)) % 10 === Number(m[3]);
}
const esVat = (v: string) => v.startsWith("ES") && esCif(v.slice(2));

/** Portuguese NIF / NIPC: weights 9..2, check = 11 - sum mod 11 (10 and 11 give 0). */
function ptNif(n: string): boolean {
  if (!/^\d{9}$/.test(n)) return false;
  const d = digits(n);
  const sum = d.slice(0, 8).reduce((s, x, i) => s + x * (9 - i), 0);
  const c = 11 - (sum % 11);
  return (c >= 10 ? 0 : c) === d[8];
}
const ptVat = (v: string) => v.startsWith("PT") && ptNif(v.slice(2));

/** Dutch btw number: 9 digits, weights 9..2 on the first eight, sum mod 11 is the ninth; then "B" and two digits. */
function nlVat(v: string): boolean {
  const m = /^NL(\d{9})B\d{2}$/.exec(v);
  if (!m) return false;
  const d = digits(m[1]!);
  const sum = d.slice(0, 8).reduce((s, x, i) => s + x * (9 - i), 0);
  return sum % 11 === d[8] && sum % 11 !== 10;
}

/** UK VAT: weights 8..2 on seven digits plus the last two as a number, total divisible by 97. */
function gbVat(v: string): boolean {
  const m = /^GB(\d{9})$/.exec(v);
  if (!m) return false;
  const d = digits(m[1]!);
  const sum = d.slice(0, 7).reduce((s, x, i) => s + x * (8 - i), 0) + Number(m[1]!.slice(7));
  return sum % 97 === 0;
}

const VAT_CHECK: Record<string, (v: string) => boolean> = {
  FR: frVat, DE: deVat, IT: itVat, ES: esVat, PT: ptVat, NL: nlVat, US: gbVat,
};

const PASSPORT: Record<string, RegExp> = {
  FR: /^\d{2}[A-Z]{2}\d{5}$/, DE: /^C[0-9CFGHJKLMNPRTVWXYZ]{8}$/, ES: /^[A-Z]{3}\d{6}$/, IT: /^[A-Z]{2}\d{7}$/,
  PT: /^[A-Z]\d{6}$/, NL: /^[A-NP-Z]{2}[A-NP-Z0-9]{6}\d$/, US: /^\d{9}$/,
};
const LICENSE: Record<string, RegExp> = {
  FR: /^[A-Z0-9]{12}$/, DE: /^[A-Z0-9]{11}$/, ES: /^[A-Z0-9]{8,12}$/, IT: /^[A-Z0-9]{8,12}$/, PT: /^[A-Z0-9]{8,12}$/,
  NL: /^[A-Z0-9]{8,12}$/, US: /^[A-Z0-9]{8,12}$/,
};
const COUNTRIES = Object.values(COUNTRY_OF_LANG);
const SEEDS = Array.from({ length: 200 }, (_, k) => `forms-${k}`);

describe("company ids", () => {
  it("SIREN and SIRET pass Luhn", () => {
    for (const s of SEEDS) {
      const r = new Rng(s);
      const n = siren(r);
      expect(n).toMatch(/^\d{9}$/);
      expect(luhn(n), n).toBe(true);
      const t = siret(r, n);
      expect(t).toMatch(/^\d{14}$/);
      expect(t.startsWith(n)).toBe(true);
      expect(luhn(t), t).toBe(true);
    }
  });

  it("VAT numbers carry a valid key in every country", () => {
    for (const c of COUNTRIES) {
      for (const s of SEEDS) {
        const v = vatNumber(new Rng(`${s}/${c}`), c);
        expect(VAT_CHECK[c]!(v), `${c} ${v}`).toBe(true);
      }
    }
  });

  it("company registration ids follow their country", () => {
    for (const s of SEEDS) {
      const r = new Rng(s);
      const fr = vatNumber(r, "FR");
      const id = companyId(r, "FR", fr);
      expect(id.slice(0, 9)).toBe(fr.slice(4));
      expect(luhn(id), id).toBe(true);
      expect(companyId(r, "DE", vatNumber(r, "DE"))).toMatch(/^HRB \d{5}$/);
      expect(companyId(r, "NL", vatNumber(r, "NL"))).toMatch(/^\d{8}$/);
      const pt = companyId(r, "PT", vatNumber(r, "PT"));
      expect(ptNif(pt), pt).toBe(true);
      expect(pt.startsWith("5")).toBe(true);
      expect(esCif(companyId(r, "ES", vatNumber(r, "ES")))).toBe(true);
      expect(luhn(companyId(r, "IT", vatNumber(r, "IT")))).toBe(true);
      expect(companyId(r, "US", vatNumber(r, "US"))).toMatch(/^\d{8}$/);
    }
  });
});

describe("documents", () => {
  it("passport and license numbers match their country patterns", () => {
    for (const c of COUNTRIES) {
      for (const s of SEEDS) {
        const r = new Rng(`${s}/${c}`);
        expect(passportNumber(r, c)).toMatch(PASSPORT[c]!);
        expect(licenseNumber(r, c)).toMatch(LICENSE[c]!);
      }
    }
  });

  it("passport dates are coherent and the expiry is after the reference year", () => {
    for (const s of SEEDS) {
      const r = new Rng(s);
      const who = person(r, "fr");
      const id = formsIdentity(r, who, "fr", "Amber Falcon");
      const p = passportOf(r, { ...who, ...id }, "FR");
      expect(p.issuedOn < p.expiry).toBe(true);
      expect(Number(p.issuedOn.slice(0, 4))).toBeLessThanOrEqual(REFERENCE_YEAR);
      expect(Number(p.expiry.slice(0, 4))).toBeGreaterThan(REFERENCE_YEAR);
      expect(p.lastName).toBe(who.family);
      expect(p.firstNames.split(" ")[0]).toBe(who.given);
      expect(p.issuingCountry).toBe("FR");
      expect(p.number).toMatch(PASSPORT.FR!);
      const l = licenseOf(r, { ...who, ...id }, "FR");
      expect(l.issuedOn < l.expiry).toBe(true);
      expect(Number(l.expiry.slice(0, 4))).toBeGreaterThan(REFERENCE_YEAR);
      expect(l.fullName).toBe(`${who.given} ${who.family}`);
    }
  });

  it("about one passport in five has two first names", () => {
    let two = 0;
    for (const s of SEEDS) {
      const r = new Rng(s);
      const who = person(r, "en");
      if (passportOf(r, { ...who, ...formsIdentity(r, who, "en", "B") }, "US").firstNames.includes(" ")) two++;
    }
    expect(two).toBeGreaterThan(20);
    expect(two).toBeLessThan(70);
  });

  it("loyalty numbers have 9 to 12 digits", () => {
    for (const s of SEEDS) expect(loyaltyNumber(new Rng(s))).toMatch(/^\d{9,12}$/);
  });

  it("the identity completion is canonical and complete", () => {
    for (const s of SEEDS.slice(0, 50)) {
      const r = new Rng(s);
      const who = person(r, "de");
      const id = formsIdentity(r, who, "de", "Cobalt Bay");
      expect(["Féminin", "Masculin"]).toContain(id.sex);
      expect(id.nationality).toBe("DE");
      expect(id.honorific).toBe(id.sex === "Féminin" ? "Frau" : "Herr");
      for (const v of [id.birthName, id.birthPlace, id.jobTitle, id.department, id.website, id.workPhone]) expect(v).not.toBe("");
      expect(id.workPhone).not.toBe(who.phone);
      expect(deVat(id.vatNumber)).toBe(true);
      expect(id.companyRegistration).toMatch(/^HRB \d{5}$/);
    }
  });

  it("same seed, same values", () => {
    const draw = (seed: string) => {
      const r = new Rng(seed);
      const who = person(r, "it");
      const id = formsIdentity(r, who, "it", "X");
      return JSON.stringify([id, passportOf(r, { ...who, ...id }, "IT"), licenseOf(r, { ...who, ...id }, "IT"), loyaltyNumber(r)]);
    };
    expect(draw("same")).toBe(draw("same"));
    expect(draw("same")).not.toBe(draw("other"));
  });
});

describe("forms lexicon", () => {
  it("has at least three labels per role and language, one abbreviated", () => {
    for (const [role, byLang] of Object.entries(FORMS_LABELS)) {
      for (const lang of FORMS_LANGS) {
        const l = byLang[lang];
        expect(l.full.length + l.short.length, `${role} ${lang}`).toBeGreaterThanOrEqual(3);
        expect(l.short.length, `${role} ${lang}`).toBeGreaterThanOrEqual(1);
        expect(formsLabels(role as FormsRole, lang)).toEqual([...l.full, ...l.short]);
      }
    }
    expect(Object.keys(FORMS_LABELS)).toHaveLength(25);
  });

  it("falls back to English labels for another language", () => {
    expect(formsLabels("vat_number", "ja")).toEqual(formsLabels("vat_number", "en"));
  });
});
