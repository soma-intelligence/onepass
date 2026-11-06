// Forms coverage, Task 9: date and radio groups, traveller blocks and work
// phones in the page analysis (spec sections 4, 6, 7; rulings R3, R7, R9).
import { describe, expect, it } from "vitest";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import type { FieldInfo, FormInfo } from "../../src/shared/messages";
import { testGeometry } from "./helpers";

const SITE = "https://blue-harbor-7.test/booking";

function analyze(body: string): { forms: FormInfo[]; refs: RefRegistry } {
  document.documentElement.innerHTML = `<head><title>Blue Harbor</title></head><body>${body}</body>`;
  const refs = new RefRegistry();
  return { forms: analyzeDocument(document, refs, { url: SITE, geometry: testGeometry }).forms, refs };
}

const id = (refs: RefRegistry, ref: string) => (refs.get(ref) as HTMLElement).id;

/** Each field as "<id>": role, parts' ids, person and work flag. */
function fields(refs: RefRegistry, form: FormInfo): Record<string, { role: string; parts?: string[]; person?: number; work?: true }> {
  const out: Record<string, { role: string; parts?: string[]; person?: number; work?: true }> = {};
  for (const f of form.fields as FieldInfo[]) {
    const e: { role: string; parts?: string[]; person?: number; work?: true } = { role: f.role };
    if (f.parts) e.parts = f.parts.map((p) => id(refs, p));
    if (f.person !== undefined) e.person = f.person;
    if (f.work) e.work = true;
    out[id(refs, f.ref)] = e;
  }
  return out;
}

const row = (i: string, label: string, extra = "") => `<div><label for="${i}">${label}</label><input id="${i}" name="${i}"${extra}></div>`;
const days = Array.from({ length: 31 }, (_, i) => `<option value="${i + 1}">${i + 1}</option>`).join("");
const monthNames = (names: string[]) => names.map((m, i) => `<option value="${i + 1}">${m}</option>`).join("");
const years = (from: number) => Array.from({ length: 60 }, (_, i) => `<option>${from - i}</option>`).join("");
const FR_MONTHS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"];
const DE_MONTHS = ["Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember"];
const EN_MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

const dateParts = (legend: string, [d, m, y]: string[], months: string[], from = 2010, prefix = "b") => `<fieldset><legend>${legend}</legend>`
  + `<label for="${prefix}d">${d}</label><select id="${prefix}d" name="${prefix}d"><option value="">--</option>${days}</select>`
  + `<label for="${prefix}m">${m}</label><select id="${prefix}m" name="${prefix}m"><option value="">--</option>${monthNames(months)}</select>`
  + `<label for="${prefix}y">${y}</label><select id="${prefix}y" name="${prefix}y"><option value="">--</option>${years(from)}</select></fieldset>`;

describe("date groups", () => {
  it.each([
    ["Date de naissance", ["Jour", "Mois", "Année"], FR_MONTHS],
    ["Geburtsdatum", ["Tag", "Monat", "Jahr"], DE_MONTHS],
    ["Date of birth", ["Day", "Month", "Year"], EN_MONTHS],
  ])("three lists under %s are one bday field with its parts in day, month, year order", (legend, words, months) => {
    const { forms, refs } = analyze(`<form id="f">${row("g", "Prénom")}${row("fa", "Nom")}${dateParts(legend, words, months)}`
      + '<button type="submit">OK</button></form>');
    expect(fields(refs, forms[0]!)).toEqual({
      g: { role: "given_name" }, fa: { role: "family_name" }, bd: { role: "bday", parts: ["bd", "bm", "by"] },
    });
  });

  it("three lists under Date d'expiration next to a passport number are the passport expiry", () => {
    const { forms, refs } = analyze(`<form id="f">${row("g", "Prénom")}${row("pn", "Numéro de passeport")}`
      + `${dateParts("Date d'expiration", ["Jour", "Mois", "Année"], FR_MONTHS, 2040, "x")}<button type="submit">OK</button></form>`);
    expect(fields(refs, forms[0]!).xd).toEqual({ role: "passport_expiry", parts: ["xd", "xm", "xy"] });
  });

  it("a card's month and year lists under Date d'expiration stay the card's two fields", () => {
    const { forms, refs } = analyze(`<form id="f">${row("c", "Numéro de carte")}<fieldset><legend>Date d'expiration</legend>`
      + `<label for="xm">Mois</label><select id="xm" name="xm"><option value="">--</option>${monthNames(FR_MONTHS)}</select>`
      + `<label for="xy">Année</label><select id="xy" name="xy"><option value="">--</option>${years(2040)}</select></fieldset>`
      + `${row("s", "Cryptogramme")}<button type="submit">Payer</button></form>`);
    expect(fields(refs, forms[0]!)).toEqual({
      c: { role: "cc_number" }, xm: { role: "cc_exp_month" }, xy: { role: "cc_exp_year" }, s: { role: "cc_csc" },
    });
  });
});

const radios = (name: string, legend: string, opts: [string, string][]) => `<fieldset id="${name}"><legend>${legend}</legend>`
  + opts.map(([v, l], k) => `<label><input type="radio" id="${name}-${k + 1}" name="${name}" value="${v}"> ${l}</label>`).join("")
  + "</fieldset>";

describe("radio groups", () => {
  it("Civilité (M., Mme) is one honorific_prefix field, Sexe (Homme, Femme) one sex field", () => {
    const { forms, refs } = analyze(`<form id="f">${radios("civ", "Civilité", [["m", "M."], ["mme", "Mme"]])}${row("g", "Prénom")}`
      + `${row("fa", "Nom")}${radios("sx", "Sexe", [["h", "Homme"], ["f", "Femme"]])}<button type="submit">OK</button></form>`);
    expect(fields(refs, forms[0]!)).toEqual({
      "civ-1": { role: "honorific_prefix", parts: ["civ-1", "civ-2"] },
      g: { role: "given_name" },
      fa: { role: "family_name" },
      "sx-1": { role: "sex", parts: ["sx-1", "sx-2"] },
    });
  });

  it("a radio group about something else is not a field", () => {
    const { forms, refs } = analyze(`<form id="f">${row("g", "Prénom")}${row("fa", "Nom")}`
      + `${radios("ml", "Repas", [["v", "Végétarien"], ["s", "Standard"]])}<button type="submit">OK</button></form>`);
    expect(Object.keys(fields(refs, forms[0]!))).toEqual(["g", "fa"]);
  });
});

const block = (legend: string, inner: string) => `<fieldset>${legend ? `<legend>${legend}</legend>` : ""}${inner}</fieldset>`;
const names = (p: string) => row(`${p}g`, "Prénom") + row(`${p}f`, "Nom");

describe("person blocks", () => {
  it("blocks Passager 2 and Passenger 3 give persons 1 and 2; passenger 1 and the contact are the owner", () => {
    const { forms, refs } = analyze('<form id="f">'
      + block("Contact", row("e", "E-mail", ' type="email"') + row("t", "Téléphone", ' type="tel"'))
      + block("Passager 1", names("a")) + block("Passager 2", names("b")) + block("Passenger 3", names("c"))
      + '<button type="submit">Réserver</button></form>');
    const f = fields(refs, forms[0]!);
    expect(f.e).toEqual({ role: "email" });
    expect([f.ag, f.af]).toEqual([{ role: "given_name" }, { role: "family_name" }]);
    expect([f.bg, f.bf]).toEqual([{ role: "given_name", person: 1 }, { role: "family_name", person: 1 }]);
    expect([f.cg, f.cf]).toEqual([{ role: "given_name", person: 2 }, { role: "family_name", person: 2 }]);
  });

  it("2e passager and second passenger are rank 2", () => {
    for (const legend of ["2e passager", "Second passenger"]) {
      const { forms, refs } = analyze(`<form id="f">${block("", names("a"))}${block(legend, names("b"))}<button type="submit">OK</button></form>`);
      expect(fields(refs, forms[0]!).bg, legend).toEqual({ role: "given_name", person: 1 });
    }
  });

  it("names passengers[1][first_name], pax_2_ and adult-3- give persons from the field names", () => {
    const named = (n: string, label: string) => `<div><label for="${n}">${label}</label><input id="${n.replace(/\W/g, "_")}" name="${n}"></div>`;
    const { forms, refs } = analyze('<form id="f">'
      + named("passengers[0][first_name]", "Prénom") + named("passengers[0][last_name]", "Nom")
      + named("passengers[1][first_name]", "Prénom") + named("pax_2_last_name", "Nom")
      + named("adult-3-first_name", "Prénom") + '<button type="submit">OK</button></form>');
    const f = fields(refs, forms[0]!);
    expect(f.passengers_0__first_name_).toEqual({ role: "given_name" });
    expect(f.passengers_1__first_name_).toEqual({ role: "given_name", person: 1 });
    expect(f.pax_2_last_name).toEqual({ role: "family_name", person: 1 });
    expect(f.adult_3_first_name).toEqual({ role: "given_name", person: 2 });
  });

  it("unlabelled repeated name blocks: only the first is the owner", () => {
    const { forms, refs } = analyze(`<form id="f">${block("", names("a") + row("ap", "Numéro de passeport"))}`
      + `${block("", names("b") + row("bp", "Numéro de passeport"))}<button type="submit">OK</button></form>`);
    const f = fields(refs, forms[0]!);
    expect(f.ag).toEqual({ role: "given_name" });
    expect(f.ap).toEqual({ role: "passport_number" });
    expect(f.bg).toEqual({ role: "given_name", person: 1 });
    expect(f.bp).toEqual({ role: "passport_number", person: 1 });
  });

  it("billing and shipping address blocks are both the owner's", () => {
    const addr = (p: string) => row(`${p}a`, "Adresse") + row(`${p}z`, "Code postal") + row(`${p}c`, "Ville");
    const { forms, refs } = analyze(`<form id="f">${block("Adresse de facturation", addr("b"))}`
      + `${block("Adresse de livraison", addr("s"))}<button type="submit">OK</button></form>`);
    const f = fields(refs, forms[0]!);
    for (const k of ["ba", "bz", "bc", "sa", "sz", "sc"]) expect(f[k]?.person, k).toBeUndefined();
  });
});

describe("work phones", () => {
  it("autocomplete work tel and Téléphone professionnel are tel with the work flag", () => {
    const { forms, refs } = analyze(`<form id="f">${row("g", "Prénom")}${row("t", "Téléphone")}`
      + `${row("w", "Téléphone professionnel")}${row("w2", "Phone", ' autocomplete="work tel"')}<button type="submit">OK</button></form>`);
    expect(fields(refs, forms[0]!)).toEqual({
      g: { role: "given_name" }, t: { role: "tel" }, w: { role: "tel", work: true }, w2: { role: "tel", work: true },
    });
  });
});

describe("person blocks: counts are not ranks", () => {
  it("a heading 2 adultes over every traveller block is a count", () => {
    const { forms, refs } = analyze(`<form id="f"><div><h3>Réservation pour 2 adultes</h3>`
      + `${block("Passager 1", names("a"))}${block("Passager 2", names("b"))}</div><button type="submit">OK</button></form>`);
    const f = fields(refs, forms[0]!);
    expect(f.ag).toEqual({ role: "given_name" });
    expect(f.bg).toEqual({ role: "given_name", person: 1 });
  });
});
