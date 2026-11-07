// Forms coverage, Task 8: roles of travel, company, car rental and
// administrative identity fields in the seven languages (spec section 3).
// Labels are written here from the spec tables, never taken from the lab.
import { describe, expect, it } from "vitest";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import type { FieldRole, FormKind } from "../../src/shared/messages";
import { testGeometry } from "./helpers";

const SITE = "https://blue-harbor-7.test/";

/** [id, label, input type (text by default)]. */
type Row = [string, string, string?];

function analyze(body: string): { kinds: FormKind[]; roles: Record<string, FieldRole> } {
  document.documentElement.innerHTML = `<head><title>Blue Harbor</title></head><body>${body}</body>`;
  const refs = new RefRegistry();
  const a = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
  const roles: Record<string, FieldRole> = {};
  for (const form of a.forms) for (const fi of form.fields) roles[(refs.get(fi.ref) as HTMLElement).id] = fi.role;
  return { kinds: a.forms.map((f) => f.kind), roles };
}

const rowHtml = ([id, label, type]: Row) =>
  `<div><label for="${id}">${label}</label><input id="${id}" name="f_${id}" type="${type ?? "text"}"></div>`;

function form(rows: Row[], button = "OK"): { kinds: FormKind[]; roles: Record<string, FieldRole> } {
  return analyze(`<form id="f">${rows.map(rowHtml).join("")}<button type="submit">${button}</button></form>`);
}

const ADMIN: Record<string, FieldRole> = {
  ci: "honorific_prefix", g: "given_name", mi: "additional_name", fa: "family_name", bn: "birth_name", sx: "sex",
  bd: "bday", bp: "birth_place", bc: "birth_country", na: "nationality",
};
const TRAVEL: Record<string, FieldRole> = {
  g: "given_name", fa: "family_name", pn: "passport_number", pi: "passport_issue_date", pe: "passport_expiry",
  pc: "passport_issuing_country", lo: "loyalty_number", e: "email",
};
const RENTAL: Record<string, FieldRole> = {
  g: "given_name", fa: "family_name", ln: "license_number", li: "license_issue_date", le: "license_expiry",
  lc: "license_issuing_country",
};
const COMPANY: Record<string, FieldRole> = {
  o: "organization", jt: "job_title", dp: "department", vat: "vat_number", cid: "company_id", w: "website", e: "email",
};

type Labels = Record<string, string>;
interface Lang { admin: Labels; travel: Labels; rental: Labels; company: Labels }

const LANGS: Record<string, Lang> = {
  fr: {
    admin: { ci: "Civilité", g: "Prénom", mi: "Deuxième prénom", fa: "Nom", bn: "Nom de naissance", sx: "Sexe",
      bd: "Date de naissance", bp: "Lieu de naissance", bc: "Pays de naissance", na: "Nationalité" },
    travel: { g: "Prénom", fa: "Nom", pn: "Numéro de passeport", pi: "Date de délivrance", pe: "Date d'expiration",
      pc: "Pays de délivrance", lo: "Numéro de fidélité", e: "E-mail" },
    rental: { g: "Prénom", fa: "Nom", ln: "Numéro de permis", li: "Date de délivrance du permis",
      le: "Date d'expiration du permis", lc: "Pays de délivrance du permis" },
    company: { o: "Société", jt: "Poste", dp: "Service", vat: "Numéro de TVA", cid: "SIRET", w: "Site web", e: "E-mail" },
  },
  en: {
    admin: { ci: "Title", g: "First name", mi: "Middle name", fa: "Last name", bn: "Maiden name", sx: "Gender",
      bd: "Date of birth", bp: "Place of birth", bc: "Country of birth", na: "Nationality" },
    travel: { g: "First name", fa: "Last name", pn: "Passport number", pi: "Date of issue", pe: "Expiry date",
      pc: "Issuing country", lo: "Frequent flyer number", e: "Email" },
    rental: { g: "First name", fa: "Last name", ln: "Driver's license number", li: "License issue date",
      le: "License expiry date", lc: "Country of issue" },
    company: { o: "Company", jt: "Job title", dp: "Department", vat: "VAT number", cid: "Company registration number",
      w: "Website", e: "Email" },
  },
  de: {
    admin: { ci: "Anrede", g: "Vorname", mi: "Weitere Vornamen", fa: "Nachname", bn: "Geburtsname", sx: "Geschlecht",
      bd: "Geburtsdatum", bp: "Geburtsort", bc: "Geburtsland", na: "Staatsangehörigkeit" },
    travel: { g: "Vorname", fa: "Nachname", pn: "Reisepassnummer", pi: "Ausstellungsdatum", pe: "Gültig bis",
      pc: "Ausstellungsland", lo: "Vielfliegernummer", e: "E-Mail" },
    rental: { g: "Vorname", fa: "Nachname", ln: "Führerscheinnummer", li: "Ausstellungsdatum des Führerscheins",
      le: "Führerschein gültig bis", lc: "Ausstellungsland" },
    company: { o: "Firma", jt: "Position", dp: "Abteilung", vat: "USt-IdNr.", cid: "Handelsregisternummer", w: "Webseite",
      e: "E-Mail" },
  },
  es: {
    admin: { ci: "Tratamiento", g: "Nombre", mi: "Segundo nombre", fa: "Apellidos", bn: "Apellido de soltera", sx: "Sexo",
      bd: "Fecha de nacimiento", bp: "Lugar de nacimiento", bc: "País de nacimiento", na: "Nacionalidad" },
    travel: { g: "Nombre", fa: "Apellidos", pn: "Número de pasaporte", pi: "Fecha de expedición", pe: "Fecha de caducidad",
      pc: "País de expedición", lo: "Número de viajero frecuente", e: "Correo electrónico" },
    rental: { g: "Nombre", fa: "Apellidos", ln: "Número de permiso de conducir", li: "Fecha de expedición del permiso",
      le: "Fecha de caducidad del permiso", lc: "País de expedición" },
    company: { o: "Empresa", jt: "Cargo", dp: "Departamento", vat: "Número de IVA", cid: "CIF", w: "Sitio web",
      e: "Correo electrónico" },
  },
  it: {
    admin: { ci: "Titolo", g: "Nome", mi: "Secondo nome", fa: "Cognome", bn: "Cognome da nubile", sx: "Sesso",
      bd: "Data di nascita", bp: "Luogo di nascita", bc: "Paese di nascita", na: "Cittadinanza" },
    travel: { g: "Nome", fa: "Cognome", pn: "Numero di passaporto", pi: "Data di rilascio", pe: "Data di scadenza",
      pc: "Paese di rilascio", lo: "Codice fedeltà", e: "Email" },
    rental: { g: "Nome", fa: "Cognome", ln: "Numero di patente", li: "Data di rilascio della patente", le: "Scadenza patente",
      lc: "Paese di rilascio" },
    company: { o: "Azienda", jt: "Ruolo", dp: "Reparto", vat: "Partita IVA", cid: "Numero REA", w: "Sito web", e: "Email" },
  },
  pt: {
    admin: { ci: "Tratamento", g: "Nome", mi: "Nome do meio", fa: "Apelido", bn: "Nome de solteira", sx: "Sexo",
      bd: "Data de nascimento", bp: "Local de nascimento", bc: "País de nascimento", na: "Nacionalidade" },
    travel: { g: "Nome", fa: "Apelido", pn: "Número do passaporte", pi: "Data de emissão", pe: "Data de validade",
      pc: "País emissor", lo: "Número de passageiro frequente", e: "E-mail" },
    rental: { g: "Nome", fa: "Apelido", ln: "Número da carta de condução", li: "Data de emissão da carta",
      le: "Validade da carta", lc: "País emissor" },
    company: { o: "Empresa", jt: "Função", dp: "Departamento", vat: "Número de IVA", cid: "NIPC", w: "Website", e: "E-mail" },
  },
  nl: {
    admin: { ci: "Aanhef", g: "Voornaam", mi: "Tweede voornaam", fa: "Achternaam", bn: "Meisjesnaam", sx: "Geslacht",
      bd: "Geboortedatum", bp: "Geboorteplaats", bc: "Geboorteland", na: "Nationaliteit" },
    travel: { g: "Voornaam", fa: "Achternaam", pn: "Paspoortnummer", pi: "Datum van afgifte", pe: "Geldig tot",
      pc: "Land van afgifte", lo: "Frequent flyer nummer", e: "E-mailadres" },
    rental: { g: "Voornaam", fa: "Achternaam", ln: "Rijbewijsnummer", li: "Afgiftedatum rijbewijs",
      le: "Vervaldatum rijbewijs", lc: "Land van afgifte" },
    company: { o: "Bedrijfsnaam", jt: "Functie", dp: "Afdeling", vat: "BTW-nummer", cid: "KvK-nummer", w: "Website",
      e: "E-mailadres" },
  },
};

const rows = (labels: Labels): Row[] => Object.entries(labels).map(([id, label]) => [id, label]);

describe.each(Object.entries(LANGS))("forms roles (%s)", (_lang, l) => {
  it("administrative identity", () => {
    expect(form(rows(l.admin))).toEqual({ kinds: ["identity"], roles: ADMIN });
  });
  it("travel booking", () => {
    expect(form(rows(l.travel))).toEqual({ kinds: ["identity"], roles: TRAVEL });
  });
  it("car rental", () => {
    expect(form(rows(l.rental))).toEqual({ kinds: ["identity"], roles: RENTAL });
  });
  it("company", () => {
    expect(form(rows(l.company))).toEqual({ kinds: ["identity"], roles: COMPANY });
  });
});

describe("forms roles: meaning by context", () => {
  it("Nom de naissance next to Nom is the birth name, Nom the family name", () => {
    const r = form([["g", "Prénom"], ["fa", "Nom"], ["bn", "Nom de naissance"]]);
    expect(r.roles).toEqual({ g: "given_name", fa: "family_name", bn: "birth_name" });
  });

  it("Date d'expiration next to a card number is the card expiry", () => {
    const r = form([["n", "Titulaire de la carte"], ["c", "Numéro de carte"], ["x", "Date d'expiration"], ["s", "Cryptogramme"]]);
    expect(r).toEqual({ kinds: ["card"], roles: { n: "cc_name", c: "cc_number", x: "cc_exp", s: "cc_csc" } });
  });

  it("Date d'expiration alone stays the card expiry", () => {
    const r = form([["c", "Numéro de carte"], ["x", "Date d'expiration"]]);
    expect(r.roles.x).toBe("cc_exp");
  });

  it("Date d'expiration next to a passport number is the passport's", () => {
    const r = form([["g", "Prénom"], ["fa", "Nom"], ["pn", "Numéro de passeport"], ["x", "Date d'expiration"]]);
    expect(r.roles.x).toBe("passport_expiry");
  });

  it("with a passport and a license, the label word says which document a date is", () => {
    const r = form([
      ["pn", "Numéro de passeport"], ["pe", "Date d'expiration du passeport"],
      ["ln", "Numéro de permis de conduire"], ["le", "Date d'expiration du permis"], ["li", "Date de délivrance du permis"],
    ]);
    expect(r.roles).toEqual({
      pn: "passport_number", pe: "passport_expiry", ln: "license_number", le: "license_expiry", li: "license_issue_date",
    });
  });

  it("Pays de naissance, Pays de délivrance and Nationalité are not the address country", () => {
    const r = form([["a", "Adresse"], ["z", "Code postal"], ["ci", "Ville"], ["co", "Pays"], ["pn", "Numéro de passeport"],
      ["bc", "Pays de naissance"], ["pc", "Pays de délivrance"], ["na", "Nationalité"]]);
    expect(r.roles).toMatchObject({ co: "country", bc: "birth_country", pc: "passport_issuing_country", na: "nationality" });
  });

  it("Département next to Société is a department, in an address block a region", () => {
    const company = analyze('<form id="f"><fieldset><legend>Entreprise</legend>'
      + rowHtml(["o", "Société"]) + rowHtml(["dp", "Département"]) + "</fieldset><fieldset><legend>Adresse</legend>"
      + rowHtml(["a", "Adresse"]) + rowHtml(["z", "Code postal"]) + rowHtml(["ci", "Ville"]) + rowHtml(["r", "Département"])
      + '</fieldset><button type="submit">OK</button></form>');
    expect(company.roles).toMatchObject({ o: "organization", dp: "department", r: "region" });
    const address = form([["a", "Adresse"], ["z", "Code postal"], ["ci", "Ville"], ["r", "Département"]]);
    expect(address.roles.r).toBe("region");
  });

  it("a Dutch tussenvoegsel is no middle name: left unknown", () => {
    const r = form([["g", "Voornaam"], ["tv", "Tussenvoegsel"], ["fa", "Achternaam"]]);
    expect(r.roles).toEqual({ g: "given_name", fa: "family_name" });
  });

  it("Job title is not a civility; Title alone is", () => {
    expect(form([["g", "First name"], ["jt", "Job title"]]).roles.jt).toBe("job_title");
    expect(form([["t", "Title"], ["g", "First name"]]).roles.t).toBe("honorific_prefix");
  });

  it("a website field by its url type", () => {
    expect(form([["o", "Company"], ["w", "Homepage", "url"]]).roles.w).toBe("website");
  });

  it("an issuing country or issue date with no document number in the form is left alone", () => {
    const r = form([["g", "First name"], ["fa", "Last name"], ["pc", "Issuing country"], ["pi", "Date of issue"]]);
    expect(r.roles).toEqual({ g: "given_name", fa: "family_name" });
  });
});

// Short forms common on real booking and rental pages ("Né(e) à", "Nº socio", "DL #"): a check
// of the generated worlds after Task 10 found them unread; the terms come from usage, not the lab.
describe("forms roles: short forms", () => {
  it.each([
    ["Né(e) à", [["g", "Prénom"], ["fa", "Nom"], ["x", "Né(e) à"]], "birth_place"],
    ["Pays où vous êtes né(e)", [["g", "Prénom"], ["fa", "Nom"], ["x", "Pays où vous êtes né(e)"]], "birth_country"],
    ["Trat.", [["x", "Trat."], ["g", "Nombre"], ["fa", "Apellidos"]], "honorific_prefix"],
    ["Nº socio", [["g", "Nombre"], ["fa", "Apellidos"], ["pn", "Número de pasaporte"], ["x", "Nº socio"]], "loyalty_number"],
    ["Nº carné", [["g", "Nombre"], ["fa", "Apellidos"], ["x", "Nº carné"]], "license_number"],
    ["DL #", [["g", "First name"], ["fa", "Last name"], ["x", "DL #"]], "license_number"],
    ["Web", [["o", "Société"], ["x", "Web"]], "website"],
    ["Issued by", [["g", "First name"], ["pn", "Passport number"], ["x", "Issued by"]], "passport_issuing_country"],
    ["Pays permis", [["g", "Prénom"], ["ln", "Numéro de permis"], ["x", "Pays permis"]], "license_issuing_country"],
    ["Délivr. permis", [["g", "Prénom"], ["ln", "Numéro de permis"], ["x", "Délivr. permis"]], "license_issue_date"],
    ["Afgifte rijb.", [["g", "Voornaam"], ["ln", "Rijbewijsnummer"], ["x", "Afgifte rijb."]], "license_issue_date"],
    ["Issued", [["g", "First name"], ["pn", "Passport number"], ["x", "Issued"]], "passport_issue_date"],
    // Task 11 witnesses (seed forms-2026-11-06-a sites 61, 87, 167).
    ["Birth surname", [["g", "First name"], ["fa", "Surname"], ["x", "Birth surname"]], "birth_name"],
    ["Last name at birth", [["g", "First name"], ["fa", "Last name"], ["x", "Last name at birth"]], "birth_name"],
    ["Pays naiss.", [["g", "Prénom"], ["fa", "Nom"], ["x", "Pays naiss."]], "birth_country"],
    ["Civ.", [["x", "Civ."], ["g", "Prénom"], ["fa", "Nom"]], "honorific_prefix"],
  ] as [string, Row[], FieldRole][])("%s", (_name, rs, role) => {
    expect(form(rs).roles.x).toBe(role);
  });

  // Task 14 witness (seed forms-2026-11-06-a site 114): a list is never a document number, whatever its name says.
  it("a list named dl_country under Rijbewijs afgegeven in is the license's issuing country", () => {
    const r = analyze(`<form id="f">${rowHtml(["g", "Voornaam"])}${rowHtml(["ln", "Nummer van het rijbewijs"])}`
      + '<div><label for="dl_country">Rijbewijs afgegeven in</label><select id="dl_country" name="dl_country"><option value="">--</option>'
      + '<option value="FR">Frankrijk</option><option value="NL">Nederland</option></select></div><button type="submit">OK</button></form>');
    expect(r.roles.dl_country).toBe("license_issuing_country");
  });

  // Task 14 witness (seed forms-2026-11-06-a site 155): the short Italian tax code of a company form.
  it("Cod. fisc. next to a company and its VAT number is the company registration, never on a person's form", () => {
    expect(form([["g", "Nome"], ["o", "Società"], ["vat", "Numero di partita IVA"], ["x", "Cod. fisc."]]).roles.x).toBe("company_id");
    expect(form([["g", "Nome"], ["fa", "Cognome"], ["x", "Codice fiscale"], ["e", "Email", "email"]]).roles.x).toBeUndefined();
  });

  it("a radio group under the legend Civ. is the civility", () => {
    const r = analyze('<form id="f"><fieldset><legend>Civ.</legend><label><input type="radio" id="c1" name="civ" value="1"> M.</label>'
      + '<label><input type="radio" id="c2" name="civ" value="2"> Mme</label></fieldset>'
      + `${rowHtml(["g", "Prénom"])}${rowHtml(["fa", "Nom"])}<button type="submit">OK</button></form>`);
    expect(r.roles.c1).toBe("honorific_prefix");
  });

  it("three lists under the legend Délivr. next to a passport number are its issue date", () => {
    const opts = (n: number, from = 1) => Array.from({ length: n }, (_, i) => `<option>${from + i}</option>`).join("");
    const r = analyze(`<form id="f">${rowHtml(["pn", "Numéro de passeport"])}<fieldset><legend>Délivr.</legend>`
      + `<label for="d">Jour</label><select id="d" name="issue_day">${opts(31)}</select>`
      + `<label for="m">MM</label><select id="m" name="issue_month">${opts(12)}</select>`
      + `<label for="y">Année de naissance</label><select id="y" name="issue_year">${opts(30, 2000)}</select>`
      + '</fieldset><button type="submit">OK</button></form>');
    expect(r.roles.d).toBe("passport_issue_date");
  });
});
