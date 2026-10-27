import { describe, expect, it } from "vitest";
import { classifyField } from "../../src/content/detect/fields";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import type { FieldRole, FormKind } from "../../src/shared/messages";
import { testGeometry } from "./helpers";

const SITE = "https://atlas-cloud.test/";

/** [id, input type, native label]; every field is unlabelled for `autocomplete`. */
type Row = [string, string, string];

/** One form of labelled fields, no `autocomplete`, analyzed; returns its kind and roles by id. */
function analyzeForm(rows: Row[], button: string, title = "Atlas Cloud"): { kind: FormKind; roles: Record<string, FieldRole> } {
  const fields = rows
    .map(([id, type, label]) => `<div><label for="${id}">${label}</label><input id="${id}" name="f_${id}" type="${type}"></div>`)
    .join("");
  document.documentElement.innerHTML = `<head><title>${title}</title></head><body><form id="f">${fields}<button id="go" type="submit">${button}</button></form></body>`;
  const refs = new RefRegistry();
  const a = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
  expect(a.forms).toHaveLength(1);
  const form = a.forms[0]!;
  const roles: Record<string, FieldRole> = {};
  for (const fi of form.fields) roles[(refs.get(fi.ref) as HTMLElement).id] = fi.role;
  return { kind: form.kind, roles };
}

interface Lang {
  login: [Row[], string];
  signup: [Row[], string];
  card: [Row[], string];
  address: [Row[], string];
  identity: [Row[], string];
}

const LOGIN_ROLES = { u: "username", p: "current_password" };
const SIGNUP_ROLES = { e: "email", p1: "new_password", p2: "confirm_password" };
const CARD_ROLES = { n: "cc_name", c: "cc_number", x: "cc_exp", s: "cc_csc" };
const ADDRESS_ROLES = { a1: "address_line1", a2: "address_line2", z: "postal_code", ci: "city", r: "region", co: "country" };
const IDENTITY_ROLES = { g: "given_name", fa: "family_name", t: "tel", b: "bday" };

const LANGS: Record<"de" | "es" | "it" | "pt" | "nl", Lang> = {
  de: {
    login: [[["u", "text", "Benutzername"], ["p", "password", "Kennwort"]], "Anmelden"],
    signup: [[["e", "text", "E-Mail-Adresse"], ["p1", "password", "Neues Passwort"], ["p2", "password", "Passwort wiederholen"]], "Registrieren"],
    card: [[["n", "text", "Karteninhaber"], ["c", "text", "Kartennummer"], ["x", "text", "Ablaufdatum (MM/JJ)"], ["s", "text", "Prüfziffer"]], "Jetzt bezahlen"],
    address: [[["a1", "text", "Straße und Hausnummer"], ["a2", "text", "Adresszusatz"], ["z", "text", "Postleitzahl"], ["ci", "text", "Ort"], ["r", "text", "Bundesland"], ["co", "text", "Land"]], "Speichern"],
    identity: [[["g", "text", "Vorname"], ["fa", "text", "Nachname"], ["t", "text", "Telefonnummer"], ["b", "text", "Geburtsdatum"]], "Speichern"],
  },
  es: {
    login: [[["u", "text", "Nombre de usuario"], ["p", "password", "Contraseña"]], "Iniciar sesión"],
    signup: [[["e", "text", "Correo electrónico"], ["p1", "password", "Nueva contraseña"], ["p2", "password", "Confirmar contraseña"]], "Crear cuenta"],
    card: [[["n", "text", "Titular de la tarjeta"], ["c", "text", "Número de tarjeta"], ["x", "text", "Fecha de vencimiento"], ["s", "text", "Código de seguridad"]], "Pagar"],
    address: [[["a1", "text", "Dirección"], ["a2", "text", "Piso, puerta, escalera"], ["z", "text", "Código postal"], ["ci", "text", "Ciudad"], ["r", "text", "Provincia"], ["co", "text", "País"]], "Guardar"],
    identity: [[["g", "text", "Nombre"], ["fa", "text", "Apellidos"], ["t", "text", "Teléfono"], ["b", "text", "Fecha de nacimiento"]], "Guardar"],
  },
  it: {
    login: [[["u", "text", "Nome utente"], ["p", "password", "Password"]], "Accedi"],
    signup: [[["e", "text", "Indirizzo email"], ["p1", "password", "Nuova password"], ["p2", "password", "Conferma password"]], "Registrati"],
    card: [[["n", "text", "Titolare della carta"], ["c", "text", "Numero della carta"], ["x", "text", "Data di scadenza"], ["s", "text", "Codice di sicurezza"]], "Paga ora"],
    address: [[["a1", "text", "Indirizzo"], ["a2", "text", "Interno, scala"], ["z", "text", "CAP"], ["ci", "text", "Città"], ["r", "text", "Provincia"], ["co", "text", "Paese"]], "Salva"],
    identity: [[["g", "text", "Nome"], ["fa", "text", "Cognome"], ["t", "text", "Telefono"], ["b", "text", "Data di nascita"]], "Salva"],
  },
  pt: {
    login: [[["u", "text", "Nome de utilizador"], ["p", "password", "Palavra-passe"]], "Entrar"],
    signup: [[["e", "text", "Correio eletrónico"], ["p1", "password", "Nova senha"], ["p2", "password", "Confirmar senha"]], "Criar conta"],
    card: [[["n", "text", "Nome no cartão"], ["c", "text", "Número do cartão"], ["x", "text", "Validade"], ["s", "text", "Código de segurança"]], "Pagar"],
    address: [[["a1", "text", "Morada"], ["a2", "text", "Complemento"], ["z", "text", "Código postal"], ["ci", "text", "Cidade"], ["r", "text", "Distrito"], ["co", "text", "País"]], "Guardar"],
    identity: [[["g", "text", "Primeiro nome"], ["fa", "text", "Sobrenome"], ["t", "text", "Telemóvel"], ["b", "text", "Data de nascimento"]], "Guardar"],
  },
  nl: {
    login: [[["u", "text", "Gebruikersnaam"], ["p", "password", "Wachtwoord"]], "Inloggen"],
    signup: [[["e", "text", "E-mailadres"], ["p1", "password", "Nieuw wachtwoord"], ["p2", "password", "Herhaal wachtwoord"]], "Account aanmaken"],
    card: [[["n", "text", "Naam op kaart"], ["c", "text", "Kaartnummer"], ["x", "text", "Vervaldatum"], ["s", "text", "Beveiligingscode"]], "Betalen"],
    address: [[["a1", "text", "Straat en huisnummer"], ["a2", "text", "Toevoeging"], ["z", "text", "Postcode"], ["ci", "text", "Woonplaats"], ["r", "text", "Provincie"], ["co", "text", "Land"]], "Opslaan"],
    identity: [[["g", "text", "Voornaam"], ["fa", "text", "Achternaam"], ["t", "text", "Telefoonnummer"], ["b", "text", "Geboortedatum"]], "Opslaan"],
  },
};

describe("multilingual lexicon (de, es, it, pt, nl)", () => {
  for (const [lang, t] of Object.entries(LANGS)) {
    it(`lexicon_${lang}_login`, () => {
      expect(analyzeForm(...t.login)).toEqual({ kind: "login", roles: LOGIN_ROLES });
    });
    it(`lexicon_${lang}_signup`, () => {
      expect(analyzeForm(...t.signup)).toEqual({ kind: "signup", roles: SIGNUP_ROLES });
    });
    it(`lexicon_${lang}_card`, () => {
      expect(analyzeForm(...t.card)).toEqual({ kind: "card", roles: CARD_ROLES });
    });
    it(`lexicon_${lang}_address`, () => {
      expect(analyzeForm(...t.address)).toEqual({ kind: "address", roles: ADDRESS_ROLES });
    });
    it(`lexicon_${lang}_identity`, () => {
      expect(analyzeForm(...t.identity)).toEqual({ kind: "identity", roles: IDENTITY_ROLES });
    });
  }
});

describe("identifier-only step in other languages", () => {
  it.each([
    ["es", "Identificador", "Continuar", "Iniciar sesión"],
    ["es", "Usuario", "CONTINUAR", "Sign in"],
    ["de", "Benutzername", "Weiter", "Anmelden"],
    ["it", "Nome utente", "Avanti", "Accedi"],
    ["pt", "Utilizador", "Seguinte", "Iniciar sessão"],
    ["nl", "Gebruikersnaam", "Volgende", "Inloggen"],
  ])("%s: %s + %s is a login step", (_lang, label, button, title) => {
    expect(analyzeForm([["u", "text", label]], button, title)).toEqual({ kind: "login", roles: { u: "username" } });
  });
});

describe("one-time codes in other languages", () => {
  it.each([
    ["de", "Bestätigungscode"],
    ["es", "Código de verificación"],
    ["it", "Codice di verifica"],
    ["pt", "Código de verificação"],
    ["nl", "Verificatiecode"],
  ])("%s: %s is an otp form", (_lang, label) => {
    expect(analyzeForm([["o", "text", label]], "OK")).toEqual({ kind: "otp", roles: { o: "otp" } });
  });
});

describe("review fixes: whole-text words and attribute names", () => {
  const roleOf = (html: string) => {
    document.body.innerHTML = html;
    return classifyField(document.getElementById("f") as HTMLInputElement).role;
  };

  it("user[...] attribute names keep their own role, a field named user is a username", () => {
    document.body.innerHTML =
      '<form id="p"><input id="g" name="user[first_name]"><input id="fa" name="user[last_name]">' +
      '<input id="e" name="user[email]"><input id="t" name="user[phone]"><button type="submit">Save</button></form>';
    const refs = new RefRegistry();
    const a = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
    const roles: Record<string, FieldRole> = {};
    for (const fi of a.forms[0]!.fields) roles[(refs.get(fi.ref) as HTMLElement).id] = fi.role;
    expect([a.forms[0]!.kind, roles]).toEqual(["identity", { g: "given_name", fa: "family_name", e: "email", t: "tel" }]);
    expect(roleOf('<input id="f" name="user">')).toBe("username");
  });

  it.each([
    ["Spending cap", "unknown"],
    ["Land line", "unknown"],
    ["Rua", "address_line1"],
    ["CAP", "postal_code"],
    ["CEP", "postal_code"],
    ["Ort", "city"],
    ["Land", "country"],
    ["Land oder Region", "country"],
    ["Land/Region", "country"],
    ["Land, Region", "country"],
    ["Land / Region", "country"],
    ["Nombre del titular", "cc_name"],
    ["Nome do titular", "cc_name"],
    ["Año", "cc_exp_year"],
    ["Año de vencimiento", "cc_exp_year"],
    ["Titular", "cc_name"],
    ["Titular do cartão", "cc_name"],
    ["Actual name", "full_name"],
    ["Portal", "unknown"],
  ])("label %s -> %s", (label, expected) => {
    expect(roleOf(`<label for="f">${label}</label><input id="f" name="x9" type="text">`)).toBe(expected);
  });

  it("Contraseña actual is the current password", () => {
    expect(roleOf('<label for="f">Contraseña actual</label><input id="f" name="x9" type="password">')).toBe("current_password");
  });
});
