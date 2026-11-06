// Forms coverage, Task 10: document dates are written like birth dates
// (spec section 6): date inputs, written formats, parts, lists in seven languages.
import { afterEach, describe, expect, it } from "vitest";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import { createFiller } from "../../src/content/filler";
import type { FieldRole } from "../../src/shared/messages";
import { testGeometry } from "../detect/helpers";

const SITE = "https://blue-harbor-7.test/booking";
const sel = (id: string) => document.getElementById(id) as HTMLSelectElement;
const inp = (id: string) => document.getElementById(id) as HTMLInputElement;

afterEach(() => {
  document.documentElement.lang = "";
  document.body.innerHTML = "";
});

function fill(html: string, values: Partial<Record<FieldRole, string>>): number {
  document.body.innerHTML = `<form>${html}<button type="submit">OK</button></form>`;
  const refs = new RefRegistry();
  const analyze = () => analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
  const filler = createFiller({ refs, geometry: testGeometry, analyze, resolve: (ref, a) => a.forms.find((f) => f.ref === ref) ?? null, settleMs: 0 });
  return filler.fillForm(analyze().forms[0]!.ref, values);
}

const row = (id: string, label: string, extra = "") => `<label for="${id}">${label}</label><input id="${id}"${extra}>`;
const PASSPORT = row("g", "Prénom") + row("fa", "Nom") + row("pn", "Numéro de passeport");
const days = (zero: boolean) => Array.from({ length: 31 }, (_, i) => `<option>${zero ? String(i + 1).padStart(2, "0") : i + 1}</option>`).join("");
const opts = (xs: string[]) => xs.map((m, i) => `<option value="${i + 1}">${m}</option>`).join("");
const years = (from: number, n: number) => Array.from({ length: n }, (_, i) => `<option>${from + i}</option>`).join("");

describe("document dates", () => {
  it("a passport expiry in a date input gets the ISO date", () => {
    fill(PASSPORT + row("x", "Date d'expiration", ' type="date"'), { given_name: "Alex", passport_expiry: "2031-05-02" });
    expect(inp("x").value).toBe("2031-05-02");
  });

  it("a passport expiry text box follows its placeholder, else the page's language", () => {
    fill(PASSPORT + row("x", "Date d'expiration", ' placeholder="JJ/MM/AAAA"'), { passport_expiry: "2031-05-02" });
    expect(inp("x").value).toBe("02/05/2031");
    document.documentElement.lang = "de";
    fill(row("pn", "Reisepassnummer") + row("x", "Gültig bis"), { passport_expiry: "2031-05-02" });
    expect(inp("x").value).toBe("02.05.2031");
  });

  it("a license issue date in three lists: day without zero, month names in Spanish, years", () => {
    fill(row("ln", "Número de permiso de conducir")
      + "<fieldset><legend>Fecha de expedición</legend>"
      + `<label for="d">Día</label><select id="d"><option value="">--</option>${days(false)}</select>`
      + `<label for="m">Mes</label><select id="m"><option value="">--</option>${opts(["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"])}</select>`
      + `<label for="y">Año</label><select id="y"><option value="">--</option>${years(1990, 40)}</select></fieldset>`,
    { license_issue_date: "2016-03-09" });
    expect([sel("d").value, sel("m").value, sel("y").value]).toEqual(["9", "3", "2016"]);
  });

  it("a passport expiry in three boxes: each its part; a part nothing designates stays empty", () => {
    fill(PASSPORT + "<fieldset><legend>Date d'expiration</legend>"
      + row("d", "Jour", ' maxlength="2"') + row("m", "Mois", ' maxlength="2"') + row("z", "Autre") + "</fieldset>",
    { passport_expiry: "2031-05-02" });
    expect([inp("d").value, inp("m").value, inp("z").value]).toEqual(["02", "05", ""]);
  });

  it("a birth date year box of two characters gets two digits", () => {
    fill(row("g", "Prénom") + row("fa", "Nom") + row("y", "Année de naissance", ' autocomplete="bday-year" maxlength="2"'),
      { given_name: "Alex", bday: "1990-04-12" });
    expect(inp("y").value).toBe("90");
  });
});
