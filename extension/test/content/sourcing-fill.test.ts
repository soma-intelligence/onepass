// Forms coverage, Task 12: what the filler writes from an identity fill on travel and company
// pages: the work phone into a work tel, never another passenger, never the birth country.
import { afterEach, describe, expect, it } from "vitest";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import { createFiller, type FillHints } from "../../src/content/filler";
import type { FieldRole } from "../../src/shared/messages";
import { testGeometry } from "../detect/helpers";

const SITE = "https://blue-harbor-7.test/booking";
const inp = (id: string) => document.getElementById(id) as HTMLInputElement;

afterEach(() => {
  document.documentElement.lang = "";
  document.body.innerHTML = "";
});

function fill(html: string, values: Partial<Record<FieldRole, string>>, hints?: FillHints): FieldRole[] {
  document.documentElement.lang = "fr";
  document.body.innerHTML = `<form>${html}<button type="submit">Réserver</button></form>`;
  const refs = new RefRegistry();
  const analyze = () => analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
  const filler = createFiller({ refs, geometry: testGeometry, analyze, resolve: (ref, a) => a.forms.find((f) => f.ref === ref) ?? null, settleMs: 0 });
  return filler.fill(analyze().forms[0]!.ref, values, hints).filled;
}

const row = (id: string, label: string, extra = "") => `<label for="${id}">${label}</label><input id="${id}" name="${id}"${extra}>`;

describe("identity sourcing in the page", () => {
  it("a work phone field gets the work phone, the other phone the mobile one", () => {
    fill(row("o", "Société") + row("g", "Prénom") + row("f", "Nom") + row("t", "Téléphone") + row("w", "Téléphone professionnel"),
      { organization: "Atlas", given_name: "Léa", family_name: "Martin", tel: "+33 6 12 34 56 78" }, { work_tel: "+33 1 23 45 67 89" });
    expect(inp("t").value).toBe("+33 6 12 34 56 78");
    expect(inp("w").value).toBe("+33 1 23 45 67 89");
  });

  it("without a work phone, a work tel field gets today's phone", () => {
    fill(row("o", "Société") + row("g", "Prénom") + row("w", "Téléphone professionnel"), { organization: "Atlas", given_name: "Léa", tel: "+33 6 12 34 56 78" });
    expect(inp("w").value).toBe("+33 6 12 34 56 78");
  });

  it("a birth country is never written, even with a value", () => {
    fill(row("g", "Prénom") + row("f", "Nom") + row("bc", "Pays de naissance"), { given_name: "Léa", family_name: "Martin", birth_country: "FR" } as Partial<Record<FieldRole, string>>);
    expect(inp("bc").value).toBe("");
  });

  it("a travel page: passenger 1 and the contact block, never passenger 2", () => {
    const html = '<fieldset><legend>Passager 1</legend>' + row("g1", "Prénom") + row("f1", "Nom") + row("p1", "Numéro de passeport") + "</fieldset>"
      + '<fieldset><legend>Passager 2</legend>' + row("g2", "Prénom") + row("f2", "Nom") + row("p2", "Numéro de passeport") + "</fieldset>"
      + '<fieldset><legend>Contact</legend>' + row("e", "E-mail") + row("t", "Téléphone") + "</fieldset>";
    fill(html, { given_name: "Léa", family_name: "Martin", passport_number: "18AB12345", email: "lea@atlas.dev", tel: "+33 6 12 34 56 78" });
    expect([inp("g1").value, inp("f1").value, inp("p1").value, inp("e").value, inp("t").value]).toEqual(["Léa", "Martin", "18AB12345", "lea@atlas.dev", "+33 6 12 34 56 78"]);
    expect([inp("g2").value, inp("f2").value, inp("p2").value]).toEqual(["", "", ""]);
  });
});
