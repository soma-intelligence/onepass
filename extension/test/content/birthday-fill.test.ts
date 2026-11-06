// Birth dates written as the field wants them (one-click signup, spec 5).
import { afterEach, describe, expect, it } from "vitest";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import { createFiller } from "../../src/content/filler";
import { testGeometry } from "../detect/helpers";

const SITE = "https://shop.test/signup";
const BDAY = "1990-04-12";

const sel = (id: string) => document.getElementById(id) as HTMLSelectElement;
const inp = (id: string) => document.getElementById(id) as HTMLInputElement;

afterEach(() => {
  document.documentElement.lang = "";
  document.body.innerHTML = "";
});

function setup(html: string) {
  document.body.innerHTML = html;
  const refs = new RefRegistry();
  const analyze = () => analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
  const filler = createFiller({
    refs,
    geometry: testGeometry,
    analyze,
    resolve: (ref, a) => a.forms.find((f) => f.ref === ref) ?? null,
    settleMs: 0,
  });
  return (bday: string) => filler.fillForm(analyze().forms[0]!.ref, { given_name: "Alex", bday });
}

const FORM = (date: string) => `
<form>
  <label for="gn">First name</label><input id="gn" autocomplete="given-name">
  ${date}
  <button type="submit">Create account</button>
</form>`;

const days = Array.from({ length: 31 }, (_, i) => `<option value="${i + 1}">${i + 1}</option>`).join("");
const months = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"]
  .map((m, i) => `<option value="${i + 1}">${m}</option>`)
  .join("");
const years = Array.from({ length: 80 }, (_, i) => `<option>${2010 - i}</option>`).join("");

describe("birth date fill", () => {
  it("a date input gets the ISO date", () => {
    const fill = setup(FORM(`<label for="b">Date of birth</label><input id="b" type="date" autocomplete="bday">`));
    fill(BDAY);
    expect(inp("b").value).toBe("1990-04-12");
  });

  it("a text field follows its written format", () => {
    const fill = setup(FORM(`<label for="b">Date de naissance</label><input id="b" autocomplete="bday" placeholder="JJ/MM/AAAA">`));
    fill(BDAY);
    expect(inp("b").value).toBe("12/04/1990");
  });

  it("without a format, an English page writes the month first", () => {
    document.documentElement.lang = "en-US";
    const fill = setup(FORM(`<label for="b">Birthday</label><input id="b" autocomplete="bday">`));
    fill(BDAY);
    expect(inp("b").value).toBe("04/12/1990");
  });

  it("three lists, day, month by name and year, all get their part", () => {
    const fill = setup(FORM(`
      <label for="d">Jour</label><select id="d" autocomplete="bday-day"><option value="">Jour</option>${days}</select>
      <label for="m">Mois</label><select id="m" autocomplete="bday-month"><option value="">Mois</option>${months}</select>
      <label for="y">Année</label><select id="y" autocomplete="bday-year"><option value="">Année</option>${years}</select>`));
    fill(BDAY);
    expect(sel("d").value).toBe("12");
    expect(sel("m").selectedOptions[0]?.textContent).toBe("avril");
    expect(sel("y").value).toBe("1990");
  });

  it("a year field gets the year", () => {
    const fill = setup(FORM(`<label for="y">Birth year</label><input id="y" autocomplete="bday-year">`));
    fill(BDAY);
    expect(inp("y").value).toBe("1990");
  });

  it("a value that is not a date writes nothing", () => {
    const fill = setup(FORM(`<label for="b">Date de naissance</label><input id="b" autocomplete="bday" placeholder="JJ/MM/AAAA">`));
    fill("someday");
    expect(inp("b").value).toBe("");
  });
});

describe("forms coverage, Task 9: groups and persons in the filler", () => {
  it("three lists under one date legend fill as one birth date", () => {
    const fill = setup(`<form><label for="gn">Prénom</label><input id="gn" autocomplete="given-name">
      <label for="fa">Nom</label><input id="fa">
      <fieldset><legend>Date de naissance</legend>
      <label for="d">Jour</label><select id="d"><option value="">--</option>${days}</select>
      <label for="m">Mois</label><select id="m"><option value="">--</option>${months}</select>
      <label for="y">Année</label><select id="y"><option value="">--</option>${years}</select></fieldset>
      <button type="submit">OK</button></form>`);
    fill(BDAY);
    expect([sel("d").value, sel("m").value, sel("y").value]).toEqual(["12", "4", "1990"]);
  });

  it("the fields of passenger 2 are never written", () => {
    const fill = setup(`<form>
      <fieldset><legend>Passager 1</legend><label for="ag">Prénom</label><input id="ag"><label for="af">Nom</label><input id="af"></fieldset>
      <fieldset><legend>Passager 2</legend><label for="bg">Prénom</label><input id="bg"><label for="bf">Nom</label><input id="bf"></fieldset>
      <button type="submit">OK</button></form>`);
    fill(BDAY);
    expect([inp("ag").value, inp("bg").value]).toEqual(["Alex", ""]);
  });
});
