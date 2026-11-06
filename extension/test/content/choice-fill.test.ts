// Forms coverage, Task 11: civility and sex lists and radio groups, nationality and issuing
// country (spec sections 7 and 8), through the filler.
import { afterEach, describe, expect, it } from "vitest";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import { createFiller, type FillHints } from "../../src/content/filler";
import type { FieldRole } from "../../src/shared/messages";
import { testGeometry } from "../detect/helpers";

const SITE = "https://blue-harbor-7.test/booking";
const sel = (id: string) => document.getElementById(id) as HTMLSelectElement;
const inp = (id: string) => document.getElementById(id) as HTMLInputElement;
const checked = (name: string) => (document.querySelector(`input[name="${name}"]:checked`) as HTMLInputElement | null)?.value ?? null;

afterEach(() => {
  document.documentElement.lang = "";
  document.body.innerHTML = "";
});

function fill(html: string, values: Partial<Record<FieldRole, string>>, hints?: FillHints, lang = "fr"): FieldRole[] {
  document.documentElement.lang = lang;
  document.body.innerHTML = `<form>${html}<button type="submit">OK</button></form>`;
  const refs = new RefRegistry();
  const analyze = () => analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
  const filler = createFiller({ refs, geometry: testGeometry, analyze, resolve: (ref, a) => a.forms.find((f) => f.ref === ref) ?? null, settleMs: 0 });
  return filler.fill(analyze().forms[0]!.ref, values, hints).filled;
}

const row = (id: string, label: string, extra = "") => `<label for="${id}">${label}</label><input id="${id}"${extra}>`;
const list = (id: string, label: string, opts: [string, string][]) =>
  `<label for="${id}">${label}</label><select id="${id}"><option value="">--</option>${opts.map(([v, t]) => `<option value="${v}">${t}</option>`).join("")}</select>`;
const radios = (name: string, legend: string, opts: [string, string][], checkedAt = -1) =>
  `<fieldset><legend>${legend}</legend>${opts.map(([v, t], i) => `<label><input type="radio" name="${name}" value="${v}"${i === checkedAt ? " checked" : ""}> ${t}</label>`).join("")}</fieldset>`;
const NAMES = row("g", "Prénom") + row("f", "Nom");

describe("civility and sex", () => {
  it("a civility list gets the vault's civility", () => {
    fill(list("c", "Civilité", [["1", "M."], ["2", "Mme"], ["3", "Mlle"]]) + NAMES, { honorific_prefix: "Mme", given_name: "Léa" });
    expect(sel("c").value).toBe("2");
  });

  it("a civility radio group, without a vault civility, follows the sex: Mme, never Mlle", () => {
    const filled = fill(radios("civ", "Civilité", [["M", "M."], ["MLLE", "Mlle"], ["MME", "Mme"]]) + NAMES, { given_name: "Léa" }, { sex: "f", civility_from_sex: true });
    expect(checked("civ")).toBe("MME");
    expect(filled).toContain("honorific_prefix");
  });

  it("a radio button fires click, input and change", () => {
    document.body.innerHTML = "";
    const seen: string[] = [];
    document.addEventListener("change", (e) => seen.push(`change:${(e.target as HTMLInputElement).value}`), true);
    document.addEventListener("input", (e) => seen.push(`input:${(e.target as HTMLInputElement).value}`), true);
    fill(radios("sx", "Sexe", [["H", "Homme"], ["F", "Femme"]]) + NAMES, { sex: "f", given_name: "Léa" });
    expect(checked("sx")).toBe("F");
    expect(seen).toContain("change:F");
    expect(seen).toContain("input:F");
  });

  it("a radio group the user already checked is left alone", () => {
    fill(radios("sx", "Sexe", [["H", "Homme"], ["F", "Femme"]], 0) + NAMES, { sex: "f", given_name: "Léa" });
    expect(checked("sx")).toBe("H");
  });

  it("a sex list in German by its labels; no civility from the sex unless asked", () => {
    fill(list("s", "Geschlecht", [["M", "Männlich"], ["W", "Weiblich"], ["D", "Divers"]]) + list("c", "Anrede", [["1", "Herr"], ["2", "Frau"]]) + row("g", "Vorname") + row("f", "Nachname"),
      { sex: "f", given_name: "Lea" }, { sex: "f" }, "de");
    expect(sel("s").value).toBe("W");
    expect(sel("c").value).toBe("");
  });
});

describe("nationality and issuing country", () => {
  it("a nationality list by country name or by demonym", () => {
    fill(list("n", "Nationalité", [["DE", "Allemagne"], ["FR", "France"]]) + NAMES, { nationality: "FR", given_name: "Léa" });
    expect(sel("n").value).toBe("FR");
    fill(list("n", "Nationalité", [["Allemande", "Allemande"], ["Française", "Française"]]) + NAMES, { nationality: "FR", given_name: "Léa" });
    expect(sel("n").value).toBe("Française");
  });

  it("a nationality text field gets the demonym in the page's language and the identity's sex", () => {
    fill(row("n", "Nationalité") + NAMES, { nationality: "FR", given_name: "Léa" }, { sex: "f" });
    expect(inp("n").value).toBe("Française");
    fill(row("n", "Nationality") + row("g", "First name") + row("f", "Last name"), { nationality: "DE", given_name: "Lea" }, { sex: "f" }, "en");
    expect(inp("n").value).toBe("German");
  });

  it("an issuing country list next to a passport number by name; a text one gets the name", () => {
    const pass = row("pn", "Numéro de passeport");
    fill(NAMES + pass + list("ic", "Pays de délivrance", [["1", "Belgique"], ["2", "France"]]), { passport_issuing_country: "FR", given_name: "Léa", passport_number: "12AB34567" });
    expect(sel("ic").value).toBe("2");
    fill(NAMES + pass + row("ic", "Pays de délivrance"), { passport_issuing_country: "FR", given_name: "Léa", passport_number: "12AB34567" });
    expect(inp("ic").value).toBe("France");
  });
});
