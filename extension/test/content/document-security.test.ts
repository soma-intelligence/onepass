// Forms coverage, Task 13: document numbers follow the card rule (spec section 9, ruling R11).
// Most guards already hold; these tests pin them for passport and license numbers.
import { afterEach, describe, expect, it, vi } from "vitest";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import { createFiller } from "../../src/content/filler";
import type { FieldRole } from "../../src/shared/messages";
import { testGeometry } from "../detect/helpers";

const SITE = "https://blue-harbor-7.test/booking";
const NUMBER = "18AB12345";
const LICENSE = "120375201234";
const inp = (id: string) => document.getElementById(id) as HTMLInputElement;

afterEach(() => {
  document.documentElement.lang = "";
  document.body.innerHTML = "";
  vi.restoreAllMocks();
});

function fill(body: string, values: Partial<Record<FieldRole, string>>, onFill?: (el: Element, role: FieldRole) => void): FieldRole[] {
  document.documentElement.lang = "fr";
  document.body.innerHTML = body;
  const refs = new RefRegistry();
  const analyze = () => analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
  const filler = createFiller({ refs, geometry: testGeometry, analyze, resolve: (ref, a) => a.forms.find((f) => f.ref === ref) ?? null, settleMs: 0, ...(onFill ? { onFill } : {}) });
  const forms = analyze().forms;
  return forms.flatMap((f) => filler.fill(f.ref, values).filled);
}

const row = (id: string, label: string, extra = "") => `<label for="${id}">${label}</label><input id="${id}" name="${id}"${extra}>`;
const TRAVEL = (inner: string) => `<form>${row("g", "Prénom")}${row("f", "Nom")}${inner}<button type="submit">Réserver</button></form>`;
const VALUES = { given_name: "Léa", family_name: "Martin", passport_number: NUMBER, license_number: LICENSE };

describe("document numbers: the card rule", () => {
  it.each([
    ["display:none", ' style="display:none"'],
    ["visibility:hidden", ' style="visibility:hidden"'],
    ["opacity:0", ' style="opacity:0"'],
    ["off screen", ' data-test-rect="-5000,0,200,30"'],
    ["zero size", ' data-test-rect="0,0,0,0"'],
    ["clipped", ' style="clip-path:inset(100%)"'],
    ["aria-hidden", ' aria-hidden="true"'],
  ])("never into a %s trap; the visible passport field is filled", (_n, trap) => {
    fill(TRAVEL(row("trap", "Numéro de passeport", trap) + row("pn", "Numéro de passeport")), VALUES);
    expect(inp("trap").value).toBe("");
    expect(inp("pn").value).toBe(NUMBER);
  });

  it("only a field of the exact role: never an unknown field, an identifier or a code", () => {
    fill(TRAVEL(row("x", "Remarque") + row("u", "Identifiant", ' autocomplete="username"') + row("c", "Code reçu par SMS", ' autocomplete="one-time-code"') + row("ln", "Numéro de permis")), VALUES);
    expect([inp("x").value, inp("u").value, inp("c").value]).toEqual(["", "", ""]);
    expect(inp("ln").value).toBe(LICENSE);
  });

  it("never into a sign-in, sign-up, code or password change form", () => {
    const pass = row("pn", "Numéro de passeport");
    for (const form of [
      `<form>${row("e", "E-mail", ' type="email" autocomplete="username"')}${row("p", "Mot de passe", ' type="password" autocomplete="current-password"')}${pass}<button>Se connecter</button></form>`,
      `<form>${row("e", "E-mail", ' type="email" autocomplete="username"')}${row("p", "Mot de passe", ' type="password" autocomplete="new-password"')}${row("p2", "Confirmer", ' type="password" autocomplete="new-password"')}${pass}<button>Créer un compte</button></form>`,
      `<form>${row("o", "Code", ' autocomplete="one-time-code"')}${pass}<button>Valider</button></form>`,
      `<form>${row("p", "Mot de passe actuel", ' type="password" autocomplete="current-password"')}${row("p2", "Nouveau mot de passe", ' type="password" autocomplete="new-password"')}${pass}<button>Changer</button></form>`,
    ]) {
      fill(form, { ...VALUES, email: "lea@atlas.dev" });
      expect(inp("pn").value, form).toBe("");
    }
  });

  it("never into another passenger's block", () => {
    fill(`<form><fieldset><legend>Passager 1</legend>${row("g", "Prénom")}${row("pn", "Numéro de passeport")}</fieldset>`
      + `<fieldset><legend>Passager 2</legend>${row("g2", "Prénom")}${row("pn2", "Numéro de passeport")}</fieldset><button>Réserver</button></form>`, VALUES);
    expect(inp("pn").value).toBe(NUMBER);
    expect(inp("pn2").value).toBe("");
  });

  it("no number reaches the console nor the fill callback (roles only)", () => {
    const calls: unknown[][] = [];
    for (const k of ["log", "info", "warn", "error", "debug"] as const) vi.spyOn(console, k).mockImplementation((...a: unknown[]) => void calls.push(a));
    const told: unknown[][] = [];
    fill(TRAVEL(row("pn", "Numéro de passeport")), VALUES, (...a) => void told.push(a));
    expect(inp("pn").value).toBe(NUMBER);
    expect(JSON.stringify(calls)).not.toContain(NUMBER);
    expect(told.map((x) => x[1])).toContain("passport_number");
    expect(told.flat().some((x) => typeof x === "string" && x.includes(NUMBER))).toBe(false);
  });

  it("the hidden list behind a combobox is never chosen for an issuing country", () => {
    fill(TRAVEL(row("pn", "Numéro de passeport") + row("ic", "Pays de délivrance", ' role="combobox" aria-controls="lst"')
      + '<ul id="lst" role="listbox"></ul><select id="hidden" name="issuing" style="display:none"><option value=""></option><option value="FR">France</option></select>'),
    { ...VALUES, passport_issuing_country: "FR" });
    expect((document.getElementById("hidden") as HTMLSelectElement).value).toBe("");
  });
});
