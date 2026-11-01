// Lexicon gaps found by the autofill lab: each case is the markup of a lab
// site the heuristic left `unknown`, kept as small as the page that showed it.
import { describe, expect, it } from "vitest";
import { classifyField } from "../../src/content/detect/fields";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import type { FieldRole } from "../../src/shared/messages";
import seed from "../../lab/corpus/seed-lexicon.json";
import { testGeometry } from "./helpers";

const SITE = "https://sunny-valley-12.test/";

function roles(html: string): { kind: string; roles: Record<string, FieldRole> } {
  document.documentElement.innerHTML = `<head><title>Iniciar sesión</title></head><body>${html}</body>`;
  const refs = new RefRegistry();
  const a = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
  expect(a.forms).toHaveLength(1);
  const out: Record<string, FieldRole> = {};
  for (const fi of a.forms[0]!.fields) out[(refs.get(fi.ref) as HTMLElement).id] = fi.role;
  return { kind: a.forms[0]!.kind, roles: out };
}

describe("lexicon gaps (lab)", () => {
  // lab-2026-10-26 site 0 (inline layout): the label is plain text before the
  // field, so it only counts as nearby text; the field name "log" is
  // WordPress's identifier (wp-login.php: log, pwd).
  it("a field named log, with nearby text Nombre de usuario, is the username", () => {
    const html = '<form id="f" method="post" action="/login">'
      + '<div class="field lab-inline"><span class="lab-text">Nombre de usuario</span><input id="log" name="log" type="text"></div>'
      + '<div class="field lab-inline"><span class="lab-text">Tu contraseña</span><input id="p" name="mvrcquoj6shnm772u8" type="password"></div>'
      + '<button type="submit" id="lab-submit">Iniciar sesión</button></form>';
    expect(roles(html)).toEqual({ kind: "login", roles: { log: "username", p: "current_password" } });
  });

  it("the WordPress login form (log, pwd) without labels", () => {
    const html = '<form id="f" method="post" action="/wp-login.php"><input id="user_login" name="log" type="text">'
      + '<input id="user_pass" name="pwd" type="password"><button type="submit">Log In</button></form>';
    expect(roles(html)).toEqual({ kind: "login", roles: { user_login: "username", user_pass: "current_password" } });
  });

  it("log only as the whole text: a log level or a change log is not an identifier", () => {
    document.body.innerHTML = '<input id="a" name="log_level"><input id="b" name="changelog"><input id="c" placeholder="Search the log">';
    for (const id of ["a", "b", "c"]) expect(classifyField(document.getElementById(id) as HTMLInputElement).role).not.toBe("username");
  });
});

// The lab's baseline labels for Italian, Portuguese and Dutch (seed-lexicon.json,
// generator version 3): a field with one of them as its label gets its role.
const LAB_ROLE: Record<string, FieldRole> = {
  username: "username", email: "email", password: "current_password", otp: "otp", cc_name: "cc_name", cc_number: "cc_number",
  cc_exp: "cc_exp", cc_exp_month: "cc_exp_month", cc_exp_year: "cc_exp_year", cc_csc: "cc_csc", given_name: "given_name",
  family_name: "family_name", tel: "tel", birth_date: "bday", organization: "organization", address_line1: "address_line1",
  address_line2: "address_line2", postal_code: "postal_code", city: "city", country: "country",
};
const CARD = new Set(["cc_name", "cc_exp", "cc_exp_month", "cc_exp_year", "cc_csc"]);

describe("lab baseline labels it, pt, nl", () => {
  const roles = (seed as { roles: Record<string, { labels: Record<string, string[]> }> }).roles;
  for (const lang of ["it", "pt", "nl"]) {
    for (const [labRole, want] of Object.entries(LAB_ROLE)) {
      for (const label of roles[labRole]!.labels[lang] ?? []) {
        it(`${lang}: ${label} is ${want}`, () => {
          // Card fields sit next to a card number, as in the lab's card form.
          const number = CARD.has(labRole) ? '<label for="n">Card number</label><input id="n" autocomplete="cc-number">' : "";
          const type = labRole === "password" ? "password" : "text";
          document.body.innerHTML = `<form>${number}<label for="f">${label}</label><input id="f" name="x1" type="${type}"></form>`;
          expect(classifyField(document.getElementById("f") as HTMLInputElement).role).toBe(want);
        });
      }
    }
  }
});
