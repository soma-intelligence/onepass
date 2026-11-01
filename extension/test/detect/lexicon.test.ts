// Lexicon gaps found by the autofill lab: each case is the markup of a lab
// site the heuristic left `unknown`, kept as small as the page that showed it.
import { describe, expect, it } from "vitest";
import { classifyField } from "../../src/content/detect/fields";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import type { FieldRole } from "../../src/shared/messages";
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
