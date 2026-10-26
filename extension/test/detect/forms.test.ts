import { describe, expect, it } from "vitest";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import type { FieldRole, FormInfo, PageAnalysis } from "../../src/shared/messages";
import { byId, loadFixture, testGeometry } from "./helpers";

const SITE = "https://atlas-cloud.test/login";

function analyze(name: string, url = SITE): { a: PageAnalysis; refs: RefRegistry } {
  const doc = loadFixture(name);
  const refs = new RefRegistry();
  return { a: analyzeDocument(doc, refs, { url, geometry: testGeometry }), refs };
}

/** Field roles of a form keyed by element id, for readable assertions. */
function roles(f: FormInfo, refs: RefRegistry): Record<string, FieldRole> {
  const out: Record<string, FieldRole> = {};
  for (const fi of f.fields) out[(refs.get(fi.ref) as HTMLElement).id] = fi.role;
  return out;
}

function idOf(refs: RefRegistry, ref: string | undefined): string | undefined {
  return ref === undefined ? undefined : (refs.get(ref) as HTMLElement | null)?.id;
}

describe("analyzeDocument: form kinds", () => {
  it("login, English", () => {
    const { a, refs } = analyze("login-en.html");
    expect(a.url).toBe(SITE);
    expect(a.forms).toHaveLength(1);
    const f = a.forms[0]!;
    expect(f.kind).toBe("login");
    expect(idOf(refs, f.ref)).toBe("login");
    expect(roles(f, refs)).toEqual({ u: "username", p: "current_password", remember: "remember_me" });
    expect(idOf(refs, f.submitRef)).toBe("submit");
  });

  it("login, French", () => {
    const { a, refs } = analyze("login-fr.html");
    expect(a.forms.map((f) => f.kind)).toEqual(["login"]);
    expect(roles(a.forms[0]!, refs)).toMatchObject({ u: "username", p: "current_password" });
    expect(idOf(refs, a.forms[0]!.submitRef)).toBe("submit");
  });

  it("first step with identifier only and a Next button", () => {
    const { a, refs } = analyze("login-username-first.html");
    expect(a.forms).toHaveLength(1);
    expect(a.forms[0]!.kind).toBe("login");
    expect(idOf(refs, a.forms[0]!.ref)).toBe("step1");
    expect(idOf(refs, a.forms[0]!.submitRef)).toBe("next");
  });

  it("signup with password confirmation", () => {
    const { a, refs } = analyze("signup.html");
    expect(a.forms).toHaveLength(1);
    expect(a.forms[0]!.kind).toBe("signup");
    expect(roles(a.forms[0]!, refs)).toEqual({ mail: "email", pw1: "new_password", pw2: "confirm_password" });
    expect(idOf(refs, a.forms[0]!.submitRef)).toBe("submit");
  });

  it("unlabelled signup: two password fields become new and confirm", () => {
    document.body.innerHTML =
      '<form id="f"><input id="e" type="email"><input id="a" type="password"><input id="b" type="password"></form>';
    const refs = new RefRegistry();
    const a = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
    expect(a.forms[0]!.kind).toBe("signup");
    expect(roles(a.forms[0]!, refs)).toEqual({ e: "email", a: "new_password", b: "confirm_password" });
  });

  it("change password", () => {
    const { a, refs } = analyze("change-password.html");
    expect(a.forms.map((f) => f.kind)).toEqual(["change_password"]);
    expect(roles(a.forms[0]!, refs)).toEqual({ old: "current_password", new: "new_password", again: "confirm_password" });
  });

  it("OTP, single field", () => {
    const { a, refs } = analyze("otp-single.html");
    expect(a.forms.map((f) => f.kind)).toEqual(["otp"]);
    expect(roles(a.forms[0]!, refs)).toEqual({ code: "otp" });
  });

  it("OTP split into six cells is one logical field", () => {
    const { a, refs } = analyze("otp-split.html");
    expect(a.forms).toHaveLength(1);
    const f = a.forms[0]!;
    expect(f.kind).toBe("otp");
    expect(f.fields).toHaveLength(1);
    expect(f.fields[0]!.role).toBe("otp");
    expect(idOf(refs, f.fields[0]!.ref)).toBe("c1");
    expect(f.fields[0]!.parts?.map((r) => idOf(refs, r))).toEqual(["c1", "c2", "c3", "c4", "c5", "c6"]);
  });

  it("card with separate month and year", () => {
    const { a, refs } = analyze("card-split.html");
    expect(a.forms.map((f) => f.kind)).toEqual(["card"]);
    expect(roles(a.forms[0]!, refs)).toEqual({
      holder: "cc_name",
      num: "cc_number",
      mm: "cc_exp_month",
      yy: "cc_exp_year",
      cvc: "cc_csc",
    });
  });

  it("card with MM/AA", () => {
    const { a, refs } = analyze("card-mmyy.html");
    expect(a.forms.map((f) => f.kind)).toEqual(["card"]);
    expect(roles(a.forms[0]!, refs)).toEqual({ titulaire: "cc_name", num: "cc_number", exp: "cc_exp", crypto: "cc_csc" });
  });

  it("identity with address, and address alone", () => {
    const { a, refs } = analyze("identity-address.html");
    expect(a.forms.map((f) => f.kind)).toEqual(["identity", "address"]);
    expect(idOf(refs, a.forms[1]!.ref)).toBe("ship");
    expect(a.forms[1]!.submitRef).toBeUndefined();
  });

  it("fields outside any <form> are grouped by container", () => {
    const { a, refs } = analyze("no-form.html");
    expect(a.forms.map((f) => f.kind)).toEqual(["login", "card"]);
    expect(idOf(refs, a.forms[0]!.ref)).toBe("login-panel");
    expect(roles(a.forms[0]!, refs)).toEqual({ u: "email", p: "current_password" });
    expect(idOf(refs, a.forms[0]!.submitRef)).toBe("go");
    expect(idOf(refs, a.forms[1]!.ref)).toBe("card-panel");
    expect(a.forms[0]!.ref).not.toBe(a.forms[1]!.ref);
  });

  it("invisible, disabled and readonly fields are ignored", () => {
    const { a, refs } = analyze("hidden-fields.html");
    expect(a.forms).toHaveLength(1);
    expect(a.forms[0]!.kind).toBe("login");
    expect(roles(a.forms[0]!, refs)).toEqual({ u: "username", p: "current_password" });
  });

  it("login, signup and search on one page stay distinct", () => {
    const { a, refs } = analyze("multi-forms.html");
    expect(a.forms.map((f) => [idOf(refs, f.ref), f.kind])).toEqual([
      ["login", "login"],
      ["signup", "signup"],
    ]);
    expect(idOf(refs, a.forms[0]!.submitRef)).toBe("l-go");
    expect(idOf(refs, a.forms[1]!.submitRef)).toBe("s-go");
    expect(a.forms.flatMap((f) => f.fields).some((fi) => idOf(refs, fi.ref) === "q")).toBe(false);
  });

  it("card page with promo, gift and referral codes stays a card form", () => {
    const { a, refs } = analyze("card-promo.html");
    expect(a.forms.map((f) => f.kind)).toEqual(["card"]);
    expect(roles(a.forms[0]!, refs)).toEqual({ num: "cc_number", exp: "cc_exp" });
  });

  it("identity with a middle initial stays an identity form", () => {
    const { a, refs } = analyze("identity-initial.html");
    expect(a.forms.map((f) => f.kind)).toEqual(["identity"]);
    expect(roles(a.forms[0]!, refs)).toEqual({ fn: "given_name", ln: "family_name", tel: "tel" });
  });

  it("an OTP field next to identity fields does not make an otp form", () => {
    document.body.innerHTML =
      '<form><input autocomplete="given-name"><input autocomplete="family-name"><input autocomplete="one-time-code"></form>';
    const a = analyzeDocument(document, new RefRegistry(), { url: SITE, geometry: testGeometry });
    expect(a.forms.map((f) => f.kind)).toEqual(["identity"]);
  });

  it("an OTP field with an identifier is still an otp form", () => {
    document.body.innerHTML =
      '<form><input type="email" name="email" readonly><input autocomplete="username"><input autocomplete="one-time-code"></form>';
    const a = analyzeDocument(document, new RefRegistry(), { url: SITE, geometry: testGeometry });
    expect(a.forms.map((f) => f.kind)).toEqual(["otp"]);
  });

  it("a split OTP in cells wrapped one per div is one field", () => {
    document.body.innerHTML =
      "<form>" +
      [1, 2, 3, 4].map((i) => `<div><input id="k${i}" type="text" maxlength="1"></div>`).join("") +
      "</form>";
    const refs = new RefRegistry();
    const a = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
    expect(a.forms.map((f) => f.kind)).toEqual(["otp"]);
    expect(a.forms[0]!.fields[0]!.parts?.map((r) => idOf(refs, r))).toEqual(["k1", "k2", "k3", "k4"]);
  });

  it("a long page: 1200 links and 600 hidden inputs before an identifier + Next form", () => {
    const links = Array.from({ length: 1200 }, (_, i) => `<a href="/p/${i}">Page ${i}</a>`).join("");
    const hidden = Array.from({ length: 600 }, (_, i) => `<input type="hidden" name="h${i}">`).join("");
    document.body.innerHTML =
      `<nav>${links}</nav><div>${hidden}</div>` +
      '<form id="step1"><input id="e" type="email" name="email"><button id="next" type="button">Suivant</button></form>' +
      '<a id="g" href="https://accounts.google.com/o/oauth2/auth">Continue with Google</a>';
    const refs = new RefRegistry();
    const a = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
    expect(a.forms.map((f) => [idOf(refs, f.ref), f.kind, idOf(refs, f.submitRef)])).toEqual([["step1", "login", "next"]]);
    expect(a.providerButtons.map((b) => idOf(refs, b.ref))).toEqual(["g"]);
  });

  it("a login form far down a long page is found", () => {
    document.body.innerHTML =
      '<form id="f"><input name="username" data-test-rect="0,3000,200,30"><input type="password" data-test-rect="0,3040,200,30"></form>';
    const a = analyzeDocument(document, new RefRegistry(), { url: SITE, geometry: testGeometry });
    expect(a.forms.map((f) => f.kind)).toEqual(["login"]);
  });

  it("textarea address fields are analyzed", () => {
    document.body.innerHTML =
      '<form><label for="t">Adresse</label><textarea id="t" name="adresse"></textarea><input autocomplete="postal-code"></form>';
    const refs = new RefRegistry();
    const a = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
    expect(a.forms.map((f) => f.kind)).toEqual(["address"]);
    expect(roles(a.forms[0]!, refs)).toMatchObject({ t: "address_line1" });
  });

  it("a plain page has no forms and no signals", () => {
    const { a } = analyze("push-en.html");
    expect(a.forms).toEqual([]);
    expect(a.captcha).toBe(false);
    expect(a.providerButtons).toEqual([]);
    expect(a.accountChooser).toEqual([]);
  });

  it("never derives refs from page attributes", () => {
    const { a } = analyze("login-en.html");
    const all = a.forms.flatMap((f) => [f.ref, f.submitRef ?? "", ...f.fields.map((x) => x.ref)]);
    for (const r of all) expect(["login", "u", "p", "pass", "submit", "remember"]).not.toContain(r);
    expect(byId("u").getAttribute("data-onepass")).toBeNull();
  });
});

describe("analyzeDocument: page signals", () => {
  it("CAPTCHA iframe", () => {
    expect(analyze("captcha.html").a.captcha).toBe(true);
  });

  it("CAPTCHA text", () => {
    expect(analyze("captcha-text.html").a.captcha).toBe(true);
  });

  it("push approval, French", () => {
    const { a } = analyze("push.html");
    expect(a.push).toBe(true);
    expect(a.captcha).toBe(false);
  });

  it("push approval, English", () => {
    expect(analyze("push-en.html").a.push).toBe(true);
  });

  it("no push on an ordinary login page", () => {
    expect(analyze("login-en.html").a.push).toBe(false);
  });

  it("provider buttons by text, aria-label and official link", () => {
    const { a, refs } = analyze("provider-buttons.html");
    expect(a.providerButtons.map((b) => [b.provider, idOf(refs, b.ref)])).toEqual([
      ["google", "b-google"],
      ["apple", "b-apple"],
      ["microsoft", "b-ms"],
      ["github", "b-gh"],
    ]);
    // The "Continue" submit button is not a provider button and still drives the form.
    expect(a.forms.map((f) => f.kind)).toEqual(["login"]);
    expect(idOf(refs, a.forms[0]!.submitRef)).toBe("next");
  });

  it("account chooser on an official provider host", () => {
    const { a, refs } = analyze("account-chooser.html", "https://accounts.google.com/v3/signin/accountchooser");
    expect(a.accountChooser.map((e) => [e.email, idOf(refs, e.ref)])).toEqual([
      ["alex.perso@example.com", "acc1-link"],
      ["alex.pro@example.com", "acc2-link"],
      ["alex@atlas.dev", "acc4-btn"],
    ]);
  });

  it("no account chooser on a look-alike host", () => {
    const { a } = analyze("account-chooser.html", "https://accounts.google.com.evil.test/v3/signin");
    expect(a.accountChooser).toEqual([]);
  });

  it("no account chooser on the site itself", () => {
    expect(analyze("account-chooser.html").a.accountChooser).toEqual([]);
  });
});
