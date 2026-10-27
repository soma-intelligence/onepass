import { describe, expect, it } from "vitest";
import { classifyField, scoreField } from "../../src/content/detect/fields";
import { byId, loadFixture } from "./helpers";

type Fieldish = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
const role = (id: string) => classifyField(byId(id) as Fieldish).role;

describe("classifyField: autocomplete is decisive", () => {
  it.each([
    ["username", "username"],
    ["email", "email"],
    ["current-password", "current_password"],
    ["new-password", "new_password"],
    ["one-time-code", "otp"],
    ["cc-name", "cc_name"],
    ["cc-number", "cc_number"],
    ["cc-exp", "cc_exp"],
    ["cc-exp-month", "cc_exp_month"],
    ["cc-exp-year", "cc_exp_year"],
    ["cc-csc", "cc_csc"],
    ["given-name", "given_name"],
    ["family-name", "family_name"],
    ["name", "full_name"],
    ["tel", "tel"],
    ["organization", "organization"],
    ["bday", "bday"],
    ["street-address", "address_line1"],
    ["address-line1", "address_line1"],
    ["address-line2", "address_line2"],
    ["postal-code", "postal_code"],
    ["address-level2", "city"],
    ["address-level1", "region"],
    ["country", "country"],
    ["section-a billing postal-code", "postal_code"],
    ["username webauthn", "username"],
  ])("%s -> %s", (ac, expected) => {
    document.body.innerHTML = `<input id="f" type="text" name="zzz" autocomplete="${ac}">`;
    expect(role("f")).toBe(expected);
  });

  it("ignores on/off and falls back to scoring", () => {
    document.body.innerHTML = '<input id="f" type="password" autocomplete="off">';
    expect(role("f")).toBe("current_password");
  });
});

describe("classifyField: weighted scoring", () => {
  it("English login", () => {
    loadFixture("login-en.html");
    expect(role("u")).toBe("username");
    expect(role("p")).toBe("current_password");
    expect(role("remember")).toBe("remember_me");
  });

  it("French login (neighbor text, placeholder)", () => {
    loadFixture("login-fr.html");
    expect(role("u")).toBe("username");
    expect(role("p")).toBe("current_password");
    expect(role("remember")).toBe("remember_me");
  });

  it("change password labels", () => {
    loadFixture("change-password.html");
    expect(role("old")).toBe("current_password");
    expect(role("new")).toBe("new_password");
    expect(role("again")).toBe("confirm_password");
  });

  it("OTP single field", () => {
    loadFixture("otp-single.html");
    expect(role("code")).toBe("otp");
  });

  it("card fields with separate month and year", () => {
    loadFixture("card-split.html");
    expect(role("holder")).toBe("cc_name");
    expect(role("num")).toBe("cc_number");
    expect(role("mm")).toBe("cc_exp_month");
    expect(role("yy")).toBe("cc_exp_year");
    expect(role("cvc")).toBe("cc_csc");
  });

  it("French card fields with MM/AA", () => {
    loadFixture("card-mmyy.html");
    expect(role("titulaire")).toBe("cc_name");
    expect(role("num")).toBe("cc_number");
    expect(role("exp")).toBe("cc_exp");
    expect(role("crypto")).toBe("cc_csc");
  });

  it("French identity and address", () => {
    loadFixture("identity-address.html");
    expect(role("fn")).toBe("given_name");
    expect(role("ln")).toBe("family_name");
    expect(role("tel")).toBe("tel");
    expect(role("org")).toBe("organization");
    expect(role("a1")).toBe("address_line1");
    expect(role("a2")).toBe("address_line2");
    expect(role("zip")).toBe("postal_code");
    expect(role("city")).toBe("city");
    expect(role("country")).toBe("country");
  });

  it("leaves a search box unknown", () => {
    loadFixture("multi-forms.html");
    expect(role("q")).toBe("unknown");
  });

  it("returns unknown below the threshold", () => {
    document.body.innerHTML = '<input id="f" type="text" name="foo">';
    expect(classifyField(byId("f") as HTMLInputElement)).toEqual({ role: "unknown", score: 0 });
  });

  it("a checkbox can only be remember_me", () => {
    document.body.innerHTML = '<label><input id="f" type="checkbox" name="email"> Email me offers</label>';
    expect(role("f")).toBe("unknown");
  });

  it("scoreField exposes one score per role", () => {
    document.body.innerHTML = '<input id="f" type="email" name="email">';
    const s = scoreField(byId("f") as HTMLInputElement);
    expect(s.email).toBeGreaterThan(s.username);
    expect(Object.keys(s)).toContain("cc_number");
  });

  it("caps hostile attribute lengths without throwing", () => {
    const big = "password ".repeat(100_000);
    document.body.innerHTML = `<input id="f" type="text">`;
    byId("f").setAttribute("placeholder", big);
    expect(() => classifyField(byId("f") as HTMLInputElement)).not.toThrow();
  });

  it.each([
    ["Code promo", "promo"],
    ["Promo code", "promo_code"],
    ["Code parrainage", "parrain"],
    ["Coupon", "coupon"],
    ["Gift card code", "gift"],
    ["Code de réduction", "reduc"],
  ])("%s is not an OTP", (label, name) => {
    document.body.innerHTML = `<label for="f">${label}</label><input id="f" name="${name}" type="text" inputmode="numeric" maxlength="8">`;
    expect(role("f")).not.toBe("otp");
    expect(role("f")).not.toBe("cc_csc");
  });

  it("a lone maxlength=1 field is not an OTP", () => {
    document.body.innerHTML = '<input id="f" name="mi" type="text" maxlength="1">';
    expect(role("f")).toBe("unknown");
  });

  it("classifies a textarea street address", () => {
    document.body.innerHTML = '<label for="f">Adresse</label><textarea id="f" name="adresse"></textarea>';
    expect(role("f")).toBe("address_line1");
    document.body.innerHTML = '<textarea id="g" autocomplete="street-address"></textarea>';
    expect(role("g")).toBe("address_line1");
  });
});
