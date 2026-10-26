// Sanitizer of the corpus extractor: nothing personal or long leaves a page.
import { describe, expect, it } from "vitest";
import { sanitizeText, sanitizeToken } from "../../lab/corpus/sanitize.ts";

describe("sanitize", () => {
  it("redacts_email", () => {
    expect(sanitizeText("jean.dupont@exemple.fr")).toBe("<redacted>");
  });
  it("redacts_card_like", () => {
    expect(sanitizeText("4111 1111 1111 1111")).toBe("<redacted>");
  });
  it("redacts_long_digit_run", () => {
    expect(sanitizeText("Code 12345")).toBe("<redacted>");
  });
  it("keeps_short_label", () => {
    expect(sanitizeText("Mot de passe")).toBe("Mot de passe");
  });
  it("truncates_60", () => {
    const out = sanitizeText("Entrez " + "votre adresse postale complete ".repeat(4))!;
    expect(out.length).toBe(60);
  });
  it("long_token", () => {
    expect(sanitizeToken("ab-cd-".repeat(9))).toBe("<long>");
    expect(sanitizeToken("user_name")).toBe("user_name");
    expect(sanitizeToken(undefined)).toBeUndefined();
  });
  it("token_redacts_digits_email_and_opaque", () => {
    expect(sanitizeToken("field_20251026")).toBe("<redacted>");
    expect(sanitizeToken("jean@exemple.fr")).toBe("<redacted>");
    expect(sanitizeToken("a1b2c3d4e5f6g7h8i9j0k1l2m3")).toBe("<redacted>");
    expect(sanitizeToken("a".repeat(30))).toBe("<redacted>");
    expect(sanitizeToken("input-12")).toBe("input-12");
  });
});
