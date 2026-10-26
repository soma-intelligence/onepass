// Field role classifier of the corpus: autocomplete, then type, then label words.
import { describe, expect, it } from "vitest";
import { classifyRole } from "../../lab/corpus/roles.ts";

describe("classifyRole", () => {
  it("autocomplete_wins", () => {
    expect(classifyRole({ autocomplete: "cc-number", label: "Nom" })).toBe("cc_number");
  });
  it("type_password_new", () => {
    expect(classifyRole({ type: "password", autocomplete: "new-password" })).toBe("new_password");
    expect(classifyRole({ type: "password" })).toBe("password");
  });
  it("labels_in_languages", () => {
    expect(classifyRole({ type: "text", label: "Benutzername" })).toBe("username");
    expect(classifyRole({ type: "text", label: "Correo electrónico" })).toBe("email");
    expect(classifyRole({ type: "text", label: "Code postal" })).toBe("postal_code");
    expect(classifyRole({ type: "text", label: "Código postal" })).toBe("postal_code");
    expect(classifyRole({ type: "text", label: "PLZ" })).toBe("postal_code");
  });
  it("password_words_make_new_password", () => {
    for (const label of ["Confirmer le mot de passe", "New password", "Neues Passwort", "Nueva contraseña"]) {
      expect(classifyRole({ type: "password", label })).toBe("new_password");
    }
    expect(classifyRole({ type: "text", label: "Nueva contraseña" })).toBe("new_password");
    expect(classifyRole({ type: "password", label: "Mot de passe" })).toBe("password");
  });
  it("camel_case_new_password_names", () => {
    expect(classifyRole({ type: "password", name: "newPassword" })).toBe("new_password");
    expect(classifyRole({ type: "password", id: "confirmPassword" })).toBe("new_password");
    expect(classifyRole({ type: "password", name: "password" })).toBe("password");
  });
  it("current_password_autocomplete_not_overridden_by_name", () => {
    expect(classifyRole({ type: "password", autocomplete: "current-password", name: "newPassword" })).toBe("password");
  });
  it("nom_d_usage_is_family_name", () => {
    expect(classifyRole({ type: "text", label: "Nom d'usage" })).toBe("family_name");
    expect(classifyRole({ type: "text", name: "nom_d_usage" })).toBe("family_name");
  });
  it("unknown_stays_unknown", () => {
    expect(classifyRole({ type: "text", label: "Banana", name: "q7" })).toBe("unknown");
  });
});
