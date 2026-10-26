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
  it("unknown_stays_unknown", () => {
    expect(classifyRole({ type: "text", label: "Banana", name: "q7" })).toBe("unknown");
  });
});
