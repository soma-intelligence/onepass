import { afterEach, describe, expect, it } from "vitest";
import { LANGS, setLang, t, tn } from "../../src/shared/i18n";
import fr from "../../src/shared/l10n/fr.json";
import en from "../../src/shared/l10n/en.json";
import es from "../../src/shared/l10n/es.json";
import itCat from "../../src/shared/l10n/it.json";

const catalogs = { fr, en, es, it: itCat } as const;

afterEach(() => setLang("fr"));

describe("i18n", () => {
  it("fills named arguments in every language", () => {
    setLang("fr");
    expect(t("menu.noLoginForHost", { host: "exemple.fr" })).toBe("Aucun login pour exemple.fr");
    setLang("es");
    expect(t("menu.noLoginForHost", { host: "ejemplo.es" })).toBe("No hay inicios de sesión para ejemplo.es");
    setLang("it");
    expect(t("menu.noLoginForHost", { host: "esempio.it" })).toBe("Nessun login per esempio.it");
  });

  it("picks the plural form by the language's rules", () => {
    setLang("en");
    expect(tn("overlay.moreOtherAccounts", 1, { more: 1 })).toBe("1 other account");
    expect(tn("overlay.moreOtherAccounts", 3, { more: 3 })).toBe("3 other accounts");
    setLang("fr");
    expect(tn("ui.otherAccounts", 1, { name: "Google" })).toBe("Autre compte Google");
    expect(tn("ui.otherAccounts", 2, { name: "Google" })).toBe("Autres comptes Google");
  });

  it("has the same keys and placeholders in every language", () => {
    const keys = Object.keys(fr).sort();
    for (const l of LANGS) {
      const cat = catalogs[l] as Record<string, unknown>;
      expect(Object.keys(cat).sort(), l).toEqual(keys);
      for (const k of keys) {
        const ref = JSON.stringify((fr as Record<string, unknown>)[k]).match(/\{[A-Za-z]\w*\}/g) ?? [];
        const got = JSON.stringify(cat[k]).match(/\{[A-Za-z]\w*\}/g) ?? [];
        expect(new Set(got), `${l} ${k}`).toEqual(new Set(ref));
      }
    }
  });
});
