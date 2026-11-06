// Forms coverage, Task 11: the demonym table (spec section 8, ruling R8).
import { describe, expect, it } from "vitest";
import { demonym, demonymCountry } from "../../src/content/geo/demonyms";

const COUNTRIES = "AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE GB CH NO IS US CA MX BR AR JP CN IN AU MA DZ TN SN".split(" ");
const LANGS = ["fr", "en", "de", "es", "it", "pt", "nl"];

describe("demonyms", () => {
  it("every country of the spec has a demonym in the seven languages, read back to its code", () => {
    for (const l of LANGS) {
      for (const cc of COUNTRIES) {
        for (const fem of [false, true]) {
          const d = demonym(cc, l, fem);
          expect(d, `${cc} ${l}`).not.toBeNull();
          expect(demonymCountry(d!), `${d} (${l})`).toBe(cc);
        }
      }
    }
  });

  it("masculine and feminine forms of the spec", () => {
    expect(demonym("FR", "fr", true)).toBe("Française");
    expect(demonym("FR", "fr")).toBe("Français");
    expect(demonym("FR", "en")).toBe("French");
    expect(demonym("DE", "de")).toBe("Deutsch");
    expect(demonym("ES", "es", true)).toBe("Española");
    expect(demonym("IT", "it", true)).toBe("Italiana");
    expect(demonym("PT", "pt", true)).toBe("Portuguesa");
    expect(demonym("NL", "nl", true)).toBe("Nederlandse");
    expect(demonym("FR", "fr-CA", true)).toBe("Française");
  });

  it("reads nouns, case and accents, the (e) of both genders; unknown gives null", () => {
    expect(demonymCountry("Deutsche")).toBe("DE");
    expect(demonymCountry("FRANCAISE")).toBe("FR");
    expect(demonymCountry("Français(e)")).toBe("FR");
    expect(demonymCountry("Klingon")).toBeNull();
    expect(demonym("FR", "xx")).toBeNull();
  });
});
