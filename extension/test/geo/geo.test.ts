import { describe, expect, it } from "vitest";
import { COUNTRY_CODES, countryName, resolveCountry, resolveCountryValue } from "../../src/content/geo/countries";
import { fold } from "../../src/content/geo/fold";
import { regionFromPostal } from "../../src/content/geo/postal";
import { REGIONS, parentRegion, regionText, resolveRegion } from "../../src/content/geo/regions";

describe("fold", () => {
  it("drops accents, case and punctuation", () => {
    expect(fold("Île-de-France")).toBe("ile de france");
    expect(fold("  CÔTE-D'OR ")).toBe("cote d or");
    expect(fold("Baden-Württemberg")).toBe("baden wurttemberg");
    expect(fold("Straße")).toBe("strasse");
    expect(fold("Calif.")).toBe("calif");
  });
});

describe("countries", () => {
  it("has every ISO 3166-1 entry once", () => {
    expect(COUNTRY_CODES.length).toBe(250);
    expect(new Set(COUNTRY_CODES).size).toBe(COUNTRY_CODES.length);
  });

  it("resolves alpha-2, alpha-3 and numeric codes", () => {
    expect(resolveCountry("FR")).toBe("FR");
    expect(resolveCountry("fr")).toBe("FR");
    expect(resolveCountry("FRA")).toBe("FR");
    expect(resolveCountry("250")).toBe("FR");
    expect(resolveCountry("840")).toBe("US");
    expect(resolveCountry("4")).toBe("AF");
    expect(resolveCountry("DEU")).toBe("DE");
    expect(resolveCountry("GBR")).toBe("GB");
  });

  it("reads an option value as an ISO numeric code only when it has exactly 3 digits", () => {
    expect(resolveCountryValue("004")).toBe("AF");
    expect(resolveCountryValue("250")).toBe("FR");
    for (const id of ["4", "04", "1", "12", "0004", "2500"]) expect(resolveCountryValue(id)).toBeNull();
    expect(resolveCountryValue("FR")).toBe("FR");
    expect(resolveCountryValue("FRA")).toBe("FR");
    expect(resolveCountryValue("France")).toBe("FR");
  });

  it("resolves names in the page language, French and English", () => {
    expect(resolveCountry("France")).toBe("FR");
    expect(resolveCountry("Allemagne")).toBe("DE");
    expect(resolveCountry("Germany")).toBe("DE");
    expect(resolveCountry("Deutschland", ["de"])).toBe("DE");
    expect(resolveCountry("Deutschland")).toBeNull();
    expect(resolveCountry("États-Unis")).toBe("US");
    expect(resolveCountry("etats unis")).toBe("US");
    expect(resolveCountry("United States")).toBe("US");
    expect(resolveCountry("Royaume-Uni")).toBe("GB");
    expect(resolveCountry("España", ["es"])).toBe("ES");
  });

  it("knows common aliases and ignores a parenthesised suffix", () => {
    expect(resolveCountry("USA")).toBe("US");
    expect(resolveCountry("United States of America")).toBe("US");
    expect(resolveCountry("UK")).toBe("GB");
    expect(resolveCountry("Great Britain")).toBe("GB");
    expect(resolveCountry("France (+33)")).toBe("FR");
    expect(resolveCountry("Canada (CA)")).toBe("CA");
    expect(resolveCountry("🇫🇷 France")).toBe("FR");
  });

  it("refuses what is not a country", () => {
    expect(resolveCountry("")).toBeNull();
    expect(resolveCountry("Choose a country")).toBeNull();
    expect(resolveCountry("XX")).toBeNull();
    expect(resolveCountry("--")).toBeNull();
  });

  it("names a country in a language", () => {
    expect(countryName("DE", "fr")).toBe("Allemagne");
    expect(countryName("DE", "en")).toBe("Germany");
  });
});

describe("regions", () => {
  it("covers the four tables", () => {
    const by = (cc: string) => REGIONS.filter((r) => r.code.startsWith(`${cc}-`)).length;
    expect(by("US")).toBe(57); // 50 states, DC, AS GU MP PR UM VI
    expect(by("CA")).toBe(13);
    expect(by("FR")).toBe(13 + 96 + 5);
    expect(by("DE")).toBe(16);
  });

  it("resolves a canonical code, a bare code, a name and an abbreviation", () => {
    expect(resolveRegion("US-CA", null)).toEqual(["US-CA"]);
    expect(resolveRegion("CA", "US")).toEqual(["US-CA"]);
    expect(resolveRegion("California", "US")).toEqual(["US-CA"]);
    expect(resolveRegion("Calif.", "US")).toEqual(["US-CA"]);
    expect(resolveRegion("N.Y.", "US")).toEqual(["US-NY"]);
    expect(resolveRegion("Washington D.C.", "US")).toEqual(["US-DC"]);
    expect(resolveRegion("Washington", "US")).toEqual(["US-WA"]);
    expect(resolveRegion("Québec", "CA")).toEqual(["CA-QC"]);
    expect(resolveRegion("PEI", "CA")).toEqual(["CA-PE"]);
    expect(resolveRegion("Bayern", "DE")).toEqual(["DE-BY"]);
    expect(resolveRegion("Bavaria", "DE")).toEqual(["DE-BY"]);
    expect(resolveRegion("Bavière", null)).toEqual(["DE-BY"]);
    expect(resolveRegion("NRW", "DE")).toEqual(["DE-NW"]);
  });

  it("reads French departments and regions", () => {
    expect(resolveRegion("75", "FR")).toEqual(["FR-75"]);
    expect(resolveRegion("75 - Paris", "FR")).toEqual(["FR-75"]);
    expect(resolveRegion("Paris (75)", "FR")).toEqual(["FR-75"]);
    expect(resolveRegion("01", "FR")).toEqual(["FR-01"]);
    expect(resolveRegion("1", "FR")).toEqual(["FR-01"]);
    expect(resolveRegion("Ain", "FR")).toEqual(["FR-01"]);
    expect(resolveRegion("2A", "FR")).toEqual(["FR-2A"]);
    expect(resolveRegion("Rhone", "FR")).toEqual(["FR-69"]);
    expect(resolveRegion("Île-de-France", "FR")).toEqual(["FR-IDF"]);
    expect(resolveRegion("PACA", "FR")).toEqual(["FR-PAC"]);
    expect(resolveRegion("Lot", "FR")).toEqual(["FR-46"]);
    expect(resolveRegion("La Réunion", "FR")).toEqual(["FR-974"]);
  });

  it("gives every candidate when the country is unknown", () => {
    expect(resolveRegion("CA", null)).toEqual(["US-CA"]);
    expect(resolveRegion("NS", null)).toEqual(["CA-NS"]);
    expect(resolveRegion("75 - Paris", "US")).toEqual([]);
    // Parts that disagree name nothing.
    expect(resolveRegion("75 - Lyon", "FR")).toEqual([]);
  });

  it("knows the region of each French department", () => {
    expect(parentRegion("FR-69")).toBe("FR-ARA");
    expect(parentRegion("FR-75")).toBe("FR-IDF");
    expect(parentRegion("FR-2B")).toBe("FR-20R");
    expect(parentRegion("FR-29")).toBe("FR-BRE");
    expect(parentRegion("US-CA")).toBeNull();
    const depts = REGIONS.filter((r) => /^FR-(\d\d|2[AB])$/.test(r.code));
    expect(depts).toHaveLength(96);
    for (const d of depts) expect(parentRegion(d.code), d.code).not.toBeNull();
  });

  it("writes a canonical region into a text field as people do", () => {
    expect(regionText("US-CA")).toBe("CA");
    expect(regionText("CA-QC")).toBe("QC");
    expect(regionText("FR-IDF")).toBe("Île-de-France");
    expect(regionText("DE-BY")).toBe("Bayern");
    expect(regionText("Rhone")).toBe("Rhone");
    expect(regionText("CA")).toBe("CA");
  });
});

describe("postal codes", () => {
  it("deduces a US state from a ZIP code", () => {
    expect(regionFromPostal("US", "94103")).toBe("US-CA");
    expect(regionFromPostal("US", "10001-1234")).toBe("US-NY");
    expect(regionFromPostal("US", "97201")).toBe("US-OR");
    expect(regionFromPostal("US", "20001")).toBe("US-DC");
    expect(regionFromPostal("US", "20120")).toBe("US-VA");
    expect(regionFromPostal("US", "73301")).toBe("US-TX");
    expect(regionFromPostal("US", "73101")).toBe("US-OK");
    expect(regionFromPostal("US", "00901")).toBe("US-PR");
    expect(regionFromPostal("US", "00802")).toBe("US-VI");
    expect(regionFromPostal("US", "96910")).toBe("US-GU");
    expect(regionFromPostal("US", "96799")).toBe("US-AS");
    expect(regionFromPostal("US", "96950")).toBe("US-MP");
    expect(regionFromPostal("US", "96813")).toBe("US-HI");
    expect(regionFromPostal("US", "99501")).toBe("US-AK");
    expect(regionFromPostal("US", "09012")).toBeNull(); // AE, military
    expect(regionFromPostal("US", "abc")).toBeNull();
  });

  it("deduces a French department, Corsica and overseas included", () => {
    expect(regionFromPostal("FR", "75008")).toBe("FR-75");
    expect(regionFromPostal("FR", "01000")).toBe("FR-01");
    expect(regionFromPostal("FR", "20000")).toBe("FR-2A");
    expect(regionFromPostal("FR", "20190")).toBe("FR-2A");
    expect(regionFromPostal("FR", "20200")).toBe("FR-2B");
    expect(regionFromPostal("FR", "20600")).toBe("FR-2B");
    expect(regionFromPostal("FR", "97400")).toBe("FR-974");
    expect(regionFromPostal("FR", "97600")).toBe("FR-976");
    expect(regionFromPostal("FR", "98000")).toBeNull();
    expect(regionFromPostal("FR", "00100")).toBeNull();
    expect(regionFromPostal("DE", "80331")).toBeNull();
  });
});
