import { describe, expect, it } from "vitest";
import { pickCountry, pickRegion, regionWanted } from "../../src/content/geo/options";

const o = (...pairs: [string, string][]) => pairs.map(([value, text]) => ({ value, text }));
const names = (...texts: string[]) => texts.map((text) => ({ value: text, text }));
const L = ["fr", "en"];

describe("country options", () => {
  it("matches a code with a name, a name with a code, whatever the case and accents", () => {
    expect(pickCountry(o(["", "Pays"], ["DE", "Allemagne"], ["FR", "France"]), "FR", L)).toBe(2);
    expect(pickCountry(names("Allemagne", "France", "États-Unis"), "US", L)).toBe(2);
    expect(pickCountry(names("Germany", "United States"), "US", L)).toBe(1);
    expect(pickCountry(o(["276", "Germany"], ["250", "France"]), "fra", L)).toBe(1);
    expect(pickCountry(o(["1", "Spain"], ["2", "Germany"]), "Deutschland", ["de", ...L])).toBe(1);
    expect(pickCountry(o(["DEU", "Deutschland"], ["FRA", "Frankreich"]), "FR", ["de", ...L])).toBe(1);
    expect(pickCountry(names("ETATS UNIS", "FRANCE"), "États-Unis", L)).toBe(0);
  });

  it("a database id as the value is not an ISO numeric code", () => {
    // "4" would be Afghanistan, "36" Australia: ids of the shop's own table.
    expect(pickCountry(o(["4", "Länd 4"], ["36", "Länd 36"]), "AF", L)).toBe(-1);
    expect(pickCountry(o(["4", "Länd 4"], ["36", "Länd 36"]), "AU", L)).toBe(-1);
    expect(pickCountry(o(["004", "Länd 4"], ["036", "Länd 36"]), "AU", L)).toBe(1);
  });

  it("an exact value wins first", () => {
    expect(pickCountry(o(["France", "France"], ["FR", "France métropolitaine"]), "FR", L)).toBe(1);
  });

  it("duplicates of one value are no tie; two values are", () => {
    // Favourite countries on top, then the full list.
    expect(pickCountry(o(["US", "United States"], ["FR", "France"], ["", "---"], ["FR", "France"], ["US", "United States"]), "US", L)).toBe(0);
    expect(pickCountry(o(["us1", "United States"], ["us2", "USA"]), "US", L)).toBe(-1);
  });

  it("never picks the placeholder or an unknown country", () => {
    expect(pickCountry(o(["", "Choose"], ["DE", "Germany"]), "FR", L)).toBe(-1);
    expect(pickCountry(o(["", "Choose"]), "", L)).toBe(-1);
  });

  it("an unresolved value falls back to plain text equality", () => {
    expect(pickCountry(names("Atlantis", "Lemuria"), "lemuria", L)).toBe(1);
  });
});

describe("region options", () => {
  it("states by code, name or abbreviation", () => {
    const states = o(["", "State"], ["AL", "Alabama"], ["CA", "California"], ["NY", "New York"]);
    expect(pickRegion(states, regionWanted("US-CA", "US", null), "US")).toBe(2);
    expect(pickRegion(states, regionWanted("Calif.", "US", null), "US")).toBe(2);
    expect(pickRegion(states, regionWanted("new york", "US", null), "US")).toBe(3);
    expect(pickRegion(names("Alabama", "California"), regionWanted("CA", "US", null), "US")).toBe(1);
    expect(pickRegion(o(["12", "California"], ["13", "Colorado"]), regionWanted("CA", null, null), null)).toBe(0);
  });

  it("French departments written in every usual way", () => {
    const depts = o(["", "Département"], ["01", "01 - Ain"], ["69", "69 - Rhône"], ["75", "75 - Paris"]);
    expect(pickRegion(depts, regionWanted("Rhone", "FR", null), "FR")).toBe(2);
    expect(pickRegion(depts, regionWanted("FR-75", "FR", null), "FR")).toBe(3);
    expect(pickRegion(names("Ain (01)", "Paris (75)"), regionWanted("75", "FR", null), "FR")).toBe(1);
  });

  it("a department picks its region when the list has regions only", () => {
    const regions = names("Auvergne-Rhône-Alpes", "Bretagne", "Île-de-France");
    expect(pickRegion(regions, regionWanted("Rhone", "FR", null), "FR")).toBe(0);
    expect(pickRegion(regions, regionWanted("FR-75", "FR", null), "FR")).toBe(2);
    // Never the other way round.
    expect(pickRegion(names("Ain", "Rhône"), regionWanted("Auvergne-Rhône-Alpes", "FR", null), "FR")).toBe(-1);
  });

  it("Länder and provinces with their exonyms", () => {
    expect(pickRegion(names("Bavaria", "Berlin", "Hesse"), regionWanted("Bayern", "DE", null), "DE")).toBe(0);
    expect(pickRegion(o(["QC", "Québec"], ["ON", "Ontario"]), regionWanted("Quebec", "CA", null), "CA")).toBe(0);
  });

  it("a state from another country's list is never picked", () => {
    // The list still shows US states: the FR department is not among them.
    expect(pickRegion(o(["CA", "California"], ["OR", "Oregon"]), regionWanted("Rhone", "FR", null), "FR")).toBe(-1);
  });

  it("deduces the state from the postal code when the item has none", () => {
    const states = o(["", "State"], ["CA", "California"], ["OR", "Oregon"]);
    expect(pickRegion(states, regionWanted("", "US", "97201"), "US")).toBe(2);
    expect(pickRegion(names("Corse-du-Sud", "Haute-Corse"), regionWanted("", "FR", "20200"), "FR")).toBe(1);
    expect(regionWanted("", null, "97201")).toEqual([]);
  });

  it("a tie picks nothing", () => {
    // "Georgia" the state and "Georgia" the country, in one odd list.
    expect(pickRegion(o(["US-GA", "Georgia"], ["GE", "Georgia"]), regionWanted("Georgia", null, null), null)).toBe(-1);
    // Two options for one state, with different values.
    expect(pickRegion(o(["5", "California"], ["6", "CA - California"]), regionWanted("CA", "US", null), "US")).toBe(-1);
  });
});
