// @vitest-environment node
// Country and region fixture cases: one host per page, one identity item per
// case built from its values, and the oracle's comparison.
import { describe, expect, it } from "vitest";
import { NO_NAME, caseMismatches, casePage, countryCases } from "../../lab/gen/cases.ts";
import { generate, loadPatterns } from "../../lab/gen/generate.ts";

describe("country cases", () => {
  const { cases, items, hosts } = countryCases();

  it("eleven cases on five .test hosts, ids in file order", () => {
    expect(cases).toHaveLength(11);
    expect(cases.map((c) => c.id)).toEqual(Array.from({ length: 11 }, (_, k) => `cs:${k + 1}`));
    expect(hosts).toEqual(["cascade-goods.test", "lumen-studio.test", "maison-ardoise.test", "northwind-bikes.test", "riverbend-market.test"]);
    for (const h of hosts) expect(casePage(h)).toMatch(/<form /);
    expect(casePage("other.test")).toBeUndefined();
  });

  it("each case has its own identity item, names split from a full name", () => {
    expect(new Set(cases.map((c) => c.title)).size).toBe(11);
    expect(items[0]).toEqual({
      type: "identity", title: "Ada Lovelace (cas 1)", vault: "Lab",
      fields: { first_name: "Ada", last_name: "Lovelace", address: { line1: "12 rue Saint-Paul", city: "Montréal", postal_code: "H2Y 1G6", region: "CA-QC", country: "CA" } },
    });
    expect(items[5]).toMatchObject({ title: "Alan Turing (cas 6)", fields: { first_name: "Alan", last_name: "Turing", mobile_phone: "+1 212 555 0100" } });
    // No name in the case: the stand-in first name the identity template requires, no last name.
    expect(items[1]).toEqual({ type: "identity", title: "Adresse (cas 2)", vault: "Lab", fields: { first_name: NO_NAME, address: { line1: "1 Harbor Road", city: "Portland", postal_code: "97201", country: "US" } } });
  });

  it("a mismatch names the selector, an empty expectation wants an empty control", () => {
    const c = cases[2]!; // shopify, France: no zone field
    expect(caseMismatches(c, { "#country": "FR", "#zone-slot": "" })).toEqual([]);
    expect(caseMismatches(c, { "#country": "US", "#zone-slot": " " })).toEqual(["#country"]);
    expect(caseMismatches(c, {})).toEqual(["#country"]);
  });

  it("every world carries the cases, their items and their hosts", () => {
    const w = generate("cases", { sites: 12, patterns: loadPatterns() });
    expect(w.cases).toEqual(cases);
    for (const it of items) expect(w.fixture.items).toContainEqual(it);
    for (const h of hosts) expect(w.hosts).toContain(h);
  });
});
