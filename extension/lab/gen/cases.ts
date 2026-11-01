// Country and region fixture cases of the autofill lab (spec
// docs/superpowers/specs/2026-10-31-country-state-select-design.md): the
// hand-written checkout pages of lab/fixtures/country-state/, served as they
// are on one .test host each at CASE_PATH, and one identity item per case in
// the world's vault. The menu_fill driver opens the in-field menu on the
// page's name field (address fields carry no menu: content/icon.ts
// ICON_ROLES), picks the case's item, and the oracle reads each
// control after the fill settled (cases.json `expect`: the value of a field,
// else the trimmed text of an element). Fictional brands and people only.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const CASE_PATH = "/checkout";
export const CASES_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "country-state");

/** Each page's host and the field the user opens the menu in (its first or full name field). */
const PAGES: Record<string, { host: string; field: string }> = {
  "shopify-like.html": { host: "cascade-goods.test", field: "#first" },
  "stripe-like.html": { host: "lumen-studio.test", field: "#billingName" },
  "amazon-like.html": { host: "riverbend-market.test", field: "#fullName" },
  "fr-boutique.html": { host: "maison-ardoise.test", field: "#prenom" },
  "react-select-like.html": { host: "northwind-bikes.test", field: "#name" },
};

export interface CountryCase {
  /** "cs:<n>", n from 1 in cases.json order. */
  id: string;
  name: string;
  page: string;
  host: string;
  /** Selector of the field the menu is opened in. */
  field: string;
  /** Title of the case's identity item (the menu row). */
  title: string;
  /** Selector -> what the control must hold once the fill settled. */
  expect: Record<string, string>;
}

/** First name of the item of a case that names nobody. */
export const NO_NAME = "Sam";

interface RawCase { name: string; page: string; values: Record<string, string>; expect: Record<string, string> }

/** The identity item a case's values (by role) stand for, as the native host fixture reads it. */
function identityItem(title: string, v: Record<string, string>): unknown {
  let first = v.given_name ?? "";
  let last = v.family_name ?? "";
  if (v.full_name && !first && !last) {
    const parts = v.full_name.trim().split(/\s+/);
    last = parts.length > 1 ? parts.pop()! : "";
    first = parts.join(" ");
  }
  const address: Record<string, string> = {};
  const keys: [string, string][] = [["address_line1", "line1"], ["city", "city"], ["postal_code", "postal_code"], ["region", "region"], ["country", "country"]];
  for (const [role, key] of keys) if (v[role]) address[key] = v[role]!;
  const fields: Record<string, unknown> = { address };
  // The identity template requires a first name: a case without a name gets a
  // stand-in one (no expectation of the cases reads a name control).
  fields.first_name = first || NO_NAME;
  if (last) fields.last_name = last;
  if (v.email) fields.email = v.email;
  if (v.tel) fields.mobile_phone = v.tel;
  return { type: "identity", title, vault: "Lab", fields };
}

/** The cases of cases.json with their hosts and items (in file order). */
export function countryCases(dir: string = CASES_DIR): { cases: CountryCase[]; items: unknown[]; hosts: string[] } {
  const raw = (JSON.parse(readFileSync(join(dir, "cases.json"), "utf8")) as { cases: RawCase[] }).cases;
  const cases: CountryCase[] = [];
  const items: unknown[] = [];
  raw.forEach((c, k) => {
    const page = PAGES[c.page];
    if (!page) throw new Error(`lab: country case ${k + 1}: no host for page ${c.page}`);
    const who = c.values.full_name ?? [c.values.given_name, c.values.family_name].filter(Boolean).join(" ");
    const title = `${who || "Adresse"} (cas ${k + 1})`;
    cases.push({ id: `cs:${k + 1}`, name: c.name, page: c.page, host: page.host, field: page.field, title, expect: c.expect });
    items.push(identityItem(title, c.values));
  });
  return { cases, items, hosts: [...new Set(cases.map((c) => c.host))].sort() };
}

/** The page of `host` (static HTML of the fixture folder), or undefined for another host. */
export function casePage(host: string, dir: string = CASES_DIR): string | undefined {
  const page = Object.entries(PAGES).find(([, p]) => p.host === host)?.[0];
  return page ? readFileSync(join(dir, page), "utf8") : undefined;
}

/** Selectors whose control does not hold what the case expects (`got`: selector -> value read in the page). */
export function caseMismatches(c: CountryCase, got: Record<string, string>): string[] {
  return Object.entries(c.expect).filter(([sel, want]) => (got[sel] ?? "").trim() !== want).map(([sel]) => sel);
}
