// Which vault item a filled form came from (smart fill metric `wrong_item`).
// The driver reads the site's field values in the page, keeps them in its
// own memory only, and asks here which fields hold a value of another vault
// item than the scenario's: names come back, never a value. A field that
// matches the scenario's own item is right, whatever else it matches; a
// field that matches no item at all is a fill problem (wrong_fill), not a
// wrong item. Short or shared values (expiry, CVC, country, code) are not
// telling and are left out.
import type { LabRole, Site, World } from "../gen/model.ts";
import { expectedValues, matches } from "../server/rp.ts";

type Values = Partial<Record<LabRole, string>>;

/** Roles whose value tells one item from another. */
const TELLING = new Set<LabRole>(["username", "email", "password", "cc_name", "cc_number", "given_name", "family_name", "tel",
  "birth_date", "organization", "address_line1", "address_line2", "postal_code", "city", "passport_number", "license_number",
  "vat_number", "company_id", "birth_name", "birth_place", "loyalty_number"]);

interface Doc { type: string; title: string; fields: Record<string, string> }
const docOf = (world: World, title: string | undefined) =>
  title === undefined ? undefined : (world.fixture.items as Doc[]).find((i) => i.title === title)?.fields;

/**
 * The values the vault holds for `site`'s own items (login, card or identity). A travel site's form
 * takes the passport's names, but the identity's own names are the user's too.
 */
function ownValues(world: World, site: Site): Values[] {
  if (site.identityTitle !== undefined && site.forms?.passportTitle !== undefined) {
    const id = docOf(world, site.identityTitle);
    return [expectedValues(world, site), { given_name: id?.first_name ?? "", family_name: id?.last_name ?? "" }];
  }
  return [ownValue(world, site)];
}

function ownValue(world: World, site: Site): Values {
  if (site.cardTitle !== undefined || site.identityTitle !== undefined) return expectedValues(world, site);
  // A signup's account is the one the user types, not a vault item.
  if (site.account && site.flow !== "signup") {
    const { username, password } = site.account;
    return { username, email: username, password };
  }
  if (site.sso) return { username: site.sso.email, email: site.sso.email };
  return {};
}

/** Every item value of the world but `site`'s own: the other sites' items and the provider accounts. */
function otherValues(world: World, site: Site): Values[] {
  const out = world.sites.filter((s) => s.index !== site.index).flatMap((s) => ownValues(world, s));
  // A decoy passport (another traveller's) is another item, on its own site too.
  for (const s of world.sites) {
    const d = docOf(world, s.forms?.decoyPassportTitle);
    if (d) out.push({ passport_number: d.number, given_name: d.first_names, family_name: d.last_name, birth_date: d.birth_date, birth_place: d.birth_place });
  }
  for (const accounts of Object.values(world.idp)) {
    for (const a of accounts) out.push({ username: a.email, email: a.email, password: a.password });
  }
  return out;
}

/**
 * Names of the site's fields whose value (`values`, by field name, read in
 * the page) belongs to another vault item and not to the scenario's.
 * Fields the user typed (`typed`) are skipped.
 */
export function foreignFields(world: World, site: Site, values: Record<string, string>, typed: readonly string[] = []): string[] {
  const own = ownValues(world, site);
  const others = otherValues(world, site);
  const ownMatch = (role: LabRole, v: string, f: Site["fields"][number]) =>
    own.some((o) => o[role] !== undefined && o[role] !== "" && matches(role, v, o[role]!, site.lang, f));
  return site.fields.filter((f) => {
    if (!TELLING.has(f.role) || typed.includes(f.name)) return false;
    const v = values[f.name] ?? "";
    if (v.trim() === "") return false;
    if (ownMatch(f.role, v, f)) return false;
    return others.some((o) => {
      const theirs = o[f.role];
      return theirs !== undefined && theirs !== "" && matches(f.role, v, theirs, site.lang, f);
    });
  }).map((f) => f.name);
}
