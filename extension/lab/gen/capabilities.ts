// Capability table of the autofill lab (spec 4.5): what the extension is known
// not to do yet, with its documentary reference, turned into the expected
// outcome of a scenario. Anything not listed here expects "pass". The lab
// drives Chromium: shadow roots (open, and closed through
// chrome.dom.openOrClosedShadowRoot) and passkeys (passkey window, chain
// signature) are expected to work there.
import { isFormsFlow } from "./forms-flows.ts";
import type { DriverId, Expect, LabRole, Site } from "./model.ts";
import type { Profile } from "./population.ts";

export interface Expectation { expect: Expect; reason?: string }

/** Label languages whose "Continue with <Provider>" the generator writes and the extension does not read. */
const PROVIDER_LABEL_LANGS = new Set(["de", "es", "it", "pt", "nl"]);

/** What a forms page asks of the extension (spec 11.4), in the order a reason names them. */
export const CAPABILITIES = ["persons", "intent_contact", "roles_person", "roles_document", "roles_company", "document_source", "loyalty",
  "work_tel", "honorific_sex", "nationality", "issuing_country", "date_parts", "date_text", "radio_group"] as const;
export type Capability = (typeof CAPABILITIES)[number];

/**
 * Capabilities the extension does not have yet. Each implementation task of
 * the forms plan removes its own; a scenario that passes while one it needs
 * is still listed shows as xpass, the sign to remove it. Empty at the end.
 */
export const PENDING: ReadonlySet<Capability> = new Set<Capability>(["persons", "intent_contact", "roles_document", "document_source", "loyalty", "work_tel"]);

const PERSON_ROLES = new Set<LabRole>(["additional_name", "birth_name", "birth_place", "birth_country"]);
const COMPANY_ROLES = new Set<LabRole>(["vat_number", "company_id", "job_title", "department", "website"]);
const ISSUING_ROLES = new Set<LabRole>(["passport_issuing_country", "license_issuing_country"]);

/**
 * The capabilities `site` needs, read from its fields: several people or
 * address blocks on one page (passengers 2 and later, a shipping block), a
 * contact block apart from the people, the new person, document and company
 * roles, values that come from a document or loyalty item, the work phone,
 * civility and sex, nationality and issuing country lists, split and text
 * dates, radio groups. Empty for the older flows.
 */
export function needs(site: Site): Capability[] {
  if (!isFormsFlow(site.flow)) return [];
  const f = site.fields;
  const any = (p: (x: (typeof f)[number]) => boolean) => f.some(p);
  const doc = any((x) => /^(passport|license)_/.test(x.role));
  const on: Record<Capability, boolean> = {
    persons: any((x) => (x.person ?? 0) > 0 || x.block === "shipping"),
    intent_contact: any((x) => x.block === "contact"),
    roles_person: any((x) => PERSON_ROLES.has(x.role)),
    roles_document: doc,
    roles_company: any((x) => COMPANY_ROLES.has(x.role)),
    document_source: doc || site.forms?.passportTitle !== undefined,
    loyalty: any((x) => x.role === "loyalty_number"),
    work_tel: any((x) => x.role === "tel_work"),
    honorific_sex: any((x) => x.role === "honorific" || x.role === "sex"),
    nationality: any((x) => x.role === "nationality"),
    issuing_country: any((x) => ISSUING_ROLES.has(x.role)),
    date_parts: any((x) => x.render?.date?.kind === "part"),
    date_text: any((x) => x.render?.date?.kind === "text"),
    radio_group: any((x) => x.render?.choice?.kind === "radio"),
  };
  const out = CAPABILITIES.filter((c) => on[c]);
  // A forms page always asks something new: at least the people of its form.
  return out.length > 0 ? out : ["roles_person"];
}

export function expectationFor(site: Site, driver: DriverId, profile?: Profile, pending: ReadonlySet<Capability> = PENDING): Expectation {
  // Lab control without the extension: the bench itself must accept the passkey.
  if (driver === "passkey_control") return { expect: "pass" };
  // A lookalike copy must never be filled with the real site's item.
  if (driver === "lookalike") return { expect: "nofill", reason: "lookalike host" };
  // Security expectation first: a cross-site frame must stay empty whatever else is missing.
  if (site.traits.includes("iframe_cross_site")) return { expect: "nofill", reason: "R-10" };
  // An empty vault has nothing to offer. The password generator of a signup form needs no item.
  if (profile?.vaultSize === 0 && !(site.flow === "signup" && driver === "menu_fill")) return { expect: "nofill", reason: "empty vault" };
  // The sso button is labelled in the label language; the extension reads provider buttons in French and English only.
  if (site.flow === "sso" && driver === "one_click" && PROVIDER_LABEL_LANGS.has(site.labelLang)) {
    return { expect: "xfail", reason: "provider button fr/en only (shared/providers.ts)" };
  }
  const missing = needs(site).find((c) => pending.has(c));
  if (missing) return { expect: "xfail", reason: `forms: ${missing}` };
  return { expect: "pass" };
}
