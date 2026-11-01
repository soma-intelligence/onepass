// Capability table of the autofill lab (spec 4.5): what the extension is known
// not to do yet, with its documentary reference, turned into the expected
// outcome of a scenario. Anything not listed here expects "pass". The lab
// drives Chromium: shadow roots (open, and closed through
// chrome.dom.openOrClosedShadowRoot) and passkeys (passkey window, chain
// signature) are expected to work there.
import type { DriverId, Expect, Site } from "./model.ts";
import type { Profile } from "./population.ts";

export interface Expectation { expect: Expect; reason?: string }

/** Label languages whose "Continue with <Provider>" the generator writes and the extension does not read. */
const PROVIDER_LABEL_LANGS = new Set(["de", "es", "it", "pt", "nl"]);

export function expectationFor(site: Site, driver: DriverId, profile?: Profile): Expectation {
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
  return { expect: "pass" };
}
