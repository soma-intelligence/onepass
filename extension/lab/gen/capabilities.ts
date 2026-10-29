// Capability table of the autofill lab (spec 4.5): what the extension is known
// not to do yet, with its documentary reference, turned into the expected
// outcome of a scenario. Anything not listed here expects "pass".
import type { DriverId, Expect, Site } from "./model.ts";

export interface Expectation { expect: Expect; reason?: string }

export function expectationFor(site: Site, driver: DriverId): Expectation {
  // Lab control without the extension: the bench itself must accept the passkey.
  if (driver === "passkey_control") return { expect: "pass" };
  // A lookalike copy must never be filled with the real site's item.
  if (driver === "lookalike") return { expect: "nofill", reason: "lookalike host" };
  // Security expectation first: a cross-site frame must stay empty whatever else is missing.
  if (site.traits.includes("iframe_cross_site")) return { expect: "nofill", reason: "R-10" };
  if (site.flow === "login_passkey" && (driver === "one_click" || driver === "smart_fill")) return { expect: "xfail", reason: "R-16 passkeys" };
  if (site.traits.includes("shadow_open") || site.traits.includes("shadow_closed")) {
    return { expect: "xfail", reason: "shadow DOM (content/index.ts)" };
  }
  return { expect: "pass" };
}
