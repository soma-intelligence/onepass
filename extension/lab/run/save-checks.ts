// Pure checks of the save scenarios (drive.ts saveTyped), apart so the unit
// tests reach them without a browser: the premise each variant needs in the
// vault before the sign-in, and the reading of the update card's text.
import type { SaveVariant } from "../gen/model.ts";
import type { VaultLogin } from "./host-control.ts";

const same = (a: string, b: string) => a.trim().toLowerCase() === b.trim().toLowerCase();

/**
 * Why the vault read before the sign-in breaks the variant's premise (a `lab:`
 * error), or undefined when it holds. `first` holds the non-pending logins of
 * the site; `existing` is the site's own account (the vault's login there);
 * `typed` is the identifier the user types.
 * - new_auto: a first login ever on the site (spec 4.1), so none in the vault.
 * - update_card: the vault's login of the typed identifier, whose password changes.
 * - second_account, failed_login: the site's existing login in the vault, so a
 *   scenario that lands on a first-login host is loud, not a quiet pass.
 */
export function savePremise(v: SaveVariant, host: string, first: VaultLogin[], existing: string, typed: string): string | undefined {
  if (v === "new_auto" && first.length > 0) return `lab: new_auto needs a vault without any login for ${host} (${first.length} there)`;
  if (v === "update_card" && !first.some((l) => same(l.username, typed))) return "lab: update_card needs the vault's login of the typed identifier";
  if ((v === "second_account" || v === "failed_login") && !first.some((l) => same(l.username, existing))) {
    return `lab: ${v} needs the site's existing login in the vault (${host} has ${first.length} other login${first.length === 1 ? "" : "s"})`;
  }
  return undefined;
}

/**
 * The update card's text against the typed identifier: true when the card names
 * another login, false when it names the typed one, undefined when no text was
 * read. This proves which login the card names, not which one its confirm would
 * update.
 */
export function cardNamesOther(text: string | undefined, typed: string): boolean | undefined {
  if (text === undefined || text.trim() === "") return undefined;
  return !text.toLowerCase().includes(typed.trim().toLowerCase());
}

/** The `lab:` error of an update card shown but never read (a pill left folded, an unreadable frame): never a pass. */
export function unreadCard(v: SaveVariant, cardShown: boolean, textRead: boolean): string | undefined {
  return v === "update_card" && cardShown && !textRead ? "lab: update card shown but its text was never read" : undefined;
}
