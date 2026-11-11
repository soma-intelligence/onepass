// The passkey sign-in button of a page ("Use passkey", "Sign in with a passkey"), read from its
// label alone. Used to tell a passkey-only page is a sign-in page (no field, no provider button)
// and, after a gesture of the user there, to press that one button.
import { CREATE_WORDS, PASSKEY_WORDS, normalizeText } from "./lexicon";
import { buttonLabel } from "./provider";
import { type Geometry, isRendered } from "./visibility";

/** Controls that may be the passkey sign-in button of a page, and how many are read. */
const PASSKEY_BUTTONS = 'button, [role="button"], input[type="submit" i], input[type="button" i], a';
const MAX_PASSKEY_BUTTONS = 500;

/**
 * The page's one rendered, enabled button that reads as a passkey sign-in. Null when there is
 * none, several (which one is not ours to guess), or only buttons that make a passkey or an
 * account.
 */
export function findPasskeySignIn(doc: Document, geometry: Geometry): HTMLElement | null {
  const found: HTMLElement[] = [];
  for (const el of Array.from(doc.querySelectorAll(PASSKEY_BUTTONS)).slice(0, MAX_PASSKEY_BUTTONS)) {
    if (!(el instanceof HTMLElement) || found.some((x) => x.contains(el))) continue;
    const label = normalizeText(buttonLabel(el));
    if (!PASSKEY_WORDS.test(label) || CREATE_WORDS.test(label) || el.matches(":disabled") || !isRendered(el, geometry)) continue;
    found.push(el);
    if (found.length > 1) return null;
  }
  return found[0] ?? null;
}
