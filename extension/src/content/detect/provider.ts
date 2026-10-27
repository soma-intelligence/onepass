// Provider sign-in buttons and provider account choosers (spec 8.7).

import type { ProviderId } from "../../shared/messages";
import { providerForHost, providerFromButtonText } from "../../shared/providers";
import { normalizeText } from "./lexicon";
import type { RefRegistry } from "./refs";
import { ownText } from "./text";
import { type Geometry, isRendered } from "./visibility";

/** Most candidate elements inspected per page. */
const MAX_CANDIDATES = 2000;
/** Most account chooser entries reported. */
const MAX_ACCOUNTS = 50;

/** Buttons and links that do not leave for another site (relative or no href). */
const BUTTON_SELECTOR =
  'button, [role="button"], [role="link"], input[type="submit" i], input[type="button" i], a:not([href*="//"])';
/** Absolute links, queried and capped separately: a page may hold thousands. */
const ABSOLUTE_LINK_SELECTOR = 'a[href*="//"]';

/** Wording that makes a link to an official host a sign-in link. */
const SIGN_IN_WORDS = /\b(sign in|sign up|log in|login|connect|connexion|se connecter|continue|continuer|inscription)\b/;

const EMAIL = /[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}/gi;
const EMAIL_EXACT = /^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/i;

const LIST_SELECTOR = 'ul, ol, [role="list"], [role="listbox"], [role="menu"]';
const ENTRY_SELECTOR =
  '[data-email], [data-identifier], li, [role="option"], [role="listitem"], [role="link"], [role="button"], a, button';
const CLICKABLE_SELECTOR = 'a[href], button, [role="link"], [role="button"], [role="option"], [tabindex]';

/** Accessible-ish label: aria-label, else text, else value. Capped. */
export function buttonLabel(el: Element): string {
  const aria = el.getAttribute("aria-label");
  if (aria && aria.trim() !== "") return aria.slice(0, 200);
  const text = ownText(el);
  if (text.trim() !== "") return text;
  return el instanceof HTMLInputElement ? el.value.slice(0, 200) : "";
}

function isDisabled(el: Element): boolean {
  return el.matches(":disabled") || el.getAttribute("aria-disabled") === "true";
}

/** Provider named by a sign-in button: label first, then a link to an official host. */
export function providerOfButton(el: Element): ProviderId | null {
  const label = buttonLabel(el);
  const byText = providerFromButtonText(label);
  if (byText !== null) return byText;
  if (el instanceof HTMLAnchorElement && el.hasAttribute("href")) {
    let host: string;
    try {
      host = new URL(el.getAttribute("href") ?? "", el.ownerDocument.baseURI).host;
    } catch {
      return null;
    }
    const p = providerForHost(host);
    if (p !== null && SIGN_IN_WORDS.test(normalizeText(label))) return p;
  }
  return null;
}

/** "Continue with <provider>" buttons, outermost element only, in document order. */
export function detectProviderButtons(
  doc: Document,
  refs: RefRegistry,
  geometry: Geometry,
): { provider: ProviderId; ref: string }[] {
  const matched: Element[] = [];
  const out: { provider: ProviderId; ref: string }[] = [];
  const candidates = [
    ...Array.from(doc.querySelectorAll(BUTTON_SELECTOR)).slice(0, MAX_CANDIDATES),
    ...Array.from(doc.querySelectorAll(ABSOLUTE_LINK_SELECTOR)).slice(0, MAX_CANDIDATES),
  ].sort((a, b) => (a === b ? 0 : a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1));
  for (const el of candidates) {
    if (matched.some((m) => m.contains(el))) continue;
    const provider = providerOfButton(el);
    if (provider === null || isDisabled(el) || !isRendered(el, geometry)) continue;
    matched.push(el);
    out.push({ provider, ref: refs.refFor(el) });
  }
  return out;
}

function entryEmail(el: Element): string | null {
  for (const attr of ["data-email", "data-identifier"]) {
    const v = (el.getAttribute(attr) ?? "").trim().slice(0, 254);
    if (EMAIL_EXACT.test(v)) return v.toLowerCase();
  }
  const found = ownText(el, 300).match(EMAIL);
  return found?.length === 1 && found[0] !== undefined ? found[0].toLowerCase() : null;
}

/**
 * Entries of a provider account chooser: list items showing exactly one email
 * (text or `data-email` / `data-identifier`). The caller only uses this on an
 * official provider host (exact match, spec 8.7).
 */
export function detectAccountChooser(
  doc: Document,
  refs: RefRegistry,
  geometry: Geometry,
): { email: string; ref: string }[] {
  const seen = new Set<string>();
  const out: { email: string; ref: string }[] = [];
  for (const el of Array.from(doc.querySelectorAll(ENTRY_SELECTOR)).slice(0, MAX_CANDIDATES)) {
    if (out.length >= MAX_ACCOUNTS) break;
    if (!el.closest(LIST_SELECTOR)) continue;
    const email = entryEmail(el);
    if (email === null || seen.has(email)) continue;
    const target = el.matches(CLICKABLE_SELECTOR) ? el : (el.querySelector(CLICKABLE_SELECTOR) ?? el);
    if (isDisabled(target) || !isRendered(target, geometry)) continue;
    seen.add(email);
    out.push({ email, ref: refs.refFor(target) });
  }
  return out;
}
