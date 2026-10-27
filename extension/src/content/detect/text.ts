/** Default cap on page text read for signal detection (hostile pages). */
export const MAX_PAGE_TEXT = 20_000;

const SKIPPED_PARENTS = "script, style, noscript, template, [hidden], [aria-hidden=\"true\" i]";

/**
 * Visible-ish text of the page body, lowercased, accents stripped, whitespace
 * collapsed, curly apostrophes made straight. Skips scripts, styles, templates
 * and explicitly hidden subtrees. Capped at `max` characters.
 */
export function pageText(doc: Document, max = MAX_PAGE_TEXT): string {
  const root = doc.body ?? doc.documentElement;
  if (!root) return "";
  let out = "";
  const walker = doc.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n !== null && out.length < max; n = walker.nextNode()) {
    if (n.parentElement?.closest(SKIPPED_PARENTS)) continue;
    out += ` ${n.nodeValue ?? ""}`;
  }
  return out
    .slice(0, max)
    .normalize("NFD")
    .replace(/\p{M}/gu, "")
    .replace(/[‘’]/g, "'")
    .toLowerCase()
    .replace(/\s+/g, " ");
}

/** Subtrees whose text is not a label: nested controls, scripts, templates. */
const NON_TEXT = "select, option, textarea, script, style, template";

/**
 * Text of `el`, text nodes joined by spaces, without the text of nested form controls (a wrapping label must
 * not read the options of its own select), capped at `max` characters.
 */
export function ownText(el: Element, max = 200): string {
  const outer = el.closest(NON_TEXT);
  let out = "";
  const walker = el.ownerDocument.createTreeWalker(el, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n !== null && out.length < max; n = walker.nextNode()) {
    if ((n.parentElement?.closest(NON_TEXT) ?? null) !== outer) continue;
    out += ` ${n.nodeValue ?? ""}`;
  }
  return out.slice(0, max);
}
