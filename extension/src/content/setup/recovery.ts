// Finds a block of recovery codes on a page: 6 to 32 tokens of one shape inside one list,
// table, `pre` or grid, with recovery wording near it. Text only, nothing is sent anywhere.

const MIN_CODES = 6;
const MAX_CODES = 32;
const TOKEN = /^[A-Za-z0-9]{4,}(?:[- ][A-Za-z0-9]{4,})*$/;
const WORDING = /recovery|backup|secours|r[eé]cup[eé]ration|recuperaci[oó]n|respaldo|recupero/i;
const HEADING = "h1,h2,h3,h4,h5,h6,legend,summary,[role=heading]";
const MAX_ANCESTORS = 4;
const MAX_SIBLINGS = 3;
const MAX_SCAN = 4000;

/** Group lengths and separators: codes of one issuer share them, SKUs and prose do not. */
function shapeOf(token: string): string {
  return token.replace(/[A-Za-z0-9]+/g, (g) => String(g.length));
}

function items(container: Element): string[] {
  const tag = container.tagName.toLowerCase();
  let raw: string[];
  if (tag === "pre") raw = (container.textContent ?? "").split(/\r?\n/);
  else if (tag === "table") raw = [...container.querySelectorAll("td,th")].map((c) => c.textContent ?? "");
  else if (tag === "ul" || tag === "ol") raw = [...container.children].filter((c) => c.tagName === "LI").map((c) => c.textContent ?? "");
  else raw = [...container.children].map((c) => c.textContent ?? "");
  return raw.map((t) => t.replace(/\s+/g, " ").trim()).filter((t) => t.length > 0);
}

function isGrid(el: Element): boolean {
  try {
    const d = el.ownerDocument.defaultView?.getComputedStyle(el).display ?? "";
    return d === "grid" || d === "inline-grid";
  } catch {
    return false;
  }
}

function wordingNear(container: Element, title: string): boolean {
  if (WORDING.test(title)) return true;
  if (WORDING.test(container.getAttribute("aria-label") ?? "")) return true;
  let level: Element | null = container;
  for (let i = 0; i <= MAX_ANCESTORS && level && level.tagName !== "BODY"; i++) {
    let sib = level.previousElementSibling;
    for (let n = 0; sib && n < MAX_SIBLINGS; n++, sib = sib.previousElementSibling) {
      if (WORDING.test((sib.textContent ?? "").slice(0, 300))) return true;
    }
    const parent: Element | null = level.parentElement;
    const head = parent?.querySelector(HEADING);
    if (head && head !== level && !container.contains(head) && WORDING.test(head.textContent ?? "")) return true;
    level = parent;
  }
  return false;
}

/** The codes of the first fitting container, or null. */
export function findRecoveryCodes(root: ParentNode): string[] | null {
  const doc: Document | null = root.nodeType === 9 ? (root as Document) : (root as Node).ownerDocument;
  const title = doc?.title ?? "";
  const all = [...root.querySelectorAll("ul,ol,table,pre,div,section")].slice(0, MAX_SCAN);
  for (const el of all) {
    const tag = el.tagName.toLowerCase();
    if ((tag === "div" || tag === "section") && !isGrid(el)) continue;
    const list = items(el);
    if (list.length < MIN_CODES || list.length > MAX_CODES) continue;
    if (!list.every((t) => TOKEN.test(t))) continue;
    const shape = shapeOf(list[0]!);
    if (!list.every((t) => shapeOf(t) === shape)) continue;
    if (!wordingNear(el, title)) continue;
    return list;
  }
  return null;
}
