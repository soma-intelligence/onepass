// Elements of a page that may show a two-factor setup QR code. Layout only: no pixel is read here.

export type CandidateKind = "img" | "canvas" | "svg" | "background" | "link";
export interface Candidate {
  kind: CandidateKind;
  el: Element;
  area: number;
}

const MIN_SIDE = 80;
const MIN_RATIO = 0.8;
const MAX_RATIO = 1.25;
const MAX_CANDIDATES = 12;
const MAX_SCAN = 6000;

function hidden(el: Element): boolean {
  const view = el.ownerDocument.defaultView;
  if (!view) return false;
  for (let n: Element | null = el; n; n = n.parentElement) {
    const s = view.getComputedStyle(n);
    if (s.display === "none" || s.visibility === "hidden" || s.visibility === "collapse") return true;
    if (n === el && Number(s.opacity) === 0 && s.opacity !== "") return true;
  }
  return false;
}

function squareArea(el: Element): number | null {
  const r = el.getBoundingClientRect();
  if (r.width < MIN_SIDE || r.height < MIN_SIDE) return null;
  const ratio = r.width / r.height;
  if (ratio < MIN_RATIO || ratio > MAX_RATIO) return null;
  return r.width * r.height;
}

function hasBackgroundUrl(el: Element): boolean {
  const bg = el.ownerDocument.defaultView?.getComputedStyle(el).backgroundImage ?? "";
  return bg.includes("url(");
}

/** Links first, then visible near-square images, largest first, 12 at most. */
export function findCandidates(doc: Document): Candidate[] {
  // Shadow roots are not walked: the tab capture covers what they show.
  const links: Candidate[] = [...doc.querySelectorAll('a[href^="otpauth:" i]')].map((el) => ({ kind: "link", el, area: 0 }));
  const shapes: Candidate[] = [];
  // Direct queries, no cap: a QR modal appended at the end of a heavy page is found.
  for (const el of doc.querySelectorAll("img,canvas,svg")) {
    const tag = el.tagName.toLowerCase();
    if (tag === "svg" && el.namespaceURI !== "http://www.w3.org/2000/svg") continue;
    const area = squareArea(el);
    if (area === null || hidden(el)) continue;
    shapes.push({ kind: tag as CandidateKind, el, area });
  }
  // Only the walk for CSS backgrounds is capped.
  let seen = 0;
  for (const el of doc.querySelectorAll("*")) {
    if (++seen > MAX_SCAN) break;
    const tag = el.tagName.toLowerCase();
    if (tag === "img" || tag === "canvas" || tag === "svg") continue;
    // Cheap size test first: a computed style per element is the costly part.
    const area = squareArea(el);
    if (area === null || !hasBackgroundUrl(el) || hidden(el)) continue;
    shapes.push({ kind: "background", el, area });
  }
  shapes.sort((a, b) => b.area - a.area);
  return [...links, ...shapes].slice(0, MAX_CANDIDATES);
}
