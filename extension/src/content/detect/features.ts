// Shared field feature extractor. One implementation feeds the corpus crawler
// (passed to Playwright page.evaluate), the training dataset and, later, the
// extension's runtime classifier, so training and runtime see identical features.
//
// extractFeatures is serialized by page.evaluate: it must stay fully
// self-contained (every helper nested in its body, no import used at run time,
// no module-level value read). It only reads structure and attributes, never a
// field value.

export const FEATURE_VERSION = 1;

export type Visibility = "visible" | "display_none" | "offscreen" | "opacity" | "zero_size";
export type Framework = "react" | "vue" | "angular" | "other";

export interface FieldFeatures {
  index: number;                 // position among the eligible fields of its form, 0-based
  tag: string;
  type?: string;
  name?: string;
  id?: string;
  autocomplete?: string;
  inputmode?: string;
  maxlength?: number;
  hasPattern: boolean;
  required: boolean;
  label?: string;                // aria-labelledby, <label>, or the preceding sibling text (normalized)
  placeholder?: string;
  ariaLabel?: string;
  before?: string;               // text right before the field, last 40 characters (normalized)
  after?: string;                // text right after the field, first 40 characters (normalized)
  depth: number;                 // element ancestors up to the root
  siblings: number;              // other input, select and textarea elements under the same parent
  visibility: Visibility;
  width: number;
  height: number;
  formButtons: string[];
  pageTitle?: string;
  neighbourLabels: string[];     // labels of the 2 previous and the 2 next fields of the form
  lab?: string;                  // data-lab-field, only with the labField option (dataset builder); ml/ingest.py strips it before training
}

export interface ExtractOptions {
  /** Most fields emitted (default 300); `truncated` is set past it. */
  maxFields?: number;
  /**
   * Reads the page-supplied `data-lab-field` mark into `lab`. On only in the dataset builder
   * (lab/dataset/build.ts); the extension never sets it, so a page cannot steer the classifier.
   */
  labField?: boolean;
  /** Called once per emitted field with its element, after the field's features are complete. Never serialized. */
  onField?: (el: Element, f: FieldFeatures) => void;
  /**
   * Shadow roots of the page read after the document (the extension's analysis, spec D1, D2):
   * their forms and fields are emitted as the document's are, labels and neighbour text read
   * inside each root, depth and visibility through its host. Never serialized: the corpus and
   * the dataset builder read the document alone.
   */
  roots?: readonly ShadowRoot[];
}

export interface PageFeatures {
  forms: { fields: FieldFeatures[]; buttons: string[] }[];
  framework: Framework;
  iframes: { origin: string; sameSite: boolean }[];
  shadowFields: number;
  truncated: boolean;
}

/** NFKC, lower case, whitespace folded. Same logic as the normalizer nested in extractFeatures. */
export function normalizeText(s: string): string {
  return s.normalize("NFKC").toLowerCase().replace(/\s+/g, " ").trim();
}

export function extractFeatures(doc: Document, opts?: ExtractOptions): PageFeatures {
  const maxFields = opts?.maxFields ?? 300;
  const labField = opts?.labField === true;
  const onField = opts?.onField;
  const roots = opts?.roots ?? [];
  const TEXT_CAP = 120;
  const NEIGHBOUR_CAP = 40;
  const FIELD_SEL = "input, select, textarea";
  const SKIP_TYPES = ["hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file"];
  const SKIP_SUBTREE = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE"]);
  const SKIP_PARENT = new Set(["OPTION", "TEXTAREA"]); // default values and choices are not neighbour text
  const win = (doc.defaultView ?? window) as Window & typeof globalThis;

  // Keep identical to normalizeText above.
  const norm = (s: string): string => s.normalize("NFKC").toLowerCase().replace(/\s+/g, " ").trim();
  const text = (s: string | null | undefined, cap = TEXT_CAP): string | undefined => {
    if (s == null) return undefined;
    const t = norm(s);
    return t ? t.slice(0, cap) : undefined;
  };
  const textOf = (el: Element | null): string | undefined => (el ? text(el.textContent) : undefined);
  // Parent across a shadow boundary: the host of the root (a document's root element has none).
  const up = (n: Element): Element | null => {
    if (n.parentElement) return n.parentElement;
    const p = n.parentNode as (Node & { host?: Element }) | null;
    return p && p.nodeType === 11 && p.host ? p.host : null;
  };

  function eligible(el: Element): boolean {
    const type = el instanceof win.HTMLInputElement ? el.type : undefined;
    return !(type && SKIP_TYPES.includes(type));
  }

  function visibilityOf(el: Element): { v: Visibility; w: number; h: number } {
    const r = el.getBoundingClientRect();
    const w = Math.round(r.width);
    const h = Math.round(r.height);
    try {
      const own = win.getComputedStyle(el);
      if (own.visibility === "hidden" || own.visibility === "collapse") return { v: "display_none", w, h };
      let opaque = true;
      for (let n: Element | null = el; n; n = up(n)) {
        const cs = n === el ? own : win.getComputedStyle(n);
        if (cs.display === "none") return { v: "display_none", w, h };
        if (parseFloat(cs.opacity) === 0) opaque = false;
      }
      if (!opaque) return { v: "opacity", w, h };
    } catch { /* no computed style available: fall through to geometry */ }
    if (r.width <= 1 || r.height <= 1) return { v: "zero_size", w, h };
    const root = doc.documentElement;
    if (r.right < 0 || r.bottom < 0 || r.left > (win.innerWidth || 1024) + 2000 || r.top > (root?.scrollHeight ?? 0) + 2000) return { v: "offscreen", w, h };
    return { v: "visible", w, h };
  }

  function labelOf(el: HTMLInputElement): string | undefined {
    const by = el.getAttribute("aria-labelledby");
    if (by) {
      // Ids are scoped to the field's own tree (the document or its shadow root).
      const scope = el.getRootNode() as Document | ShadowRoot;
      const byId = (i: string) => (typeof scope.getElementById === "function" ? scope.getElementById(i) : doc.getElementById(i));
      const t = by.split(/\s+/).map((i) => textOf(byId(i)) ?? "").join(" ").trim();
      if (t) return text(t);
    }
    const labels = el.labels ? Array.from(el.labels) : [];
    if (!labels.length) {
      const wrap = el.closest("label");
      if (wrap) labels.push(wrap as HTMLLabelElement);
    }
    for (const l of labels) {
      const t = textOf(l);
      if (t) return t;
    }
    const prev = el.previousElementSibling;
    if (prev && !SKIP_SUBTREE.has(prev.tagName) && !prev.matches(FIELD_SEL) && !prev.querySelector(FIELD_SEL)) return textOf(prev);
    return undefined;
  }

  // One pass over the body: text runs and field markers in document order.
  type Tok = { t: string } | { f: Element };
  const toks: Tok[] = [];
  const tokOf = new Map<Element, number>();
  const root = doc.body ?? doc.documentElement;
  const walk = (scope: Node) => {
    const walker = doc.createTreeWalker(scope, 1 | 4, {
      acceptNode(n: Node): number {
        if (n.nodeType === 1) return SKIP_SUBTREE.has((n as Element).tagName) ? 2 : 1;
        return SKIP_PARENT.has(n.parentElement?.tagName ?? "") ? 2 : 1;
      },
    });
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      if (n.nodeType === 3) {
        const t = text(n.nodeValue);
        if (t) toks.push({ t });
      } else if ((n as Element).matches(FIELD_SEL)) {
        tokOf.set(n as Element, toks.length);
        toks.push({ f: n as Element });
      }
    }
  };
  if (root) walk(root);
  for (const r of roots) {
    // A break between trees: neighbour text never runs from one into the next.
    toks.push({ f: r.host });
    walk(r);
  }
  function neighbour(el: Element, dir: -1 | 1): string | undefined {
    const at = tokOf.get(el);
    if (at === undefined) return undefined;
    const parts: string[] = [];
    let len = 0;
    for (let i = at + dir; i >= 0 && i < toks.length && len < NEIGHBOUR_CAP; i += dir) {
      const k = toks[i]!;
      if (!("t" in k)) break;
      parts.push(k.t);
      len += k.t.length + 1;
    }
    if (!parts.length) return undefined;
    const joined = (dir < 0 ? parts.reverse() : parts).join(" ");
    return dir < 0 ? joined.slice(-NEIGHBOUR_CAP).trim() : joined.slice(0, NEIGHBOUR_CAP).trim();
  }

  const pageTitle = text(doc.title, 100);

  function buttonsIn(scope: ParentNode): string[] {
    const out: string[] = [];
    for (const b of Array.from(scope.querySelectorAll("button, input[type=submit], input[type=button], [role=button]"))) {
      const t = b instanceof win.HTMLInputElement ? text(b.getAttribute("value"), 60) : text(b.textContent, 60);
      if (t) out.push(t);
      if (out.length >= 12) break;
    }
    return out;
  }

  // Count of field children per parent, computed once (a per-field scan is quadratic on a flat 5000-input form).
  const fieldKids = new Map<Element, number>();
  function kidsOf(parent: Element): number {
    let n = fieldKids.get(parent);
    if (n === undefined) {
      n = 0;
      for (let c = parent.firstElementChild; c; c = c.nextElementSibling) if (c.matches(FIELD_SEL)) n++;
      fieldKids.set(parent, n);
    }
    return n;
  }

  let emitted = 0;
  let truncated = false;
  function build(els: Element[], buttons: string[]): { fields: FieldFeatures[]; buttons: string[] } | null {
    const fields: FieldFeatures[] = [];
    const used: Element[] = [];
    for (const el of els) {
      if (!eligible(el)) continue;
      if (emitted >= maxFields) { truncated = true; break; }
      emitted++;
      used.push(el);
    }
    if (!used.length) return null;
    const own = used.map((el) => {
      const inp = el as HTMLInputElement;
      const vis = visibilityOf(el);
      const parent = el.parentElement;
      let depth = 0;
      for (let n = up(el); n; n = up(n)) depth++;
      const f: FieldFeatures = {
        index: 0, tag: el.tagName.toLowerCase(), type: el instanceof win.HTMLInputElement ? el.type : undefined,
        name: el.getAttribute("name") ?? undefined, id: el.id || undefined,
        autocomplete: el.getAttribute("autocomplete") ?? undefined, inputmode: el.getAttribute("inputmode") ?? undefined,
        maxlength: inp.maxLength > 0 ? inp.maxLength : undefined,
        hasPattern: el.hasAttribute("pattern"), required: (el as HTMLInputElement).required === true,
        label: labelOf(inp), placeholder: text(el.getAttribute("placeholder")), ariaLabel: text(el.getAttribute("aria-label")),
        before: neighbour(el, -1), after: neighbour(el, 1), depth,
        siblings: parent ? kidsOf(parent) - (el.matches(FIELD_SEL) ? 1 : 0) : 0,
        visibility: vis.v, width: vis.w, height: vis.h, formButtons: buttons, pageTitle, neighbourLabels: [],
      };
      const lab = labField ? el.getAttribute("data-lab-field") : null;
      if (lab !== null) f.lab = lab;
      return f;
    });
    own.forEach((f, i) => { f.index = i; });
    const name = (f: FieldFeatures | undefined): string | undefined => (f ? f.label ?? f.ariaLabel ?? f.placeholder : undefined);
    own.forEach((f, i) => {
      f.neighbourLabels = [own[i - 2], own[i - 1], own[i + 1], own[i + 2]].map(name).filter((x): x is string => !!x);
    });
    fields.push(...own);
    if (onField) used.forEach((el, i) => onField(el, own[i]!));
    return { fields, buttons };
  }

  const forms: PageFeatures["forms"] = [];
  const inForm = new Set<Element>();
  for (const scope of [doc, ...roots] as (Document | ShadowRoot)[]) {
    for (const f of Array.from(scope.querySelectorAll("form"))) {
      const els = Array.from(f.querySelectorAll(FIELD_SEL));
      els.forEach((e) => inForm.add(e));
      const built = build(els, buttonsIn(f));
      if (built) forms.push(built);
    }
    const orphans = Array.from(scope.querySelectorAll(FIELD_SEL)).filter((e) => !inForm.has(e));
    if (orphans.length) {
      const built = build(orphans, buttonsIn(scope));
      if (built) forms.push(built);
    }
  }

  const hostSite = (a: string, b: string): boolean => {
    const base = (h: string) => h.split(".").slice(-2).join(".");
    return !!a && !!b && base(a) === base(b);
  };
  let pageHost = doc.defaultView?.location?.hostname || doc.location?.hostname || "";
  if (!pageHost) {
    try { pageHost = new URL(doc.baseURI).hostname; } catch { /* no base URL */ }
  }
  const iframes: PageFeatures["iframes"] = [];
  for (const i of Array.from(doc.querySelectorAll("iframe[src]"))) {
    try {
      const u = new URL(i.getAttribute("src") ?? "", doc.baseURI);
      if (u.protocol === "http:" || u.protocol === "https:") iframes.push({ origin: u.origin, sameSite: hostSite(u.hostname, pageHost) });
    } catch { /* malformed or unresolvable src */ }
  }

  let shadowFields = 0;
  let framework: Framework = "other";
  const react = !!doc.querySelector("[data-reactroot], [data-reactid], #__next");
  let vue = !!doc.querySelector("[data-v-app], [data-server-rendered], #__nuxt");
  let angular = !!doc.querySelector("[ng-version], [ng-app], [ng-controller]");
  const all = Array.from(doc.querySelectorAll("*"));
  for (let i = 0; i < all.length; i++) {
    const el = all[i]!;
    if (el.shadowRoot) shadowFields += el.shadowRoot.querySelectorAll(FIELD_SEL).length;
    if (i < 1500 && !(vue && angular)) {
      for (const a of Array.from(el.attributes)) {
        if (/^data-v-[0-9a-f]{6,8}$/.test(a.name)) vue = true;
        else if (/^_ng(host|content)-/.test(a.name)) angular = true;
      }
    }
  }
  if (react) framework = "react";
  else if (vue) framework = "vue";
  else if (angular) framework = "angular";

  return { forms, framework, iframes, shadowFields, truncated };
}
