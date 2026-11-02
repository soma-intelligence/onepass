// Probe of the real-site bench (docs/superpowers/specs/2026-11-02-real-site-bench-and-retrain-design.md).
// Built by bench/build-probe.mjs into dist-bench/probe.js and injected by core/onepass-bench over
// the DevTools protocol. It runs the content script's own code on a real page: analyzeDocument
// (field detection and roles), buildPageContext (what the planner sees), extractFeatures (the
// classifier's features) and createFiller (the extension's filler). The planner itself is
// onepass_core::fill_plan, called by the Rust side.
//
// Nothing here sends anything: installGuard cancels every submit, and the Rust side refuses any
// request other than GET or HEAD before it leaves the browser. readback returns booleans only:
// no value ever leaves the page.
import { buildPageContext } from "../src/content/context";
import { extractFeatures, FEATURE_VERSION, type FieldFeatures } from "../src/content/detect/features";
import { analyzeDocument } from "../src/content/detect/forms";
import { RefRegistry } from "../src/content/detect/refs";
import { collectShadowRoots } from "../src/content/detect/shadow";
import { domGeometry, type Geometry, isVisible } from "../src/content/detect/visibility";
import { createFiller, nativeValue } from "../src/content/filler";
import type { FieldRole, PageAnalysis, PageContext } from "../src/shared/messages";
import { sanitizeText, sanitizeToken } from "../src/shared/sanitize";

export interface ProbeOptions {
  geometry?: Geometry;
  /** Origin of the page; defaults to `location.origin`. */
  origin?: string;
  doc?: Document;
}

export interface TruthObservation {
  selector: string;
  found: boolean;
  /** Extension FieldRole, null when no detected form holds the field. */
  detected: FieldRole | null;
  features: FieldFeatures | null;
}

export interface Analysis {
  context: PageContext;
  truth: TruthObservation[];
  framework: string;
  lang: string;
  forms: number;
  featureVersion: number;
}

export interface SurveyField {
  selector: string;
  detected: FieldRole | null;
  features: FieldFeatures;
}

export interface PlanGroupIn {
  form_ref: string;
  fields: [string, string][];
}

export interface Readback {
  selector: string;
  found: boolean;
  filled: boolean;
  expected_value: boolean;
}

function esc(s: string): string {
  return typeof CSS !== "undefined" && CSS.escape ? CSS.escape(s) : s.replace(/[^a-zA-Z0-9_-]/g, (c) => `\\${c}`);
}

/** A selector that finds `el` alone: its id, else tag and name, else a nth-of-type path. */
export function cssPath(doc: Document, el: Element): string {
  const unique = (sel: string): boolean => {
    try {
      const all = doc.querySelectorAll(sel);
      return all.length === 1 && all[0] === el;
    } catch {
      return false;
    }
  };
  if (el.id && unique(`#${esc(el.id)}`)) return `#${esc(el.id)}`;
  const name = el.getAttribute("name");
  if (name) {
    const sel = `${el.localName}[name="${name.replace(/["\\]/g, "\\$&")}"]`;
    if (unique(sel)) return sel;
  }
  const parts: string[] = [];
  for (let t: Element | null = el; t && t !== doc.documentElement; t = t.parentElement) {
    if (t.id && unique(`#${esc(t.id)}`)) {
      parts.unshift(`#${esc(t.id)}`);
      break;
    }
    const same = t.parentElement ? Array.from(t.parentElement.children).filter((c) => c.localName === t!.localName) : [];
    parts.unshift(same.length > 1 ? `${t.localName}:nth-of-type(${same.indexOf(t) + 1})` : t.localName);
  }
  return parts.join(" > ");
}

function query(doc: Document, selector: string): Element | null {
  try {
    return doc.querySelector(selector);
  } catch {
    return null;
  }
}

export function createProbe(opts: ProbeOptions = {}) {
  const doc = opts.doc ?? document;
  const geometry = opts.geometry ?? domGeometry;
  const origin = opts.origin ?? doc.defaultView?.location.origin ?? "";
  const refs = new RefRegistry();
  const url = doc.URL;
  /** Value of each truth field when it was analysed: a select holds a value before any fill. Stays in the page. */
  const initial = new Map<string, string>();
  const analyze = (): PageAnalysis => analyzeDocument(doc, refs, { url, geometry });

  const rolesOf = (analysis: PageAnalysis): Map<Element, FieldRole> => {
    const roles = new Map<Element, FieldRole>();
    for (const form of analysis.forms) {
      for (const f of form.fields) {
        for (const r of f.parts ?? [f.ref]) {
          const el = refs.get(r);
          if (el) roles.set(el, f.role);
        }
      }
    }
    return roles;
  };

  return {
    /** Every field the feature extractor reaches, with a selector and the detected role (to write a truth by hand). */
    survey(): SurveyField[] {
      const roles = rolesOf(analyze());
      const out: SurveyField[] = [];
      extractFeatures(doc, { onField: (el, f) => out.push({ selector: cssPath(doc, el), detected: roles.get(el) ?? null, features: f }) });
      return out;
    },

    analyze(selectors: string[]): Analysis {
      const analysis = analyze();
      const roles = rolesOf(analysis);
      const features = new Map<Element, FieldFeatures>();
      const page = extractFeatures(doc, { roots: collectShadowRoots(doc), onField: (el, f) => features.set(el, f) });
      const context = buildPageContext(doc, refs, analysis, { origin, topOrigin: origin, frame: "top" }, geometry);
      const truth = selectors.map((selector): TruthObservation => {
        const el = query(doc, selector);
        if (el !== null && !initial.has(selector)) initial.set(selector, nativeValue(el));
        return { selector, found: el !== null, detected: (el && roles.get(el)) ?? null, features: (el && features.get(el)) ?? null };
      });
      return { context, truth, framework: page.framework, lang: doc.documentElement?.lang ?? "", forms: analysis.forms.length, featureVersion: FEATURE_VERSION };
    },

    /** Fills each group's form through the extension filler; resolves to the number of controls written. */
    async fill(groups: PlanGroupIn[], values: Partial<Record<FieldRole, string>>): Promise<number> {
      const filler = createFiller({
        refs,
        geometry,
        analyze,
        resolve: (ref, a) => a.forms.find((f) => f.ref === ref) ?? null,
        lang: () => doc.documentElement?.lang ?? null,
        settleMs: 1000,
      });
      let written = 0;
      for (const g of groups) {
        if (refs.get(g.form_ref) === null) continue;
        const res = filler.fill(g.form_ref, values);
        written += (await res.done).length;
      }
      return written;
    },

    /** Whether each field was written since it was analysed, and whether it now holds one of `expect`. Never the value. */
    readback(fields: { selector: string; expect: string[] }[]): Readback[] {
      return fields.map(({ selector, expect }) => {
        const el = query(doc, selector);
        if (el === null) return { selector, found: false, filled: false, expected_value: false };
        const v = nativeValue(el);
        const filled = v !== "" && v !== (initial.get(selector) ?? "");
        return { selector, found: true, filled, expected_value: filled && expect.includes(v) };
      });
    },
  };
}

/** Cancels every form submission of the page: submit events (capture phase), submit() and requestSubmit(). */
export function installGuard(win: Window & typeof globalThis): void {
  const proto = win.HTMLFormElement.prototype;
  proto.submit = function submit() {};
  proto.requestSubmit = function requestSubmit() {};
  win.addEventListener(
    "submit",
    (e) => {
      e.preventDefault();
      e.stopImmediatePropagation();
    },
    true,
  );
}

const DROP_TAGS = new Set([
  "script", "style", "link", "noscript", "template", "img", "picture", "source", "video", "audio",
  "canvas", "svg", "iframe", "frame", "frameset", "object", "embed", "track", "map", "base",
]);
const KEEP_ATTRS = new Set([
  "id", "name", "type", "autocomplete", "for", "placeholder", "aria-label", "aria-labelledby",
  "aria-describedby", "aria-hidden", "hidden", "role", "class", "maxlength", "minlength", "inputmode",
  "pattern", "required", "title", "action", "method", "disabled", "readonly", "passwordrules", "tabindex",
]);
const BUTTON_VALUE_TYPES = new Set(["submit", "button", "reset"]);
const FIELD_TAGS = new Set(["input", "select", "textarea"]);
const MAX_TEXT_NODE = 80;

export interface PruneOptions {
  geometry?: Geometry;
  /** Override of the "is this element shown" test (tests); defaults to computed style and, for fields, isVisible. */
  visible?: (el: Element) => boolean;
}

function shown(el: Element, geometry: Geometry): boolean {
  const tag = el.localName;
  if (tag === "input" && (el as HTMLInputElement).type === "hidden") return true;
  if (FIELD_TAGS.has(tag)) return isVisible(el, geometry);
  const s = el.ownerDocument.defaultView?.getComputedStyle(el);
  return !s || (s.display !== "none" && s.visibility !== "hidden" && s.visibility !== "collapse");
}

function cleanAttrs(el: Element): void {
  const tag = el.localName;
  for (const a of Array.from(el.attributes)) {
    const n = a.name.toLowerCase();
    if (n === "value" && (tag === "button" || (tag === "input" && BUTTON_VALUE_TYPES.has((el as HTMLInputElement).type)))) {
      const t = sanitizeText(a.value);
      if (t === undefined || t === "<redacted>") el.removeAttribute(a.name);
      else el.setAttribute(a.name, t);
      continue;
    }
    if (n === "href") {
      const path = a.value.split(/[?#]/)[0] ?? "";
      const t = sanitizeToken(path);
      if (t === undefined || t === "<redacted>" || t === "<long>") el.removeAttribute(a.name);
      else el.setAttribute(a.name, t);
      continue;
    }
    if (!KEEP_ATTRS.has(n)) {
      el.removeAttribute(a.name);
      continue;
    }
    const textual = n === "placeholder" || n === "aria-label" || n === "title";
    const t = textual ? sanitizeText(a.value) : n === "class" ? a.value.split(/\s+/).map((c) => sanitizeToken(c)).filter((c) => c && c !== "<redacted>" && c !== "<long>").join(" ") : sanitizeToken(a.value) ?? "";
    if (t === undefined || t === "<redacted>" || t === "<long>") el.removeAttribute(a.name);
    else el.setAttribute(a.name, t);
  }
}

/**
 * A pruned copy of the rendered page for offline replay (spec 5.1): forms, labels, headings and
 * buttons survive; scripts, styles, media, frames, comments, hidden elements, prose, numbers,
 * addresses and every field value do not. The live document is not changed.
 */
export function prune(doc: Document, opts: PruneOptions = {}): string {
  const geometry = opts.geometry ?? domGeometry;
  const visible = opts.visible ?? ((el: Element) => shown(el, geometry));
  const out = doc.implementation.createHTMLDocument("");
  const lang = sanitizeToken(doc.documentElement?.getAttribute("lang"));
  if (lang && lang !== "<redacted>" && lang !== "<long>") out.documentElement.setAttribute("lang", lang);
  const title = sanitizeText(doc.title);
  if (title && title !== "<redacted>") out.title = title;
  else out.head.querySelector("title")?.remove();

  const copy = (src: Node, into: Node): void => {
    for (const child of Array.from(src.childNodes)) {
      if (child.nodeType === 3) {
        const raw = (child.textContent ?? "").replace(/\s+/g, " ").trim();
        if (raw === "" || raw.length > MAX_TEXT_NODE) continue;
        const t = sanitizeText(raw);
        if (t === undefined || t === "<redacted>") continue;
        into.appendChild(out.createTextNode(t));
        continue;
      }
      if (child.nodeType !== 1) continue;
      const el = child as Element;
      const tag = el.localName;
      if (DROP_TAGS.has(tag) || !visible(el)) continue;
      const clone = out.createElement(tag);
      for (const a of Array.from(el.attributes)) clone.setAttribute(a.name, a.value);
      cleanAttrs(clone);
      into.appendChild(clone);
      if (tag === "textarea") continue;
      copy(el, clone);
      if (tag === "select") {
        // Options keep their text (sanitized above), never their value attribute.
        for (const o of Array.from(clone.querySelectorAll("option"))) o.removeAttribute("value");
      }
    }
  };
  if (doc.body) copy(doc.body, out.body);
  return `<!doctype html>\n${out.documentElement.outerHTML}\n`;
}
