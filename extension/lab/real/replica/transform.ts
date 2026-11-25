// Turns the rendered DOM of a real page into a static, self-contained replica:
// no script, no handler, no outside resource, no session or personal value.
// Stylesheets the page loaded are inlined; images become grey placeholders.
import { JSDOM, VirtualConsole } from "jsdom";

/** Per-sheet and total caps of inlined CSS (bytes of text). */
export const MAX_SHEET = 800_000;
export const MAX_CSS_TOTAL = 3_000_000;

const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g;
/** Opaque tokens: 25+ characters of letters, digits, "-" or "_" with at least one digit and one letter. */
const TOKEN = /\b(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{25,}\b/g;
/** JWT-like dotted tokens. */
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g;

export const REDACTED = "[redacted]";

/** Text with every email address and opaque token replaced. */
export function redactText(s: string): string {
  return s.replace(JWT, REDACTED).replace(EMAIL, REDACTED).replace(TOKEN, REDACTED);
}

export function isSensitiveValue(s: string): boolean {
  return redactText(s) !== s;
}

/** A grey 1x1 SVG: replaced images keep their box without any request. */
export const IMG_PLACEHOLDER = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='1' height='1'%3E%3Crect width='1' height='1' fill='%23d9d9de'/%3E%3C/svg%3E";

/** Every `url(...)` in CSS that is not a data: URL becomes an empty data URL (fonts, images: no request). */
export function neutralizeCssUrls(css: string): string {
  return css
    .replace(/url\(\s*(['"]?)(?!data:)[^)'"]*\1\s*\)/gi, 'url("data:,")')
    .replace(/@import\s+(?:url\([^)]*\)|"[^"]*"|'[^']*')[^;]*;/gi, "");
}

/** Absolute http(s) URL without query, keeping the fragment; undefined for anything else. */
function stripQuery(raw: string, base: string): string | undefined {
  const t = raw.trim();
  if (t.startsWith("#")) return t;
  let u: URL;
  try { u = new URL(t, base); } catch { return undefined; }
  if (u.protocol !== "http:" && u.protocol !== "https:" && u.protocol !== "mailto:") return undefined;
  if (u.protocol === "mailto:") return "mailto:";
  u.search = "";
  return u.href;
}

export interface CleanOptions {
  /** Final URL of the page (resolves relative links and stylesheets). */
  url: string;
  /** Stylesheet text by absolute URL, as the page loaded it. */
  css?: ReadonlyMap<string, string>;
  /** Marker written into `<meta name="onepass-lab-replica">`. */
  kind: "home" | "login";
}

export interface CleanResult {
  html: string;
  inlinedCss: number;
}

const DROP = "script, noscript, template, object, embed, applet, base, portal, frame, frameset";
const KEEP_VALUE_TYPES = new Set(["button", "submit", "reset", "checkbox", "radio", "image"]);
const URL_ATTRS = ["href", "action", "formaction", "poster", "background", "cite", "longdesc", "data", "ping", "xlink:href"];

/** Attributes that shape the page, never a value a site issued to a session: kept as is. */
const STRUCTURAL_ATTRS = new Set(["class", "id", "for", "name", "type", "role", "rel", "lang", "dir", "width", "height", "autocomplete", "inputmode", "media", "sizes", "slot", "part", "is"]);
const SVG_NS = "http://www.w3.org/2000/svg";

/** The document as HTML, with a standards-mode doctype. */
export function serialize(doc: Document): string {
  return "<!DOCTYPE html>\n" + doc.documentElement.outerHTML;
}

export function parse(html: string): JSDOM {
  // Silent console: real pages ship CSS jsdom cannot parse. No script runs (jsdom default).
  return new JSDOM(html, { virtualConsole: new VirtualConsole() });
}

/** Cleans one rendered page (see the file header). */
export function cleanPage(html: string, opts: CleanOptions): CleanResult {
  const dom = parse(html);
  const doc = dom.window.document;
  let inlined = 0;
  let cssBudget = MAX_CSS_TOTAL;

  for (const el of Array.from(doc.querySelectorAll(DROP))) el.remove();
  // Comments can carry build ids or session hints; none is needed.
  const walker = doc.createTreeWalker(doc, 128 /* NodeFilter.SHOW_COMMENT */);
  const comments: Node[] = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) comments.push(n);
  for (const c of comments) c.parentNode?.removeChild(c);

  // Head: one charset, no refresh, no CSP, no token-carrying meta.
  for (const m of Array.from(doc.querySelectorAll("meta"))) {
    const equiv = (m.getAttribute("http-equiv") ?? "").toLowerCase();
    const name = (m.getAttribute("name") ?? "").toLowerCase();
    if (m.hasAttribute("charset") || equiv === "refresh" || equiv === "content-security-policy" || equiv === "content-type" || equiv === "set-cookie") m.remove();
    else if (/csrf|token|nonce|session|user|account/.test(name) || isSensitiveValue(m.getAttribute("content") ?? "")) m.remove();
  }

  // Stylesheets: inline what the page loaded, drop every other <link>.
  for (const link of Array.from(doc.querySelectorAll("link"))) {
    const rel = (link.getAttribute("rel") ?? "").toLowerCase().split(/\s+/);
    const href = link.getAttribute("href");
    if (rel.includes("stylesheet") && href && !rel.includes("alternate")) {
      let abs: string | undefined;
      try { abs = new URL(href, opts.url).href; } catch { abs = undefined; }
      const text = abs ? opts.css?.get(abs) : undefined;
      if (text !== undefined && text.length <= MAX_SHEET && text.length <= cssBudget) {
        cssBudget -= text.length;
        const style = doc.createElement("style");
        style.setAttribute("data-onepass-lab-from", bareOrigin(abs!));
        const media = link.getAttribute("media");
        if (media) style.setAttribute("media", media);
        style.textContent = neutralizeCssUrls(text);
        link.replaceWith(style);
        inlined++;
        continue;
      }
    }
    link.remove();
  }
  for (const style of Array.from(doc.querySelectorAll("style"))) {
    if (!style.hasAttribute("data-onepass-lab-from")) style.textContent = neutralizeCssUrls(style.textContent ?? "");
  }

  // Embedded content: no request ever leaves a replica.
  for (const img of Array.from(doc.querySelectorAll("img"))) {
    const src = img.getAttribute("src") ?? "";
    if (!src.startsWith("data:")) img.setAttribute("src", IMG_PLACEHOLDER);
    img.removeAttribute("srcset");
    img.removeAttribute("loading");
  }
  for (const s of Array.from(doc.querySelectorAll("picture source, video source, audio source, track"))) s.remove();
  for (const m of Array.from(doc.querySelectorAll("video, audio"))) { m.removeAttribute("src"); m.removeAttribute("autoplay"); }
  for (const f of Array.from(doc.querySelectorAll("iframe"))) {
    const box = doc.createElement("div");
    box.setAttribute("data-onepass-lab-iframe", "");
    const w = f.getAttribute("width");
    const h = f.getAttribute("height");
    const style = f.getAttribute("style") ?? "";
    box.setAttribute("style", `${style};${w ? `width:${/^\d+$/.test(w) ? w + "px" : w};` : ""}${h ? `height:${/^\d+$/.test(h) ? h + "px" : h};` : ""}`);
    if (f.getAttribute("class")) box.setAttribute("class", f.getAttribute("class")!);
    f.replaceWith(box);
  }

  // Every element: handlers, sensitive attributes, query strings, inline style URLs.
  for (const el of Array.from(doc.querySelectorAll("*"))) {
    for (const attr of Array.from(el.attributes)) {
      const name = attr.name.toLowerCase();
      const value = attr.value;
      if (name.startsWith("on") || name === "nonce" || name === "integrity" || name === "srcdoc" || name === "jsaction" || name === "imagesrcset") { el.removeAttribute(attr.name); continue; }
      if (/^\s*(javascript|vbscript|blob|filesystem):/i.test(value)) { el.removeAttribute(attr.name); continue; }
      if (name === "style") { el.setAttribute("style", neutralizeCssUrls(value)); continue; }
      if (URL_ATTRS.includes(name)) {
        const kept = stripQuery(value, opts.url);
        if (kept === undefined) el.removeAttribute(attr.name);
        else el.setAttribute(attr.name, kept);
        continue;
      }
      if (name === "value" && el.tagName === "INPUT") continue; // handled below
      if (name === "src" && el.tagName === "IMG") continue;
      if (name === "src") { el.removeAttribute(attr.name); continue; }
      if (STRUCTURAL_ATTRS.has(name) || el.namespaceURI === SVG_NS) continue;
      if (isSensitiveValue(value)) el.removeAttribute(attr.name);
    }
  }
  for (const input of Array.from(doc.querySelectorAll("input"))) {
    const type = (input.getAttribute("type") ?? "text").toLowerCase();
    if (type === "hidden") input.removeAttribute("value");
    else if (!KEEP_VALUE_TYPES.has(type)) input.removeAttribute("value");
    else if (isSensitiveValue(input.getAttribute("value") ?? "")) input.removeAttribute("value");
  }
  for (const ta of Array.from(doc.querySelectorAll("textarea"))) ta.textContent = "";
  for (const opt of Array.from(doc.querySelectorAll("option[value]"))) {
    if (isSensitiveValue(opt.getAttribute("value") ?? "")) opt.removeAttribute("value");
  }

  // Text: no address, no opaque token.
  const texts = doc.createTreeWalker(doc.body ?? doc, 4 /* NodeFilter.SHOW_TEXT */);
  for (let n = texts.nextNode(); n; n = texts.nextNode()) {
    const parentTag = n.parentElement?.tagName;
    if (parentTag === "STYLE") continue;
    const v = n.nodeValue ?? "";
    const r = redactText(v);
    if (r !== v) n.nodeValue = r;
  }
  const title = doc.querySelector("title");
  if (title) title.textContent = redactText(title.textContent ?? "");

  // Marker and charset first in <head>.
  const head = doc.head ?? doc.documentElement.insertBefore(doc.createElement("head"), doc.body);
  const marker = doc.createElement("meta");
  marker.setAttribute("name", "onepass-lab-replica");
  marker.setAttribute("content", opts.kind);
  head.prepend(marker);
  const charset = doc.createElement("meta");
  charset.setAttribute("charset", "utf-8");
  head.prepend(charset);

  return { html: serialize(doc), inlinedCss: inlined };
}

function bareOrigin(url: string): string {
  try { return new URL(url).origin; } catch { return ""; }
}
