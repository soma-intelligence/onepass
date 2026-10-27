// Picks, without any click, up to 6 form pages of a site: links of the home page
// that match the seed lexicon, then sitemap entries, then common paths.
import { JSDOM } from "jsdom";
import { getDomain } from "tldts";

/** Shape of seed-lexicon.json that discovery reads: button words per intent and language. */
export interface SeedLexicon {
  buttons: Record<string, Record<string, string[]>>;
}

export const COMMON_PATHS = ["/login", "/signin", "/register", "/signup", "/account", "/checkout"];
const MAX_PAGES = 6;
const INTENTS = ["signin", "signup", "pay"];
const LOGOUT = /log[\s_-]?out|sign[\s_-]?out|deconnexion|d[ée]connecter|abmelden|ausloggen|cerrar sesi|desconectar|salir/;
const PATH_WORDS = /login|log-in|signin|sign-in|register|signup|sign-up|account|checkout|connexion|inscription|anmelden|registrieren|iniciar-sesion|registro|cuenta|compte|paiement|kasse|pago/;

const fold = (s: string): string => s.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase().replace(/\s+/g, " ").trim();

function words(lexicon: SeedLexicon): string[] {
  const out: string[] = [];
  for (const intent of INTENTS) for (const list of Object.values(lexicon.buttons[intent] ?? {})) for (const w of list) out.push(fold(w));
  return out;
}

/** Absolute http(s) URL without fragment, or undefined. */
function normalize(href: string, base: string): string | undefined {
  if (href.trim().startsWith("#")) return undefined;
  let u: URL;
  try { u = new URL(href, base); } catch { return undefined; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return undefined;
  u.hash = "";
  return u.href;
}

/** Untrusted pages can carry malformed percent sequences: fall back to the raw text. */
function safeDecode(s: string): string {
  try { return decodeURIComponent(s); } catch { return s; }
}

function sitemapLocs(xml: string): string[] {
  const out: string[] = [];
  for (const m of xml.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)) out.push((m[1] ?? "").replace(/&amp;/g, "&"));
  return out;
}

export function discoverFormPages(home: { url: string; html: string }, sitemapXml: string | undefined, lexicon: SeedLexicon): string[] {
  const site = getDomain(new URL(home.url).hostname);
  const origin = new URL(home.url).origin;
  const result: string[] = [];
  const seen = new Set<string>();
  const add = (url: string | undefined): void => {
    if (!url || result.length >= MAX_PAGES || seen.has(url)) return;
    const host = new URL(url).hostname;
    if (getDomain(host) !== site && host !== new URL(home.url).hostname) return;
    if (LOGOUT.test(fold(safeDecode(new URL(url).pathname)))) return;
    seen.add(url);
    result.push(url);
  };

  const lex = words(lexicon);
  const doc = new JSDOM(home.html).window.document;
  for (const a of Array.from(doc.querySelectorAll("a[href]"))) {
    const text = fold(a.textContent ?? "");
    if (LOGOUT.test(text)) continue;
    if (lex.some((w) => w && text === w)) add(normalize(a.getAttribute("href") ?? "", home.url));
  }
  for (const a of Array.from(doc.querySelectorAll("a[href]"))) {
    const text = fold(a.textContent ?? "");
    if (LOGOUT.test(text)) continue;
    if (lex.some((w) => w && text.includes(w))) add(normalize(a.getAttribute("href") ?? "", home.url));
  }
  if (sitemapXml) {
    for (const loc of sitemapLocs(sitemapXml)) {
      const url = normalize(loc, home.url);
      if (url && PATH_WORDS.test(fold(new URL(url).pathname))) add(url);
    }
  }
  for (const p of COMMON_PATHS) add(origin + p);
  return result;
}
