// Corpus extractor: loads public login/signup/checkout/address pages in a
// fresh Chromium context and records only the DOM structure (no values, no
// clicks, no submission). Respects robots.txt, one page per host, paced.
// Usage: node --experimental-strip-types lab/corpus/extract.ts --sites <json> --out <dir> [--only <host>] [--delay-ms 5000]
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import type { ProviderId } from "../gen/model.ts";
import { isAllowed, robotsEntry } from "./robots.ts";
import type { RobotsEntry } from "./robots.ts";
import { classifyRole } from "./roles.ts";
import { sanitizeOrigin, sanitizeText, sanitizeToken } from "./sanitize.ts";
import { stableJson } from "./types.ts";
import type { Category, FormStep, Sample, SampleField, SampleForm } from "./types.ts";

const USER_AGENT = "Mozilla/5.0 (compatible; OnePassLabCorpus/1; structure-only research crawler)";
const ROBOTS_AGENT = "OnePassLabCorpus";
const USAGE = `Usage: node --experimental-strip-types lab/corpus/extract.ts --sites <json> --out <dir> [--only <host>] [--delay-ms 5000]

Captures the DOM structure (never values) of the public pages listed in the sites file.
  --sites     JSON array of { "url": string, "category": string }
  --out       directory receiving samples/<host>.json files
  --only      restrict the run to one host
  --delay-ms  minimum pause between two page requests (default 5000)
  --help      print this text`;

interface RawField {
  tag: string; type?: string; name?: string; id?: string; autocomplete?: string; inputmode?: string;
  maxlength?: number; hasPattern: boolean; required: boolean; label?: string; visibility: SampleField["visibility"];
}
interface RawPage {
  lang?: string; forms: { fields: RawField[]; buttons: string[] }[];
  iframes: string[]; shadowFields: number; providerTexts: string[];
}

// Passive init script: records calls to navigator.credentials, never alters them.
const INIT_SCRIPT = `(() => {
  const calls = (window.__lab_webauthn = []);
  const c = navigator.credentials;
  if (!c) return;
  for (const k of ["get", "create"]) {
    const orig = c[k] && c[k].bind(c);
    if (!orig) continue;
    c[k] = function (opts) { if (opts && opts.publicKey) calls.push(k); return orig(opts); };
  }
})();`;

/** Runs inside the page: structure only, never reads a field value. */
function pageExtract(): RawPage {
  const textOf = (el: Element | null) => (el?.textContent ?? "").replace(/\s+/g, " ").trim().slice(0, 200);
  function visibility(el: Element): RawField["visibility"] {
    const cs = getComputedStyle(el);
    if (cs.display === "none" || cs.visibility === "hidden") return "display_none";
    if (parseFloat(cs.opacity) === 0) return "opacity";
    const r = el.getBoundingClientRect();
    if (r.width <= 1 || r.height <= 1) return "zero_size";
    if (r.right < 0 || r.bottom < 0 || r.left > innerWidth + 2000 || r.top > document.documentElement.scrollHeight + 2000) return "offscreen";
    return "visible";
  }
  function labelOf(el: HTMLInputElement): string | undefined {
    const aria = el.getAttribute("aria-label");
    if (aria) return aria;
    const by = el.getAttribute("aria-labelledby");
    if (by) {
      const t = by.split(/\s+/).map((i) => textOf(document.getElementById(i))).join(" ").trim();
      if (t) return t;
    }
    if (el.id) {
      const l = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
      if (l && textOf(l)) return textOf(l);
    }
    const wrap = el.closest("label");
    if (wrap && textOf(wrap)) return textOf(wrap);
    if (el.placeholder) return el.placeholder;
    const prev = el.previousElementSibling;
    if (prev && textOf(prev)) return textOf(prev);
    return undefined;
  }
  function fieldOf(el: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement): RawField | null {
    const type = el instanceof HTMLInputElement ? el.type : undefined;
    if (type && ["hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file"].includes(type)) return null;
    const inp = el as HTMLInputElement;
    const ml = inp.maxLength;
    return {
      tag: el.tagName.toLowerCase(), type, name: el.getAttribute("name") ?? undefined, id: el.id || undefined,
      autocomplete: el.getAttribute("autocomplete") ?? undefined, inputmode: el.getAttribute("inputmode") ?? undefined,
      maxlength: ml > 0 ? ml : undefined, hasPattern: el.hasAttribute("pattern"), required: el.required,
      label: labelOf(inp), visibility: visibility(el),
    };
  }
  const SEL = "input, select, textarea";
  function buttonsIn(root: ParentNode): string[] {
    const out: string[] = [];
    root.querySelectorAll("button, input[type=submit], input[type=button], [role=button]").forEach((b) => {
      const t = b instanceof HTMLInputElement ? b.getAttribute("value") ?? "" : textOf(b);
      if (t) out.push(t);
    });
    return out;
  }
  const forms: RawPage["forms"] = [];
  const inForm = new Set<Element>();
  document.querySelectorAll("form").forEach((f) => {
    const fields = Array.from(f.querySelectorAll<HTMLInputElement>(SEL)).map((e) => { inForm.add(e); return fieldOf(e); }).filter((x): x is RawField => !!x);
    if (fields.length) forms.push({ fields, buttons: buttonsIn(f) });
  });
  const orphans = Array.from(document.querySelectorAll<HTMLInputElement>(SEL)).filter((e) => !inForm.has(e)).map(fieldOf).filter((x): x is RawField => !!x);
  if (orphans.length) forms.push({ fields: orphans, buttons: buttonsIn(document) });

  const iframes: string[] = [];
  document.querySelectorAll("iframe[src]").forEach((i) => iframes.push(i.getAttribute("src") ?? ""));
  let shadowFields = 0;
  document.querySelectorAll("*").forEach((el) => {
    if (el.shadowRoot) shadowFields += el.shadowRoot.querySelectorAll("input, select, textarea").length;
  });
  const providerTexts: string[] = [];
  document.querySelectorAll("button, a, [role=button]").forEach((b) => {
    const t = textOf(b);
    if (/google|apple|microsoft/i.test(t) && t.length < 80) providerTexts.push(t);
  });
  return { lang: document.documentElement.lang || undefined, forms, iframes, shadowFields, providerTexts };
}

function stepOf(fields: SampleField[]): FormStep {
  const vis = fields.filter((f) => f.visibility === "visible");
  const has = (r: SampleField["role"][]) => vis.some((f) => r.includes(f.role));
  const pw = has(["password", "new_password"]);
  const id = has(["username", "email"]);
  if (pw && id) return "both";
  if (pw) return "password";
  if (has(["otp"])) return "code";
  if (id) return "identifier";
  return "other";
}

function hostSite(a: string, b: string): boolean {
  const base = (h: string) => h.split(".").slice(-2).join(".");
  return base(a) === base(b);
}

const robotsCache = new Map<string, RobotsEntry>();

async function getRobots(origin: string): Promise<RobotsEntry> {
  const hit = robotsCache.get(origin);
  if (hit !== undefined) return hit;
  let entry: RobotsEntry;
  try {
    const res = await fetch(origin + "/robots.txt", { headers: { "user-agent": USER_AGENT }, signal: AbortSignal.timeout(10_000) });
    const text = res.ok ? await res.text() : "";
    entry = robotsEntry({ status: res.status, ok: res.ok, redirected: res.redirected, contentType: res.headers.get("content-type") ?? "" }, () => text);
  } catch {
    entry = "deny";
  }
  robotsCache.set(origin, entry);
  return entry;
}

async function urlAllowed(u: URL): Promise<boolean> {
  const e = await getRobots(u.origin);
  if (e === "deny") return false;
  return e === null || isAllowed(e, ROBOTS_AGENT, u.pathname + u.search);
}

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--help" || a === "-h") out.help = true;
    else if (a.startsWith("--")) out[a.slice(2)] = argv[++i] ?? "";
  }
  return out;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { console.log(USAGE); return; }
  if (typeof args.sites !== "string" || typeof args.out !== "string") { console.error(USAGE); process.exitCode = 2; return; }
  const delay = Math.max(5000, Number(args["delay-ms"] ?? 5000) || 5000); // never faster than 5 s
  const sites = JSON.parse(readFileSync(args.sites, "utf8")) as { url: string; category: Category }[];
  mkdirSync(args.out, { recursive: true });

  const pw = (await import("playwright-core")) as unknown as { chromium?: any; default?: { chromium: any } };
  const chromium = pw.chromium ?? pw.default!.chromium;
  const browser = await chromium.launch({ channel: "chromium" });
  const seen = new Set<string>();
  let first = true;
  let dupes = 0;
  try {
    for (const site of sites) {
      const url = new URL(site.url);
      if (typeof args.only === "string" && url.hostname !== args.only) continue;
      const base: Sample = { source_url: site.url, host: url.hostname, category: site.category, captured_at: new Date().toISOString(), extractor: 1, status: "ok" };
      if (seen.has(url.hostname)) { // one page per host and pass: say so instead of dropping silently
        const n = ++dupes;
        writeFileSync(`${args.out}/${url.hostname}.dup${n}.json`, stableJson({ ...base, status: "skipped: duplicate host" }));
        console.log(`${url.hostname}: skipped: duplicate host`);
        continue;
      }
      seen.add(url.hostname);
      if (!first) await new Promise((r) => setTimeout(r, delay));
      first = false;
      let sample: Sample;
      if (!(await urlAllowed(url))) {
        sample = { ...base, status: "skipped: robots" };
      } else {
        const ctx = await browser.newContext({ userAgent: USER_AGENT, serviceWorkers: "block" });
        let blocked = false;
        let timedOut = false;
        const deadline = setTimeout(() => { timedOut = true; ctx.close().catch(() => {}); }, 30_000); // covers goto, wait and evaluate
        try {
          const page = await ctx.newPage();
          await page.route("**/*", async (route: any) => {
            const req = route.request();
            if (req.isNavigationRequest() && req.frame() === page.mainFrame() && !(await urlAllowed(new URL(req.url())))) {
              blocked = true;
              await route.abort().catch(() => {});
            } else {
              await route.continue().catch(() => {});
            }
          });
          await page.addInitScript(INIT_SCRIPT);
          await page.goto(site.url, { timeout: 30_000, waitUntil: "domcontentloaded" });
          await page.waitForTimeout(2500);
          if (blocked || !(await urlAllowed(new URL(page.url())))) {
            sample = { ...base, status: "skipped: robots" };
          } else {
            const raw: RawPage = await page.evaluate(pageExtract);
            const calls: ("get" | "create")[] = await page.evaluate(() => (window as any).__lab_webauthn ?? []);
            sample = build(base, raw, calls);
          }
        } catch (e) {
          sample = timedOut
            ? { ...base, status: "error: timeout" }
            : blocked
            ? { ...base, status: "skipped: robots" }
            : { ...base, status: `error: ${sanitizeText(e instanceof Error ? e.message.split("\n")[0] : String(e)) ?? "unknown"}` };
        } finally {
          clearTimeout(deadline);
          await ctx.close().catch(() => {});
        }
      }
      writeFileSync(`${args.out}/${url.hostname}.json`, stableJson(sample));
      console.log(`${url.hostname}: ${sample.status}`);
    }
  } finally {
    await browser.close();
  }
}

function build(base: Sample, raw: RawPage, calls: ("get" | "create")[]): Sample {
  const forms: SampleForm[] = raw.forms.map((f) => {
    const fields: SampleField[] = f.fields.map((x) => {
      const out: SampleField = {
        tag: x.tag, type: x.type, name: sanitizeToken(x.name), id: sanitizeToken(x.id), autocomplete: sanitizeToken(x.autocomplete),
        inputmode: sanitizeToken(x.inputmode), maxlength: x.maxlength, hasPattern: x.hasPattern, required: x.required,
        label: sanitizeText(x.label), visibility: x.visibility, role: "unknown",
      };
      out.role = classifyRole(out);
      return out;
    });
    return { step: stepOf(fields), fields, buttons: f.buttons.map((b) => sanitizeText(b)).filter((b): b is string => !!b) };
  });
  const iframes: { origin: string; sameSite: boolean }[] = [];
  for (const src of raw.iframes) {
    try {
      const u = new URL(src, base.source_url);
      if (u.protocol === "http:" || u.protocol === "https:") iframes.push({ origin: sanitizeOrigin(u.origin), sameSite: hostSite(u.hostname, base.host) });
    } catch { /* ignore malformed src */ }
  }
  const providers = new Set<ProviderId>();
  for (const t of raw.providerTexts) for (const p of ["google", "apple", "microsoft"] as ProviderId[]) if (t.toLowerCase().includes(p)) providers.add(p);
  const lang = raw.lang?.toLowerCase().split("-")[0];
  return {
    ...base, lang: lang || "und", forms, iframes, shadowFields: raw.shadowFields,
    webauthnCalls: [...new Set(calls)], providerButtons: [...providers].sort(),
  };
}

main().catch((e) => { console.error(e instanceof Error ? e.message : e); process.exitCode = 1; });
