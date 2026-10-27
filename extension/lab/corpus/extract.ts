// Corpus extractor: loads public login/signup/checkout/address pages in a
// fresh Chromium context and records only the DOM structure (no values, no
// clicks, no submission). Respects robots.txt, one page per host, paced.
// Usage: node --experimental-strip-types lab/corpus/extract.ts --sites <json> --out <dir> [--only <host>] [--delay-ms 5000]
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { isAllowed, robotsEntry } from "./robots.ts";
import type { RobotsEntry } from "./robots.ts";
import { build, type PageExtra } from "./build.ts";
import { sanitizeText } from "./sanitize.ts";
import { extractFeatures } from "../../src/content/detect/features.ts";
import type { PageFeatures } from "../../src/content/detect/features.ts";
import { stableJson } from "./types.ts";
import type { Category, Sample } from "./types.ts";

const USER_AGENT = "Mozilla/5.0 (compatible; OnePassLabCorpus/1; structure-only research crawler)";
const ROBOTS_AGENT = "OnePassLabCorpus";
const USAGE = `Usage: node --experimental-strip-types lab/corpus/extract.ts --sites <json> --out <dir> [--only <host>] [--delay-ms 5000]

Captures the DOM structure (never values) of the public pages listed in the sites file.
  --sites     JSON array of { "url": string, "category": string }
  --out       directory receiving samples/<host>.json files
  --only      restrict the run to one host
  --delay-ms  minimum pause between two page requests (default 5000)
  --help      print this text`;

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

/** Runs inside the page: document language and the text of sign-in provider buttons. */
function pageExtra(): PageExtra {
  const textOf = (el: Element) => (el.textContent ?? "").replace(/\s+/g, " ").trim().slice(0, 200);
  const providerTexts: string[] = [];
  document.querySelectorAll("button, a, [role=button]").forEach((b) => {
    const t = textOf(b);
    if (/google|apple|microsoft/i.test(t) && t.length < 80) providerTexts.push(t);
  });
  return { lang: document.documentElement.lang || undefined, providerTexts };
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
      const base: Sample = { source_url: site.url, host: url.hostname, category: site.category, captured_at: new Date().toISOString(), extractor: 2, source: "rendered", status: "ok" };
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
            // The shared extractor is self-contained: it runs in the page from its own source.
            const features: PageFeatures = await page.evaluate(`(${extractFeatures.toString()})(document)`);
            const extra: PageExtra = await page.evaluate(pageExtra);
            const calls: ("get" | "create")[] = await page.evaluate(() => (window as any).__lab_webauthn ?? []);
            sample = build(base, features, extra, calls);
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

main().catch((e) => { console.error(e instanceof Error ? e.message : e); process.exitCode = 1; });
