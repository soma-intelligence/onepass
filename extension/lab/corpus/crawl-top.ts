// Resumable crawl of the Tranco top 1000: per site, the home page, the sitemap and
// the form pages discovery picks, each rendered and recorded as structure only.
// GET requests only, robots.txt respected, no click, no typing.
// Usage: node --experimental-strip-types lab/corpus/crawl-top.ts [--out lab/corpus/samples] [--concurrency 4] [--limit n]
import { mkdirSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { build, type PageExtra } from "./build.ts";
import { discoverFormPages, type SeedLexicon } from "./discover.ts";
import { INIT_SCRIPT, pageExtra } from "./page-capture.ts";
import { USER_AGENT, urlAllowed } from "./robots-net.ts";
import { HostPacer, SiteBudget, clearHost, pendingHosts, routeVerdict, writeAtomic } from "./schedule.ts";
import { sanitizeText } from "./sanitize.ts";
import { extractFeatures } from "../../src/content/detect/features.ts";
import type { PageFeatures } from "../../src/content/detect/features.ts";
import { stableJson } from "./types.ts";
import type { Category, Sample } from "./types.ts";

const USAGE = `Usage: node --experimental-strip-types lab/corpus/crawl-top.ts [--out <dir>] [--concurrency <n>] [--limit <n>]

Crawls the Tranco top 1000 (resumable) and writes <host>.<n>.json per page plus <host>.done.json per host.
  --out          output directory (default lab/corpus/samples)
  --concurrency  sites in parallel (default 4, never more than 4)
  --limit        only the first n pending hosts
  --help         print this text`;

const MAX_PARALLEL = 4;
const GOTO_MS = 30_000;
const IDLE_MS = 10_000;
const PAGE_DEADLINE_MS = GOTO_MS + IDLE_MS + 5_000; // goto, idle wait, extraction

export type SiteStatus = "ok" | "skipped: robots" | "abandoned" | `error: ${string}`;
export const stats = { abortedNonGet: 0, abortedRobots: 0, closedPopups: 0, closedWebSockets: 0, pages: 0 };

const guess = (url: string): Category => {
  const p = new URL(url).pathname.toLowerCase();
  if (/regist|signup|sign-up|inscription|registr/.test(p)) return "signup";
  if (/checkout|kasse|paiement|pago/.test(p)) return "checkout";
  return "login";
};
const errText = (e: unknown): string => sanitizeText(e instanceof Error ? e.message.split("\n")[0] : String(e)) ?? "unknown";

/** The browser died or disconnected: the crawl stops and no host is marked done. */
export class BrowserGone extends Error {}

/**
 * Network guards of one browser context. Routing sits on the context so popups and
 * every other page are covered: only GET leaves the browser, top-level navigations
 * obey robots.txt, WebSockets are closed, extra pages are closed, downloads cancelled.
 * Returns whether a robots refusal happened.
 */
export async function guardContext(ctx: any, allowed: (u: URL) => Promise<boolean>): Promise<{ readonly blocked: boolean }> {
  const state = { blocked: false };
  let first = true;
  await ctx.route("**/*", async (route: any) => {
    const req = route.request();
    let nav = false;
    try { nav = req.isNavigationRequest() && req.frame().parentFrame() === null; } catch { /* requests without a frame are no navigation */ }
    const verdict = routeVerdict({ method: req.method(), isMainNavigation: nav }, nav ? await allowed(new URL(req.url())) : true);
    if (verdict === "abort-method") { stats.abortedNonGet++; await route.abort().catch(() => {}); }
    else if (verdict === "abort-robots") { state.blocked = true; stats.abortedRobots++; await route.abort().catch(() => {}); }
    else await route.continue().catch(() => {});
  });
  await ctx.routeWebSocket(/.*/, (ws: any) => { stats.closedWebSockets++; ws.close().catch(() => {}); });
  ctx.on("page", (p: any) => {
    p.on("download", (d: any) => { d.cancel().catch(() => {}); });
    if (first) { first = false; return; } // the page this crawler opened
    stats.closedPopups++;
    p.close().catch(() => {});
  });
  return state;
}

/** Renders one URL. Returns the sample and, when asked, the rendered HTML. Never throws except BrowserGone. */
async function capture(browser: any, url: string, wantHtml: boolean, pacer: HostPacer): Promise<{ sample: Sample; html?: string; http4xx?: boolean }> {
  const u = new URL(url);
  const base: Sample = { source_url: url, host: u.hostname, category: guess(url), captured_at: new Date().toISOString(), extractor: 2, source: "rendered", status: "ok" };
  const gate = (h: string) => pacer.wait(h);
  const allowed = (x: URL) => urlAllowed(x, gate);
  if (!(await allowed(u))) return { sample: { ...base, status: "skipped: robots" } };
  const ctx = await browser.newContext({ userAgent: USER_AGENT, serviceWorkers: "block", acceptDownloads: false });
  let timedOut = false;
  const deadline = setTimeout(() => { timedOut = true; ctx.close().catch(() => {}); }, PAGE_DEADLINE_MS); // goto + idle wait + extraction
  try {
    const guard = await guardContext(ctx, allowed);
    const page = await ctx.newPage();
    await page.addInitScript(INIT_SCRIPT);
    const response = await page.goto(url, { timeout: GOTO_MS, waitUntil: "domcontentloaded" });
    if (response && !response.ok()) {
      const code = response.status();
      return { sample: { ...base, status: `error: http ${code}` }, http4xx: code >= 400 && code < 500 };
    }
    await page.waitForLoadState("networkidle", { timeout: IDLE_MS }).catch(() => {}); // on timeout, take what rendered
    if (guard.blocked || !(await allowed(new URL(page.url())))) return { sample: { ...base, status: "skipped: robots" } };
    const features: PageFeatures = await page.evaluate(`(${extractFeatures.toString()})(document)`);
    const extra: PageExtra = await page.evaluate(pageExtra);
    const calls: ("get" | "create")[] = await page.evaluate(() => (window as any).__lab_webauthn ?? []);
    const html = wantHtml ? ((await page.content()) as string) : undefined;
    return { sample: build(base, features, extra, calls), html };
  } catch (e) {
    if (!browser.isConnected()) throw new BrowserGone(errText(e));
    return { sample: { ...base, status: timedOut ? "error: timeout" : `error: ${errText(e)}` } };
  } finally {
    clearTimeout(deadline);
    await ctx.close().catch(() => {});
  }
}

/** Plain GET of a sitemap, robots-checked; undefined when absent, disallowed, redirected or failing. */
async function fetchSitemap(origin: string, pacer: HostPacer): Promise<string | undefined> {
  const u = new URL(origin + "/sitemap.xml");
  if (!(await urlAllowed(u, (h) => pacer.wait(h)))) return undefined;
  await pacer.wait(u.hostname);
  try {
    // A redirect could lead off-host or into a disallowed path: treat any 3xx as "no sitemap".
    const res = await fetch(u, { method: "GET", redirect: "manual", headers: { "user-agent": USER_AGENT }, signal: AbortSignal.timeout(10_000) });
    return res.ok ? (await res.text()).slice(0, 2_000_000) : undefined;
  } catch {
    return undefined;
  }
}

export async function crawlSite(browser: any, host: string, out: string, pacer: HostPacer, lexicon: SeedLexicon): Promise<{ pages: number; status: SiteStatus }> {
  const budget = new SiteBudget();
  let pages = 0;
  let status: SiteStatus = "ok";
  const writePage = (s: Sample): void => { writeAtomic(`${out}/${host}.${pages}.json`, stableJson(s)); pages++; stats.pages++; };
  // A 4xx is no site failure (guessed paths 404 often); 5xx, timeouts and navigation errors count.
  const noteError = (r: { sample: Sample; http4xx?: boolean }): void => { if (r.sample.status.startsWith("error") && !r.http4xx) budget.recordError(); };
  try {
    const homeUrl = `https://${host}/`;
    budget.allowPage(); // the home page is the first of the 6
    await pacer.wait(new URL(homeUrl).hostname);
    const home = await capture(browser, homeUrl, true, pacer);
    if (home.sample.status === "skipped: robots") return { pages, status: "skipped: robots" };
    writePage(home.sample);
    noteError(home);
    if (home.sample.status.startsWith("error")) status = home.sample.status as SiteStatus;
    let urls: string[] = [];
    if (home.html !== undefined && !budget.abandoned) {
      const sitemap = await fetchSitemap(new URL(homeUrl).origin, pacer);
      urls = discoverFormPages({ url: homeUrl, html: home.html }, sitemap, lexicon);
    }
    for (const url of urls) {
      if (url === homeUrl || !budget.allowPage()) continue;
      await pacer.wait(new URL(url).hostname);
      const r = await capture(browser, url, false, pacer);
      if (r.sample.status === "skipped: robots") continue;
      writePage(r.sample);
      noteError(r);
    }
    if (budget.abandoned) status = "abandoned";
    else if (pages > 1 || !status.startsWith("error")) status = "ok";
  } catch (e) {
    if (e instanceof BrowserGone || !browser.isConnected()) throw e;
    status = `error: ${errText(e)}`;
  }
  return { pages, status };
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
  const out = typeof args.out === "string" && args.out ? args.out : "lab/corpus/samples";
  const concurrency = Math.min(MAX_PARALLEL, Math.max(1, Number(args.concurrency ?? MAX_PARALLEL) || MAX_PARALLEL));
  const limit = args.limit === undefined ? Infinity : Math.max(0, Number(args.limit) || 0);
  const tranco = JSON.parse(readFileSync(new URL("./tranco.json", import.meta.url), "utf8")) as { hosts: string[] };
  const lexicon = JSON.parse(readFileSync(new URL("./seed-lexicon.json", import.meta.url), "utf8")) as SeedLexicon;
  mkdirSync(out, { recursive: true });
  const todo = pendingHosts(tranco.hosts, out).slice(0, limit);
  console.log(`${todo.length} hosts to crawl (${tranco.hosts.length - pendingHosts(tranco.hosts, out).length} already done), concurrency ${concurrency}`);

  const pw = (await import("playwright-core")) as unknown as { chromium?: any; default?: { chromium: any } };
  const chromium = pw.chromium ?? pw.default!.chromium;
  const browser = await chromium.launch({ channel: "chromium" });
  const pacer = new HostPacer(5000);
  let next = 0;
  let dead = false;
  const worker = async (): Promise<void> => {
    while (next < todo.length && !dead) {
      const host = todo[next++]!;
      clearHost(host, out); // leftovers of an interrupted run
      let r: { pages: number; status: SiteStatus };
      try {
        r = await crawlSite(browser, host, out, pacer, lexicon);
      } catch (e) {
        dead = true; // browser-level failure: no done marker, the host is retried next run
        console.error(`${host}: browser gone (${errText(e)}), stopping`);
        return;
      }
      if (!browser.isConnected()) { dead = true; console.error(`${host}: browser disconnected, stopping`); return; }
      try {
        writeAtomic(`${out}/${host}.done.json`, stableJson({ host, pages: r.pages, status: r.status, finishedAt: new Date().toISOString() }));
        console.log(`${host}: ${r.pages} pages, ${r.status}`);
      } catch (e) {
        console.error(`${host}: could not write done marker (${errText(e)})`);
      }
    }
  };
  try {
    await Promise.all(Array.from({ length: concurrency }, worker));
    if (dead) process.exitCode = 1;
  } finally {
    await browser.close().catch(() => {});
    console.log(`aborted non-GET requests: ${stats.abortedNonGet}; robots-blocked navigations: ${stats.abortedRobots}; popups closed: ${stats.closedPopups}; websockets closed: ${stats.closedWebSockets}; pages written: ${stats.pages}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => { console.error(e instanceof Error ? e.message : e); process.exitCode = 1; });
}
