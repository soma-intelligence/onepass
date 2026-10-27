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
import { HostPacer, SiteBudget, pendingHosts, routeVerdict, writeAtomic } from "./schedule.ts";
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
const PAGE_DEADLINE_MS = 30_000;
const IDLE_MS = 10_000;

export type SiteStatus = "ok" | "skipped: robots" | "abandoned" | `error: ${string}`;
export const stats = { abortedNonGet: 0, abortedRobots: 0, pages: 0 };

const guess = (url: string): Category => {
  const p = new URL(url).pathname.toLowerCase();
  if (/regist|signup|sign-up|inscription|registr/.test(p)) return "signup";
  if (/checkout|kasse|paiement|pago/.test(p)) return "checkout";
  return "login";
};
const errText = (e: unknown): string => sanitizeText(e instanceof Error ? e.message.split("\n")[0] : String(e)) ?? "unknown";

/** Renders one URL. Returns the sample and, when asked, the rendered HTML. Never throws. */
async function capture(browser: any, url: string, wantHtml: boolean): Promise<{ sample: Sample; html?: string }> {
  const u = new URL(url);
  const base: Sample = { source_url: url, host: u.hostname, category: guess(url), captured_at: new Date().toISOString(), extractor: 2, source: "rendered", status: "ok" };
  if (!(await urlAllowed(u))) return { sample: { ...base, status: "skipped: robots" } };
  const ctx = await browser.newContext({ userAgent: USER_AGENT, serviceWorkers: "block", acceptDownloads: false });
  let blocked = false;
  let timedOut = false;
  const deadline = setTimeout(() => { timedOut = true; ctx.close().catch(() => {}); }, PAGE_DEADLINE_MS);
  try {
    const page = await ctx.newPage();
    await page.route("**/*", async (route: any) => {
      const req = route.request();
      const nav = req.isNavigationRequest() && req.frame() === page.mainFrame();
      const verdict = routeVerdict({ method: req.method(), isMainNavigation: nav }, nav ? await urlAllowed(new URL(req.url())) : true);
      if (verdict === "abort-method") { stats.abortedNonGet++; await route.abort().catch(() => {}); }
      else if (verdict === "abort-robots") { blocked = true; stats.abortedRobots++; await route.abort().catch(() => {}); }
      else await route.continue().catch(() => {});
    });
    page.on("download", (d: any) => { d.cancel().catch(() => {}); });
    await page.addInitScript(INIT_SCRIPT);
    await page.goto(url, { timeout: PAGE_DEADLINE_MS, waitUntil: "domcontentloaded" });
    await page.waitForLoadState("networkidle", { timeout: IDLE_MS }).catch(() => {}); // on timeout, take what rendered
    if (blocked || !(await urlAllowed(new URL(page.url())))) return { sample: { ...base, status: "skipped: robots" } };
    const features: PageFeatures = await page.evaluate(`(${extractFeatures.toString()})(document)`);
    const extra: PageExtra = await page.evaluate(pageExtra);
    const calls: ("get" | "create")[] = await page.evaluate(() => (window as any).__lab_webauthn ?? []);
    const html = wantHtml ? ((await page.content()) as string) : undefined;
    return { sample: build(base, features, extra, calls), html };
  } catch (e) {
    return { sample: { ...base, status: timedOut ? "error: timeout" : blocked ? "skipped: robots" : `error: ${errText(e)}` } };
  } finally {
    clearTimeout(deadline);
    await ctx.close().catch(() => {});
  }
}

/** Plain GET of a sitemap, robots-checked; undefined when absent, disallowed or failing. */
async function fetchSitemap(origin: string): Promise<string | undefined> {
  const u = new URL(origin + "/sitemap.xml");
  if (!(await urlAllowed(u))) return undefined;
  try {
    const res = await fetch(u, { method: "GET", headers: { "user-agent": USER_AGENT }, signal: AbortSignal.timeout(10_000) });
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
  try {
    const homeUrl = `https://${host}/`;
    await pacer.wait(host);
    const home = await capture(browser, homeUrl, true);
    if (home.sample.status === "skipped: robots") return { pages, status: "skipped: robots" };
    if (home.sample.status.startsWith("error") || home.html === undefined) {
      budget.recordError();
      status = `error: ${home.sample.status.replace(/^error: /, "")}`;
    }
    const finalHome = home.html !== undefined ? homeUrl : undefined;
    let urls: string[] = [];
    if (finalHome) {
      await pacer.wait(host);
      const sitemap = await fetchSitemap(new URL(homeUrl).origin);
      urls = discoverFormPages({ url: homeUrl, html: home.html! }, sitemap, lexicon);
    }
    for (const url of urls) {
      if (!budget.allowPage()) break;
      await pacer.wait(host);
      const { sample } = await capture(browser, url, false);
      if (sample.status === "skipped: robots") continue;
      writePage(sample);
      if (sample.status.startsWith("error")) budget.recordError();
    }
    if (budget.abandoned) status = "abandoned";
  } catch (e) {
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
  const worker = async (): Promise<void> => {
    while (next < todo.length) {
      const host = todo[next++]!;
      const r = await crawlSite(browser, host, out, pacer, lexicon);
      writeAtomic(`${out}/${host}.done.json`, stableJson({ host, pages: r.pages, status: r.status, finishedAt: new Date().toISOString() }));
      console.log(`${host}: ${r.pages} pages, ${r.status}`);
    }
  };
  try {
    await Promise.all(Array.from({ length: concurrency }, worker));
  } finally {
    await browser.close();
    console.log(`aborted non-GET requests: ${stats.abortedNonGet}; robots-blocked navigations: ${stats.abortedRobots}; pages written: ${stats.pages}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => { console.error(e instanceof Error ? e.message : e); process.exitCode = 1; });
}
