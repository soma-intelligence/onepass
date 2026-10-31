// Corpus extractor: loads public login/signup/checkout/address pages in a
// fresh Chromium context and records only the DOM structure (no values, no
// clicks, no submission). Respects robots.txt, one page per host, paced.
// Usage: node --experimental-strip-types lab/corpus/extract.ts --sites <json> --out <dir> [--only <host>] [--delay-ms 5000]
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { USER_AGENT, urlAllowed } from "./robots-net.ts";
import { INIT_SCRIPT, pageExtra } from "./page-capture.ts";
import { build, type PageExtra } from "./build.ts";
import { sanitizeText } from "./sanitize.ts";
import { extractFeatures } from "../../src/content/detect/features.ts";
import type { PageFeatures } from "../../src/content/detect/features.ts";
import { stableJson } from "./types.ts";
import type { Category, Sample } from "./types.ts";

const USAGE = `Usage: node --experimental-strip-types lab/corpus/extract.ts --sites <json> --out <dir> [--only <host>] [--delay-ms 5000]

Captures the DOM structure (never values) of the public pages listed in the sites file.
  --sites     JSON array of { "url": string, "category": string }
  --out       directory receiving samples/<host>.json files
  --only      restrict the run to one host
  --delay-ms  minimum pause between two page requests (default 5000)
  --help      print this text`;

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
