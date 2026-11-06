// Fast labelled dataset build (Task 9). Generates worlds in chunks, renders each
// page of each site with the lab renderer (label marks on), loads it in a pool
// of reused headless Chromium pages (no extension, no network, no lab server:
// the HTML is the exact string renderSitePage returns, put in the page with
// setContent), extracts the features with the shared extractor, and writes one
// labelled row per field to gzip JSONL parts plus a manifest.
//
// The lab server cannot serve the pages of this build: a multi_step or OTP page
// answers only to a session that passed the previous page by POST. Rendering
// directly gives the same markup, scripts included.
//
// Delayed mounts (delayed_fields, up to 6 s) would hold a page for seconds each:
// the page's setTimeout is rewritten to fire at once, so the runtime script
// mounts the form in the next task instead of after its delay. The DOM it
// builds is the same; extraction waits until the mount point is gone.
//
// Usage: node --experimental-strip-types lab/dataset/build.ts --seed <s> --forms <n> [--workers <k>] [--out <dir>]
import { createWriteStream, mkdirSync, writeFileSync } from "node:fs";
import type { WriteStream } from "node:fs";
import { cpus } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createGzip } from "node:zlib";
import type { Gzip } from "node:zlib";
import { extractFeatures } from "../../src/content/detect/features.ts";
import { FEATURE_VERSION } from "../../src/content/detect/features.ts";
import type { PageFeatures } from "../../src/content/detect/features.ts";
import type { Patterns } from "../corpus/types.ts";
import { generate, loadPatterns } from "../gen/generate.ts";
import { GENERATOR_VERSION } from "../gen/model.ts";
import type { Site } from "../gen/model.ts";
import { renderSitePage } from "../gen/render.ts";
import { datasetPages, rowsFor } from "./rows.ts";
import type { DatasetRow } from "./rows.ts";

export const ROWS_PER_PART = 50_000;
const SITES_PER_CHUNK = 400;
const EXT_ROOT = fileURLToPath(new URL("../../", import.meta.url));

export interface BuildOptions {
  seed: string;
  forms: number;
  workers?: number;
  /** Directory receiving `<seed>-g<generator>/` (default `lab/out/dataset`). */
  out?: string;
  patterns?: Patterns;
  /** Test hook: runs before the page of task `seq` is evaluated; a throw counts as a failed form. */
  beforeEvaluate?: (seq: number) => void;
}

export interface Manifest {
  seed: string;
  generator: number;
  featureVersion: number;
  forms: number;
  rows: number;
  parts: number;
  workers: number;
  mismatches: number;
  /** Pages that produced no row (a form the extractor cannot reach, e.g. in a shadow root). Not counted in formsPerSecond. */
  skippedForms: number;
  /** Pages whose rendering or extraction threw: logged, page recycled, build continued. */
  failedForms: number;
  seconds: number;
  formsPerSecond: number;
  byTarget: Record<string, number>;
  byLang: Record<string, number>;
  bySource: Record<string, number>;
  bySplit: Record<string, number>;
}

interface Task { site: Site; step: number; seed: string }

/** Tasks of a seed, lazily: one world per chunk of sites, every page of every site. */
function* tasks(seed: string, patterns: Patterns): Generator<Task> {
  for (let chunk = 0; ; chunk++) {
    const chunkSeed = `${seed}/c${chunk}`;
    const world = generate(chunkSeed, { sites: SITES_PER_CHUNK, patterns });
    for (const site of world.sites) {
      const pages = datasetPages(site);
      for (let step = 0; step < pages.length; step++) yield { site, step, seed: chunkSeed };
    }
  }
}

/**
 * First script of the page: delays fire at once (see the header). An init script does not survive setContent, so it
 * is inlined. setContent reuses the window, so the shim must be idempotent: the native setTimeout is kept once in a
 * non-enumerable property and every install wraps that one, never a previous wrapper (nesting overflowed the stack
 * after about 10,000 forms on one page).
 */
export const FAST_TIMERS = `<script>(function(){if(!window.__nativeST){Object.defineProperty(window,"__nativeST",{value:window.setTimeout.bind(window)});}var st=window.__nativeST;window.setTimeout=function(f,d){return st.apply(null,[f,0].concat([].slice.call(arguments,2)));};})();</script>`;

/** The HTML of a page with the timer shim as its first script. */
export const withFastTimers = (html: string): string => html.replace("<head>", `<head>${FAST_TIMERS}`);

/** The mount point of a delayed form is replaced by the form: wait for that, then extract. */
export const EXTRACT = `(async () => {
  for (let i = 0; i < 200 && document.getElementById("lab-mount"); i++) await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
  return (${extractFeatures.toString()})(document, { labField: true });
})()`;

/** Every mark must name a field of the page; unless the form is out of the extractor's reach (shadow root), every field must be marked. */
function consistent(site: Site, step: number, page: PageFeatures): boolean {
  const spec = datasetPages(site)[step]!;
  const marks = new Set(page.forms.flatMap((f) => f.fields).filter((f) => f.lab !== undefined).map((f) => Number(f.lab)));
  if (site.traits.includes("shadow_open") || site.traits.includes("shadow_closed")) return marks.size === 0;
  // Radio groups (forms flows) are not extracted as fields: no row, no mark expected.
  const want = spec.fields.map((f, k) => (f.render?.choice?.kind === "radio" ? -1 : k)).filter((k) => k >= 0);
  return marks.size === want.length && want.every((k) => marks.has(k));
}

class PartWriter {
  private n = 0;
  private inPart = 0;
  private gz?: Gzip;
  private file?: WriteStream;
  private done: Promise<void>[] = [];
  readonly dir: string;
  constructor(dir: string) { this.dir = dir; }
  get parts(): number { return this.n; }
  private open(): void {
    this.gz = createGzip({ level: 4 });
    this.file = createWriteStream(join(this.dir, `part-${String(this.n++).padStart(4, "0")}.jsonl.gz`));
    this.gz.pipe(this.file);
    this.inPart = 0;
  }
  private close(): void {
    if (!this.gz || !this.file) return;
    const file = this.file;
    this.done.push(new Promise((res, rej) => { file.on("finish", () => res()); file.on("error", rej); }));
    this.gz.end();
    this.gz = undefined;
  }
  write(row: DatasetRow): void {
    if (!this.gz || this.inPart >= ROWS_PER_PART) { this.close(); this.open(); }
    this.gz!.write(`${JSON.stringify(row)}\n`);
    this.inPart++;
  }
  async finish(): Promise<void> {
    this.close();
    await Promise.all(this.done);
  }
}

const bump = (m: Record<string, number>, k: string) => { m[k] = (m[k] ?? 0) + 1; };

export async function buildDataset(opts: BuildOptions): Promise<Manifest> {
  const patterns = opts.patterns ?? loadPatterns();
  const workers = Math.max(1, opts.workers ?? cpus().length);
  const dir = join(resolve(EXT_ROOT, opts.out ?? "lab/out/dataset"), `${opts.seed}-g${GENERATOR_VERSION}`);
  mkdirSync(dir, { recursive: true });
  const writer = new PartWriter(dir);
  const m: Manifest = {
    seed: opts.seed, generator: GENERATOR_VERSION, featureVersion: FEATURE_VERSION, forms: 0, rows: 0, parts: 0, workers,
    mismatches: 0, skippedForms: 0, failedForms: 0, seconds: 0, formsPerSecond: 0, byTarget: {}, byLang: {}, bySource: {}, bySplit: {},
  };

  const pw = (await import("playwright-core")) as unknown as { chromium?: any; default?: { chromium: any } };
  const chromium = pw.chromium ?? pw.default!.chromium;
  const browser = await chromium.launch({ channel: "chromium" });
  const started = Date.now(); // throughput measurement only: no row depends on it
  const source = tasks(opts.seed, patterns);
  let claimed = 0;
  const next = (): (Task & { seq: number }) | undefined => (claimed < opts.forms ? { ...(source.next().value as Task), seq: claimed++ } : undefined);
  // Rows are written in task order, whatever order the workers finish in: a seed always gives the same files.
  const done = new Map<number, DatasetRow[] | null>();
  let written = 0;
  const flush = (): void => {
    for (let rows = done.get(written); rows !== undefined; rows = done.get(written)) {
      done.delete(written++);
      m.forms++;
      if (rows === null) m.failedForms++;
      else if (rows.length === 0) m.skippedForms++;
      for (const row of rows ?? []) {
        writer.write(row);
        m.rows++;
        bump(m.byTarget, row.target);
        bump(m.byLang, row.lang);
        bump(m.bySource, row.source);
        bump(m.bySplit, row.split);
      }
    }
  };

  const worker = async (): Promise<void> => {
    let ctx = await browser.newContext({ javaScriptEnabled: true, serviceWorkers: "block" });
    let page = await ctx.newPage();
    for (let t = next(); t; t = next()) {
      try {
        opts.beforeEvaluate?.(t.seq);
        const p = datasetPages(t.site)[t.step]!;
        const html = withFastTimers(renderSitePage(t.site, p.page, p.ctx, { labelMarks: true }));
        await page.setContent(html, { waitUntil: "domcontentloaded" });
        const features: PageFeatures = await page.evaluate(EXTRACT);
        if (!consistent(t.site, t.step, features)) {
          m.mismatches++;
          if (process.env.DATASET_DEBUG) console.error(`mismatch site ${t.site.index} ${t.site.flow} ${t.site.traits.join(",")} step ${t.step} marks ${JSON.stringify(features.forms.flatMap((f) => f.fields.map((x) => x.lab)))} spec ${datasetPages(t.site)[t.step]!.fields.length}`);
        }
        done.set(t.seq, rowsFor(t.site, t.step, features, t.seed));
      } catch (e) {
        console.error(`dataset: form ${t.seq} (site ${t.site.index}, step ${t.step}) failed: ${e instanceof Error ? e.message.split("\n")[0] : String(e)}`);
        done.set(t.seq, null);
        // A page that threw may be broken: replace it.
        await ctx.close().catch(() => undefined);
        ctx = await browser.newContext({ javaScriptEnabled: true, serviceWorkers: "block" });
        page = await ctx.newPage();
      }
      flush();
    }
    await ctx.close();
  };
  try {
    await Promise.all(Array.from({ length: workers }, worker));
  } finally {
    await browser.close();
  }
  await writer.finish();
  m.parts = writer.parts;
  m.seconds = Math.round((Date.now() - started) / 10) / 100;
  m.formsPerSecond = Math.round(((m.forms - m.skippedForms - m.failedForms) / Math.max(m.seconds, 0.001)) * 10) / 10;
  writeFileSync(join(dir, "manifest.json"), `${JSON.stringify(m, null, 2)}\n`);
  return m;
}

function parseArgs(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 2) {
    const k = argv[i]!;
    const v = argv[i + 1];
    if (!k.startsWith("--") || v === undefined || v.startsWith("--")) throw new Error(`bad argument ${k}`);
    out[k.slice(2)] = v;
  }
  return out;
}

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  const a = parseArgs(process.argv.slice(2));
  const forms = Number(a.forms);
  if (!a.seed || !Number.isInteger(forms) || forms < 1) {
    console.error("Usage: node --experimental-strip-types lab/dataset/build.ts --seed <s> --forms <n> [--workers <k>] [--out <dir>]");
    process.exit(2);
  }
  buildDataset({ seed: a.seed, forms, workers: a.workers ? Number(a.workers) : undefined, out: a.out })
    .then((m) => console.log(JSON.stringify({ forms: m.forms, rows: m.rows, parts: m.parts, mismatches: m.mismatches, skippedForms: m.skippedForms, failedForms: m.failedForms, seconds: m.seconds, formsPerSecond: m.formsPerSecond })))
    .catch((e) => { console.error(e instanceof Error ? e.message : e); process.exit(1); });
}
