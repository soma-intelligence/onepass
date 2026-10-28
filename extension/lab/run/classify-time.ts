// Per-form classify time of a model build, measured in the extension's own service worker (Task 16).
// The lab's regular build has no handle on the worker, so this builds the e2e variant of the same
// classifier (same ONEPASS_* environment) into a temp folder, loads it in headless Chromium, and times
// `modelSession.predict` (vectorize or tokenize + inference, as Task 15 measured it) over the first
// form of up to 50 static sites of the run's world; median of 3 repetitions per form after a warm-up.
//   node --experimental-strip-types lab/run/classify-time.ts --seed <s> --sites <n> --out <file.json>
import { chromium } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { timeStats } from "../classifier-info.ts";
import type { ClassifyTime } from "../compare.ts";
import { datasetPages } from "../dataset/rows.ts";
import { generate, loadPatterns } from "../gen/generate.ts";
import { renderSitePage } from "../gen/render.ts";
import { extractFeatures, type FieldFeatures } from "../../src/content/detect/features.ts";

const EXT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const SITES = 50;
const REPS = 3;

export async function measureClassifyTime(seed: string, sites: number): Promise<ClassifyTime> {
  const dir = mkdtempSync(join(tmpdir(), "onepass-classify-time-"));
  try {
    const dist = join(dir, "dist");
    execFileSync(process.execPath, ["-e", "import('./build.mjs').then((m) => m.buildAll(['chromium'], false, true, process.argv[1]))", dist], { cwd: EXT_ROOT, stdio: "inherit" });
    const ext = join(dist, "chromium-e2e");
    const world = generate(seed, { sites: Math.max(sites, SITES * 2), patterns: loadPatterns() });
    const staticSite = (s: (typeof world.sites)[number]) => !s.traits.some((t) => t === "shadow_open" || t === "shadow_closed" || t === "delayed_fields");
    const picked = world.sites.filter((s) => staticSite(s) && datasetPages(s).length > 0).slice(0, SITES);
    const ctx = await chromium.launchPersistentContext(join(dir, "profile"), {
      channel: "chromium", headless: true, args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, "--no-first-run"],
    });
    try {
      const page = ctx.pages()[0] ?? (await ctx.newPage());
      const forms: FieldFeatures[][] = [];
      for (const s of picked) {
        const p = datasetPages(s)[0]!;
        await page.setContent(renderSitePage(s, p.page, p.ctx));
        const r = (await page.evaluate(`(${extractFeatures.toString()})(document).forms.map((f) => f.fields)`)) as FieldFeatures[][];
        forms.push(...r.filter((f) => f.length > 0));
      }
      if (forms.length === 0) throw new Error("classify-time: no form to time");
      const worker = ctx.serviceWorkers().find((w) => w.url().startsWith("chrome-extension://")) ?? (await ctx.waitForEvent("serviceworker", { timeout: 15_000 }));
      const ms = await worker.evaluate(async ({ forms, reps }) => {
        type S = { predict(f: unknown[]): Promise<unknown[]> };
        const h = (globalThis as { __onepassE2E?: { modelSession: (() => Promise<S | null>) | null } }).__onepassE2E;
        const s = h?.modelSession ? await h.modelSession() : null;
        if (!s) throw new Error("classify-time: no model session in the worker");
        for (const f of forms.slice(0, 5)) await s.predict(f); // warm-up: the first run compiles kernels
        const out: number[] = [];
        for (const f of forms) {
          const r: number[] = [];
          for (let i = 0; i < reps; i++) {
            const t = performance.now();
            await s.predict(f);
            r.push(performance.now() - t);
          }
          r.sort((a, b) => a - b);
          out.push(r[Math.floor(reps / 2)]!);
        }
        return out;
      }, { forms, reps: REPS });
      return timeStats(ms);
    } finally {
      await ctx.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const a = process.argv.slice(2);
  const get = (k: string) => { const i = a.indexOf(`--${k}`); return i >= 0 ? a[i + 1] : undefined; };
  const stats = await measureClassifyTime(get("seed") ?? "", Number(get("sites") ?? SITES));
  if (get("out")) writeFileSync(get("out")!, JSON.stringify(stats, null, 2) + "\n");
  console.log(`classify time: ${JSON.stringify(stats)}`);
}
