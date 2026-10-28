// Field classifier models in real Chromium (Task 15). Runs only on a model build
// (ONEPASS_CLASSIFIER=gbm|encoder ONEPASS_MODEL_DIR=... npm run e2e); the default build skips it.
// - the worker loads the packaged model with onnxruntime-web (WASM) and runs it: for the encoder
//   this is the check that MatMulInteger and DynamicQuantizeLinear work on the web backend;
// - a cross-site child frame gets no model answer;
// - timing of `classify` per form (vectorize or tokenize + inference, in the worker) over the forms
//   of 50 lab sites rendered in this Chromium, median against the 5 ms target.
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Worker } from "@playwright/test";
import { extractFeatures, type FieldFeatures } from "../src/content/detect/features";
import { generate, loadPatterns } from "../lab/gen/generate";
import type { Site } from "../lab/gen/model";
import { renderSitePage } from "../lab/gen/render";
import { datasetPages } from "../lab/dataset/rows";
import { expect, test } from "./fixtures";

const EXT = fileURLToPath(new URL("../dist/chromium-e2e/", import.meta.url));
const kind = existsSync(join(EXT, "model")) ? readdirSync(join(EXT, "model")).find((f) => f.endsWith(".onnx"))?.replace(/\.onnx$/, "") : undefined;
const SITES = 50;
const TARGET_MS = 5;

test.describe("classifier model in the service worker", () => {
  test.skip(kind === undefined, "default (heuristic) build: no model to run");
  test.use({ build: "e2e" });

  async function predict(w: Worker, forms: FieldFeatures[][]): Promise<{ labels: string[][]; error?: string }> {
    return w.evaluate(async (forms) => {
      type S = { kind: string; predict(f: unknown[]): Promise<{ label: string; score: number }[]> };
      const h = (globalThis as { __onepassE2E?: { modelSession: (() => Promise<S | null>) | null } }).__onepassE2E;
      if (!h?.modelSession) return { labels: [], error: "no modelSession in this build" };
      const s = await h.modelSession();
      if (!s) return { labels: [], error: "model refused or not loadable (see the worker console)" };
      try {
        const labels: string[][] = [];
        for (const f of forms) labels.push((await s.predict(f)).map((p) => p.label));
        return { labels };
      } catch (e) {
        return { labels: [], error: String(e) };
      }
    }, forms);
  }

  test("model_loads_and_runs_on_onnxruntime_web", async ({ ext }) => {
    const { page } = ext;
    await page.goto("https://atlas-cloud.test/login");
    const forms = await page.evaluate(`(${extractFeatures.toString()})(document).forms.map((f) => f.fields)`) as FieldFeatures[][];
    expect(forms.length).toBeGreaterThan(0);
    const w = await ext.worker();
    const out = await predict(w, forms);
    expect(out.error, `onnxruntime-web (${kind}) in the service worker`).toBeUndefined();
    const flat = out.labels.flat();
    expect(flat).toContain("password");
    expect(flat.some((l) => l === "email" || l === "username")).toBe(true);
  });

  test("cross_site_frame_gets_no_model_answer", async ({ ext }) => {
    const { page } = ext;
    await page.goto("https://evil.test/frame");
    await expect.poll(() => page.frame({ url: /^https:\/\/atlas-cloud\.test\/login/ }) !== null).toBe(true);
    const w = await ext.worker();
    const reply = await w.evaluate(async () => {
      type Router = (m: unknown, s: unknown, r: (x: unknown) => void) => unknown;
      const h = (globalThis as { __onepassE2E?: { router: Router } }).__onepassE2E!;
      const [tab] = await chrome.tabs.query({ url: "https://evil.test/*" });
      const frames = (await chrome.webNavigation.getAllFrames({ tabId: tab!.id! })) ?? [];
      const child = frames.find((f) => f.url.startsWith("https://atlas-cloud.test/"))!;
      const sender = { id: chrome.runtime.id, url: child.url, origin: "https://atlas-cloud.test", tab: { id: tab!.id }, frameId: child.frameId };
      const ask = (fields: unknown[]) => new Promise((r) => h.router({ type: "classify", fields }, sender, r));
      const f = { index: 0, tag: "input", type: "password", hasPattern: false, required: false, depth: 3, siblings: 0, visibility: "visible", width: 0, height: 0, formButtons: [], neighbourLabels: [] };
      return { hello: await ask([]), fields: await ask([f]) };
    });
    expect(reply).toEqual({ hello: { ok: { kind, crossSite: true } }, fields: { ok: { kind, crossSite: true } } });
  });

  test("classify_per_form_median_on_50_lab_sites", async ({ ext }) => {
    test.setTimeout(300_000);
    const world = generate("t15-perf", { sites: 120, patterns: loadPatterns() });
    const staticSite = (s: Site) => !s.traits.some((t) => t === "shadow_open" || t === "shadow_closed" || t === "delayed_fields");
    const sites = world.sites.filter((s) => staticSite(s) && datasetPages(s).length > 0).slice(0, SITES);
    expect(sites).toHaveLength(SITES);
    const { page } = ext;
    await page.goto("https://atlas-cloud.test/login");
    const forms: FieldFeatures[][] = [];
    const extractMs: number[] = [];
    for (const s of sites) {
      const p = datasetPages(s)[0]!;
      await page.setContent(renderSitePage(s, p.page, p.ctx));
      const r = (await page.evaluate(`(() => { const t = performance.now(); const p = (${extractFeatures.toString()})(document); return { ms: performance.now() - t, forms: p.forms.map((f) => f.fields) }; })()`)) as { ms: number; forms: FieldFeatures[][] };
      extractMs.push(r.ms);
      forms.push(...r.forms);
    }
    expect(forms.length).toBeGreaterThanOrEqual(SITES);
    const w = await ext.worker();
    const timing = await w.evaluate(async (forms) => {
      type S = { predict(f: unknown[]): Promise<unknown[]> };
      const h = (globalThis as { __onepassE2E?: { modelSession: (() => Promise<S | null>) | null } }).__onepassE2E!;
      const s = (await h.modelSession!())!;
      for (const f of forms.slice(0, 5)) await s.predict(f); // warm-up (first run compiles kernels)
      const ms: number[] = [];
      for (const f of forms) {
        const reps: number[] = [];
        for (let i = 0; i < 5; i++) {
          const t = performance.now();
          await s.predict(f);
          reps.push(performance.now() - t);
        }
        reps.sort((a, b) => a - b);
        ms.push(reps[2]!);
      }
      return ms;
    }, forms);
    const q = (xs: number[], p: number) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor(p * xs.length))]!;
    const fields = forms.map((f) => f.length);
    const report = {
      kind,
      sites: SITES,
      forms: forms.length,
      fieldsPerForm: { median: q(fields, 0.5), max: Math.max(...fields) },
      classifyMsPerForm: { median: q(timing, 0.5), p90: q(timing, 0.9), max: Math.max(...timing) },
      extractFeaturesMsPerPage: { median: q(extractMs, 0.5), p90: q(extractMs, 0.9) },
    };
    console.log(`classifier perf ${JSON.stringify(report)}`);
    test.info().annotations.push({ type: "perf", description: JSON.stringify(report) });
    // Model A has the 5 ms target; model B's numbers are reported as they are (Task 16 decides).
    if (kind === "gbm") expect(report.classifyMsPerForm.median).toBeLessThan(TARGET_MS);
  });
});
