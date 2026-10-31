// @vitest-environment node
// Dataset rows (Task 9): labels come from the generator's Site, honeypots and
// decoys are "none", no generated secret reaches a row, label marks exist in
// dataset mode only, and a real Chromium pool renders the same pages.
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { JSDOM } from "jsdom";
import { describe, expect, it } from "vitest";
import { extractFeatures } from "../../src/content/detect/features.ts";
import type { PageFeatures } from "../../src/content/detect/features.ts";
import patternsJson from "../../lab/corpus/patterns.json";
import type { Patterns } from "../../lab/corpus/types.ts";
import { EXTRACT, buildDataset, withFastTimers } from "../../lab/dataset/build.ts";
import { datasetPages, originOf, rowsFor } from "../../lab/dataset/rows.ts";
import type { DatasetRow } from "../../lab/dataset/rows.ts";
import { splitOf } from "../../lab/dataset/split.ts";
import { generate } from "../../lab/gen/generate.ts";
import { styleOf } from "../../lab/gen/render.ts";
import type { Site } from "../../lab/gen/model.ts";
import { renderSitePage } from "../../lab/gen/render.ts";

const patterns = patternsJson as unknown as Patterns;
const dom = (html: string): Document => new JSDOM(html).window.document;
const world = generate("ds", { sites: 60, patterns });
/** jsdom runs no script: sites that mount their form from a script have no field yet. */
const staticSite = (s: Site) => !s.traits.some((t) => t === "shadow_open" || t === "shadow_closed" || t === "delayed_fields");

describe("rowsFor", () => {
  it("labels every rendered field of a page with the role of its FieldSpec, and never carries a secret", () => {
    const rows: DatasetRow[] = [];
    let marked = 0;
    for (const s of world.sites.filter(staticSite)) {
      datasetPages(s).forEach((p, step) => {
        const html = renderSitePage(s, p.page, p.ctx, { labelMarks: true });
        const page = extractFeatures(dom(html), { labField: true });
        const got = rowsFor(s, step, page, "ds");
        const flat = page.forms.flatMap((f) => f.fields);
        expect(got).toHaveLength(flat.length);
        // exactly one label per rendered input, and it is the role of the spec at its mark
        flat.forEach((f, i) => {
          const expected = f.lab === undefined ? "none" : p.fields[Number(f.lab)]!.role;
          expect(got[i]!.target).toBe(expected);
        });
        // every field of the page is rendered once at least (split OTP cells share a mark)
        const labelled = new Set(flat.filter((f) => f.lab !== undefined).map((f) => Number(f.lab)));
        if (!s.traits.includes("decoy_form")) expect([...labelled].sort()).toEqual(p.fields.map((_, k) => k).filter((k) => labelled.has(k)));
        marked += labelled.size;
        rows.push(...got);
      });
    }
    expect(rows.length).toBeGreaterThan(100);
    expect(marked).toBeGreaterThan(50);
    expect(rows.every((r) => typeof r.target === "string")).toBe(true);
    expect(rows.every((r) => !("lab" in r) && r.featureVersion >= 1 && r.generator === 2 && r.seed === "ds")).toBe(true);
    const json = JSON.stringify(rows);
    for (const s of world.sites) {
      for (const secret of [s.account?.password, s.account?.totpSecret]) if (secret && secret.length >= 6) expect(json).not.toContain(secret);
    }
    for (const accounts of Object.values(world.idp)) for (const a of accounts) expect(json).not.toContain(a.password);
    for (const item of world.fixture.items) {
      for (const v of Object.values((item as { fields: Record<string, unknown> }).fields)) {
        if (typeof v === "string" && v.length >= 8) expect(json).not.toContain(v);
      }
    }
  });

  it("labels honeypot and decoy fields none, and the real fields of the same page by role", () => {
    const honey = world.sites.find((s) => s.honeypot && staticSite(s) && !s.traits.includes("iframe_cross_site"));
    expect(honey).toBeDefined();
    const s = honey!;
    const rows = datasetPages(s).flatMap((p, step) => rowsFor(s, step, extractFeatures(dom(renderSitePage(s, p.page, p.ctx, { labelMarks: true })), { labField: true }), "ds"));
    expect(rows.filter((r) => r.target === "none").length).toBeGreaterThanOrEqual(1);
    expect(rows.some((r) => r.target !== "none")).toBe(true);
    const decoy = world.sites.find((s2) => s2.traits.includes("decoy_form") && staticSite(s2));
    expect(decoy).toBeDefined();
    const d = decoy!;
    const page = extractFeatures(dom(renderSitePage(d, datasetPages(d)[0]!.page, {}, { labelMarks: true })), { labField: true });
    const lab = page.forms.map((f) => f.fields.map((x) => x.lab !== undefined));
    expect(lab.some((l) => l.every((x) => !x))).toBe(true); // the decoy form: nothing marked
  });

  it("maps multi_step fields back through the step offset", () => {
    const ms = world.sites.filter((s) => s.steps && staticSite(s));
    expect(ms.length).toBeGreaterThan(0);
    for (const s of ms) {
      datasetPages(s).forEach((p, step) => {
        expect(p.fields).toEqual(s.steps![step]);
        const page = extractFeatures(dom(renderSitePage(s, p.page, p.ctx, { labelMarks: true })), { labField: true });
        const roles = rowsFor(s, step, page, "ds").map((r) => r.target).filter((l) => l !== "none");
        expect(roles).toEqual(s.steps![step]!.map((f) => f.role));
      });
    }
  });

  it("derives origin deterministically and splits by it", () => {
    const a = world.sites[0]!;
    expect(originOf(a)).toBe(originOf(a));
    expect(originOf(a)).not.toBe(originOf(world.sites[1]!));
    expect(originOf(a)).toMatch(/^synthetic:/);
    const page = extractFeatures(dom(renderSitePage(a, datasetPages(a)[0]!.page, {}, { labelMarks: true })), { labField: true });
    for (const r of rowsFor(a, 0, page, "ds")) expect(r.split).toBe(splitOf(originOf(a), "ds"));
  });
});

describe("target and label text", () => {
  it("keeps the label text of the page in `label` and the role in `target`", () => {
    const roleNames = new Set<string>(["username", "email", "password", "new_password", "otp", "cc_name", "cc_number", "cc_exp", "cc_exp_month", "cc_exp_year", "cc_csc", "given_name", "family_name", "tel", "birth_date", "organization", "address_line1", "address_line2", "postal_code", "city", "country", "none"]);
    let n = 0;
    for (const s of world.sites.filter(staticSite)) {
      datasetPages(s).forEach((p, step) => {
        const page = extractFeatures(dom(renderSitePage(s, p.page, p.ctx, { labelMarks: true })), { labField: true });
        const flat = page.forms.flatMap((f) => f.fields);
        rowsFor(s, step, page, "ds").forEach((r, i) => {
          expect(r.label).toBe(flat[i]!.label);
          if (r.label !== undefined && roleNames.has(r.label)) expect(r.label).toBe(flat[i]!.label); // only when the page text is that very word
          n++;
        });
      });
    }
    expect(n).toBeGreaterThan(100);
    // Label text that is itself a role word ("email", "password") is the page's real text; most labels are not.
    const rows = world.sites.filter(staticSite).flatMap((s) => datasetPages(s).flatMap((p, step) => rowsFor(s, step, extractFeatures(dom(renderSitePage(s, p.page, p.ctx, { labelMarks: true })), { labField: true }), "ds")));
    const same = rows.filter((r) => r.label === r.target).length;
    expect(same / rows.length).toBeLessThan(0.2);
    expect(rows.some((r) => r.label !== undefined && r.label !== r.target)).toBe(true);
  });
});

describe("datasetPages follows the routes the lab serves", () => {
  const bigWorld = generate("pages", { sites: 400, patterns });
  it("serves /password only to username-first logins, /otp only to sites with a code field, steps only to multi_step", () => {
    for (const s of bigWorld.sites) {
      const pages = datasetPages(s).map((p) => p.page);
      const hasPassword = s.fields.some((f) => f.role === "password");
      const hasOtp = s.fields.some((f) => f.role === "otp");
      if (s.steps) {
        expect(pages.filter((p) => p === "step")).toHaveLength(s.steps.length - 1);
        expect(pages).not.toContain("password");
        expect(pages).not.toContain("otp");
        continue;
      }
      expect(pages.includes("password")).toBe(styleOf(s) === "username_first" && hasPassword);
      expect(pages.includes("otp")).toBe(hasOtp);
      expect(pages.includes("step")).toBe(false);
      expect(pages.filter((p) => p === "entry" || p === "frame").length).toBeLessThanOrEqual(1);
    }
    // the phantom pages are gone: password-only pages are a minority of pages
    const all = bigWorld.sites.flatMap((s) => datasetPages(s));
    expect(all.filter((p) => p.page === "password").length).toBeLessThan(all.length / 5);
  });
});

describe("label marks", () => {
  it("are absent unless dataset mode asks for them", () => {
    for (const s of world.sites) {
      for (const p of datasetPages(s)) {
        expect(renderSitePage(s, p.page, p.ctx)).not.toContain("data-lab-field");
        expect(renderSitePage(s, p.page, p.ctx, {})).not.toContain("data-lab-field");
        expect(renderSitePage(s, p.page, p.ctx, { labelMarks: false })).not.toContain("data-lab-field");
      }
    }
    const s = world.sites.find((x) => staticSite(x) && datasetPages(x).length > 0)!;
    const p = datasetPages(s)[0]!;
    expect(renderSitePage(s, p.page, p.ctx, { labelMarks: true })).toContain("data-lab-field");
  });
});

describe("buildDataset", () => {
  const readRows = (dir: string): { text: string; rows: DatasetRow[]; files: string[] } => {
    const files = readdirSync(dir).filter((f) => /^part-\d{4}\.jsonl\.gz$/.test(f)).sort();
    const text = files.map((f) => gunzipSync(readFileSync(join(dir, f))).toString("utf8")).join("");
    return { text, rows: text.split("\n").filter(Boolean).map((l) => JSON.parse(l) as DatasetRow), files };
  };

  it("renders in Chromium, writes gzip parts and a manifest, matches every spec and carries no secret", async () => {
    const out = mkdtempSync(join(tmpdir(), "ds-"));
    try {
      const m = await buildDataset({ seed: "t9", forms: 120, workers: 2, out, patterns });
      expect(m.forms).toBe(120);
      const dir = join(out, "t9-g2");
      const { text, rows } = readRows(dir);
      expect(rows.length).toBe(m.rows);
      expect(Object.values(m.byTarget).reduce((a, b) => a + b, 0)).toBe(rows.length);
      expect(m.formsPerSecond).toBeGreaterThan(0);
      expect(m.skippedForms).toBeGreaterThanOrEqual(0);
      expect(rows.every((r) => r.target && r.split && r.origin.startsWith("synthetic:"))).toBe(true);
      expect(rows.some((r) => r.target === "none")).toBe(true);
      expect(rows.some((r) => r.target === "password")).toBe(true);
      expect(JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")).rows).toBe(rows.length);
      expect(m.mismatches).toBe(0);
      // Secrets of the generated world(s) behind these rows, anywhere in the written output.
      const w = generate("t9/c0", { sites: 400, patterns });
      const secrets = new Set<string>();
      for (const s of w.sites) {
        for (const v of [s.account?.password, s.account?.totpSecret, s.account?.username]) if (v && v.length >= 6) secrets.add(v);
      }
      for (const accounts of Object.values(w.idp)) for (const a of accounts) { secrets.add(a.password); secrets.add(a.email); }
      const short: string[] = [];
      for (const item of w.fixture.items) {
        for (const v of Object.values((item as { fields: Record<string, unknown> }).fields)) {
          if (typeof v === "string" && v.length >= 8) secrets.add(v);
          else if (typeof v === "string" && /^\d{3,4}$/.test(v)) short.push(v); // card security codes
        }
      }
      for (const v of secrets) expect(text, "secret in output").not.toContain(v);
      for (const v of short) expect(text, "cvc in output").not.toContain(`"${v}"`);
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  }, 180_000);

  it("writes the same bytes for one worker and for four", async () => {
    const a = mkdtempSync(join(tmpdir(), "ds-a-"));
    const b = mkdtempSync(join(tmpdir(), "ds-b-"));
    try {
      const ma = await buildDataset({ seed: "ord", forms: 150, workers: 1, out: a, patterns });
      const mb = await buildDataset({ seed: "ord", forms: 150, workers: 4, out: b, patterns });
      const ra = readRows(join(a, "ord-g2"));
      const rb = readRows(join(b, "ord-g2"));
      expect(ra.files).toEqual(rb.files);
      expect(ra.text).toBe(rb.text);
      for (const f of ra.files) expect(readFileSync(join(a, "ord-g2", f)).equals(readFileSync(join(b, "ord-g2", f)))).toBe(true);
      expect(ma.byTarget).toEqual(mb.byTarget);
      expect(ma.skippedForms).toBe(mb.skippedForms);
    } finally {
      rmSync(a, { recursive: true, force: true });
      rmSync(b, { recursive: true, force: true });
    }
  }, 180_000);

  it("survives a failing form: logged, counted, page recycled, build finishes", async () => {
    const out = mkdtempSync(join(tmpdir(), "ds-f-"));
    try {
      const m = await buildDataset({ seed: "fail", forms: 40, workers: 2, out, patterns, beforeEvaluate: (seq) => { if (seq === 7) throw new Error("forced"); } });
      expect(m.failedForms).toBe(1);
      expect(m.forms).toBe(40);
      expect(m.rows).toBeGreaterThan(0);
      expect(JSON.parse(readFileSync(join(out, "fail-g2", "manifest.json"), "utf8")).failedForms).toBe(1);
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  }, 120_000);

  it("reuses one page for 5,000 forms without nesting the timer shim", async () => {
    const pw = (await import("playwright-core")) as unknown as { chromium?: any; default?: { chromium: any } };
    const browser = await (pw.chromium ?? pw.default!.chromium).launch({ channel: "chromium" });
    try {
      const page = await browser.newPage();
      // Native setTimeout replaced by a probe that records the depth of the call stack it is reached from.
      await page.evaluate(() => {
        Error.stackTraceLimit = 100_000;
        const w = window as any;
        const native = w.setTimeout.bind(window);
        w.__depth = 0;
        w.setTimeout = (...a: any[]) => { w.__depth = new Error().stack!.split("\n").length; return native(...a); };
      });
      const sample = world.sites.find((s) => staticSite(s) && datasetPages(s).length > 0)!;
      const p = datasetPages(sample)[0]!;
      const html = withFastTimers(renderSitePage(sample, p.page, p.ctx, { labelMarks: true }));
      for (let i = 0; i < 5000; i++) await page.setContent(html, { waitUntil: "domcontentloaded" });
      const features = await page.evaluate(EXTRACT);
      expect(features.forms.length).toBeGreaterThan(0);
      await page.evaluate(() => { setTimeout(() => undefined, 0); });
      expect(await page.evaluate(() => (window as any).__depth)).toBeLessThan(30);
    } finally {
      await browser.close();
    }
  }, 180_000);
});
