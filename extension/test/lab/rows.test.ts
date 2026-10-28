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
import { buildDataset } from "../../lab/dataset/build.ts";
import { datasetPages, originOf, rowsFor } from "../../lab/dataset/rows.ts";
import type { DatasetRow } from "../../lab/dataset/rows.ts";
import { splitOf } from "../../lab/dataset/split.ts";
import { generate } from "../../lab/gen/generate.ts";
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
        const page = extractFeatures(dom(html));
        const got = rowsFor(s, step, page, "ds");
        const flat = page.forms.flatMap((f) => f.fields);
        expect(got).toHaveLength(flat.length);
        // exactly one label per rendered input, and it is the role of the spec at its mark
        flat.forEach((f, i) => {
          const expected = f.lab === undefined ? "none" : p.fields[Number(f.lab)]!.role;
          expect(got[i]!.label).toBe(expected);
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
    expect(rows.every((r) => typeof r.label === "string")).toBe(true);
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
    const rows = datasetPages(s).flatMap((p, step) => rowsFor(s, step, extractFeatures(dom(renderSitePage(s, p.page, p.ctx, { labelMarks: true }))), "ds"));
    expect(rows.filter((r) => r.label === "none").length).toBeGreaterThanOrEqual(1);
    expect(rows.some((r) => r.label !== "none")).toBe(true);
    const decoy = world.sites.find((s2) => s2.traits.includes("decoy_form") && staticSite(s2));
    expect(decoy).toBeDefined();
    const d = decoy!;
    const page = extractFeatures(dom(renderSitePage(d, datasetPages(d)[0]!.page, {}, { labelMarks: true })));
    const lab = page.forms.map((f) => f.fields.map((x) => x.lab !== undefined));
    expect(lab.some((l) => l.every((x) => !x))).toBe(true); // the decoy form: nothing marked
  });

  it("maps multi_step fields back through the step offset", () => {
    const ms = world.sites.filter((s) => s.steps && staticSite(s));
    expect(ms.length).toBeGreaterThan(0);
    for (const s of ms) {
      datasetPages(s).forEach((p, step) => {
        expect(p.fields).toEqual(s.steps![step]);
        const page = extractFeatures(dom(renderSitePage(s, p.page, p.ctx, { labelMarks: true })));
        const roles = rowsFor(s, step, page, "ds").map((r) => r.label).filter((l) => l !== "none");
        expect(roles).toEqual(s.steps![step]!.map((f) => f.role));
      });
    }
  });

  it("derives origin deterministically and splits by it", () => {
    const a = world.sites[0]!;
    expect(originOf(a)).toBe(originOf(a));
    expect(originOf(a)).not.toBe(originOf(world.sites[1]!));
    expect(originOf(a)).toMatch(/^synthetic:/);
    const page = extractFeatures(dom(renderSitePage(a, datasetPages(a)[0]!.page, {}, { labelMarks: true })));
    for (const r of rowsFor(a, 0, page, "ds")) expect(r.split).toBe(splitOf(originOf(a), "ds"));
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
  it("renders in Chromium, writes gzip parts and a manifest, and every field matches its spec", async () => {
    const out = mkdtempSync(join(tmpdir(), "ds-"));
    try {
      const m = await buildDataset({ seed: "t9", forms: 60, workers: 2, out, patterns });
      expect(m.forms).toBeGreaterThanOrEqual(60);
      const dir = join(out, "t9-g2");
      const parts = readdirSync(dir).filter((f) => /^part-\d{4}\.jsonl\.gz$/.test(f));
      expect(parts.length).toBeGreaterThanOrEqual(1);
      const rows = parts.flatMap((f) => gunzipSync(readFileSync(join(dir, f))).toString("utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as DatasetRow));
      expect(rows.length).toBe(m.rows);
      expect(Object.values(m.byRole).reduce((a, b) => a + b, 0)).toBe(rows.length);
      expect(m.formsPerSecond).toBeGreaterThan(0);
      expect(rows.every((r) => r.label && r.split && r.origin.startsWith("synthetic:"))).toBe(true);
      expect(rows.some((r) => r.label === "none")).toBe(true);
      expect(rows.some((r) => r.label === "password")).toBe(true);
      expect(JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")).rows).toBe(rows.length);
      expect(m.mismatches).toBe(0); // build checks each page against the Site it rendered
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  }, 180_000);
});
