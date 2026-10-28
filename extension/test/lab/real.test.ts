// @vitest-environment node
// Real test set (Task 10): deterministic pick over categories, isolation from
// the distilled lexicon, and rows from hand labels (zero labels = zero rows).
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { corpusDirs, distillSamples } from "../../lab/corpus/distill.ts";
import { readRealTestHosts, siteOf, withoutHosts } from "../../lab/corpus/real-test-hosts.ts";
import type { Category, Sample, SampleField } from "../../lab/corpus/types.ts";
import { ALL_ROLES, defaultDirs, flatFields, loadPool, pickRealTest, queueOf, readLabels, realRows, writeLabels } from "../../lab/dataset/real.ts";
import type { RealDirs, RealPage } from "../../lab/dataset/real.ts";

const field = (over: Partial<SampleField> = {}): SampleField => ({
  tag: "input", type: "text", hasPattern: false, required: false, label: "Email", visibility: "visible", role: "email", ...over,
});
const sample = (host: string, category: Category, fields: SampleField[] = [field()]): Sample => ({
  source_url: `https://${host}/`, host, category, captured_at: "", extractor: 2, status: "ok", lang: "en",
  forms: [{ step: "other", fields, buttons: ["Go"] }],
});
const page = (host: string, category: Category, n = 0, priv = false, fields?: SampleField[]): RealPage =>
  ({ host, n, category, file: `${host}.${n}.json`, sample: sample(host, category, fields), private: priv });

const tmp: string[] = [];
afterEach(() => { while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true }); });
function dirs(): RealDirs {
  const root = mkdtempSync(join(tmpdir(), "real-"));
  tmp.push(root);
  const d = { samples: join(root, "samples"), private: join(root, "private"), labels: join(root, "labels"), privateLabels: join(root, "private", "labels") };
  mkdirSync(d.labels, { recursive: true });
  mkdirSync(d.privateLabels, { recursive: true });
  return d;
}

describe("pickRealTest", () => {
  const cats: Category[] = ["login", "signup", "checkout", "address"];
  const pool = Array.from({ length: 80 }, (_, i) => page(`site${i}.com`, cats[i % 4]!));

  it("is deterministic and independent of the input order", () => {
    const a = pickRealTest(pool, "s", 20).map((p) => p.host);
    expect(pickRealTest([...pool].reverse(), "s", 20).map((p) => p.host)).toEqual(a);
    expect(pickRealTest(pool, "other", 20).map((p) => p.host)).not.toEqual(a);
  });
  it("takes whole sites and stops as soon as the pages reach the size", () => {
    const multi = Array.from({ length: 30 }, (_, i) => [0, 1, 2].map((n) => page(`m${i}.com`, "login", n))).flat();
    const got = pickRealTest(multi, "s", 10);
    expect(got).toHaveLength(12);
    const hosts = new Set(got.map((p) => p.host));
    expect(hosts.size).toBe(4);
    for (const h of hosts) expect(got.filter((p) => p.host === h).map((p) => p.n)).toEqual([0, 1, 2]);
  });
  it("brings the rare categories first, taking turns, then login and signup", () => {
    const mixed = [
      ...Array.from({ length: 10 }, (_, i) => page(`l${i}.com`, "login")), ...Array.from({ length: 10 }, (_, i) => page(`s${i}.com`, "signup")),
      page("shop.com", "checkout"), page("home.com", "address"), page("id.com", "identity"),
    ];
    const got = pickRealTest(mixed, "s", 6);
    expect(got.slice(0, 3).map((p) => p.category).sort()).toEqual(["address", "checkout", "identity"]);
    expect(got.slice(3).every((p) => p.category === "login" || p.category === "signup")).toBe(true);
    expect(got.some((p) => p.category === "login") && got.some((p) => p.category === "signup")).toBe(true);
  });
  it("counts sub-domains of one site as one site", () => {
    const two = [page("a.example.com", "login"), page("b.example.com", "login")];
    expect(pickRealTest(two, "s", 1)).toHaveLength(2);
  });
});

describe("isolation", () => {
  it("withoutHosts drops every sample of a real test site, sub-domains and www included", () => {
    const ss = [sample("example.com", "login"), sample("www.example.com", "login"), sample("auth.example.com", "login"), sample("kept.org", "login")];
    expect(withoutHosts(ss, ["example.com"]).map((s) => s.host)).toEqual(["kept.org"]);
  });
  it("distill input contains no sample from a real-test host", () => {
    const { hosts, seed } = readRealTestHosts();
    expect(typeof seed).toBe("string");
    expect(hosts.length).toBeGreaterThan(0);
    const banned = new Set(hosts.map(siteOf));
    for (const withPrivate of [false, true]) {
      const inputs = distillSamples(corpusDirs(), withPrivate);
      expect(inputs.length).toBeGreaterThan(0);
      expect(inputs.filter((s) => banned.has(siteOf(s.host)))).toEqual([]);
    }
  });
  it("the committed list covers at least 200 pages of the pool, from fewer hosts", () => {
    const { hosts, pages } = readRealTestHosts();
    expect(pages).toBeGreaterThanOrEqual(200);
    expect(hosts.length).toBeLessThan(200);
    expect(queueOf(hosts, loadPool(defaultDirs()), [])).toHaveLength(pages);
  });
  it("the pool never holds two pages with one label file", () => {
    const names = loadPool(defaultDirs()).map((p) => `${p.host}.${p.n}`);
    expect(new Set(names).size).toBe(names.length);
  });
});

describe("labels", () => {
  it("covers every role", () => {
    expect(ALL_ROLES).toContain("cc_exp_month");
    expect(new Set(ALL_ROLES).size).toBe(ALL_ROLES.length);
  });
  it("writes atomically and reads back, ignoring invalid entries", () => {
    const d = dirs();
    const f = join(d.labels, "x.0.json");
    writeLabels(f, { 0: "email", 2: "none" });
    expect(readdirSync(d.labels)).toEqual(["x.0.json"]);
    expect(readLabels(f)).toEqual({ 0: "email", 2: "none" });
    writeFileSync(f, JSON.stringify({ 0: "email", 1: "bogus", x: "email" }));
    expect(readLabels(f)).toEqual({ 0: "email" });
    expect(readLabels(join(d.labels, "missing.json"))).toEqual({});
  });
});

describe("realRows", () => {
  it("gives no row without labels", () => {
    const d = dirs();
    expect(realRows([page("a.com", "login")], d)).toEqual([]);
  });
  it("turns labelled fields into real_test rows and skips the others", () => {
    const d = dirs();
    const fields = [field({ label: "Email" }), field({ label: "Search", role: "unknown" }), field({ label: "Password", type: "password" })];
    const pages = [page("a.com", "login", 0, false, fields), page("rec.io", "login", 0, true, fields)];
    writeLabels(join(d.labels, "a.com.0.json"), { 0: "email", 1: "none" });
    writeLabels(join(d.privateLabels, "rec.io.0.json"), { 2: "password" });
    const rows = realRows(pages, d);
    expect(rows).toHaveLength(3);
    expect(rows.every((r) => r.split === "real_test")).toBe(true);
    expect(rows.map((r) => [r.origin, r.source, r.target, r.label])).toEqual([
      ["a.com", "rendered", "email", "Email"], ["a.com", "rendered", "none", "Search"], ["rec.io", "recorded", "password", "Password"],
    ]);
    expect(rows[1]!.neighbourLabels).toEqual(["Email", "Password"]);
    expect(rows[0]!.formButtons).toEqual(["Go"]);
  });
  it("ignores a label whose index has no field", () => {
    const d = dirs();
    writeLabels(join(d.labels, "a.com.0.json"), { 5: "email" });
    expect(realRows([page("a.com", "login")], d)).toEqual([]);
  });
});

describe("queueOf", () => {
  it("takes every page with fields of each real test host, then the private pages", () => {
    const pool = [page("b.com", "login", 1), page("b.com", "login", 0), page("a.com", "signup", 2)];
    const priv = [page("rec.io", "login", 0, true)];
    expect(queueOf(["b.com", "a.com", "gone.com"], pool, priv).map((p) => p.file)).toEqual(["a.com.2.json", "b.com.0.json", "b.com.1.json", "rec.io.0.json"]);
  });
});

describe("flatFields", () => {
  it("flattens forms, and the steps of a recorded flow, in order", () => {
    const s = sample("a.com", "login", [field({ label: "A" })]);
    s.forms = undefined;
    s.steps = [[{ step: "other", buttons: [], fields: [field({ label: "A" })] }], [{ step: "other", buttons: [], fields: [field({ label: "B" }), field({ label: "C" })] }]];
    expect(flatFields(s).map((f) => f.label)).toEqual(["A", "B", "C"]);
  });
});
