// Real test set (Task 10). The honest score of the model comes from real pages
// the generator and the lexicon never saw: 200 rendered pages picked by seed
// over the categories, labelled by hand (label-server.ts), plus the owner's
// recorded flows once labelled. Labels live in lab/corpus/labels/<host>.<n>.json
// (committed) and lab/corpus/private/labels/ (git-ignored, recorded flows):
// a Record<field index, Role | "none">, the index being the position of the
// field among all the fields of the sample (its forms, or the steps of a
// recorded flow, in order). A field without a label does not enter a row.
//
// Rows follow DatasetRow with split "real_test" (the Split union of rows.ts
// already carries it). A sample keeps no geometry or page title, so width and
// height are 0 and pageTitle is absent; neighbour labels are rebuilt from the
// neighbouring fields as the extractor does.
//
// Usage:
//   node --experimental-strip-types lab/dataset/real.ts --pick [--seed <s>] [--size <n>]   write corpus/real-test-hosts.json
//   node --experimental-strip-types lab/dataset/real.ts [--out <file.jsonl>]               count the labelled rows
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { FEATURE_VERSION } from "../../src/content/detect/features.ts";
import { sampleFiles } from "../corpus/distill.ts";
import { readRealTestHosts, siteOf, REAL_TEST_HOSTS_FILE } from "../corpus/real-test-hosts.ts";
import { stableJson } from "../corpus/types.ts";
import type { Sample, SampleField } from "../corpus/types.ts";
import { cyrb128 } from "../gen/rng.ts";
import type { Role } from "../gen/model.ts";
import type { DatasetRow } from "./rows.ts";

export const REAL_TEST_SEED = "real-test-1";
export const REAL_TEST_SIZE = 200;

const ROLE_SET: Record<Role, true> = {
  username: true, email: true, password: true, new_password: true, otp: true, cc_name: true, cc_number: true, cc_exp: true,
  cc_exp_month: true, cc_exp_year: true, cc_csc: true, given_name: true, family_name: true, tel: true, birth_date: true,
  organization: true, address_line1: true, address_line2: true, postal_code: true, city: true, country: true,
};
export const ALL_ROLES = Object.keys(ROLE_SET) as Role[];
export type LabelValue = Role | "none";
export const isLabelValue = (v: unknown): v is LabelValue => v === "none" || (typeof v === "string" && Object.hasOwn(ROLE_SET, v));

export interface RealDirs { samples: string; private: string; labels: string; privateLabels: string }

/** One sample file as a candidate of the real test set. `n` is the page number of `<host>.<n>.json` (0 for `<host>.json`). */
export interface RealPage { host: string; n: number; category: string; file: string; sample: Sample; private: boolean }

const here = dirname(fileURLToPath(import.meta.url));
export function defaultDirs(): RealDirs {
  const corpus = join(here, "..", "corpus");
  return { samples: join(corpus, "samples"), private: join(corpus, "private"), labels: join(corpus, "labels"), privateLabels: join(corpus, "private", "labels") };
}

/** Fields of a sample in label order: its forms, or every step of a recorded flow. */
export function flatFields(s: Sample): SampleField[] {
  return (s.forms ?? s.steps?.flat() ?? []).flatMap((f) => f.fields);
}

const hasVisibleField = (s: Sample): boolean => flatFields(s).some((f) => f.visibility === "visible");

function pageNumber(file: string): number {
  const m = /\.(\d+)\.json$/.exec(file);
  return m ? Number(m[1]) : 0;
}

function readPages(dir: string, priv: boolean): RealPage[] {
  if (!existsSync(dir)) return [];
  const out: RealPage[] = [];
  for (const file of sampleFiles(readdirSync(dir))) {
    const sample = JSON.parse(readFileSync(join(dir, file), "utf8")) as Sample;
    if (sample.status !== "ok" || (sample.source ?? "rendered") !== (priv ? "recorded" : "rendered") || !hasVisibleField(sample)) continue;
    out.push({ host: sample.host, n: pageNumber(file), category: sample.category, file, sample, private: priv });
  }
  return out;
}

/** Candidates of the real test set: rendered samples with a visible field, hand-picked and top 1000 (Common Crawl pages are static copies, not rendered). */
export function loadPool(dirs: RealDirs): RealPage[] {
  return [...readPages(dirs.samples, false), ...readPages(join(dirs.samples, "top1000"), false)];
}

/** Recorded flows (private), also real-test material once labelled. */
export function loadPrivate(dirs: RealDirs): RealPage[] {
  return readPages(dirs.private, true);
}

const byKey = (a: RealPage, b: RealPage) => (a.host < b.host ? -1 : a.host > b.host ? 1 : a.n - b.n);

/**
 * `size` pages by seed, spread over the categories: categories take turns
 * (alphabetical), each handing over its page of smallest hash, one page per
 * registrable site. A pure function of the pool and the seed.
 */
export function pickRealTest(pool: RealPage[], seed: string, size: number = REAL_TEST_SIZE): RealPage[] {
  const rank = (p: RealPage) => cyrb128(`${seed}|${p.host}|${p.n}`)[1];
  const queues = new Map<string, RealPage[]>();
  for (const p of [...pool].sort(byKey)) {
    const q = queues.get(p.category) ?? [];
    q.push(p);
    queues.set(p.category, q);
  }
  for (const q of queues.values()) q.sort((a, b) => rank(a) - rank(b) || byKey(a, b));
  const cats = [...queues.keys()].sort();
  const taken = new Set<string>();
  const out: RealPage[] = [];
  while (out.length < size && cats.some((c) => queues.get(c)!.length > 0)) {
    for (const c of cats) {
      if (out.length >= size) break;
      const q = queues.get(c)!;
      while (q.length > 0) {
        const p = q.shift()!;
        const site = siteOf(p.host);
        if (taken.has(site)) continue;
        taken.add(site);
        out.push(p);
        break;
      }
    }
  }
  return out;
}

/** The labelling queue: the first page with fields of each real-test host (sorted), then the private pages. */
export function queueOf(hosts: string[], pool: RealPage[], priv: RealPage[]): RealPage[] {
  const out: RealPage[] = [];
  for (const h of [...new Set(hosts)].sort()) {
    const first = pool.filter((p) => p.host === h).sort(byKey)[0];
    if (first) out.push(first);
  }
  return [...out, ...[...priv].sort(byKey)];
}

export const labelFile = (p: RealPage, dirs: RealDirs): string => join(p.private ? dirs.privateLabels : dirs.labels, `${p.host}.${p.n}.json`);

/** Labels of a file, keeping only valid entries (integer key, known role or "none"). A missing or unreadable file gives no label. */
export function readLabels(file: string): Record<number, LabelValue> {
  let raw: unknown;
  try { raw = JSON.parse(readFileSync(file, "utf8")); } catch { return {}; }
  const out: Record<number, LabelValue> = {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;
  for (const [k, v] of Object.entries(raw)) if (/^\d+$/.test(k) && isLabelValue(v)) out[Number(k)] = v;
  return out;
}

/** Atomic write: a temporary file in the same directory, then rename. */
export function writeLabels(file: string, labels: Record<number, LabelValue>): void {
  mkdirSync(dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, stableJson(labels));
  renameSync(tmp, file);
}

/** One real_test row per hand-labelled field. A page without labels gives none. */
export function realRows(pages: RealPage[], dirs: RealDirs, seed: string = REAL_TEST_SEED): DatasetRow[] {
  const rows: DatasetRow[] = [];
  for (const p of pages) {
    const labels = readLabels(labelFile(p, dirs));
    if (Object.keys(labels).length === 0) continue;
    const forms = p.sample.forms ?? p.sample.steps?.flat() ?? [];
    let at = 0;
    for (const form of forms) {
      const name = (f: SampleField | undefined) => (f ? f.label ?? f.ariaLabel ?? f.placeholder : undefined);
      form.fields.forEach((f, i) => {
        const target = labels[at++];
        if (target === undefined) return;
        const f2 = form.fields;
        rows.push({
          index: f.index ?? i, tag: f.tag, type: f.type, name: f.name, id: f.id, autocomplete: f.autocomplete, inputmode: f.inputmode,
          maxlength: f.maxlength, hasPattern: f.hasPattern, required: f.required, label: f.label, placeholder: f.placeholder,
          ariaLabel: f.ariaLabel, before: f.before, after: f.after, depth: f.depth ?? 0, siblings: f.siblings ?? 0,
          visibility: f.visibility, width: 0, height: 0, formButtons: form.buttons,
          neighbourLabels: [f2[i - 2], f2[i - 1], f2[i + 1], f2[i + 2]].map(name).filter((x): x is string => !!x),
          seed, generator: 0, featureVersion: FEATURE_VERSION, site: p.n, step: 0,
          source: p.private ? "recorded" : "rendered", origin: p.host, split: "real_test",
          lang: p.sample.lang ?? "und", framework: p.sample.framework ?? "static", traits: [], target,
        });
      });
    }
  }
  return rows;
}

function main(): void {
  const arg = (k: string): string | undefined => { const i = process.argv.indexOf(k); return i >= 0 ? process.argv[i + 1] : undefined; };
  const dirs = defaultDirs();
  if (process.argv.includes("--pick")) {
    const seed = arg("--seed") ?? REAL_TEST_SEED;
    const size = Number(arg("--size") ?? REAL_TEST_SIZE);
    const picked = pickRealTest(loadPool(dirs), seed, size);
    writeFileSync(REAL_TEST_HOSTS_FILE, stableJson({ seed, hosts: picked.map((p) => p.host).sort() }));
    const per: Record<string, number> = {};
    for (const p of picked) per[p.category] = (per[p.category] ?? 0) + 1;
    console.log(`real-test-hosts.json written: ${picked.length} hosts`, per);
    return;
  }
  const { seed, hosts } = readRealTestHosts();
  const pages = queueOf(hosts, loadPool(dirs), loadPrivate(dirs));
  const rows = realRows(pages, dirs, seed);
  const labelled = new Set(rows.map((r) => `${r.origin}.${r.site}`)).size;
  console.log(`real_test: ${rows.length} labelled fields on ${labelled} / ${pages.length} pages${rows.length === 0 ? " (0 labels)" : ""}`);
  const out = arg("--out");
  if (out) writeFileSync(out, rows.map((r) => JSON.stringify(r)).join("\n") + (rows.length ? "\n" : ""));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
