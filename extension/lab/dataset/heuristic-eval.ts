// Macro F1 of the heuristic classifier on real_test rows (Task 16).
//   node --experimental-strip-types lab/dataset/heuristic-eval.ts --rows <rows.jsonl> [--out <file.json>]
// <rows.jsonl>: DatasetRow lines (`real.ts --out`). Prints and writes {"rows": n, "macroF1": x | null, "mergedF1": y | null, "digest": sha256}.
// No rows (R4: real_test has no labels yet) gives {"rows": 0, "macroF1": null} without loading anything.
// heuristic-role.ts is bundled with esbuild (its src imports carry no extension) and run on jsdom.
import { build } from "esbuild";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";
import { rowsDigest } from "./f1.ts";

export interface HeuristicScore { rows: number; macroF1: number | null; mergedF1: number | null; digest?: string }

export async function scoreRows(file: string): Promise<HeuristicScore> {
  const rows = existsSync(file) ? readFileSync(file, "utf8").split("\n").filter((l) => l.trim() !== "").map((l) => JSON.parse(l) as { split?: string; target: string; origin: string; site: number; step: number; index: number }) : [];
  const real = rows.filter((r) => r.split === undefined || r.split === "real_test");
  if (real.length === 0) return { rows: 0, macroF1: null, mergedF1: null };
  const dir = mkdtempSync(join(tmpdir(), "onepass-heuristic-"));
  try {
    const out = join(dir, "heuristic-role.mjs");
    await build({ entryPoints: [fileURLToPath(new URL("./heuristic-role.ts", import.meta.url))], bundle: true, format: "esm", platform: "node", outfile: out, logLevel: "silent" });
    const dom = new JSDOM("<!doctype html><body></body>");
    const w = dom.window as unknown as Record<string, unknown>;
    for (const k of ["document", "HTMLInputElement", "HTMLSelectElement", "HTMLTextAreaElement", "NodeFilter", "Element", "Node"]) (globalThis as Record<string, unknown>)[k] = w[k];
    const mod = (await import(out)) as { heuristicRows(r: unknown[]): HeuristicScore };
    return { ...mod.heuristicRows(real), digest: rowsDigest(real) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const a = process.argv.slice(2);
  const get = (k: string) => { const i = a.indexOf(`--${k}`); return i >= 0 ? a[i + 1] : undefined; };
  const rows = get("rows");
  if (!rows) { console.error("usage: heuristic-eval.ts --rows <rows.jsonl> [--out <file.json>]"); process.exit(2); }
  const score = await scoreRows(rows);
  const text = JSON.stringify(score);
  if (get("out")) writeFileSync(get("out")!, text + "\n");
  console.log(text);
}
