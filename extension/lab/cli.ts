// Command line of the autofill lab (spec 9), run by `node --experimental-strip-types`:
//   lab    --seed <s> --sites <n> [--profiles <n>] [--workers 4] [--report <md>] [--classifier heuristic|gbm|encoder [--model-dir <dir>]]
//   repro  --seed <s> --site <i> [--sites <n>] [--profiles <n>] [--classifier <k> [--model-dir <dir>]]
//   compare --out <dir> <dir> <dir> --md <file> [--real-rows <rows.jsonl>]   (classifier comparison, decision rule of the spec)
//   report --out <dir> [--md <file>]
//   dataset --seed <s> --forms <n> [--workers <k>]   (labelled field dataset, lab/dataset/build.ts)
// `lab` and `repro` run the Playwright lab with the LAB_* variables, then write
// the report; the exit code is 1 when a leak was found.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Profile } from "./gen/population.ts";
import { classifierInfo, classifierOptions } from "./classifier-info.ts";
import { compareDirs, compareRuns } from "./compare.ts";
import { scoreRows } from "./dataset/heuristic-eval.ts";
import { renderReport, summarize } from "./report.ts";
import type { Result } from "./run/oracle.ts";

const EXT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const DEFAULT_SITES = 200;

type Args = Record<string, string>;

function parseArgs(argv: string[], positional?: string[]): Args {
  const out: Args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (!a.startsWith("--")) {
      if (positional) { positional.push(a); continue; }
      throw new Error(`unexpected argument ${a}`);
    }
    const v = argv[i + 1];
    if (v === undefined || v.startsWith("--")) throw new Error(`${a} needs a value`);
    out[a.slice(2)] = v;
    i++;
  }
  return out;
}

function need(a: Args, k: string): string {
  const v = a[k];
  if (v === undefined || v === "") throw new Error(`missing --${k}`);
  return v;
}

function posInt(a: Args, k: string, min: number): number {
  const n = Number(need(a, k));
  if (!Number.isInteger(n) || n < min) throw new Error(`--${k} must be an integer >= ${min}`);
  return n;
}

const absolute = (p: string): string => (isAbsolute(p) ? p : resolve(EXT_ROOT, p));

function commit(): string {
  const r = spawnSync("git", ["rev-parse", "--short", "HEAD"], { cwd: EXT_ROOT, encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : "inconnu";
}

function readResults(out: string): Result[] {
  const file = join(out, "results.jsonl");
  if (!existsSync(file)) throw new Error(`no results file: ${file}`);
  return readFileSync(file, "utf8").split("\n").filter((l) => l.trim() !== "").map((l) => JSON.parse(l) as Result);
}

/** Date, commit and duration of the run, as written by `lab` (empty for an old run without them). */
function readMeta(out: string): { date?: string; commit?: string; durationMin?: number } {
  try {
    return JSON.parse(readFileSync(join(out, "run-meta.json"), "utf8")) as { date?: string; commit?: string; durationMin?: number };
  } catch {
    return {};
  }
}

/** Write <out>/report.md (and `md` when given); returns the number of leaks. */
function writeReport(out: string, md: string | undefined): number {
  const world = JSON.parse(readFileSync(join(out, "world.json"), "utf8")) as { seed: string; sites: unknown[]; profiles?: Profile[] };
  const summary = summarize(readResults(out));
  const text = renderReport({ seed: world.seed, sites: world.sites.length, ...(world.profiles ? { profiles: world.profiles } : {}) }, summary, readMeta(out));
  writeFileSync(join(out, "report.md"), text);
  if (md !== undefined) {
    const target = absolute(md);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, text);
  }
  const o = summary.overall;
  const leaks = summary.leaks.length;
  console.log(`lab report: ${o.total} scenarios (+${summary.control.total} control), rate ${(o.rate * 100).toFixed(1)} %, ${o.fail} fail, ${leaks} leak -> ${join(out, "report.md")}`);
  return leaks;
}

function runPlaywright(env: Record<string, string>, workers: string | undefined): number {
  const args = ["playwright", "test", "-c", "lab/run/playwright.config.ts"];
  if (workers !== undefined) args.push("--workers", workers);
  const r = spawnSync("npx", args, { cwd: EXT_ROOT, stdio: "inherit", env: { ...process.env, ...env } });
  return r.status ?? 1;
}

/**
 * classifier.json of a run: kind, build marker (checked before the run), model size, offline metrics, and for a
 * model build the classify time measured in the worker. Returns false when the probe failed (marked "failed").
 */
function writeClassifierInfo(out: string, a: Args, env: Record<string, string>, seed: string, sites: number): boolean {
  const opts = classifierOptions(a);
  if (opts.kind === undefined) return true;
  const info = classifierInfo(opts.kind, opts.modelDir);
  const markerFile = join(out, "build-marker.json");
  if (existsSync(markerFile)) info.buildMarker = JSON.parse(readFileSync(markerFile, "utf8")) as NonNullable<typeof info.buildMarker>;
  let ok = true;
  if (opts.kind !== "heuristic") {
    const file = join(out, "classify-time.json");
    const r = spawnSync("node", ["--experimental-strip-types", "lab/run/classify-time.ts", "--seed", seed, "--sites", String(sites), "--out", file], { cwd: EXT_ROOT, stdio: "inherit", env: { ...process.env, ...env } });
    if (r.status === 0) {
      info.classifyMs = JSON.parse(readFileSync(file, "utf8")) as NonNullable<typeof info.classifyMs>;
      info.probe = "ok";
    } else {
      ok = false;
      info.probe = "failed";
      console.error("lab: the classify-time probe failed (marked probe failed in classifier.json; exit code 1)");
    }
  }
  writeFileSync(join(out, "classifier.json"), JSON.stringify(info, null, 2));
  return ok;
}

function runLab(env: Record<string, string>, out: string, workers: string | undefined, md: string | undefined, a: Args = {}, seed = "", sites = 0): number {
  const started = Date.now();
  const status = runPlaywright(env, workers);
  const minutes = Math.max(1, Math.round((Date.now() - started) / 60_000));
  if (!existsSync(join(out, "results.jsonl"))) {
    console.error("lab: the run produced no results (setup failed?)");
    return 1;
  }
  const meta = { date: new Date().toISOString().slice(0, 10), commit: commit(), durationMin: minutes };
  writeFileSync(join(out, "run-meta.json"), JSON.stringify(meta, null, 2));
  const probeOk = writeClassifierInfo(out, a, env, seed, sites);
  const leaks = writeReport(out, md);
  return leaks > 0 || status !== 0 || !probeOk ? 1 : 0;
}

/** `compare --out <dir> <dir> <dir> --md <file> [--real-rows <jsonl>]`: the folders are the values of --out and the arguments after it. */
async function compare(rest: string[]): Promise<number> {
  const extra: string[] = [];
  const a = parseArgs(rest, extra);
  const dirs = [need(a, "out"), ...extra].map(absolute);
  if (dirs.length < 2) throw new Error("compare needs at least two result folders (heuristic and a model)");
  const loaded = compareDirs(dirs);
  let { markdown } = loaded;
  if (a["real-rows"] !== undefined) {
    // The heuristic's real_test score comes from running classifyField on the rows (heuristic-eval.ts).
    const score = await scoreRows(absolute(a["real-rows"]));
    const runs = loaded.runs.map((r) => (r.info.classifier === "heuristic" ? { ...r, info: { ...r.info, realTestMacroF1: score.macroF1, realTestMergedF1: score.mergedF1, realTestRows: score.rows, ...(score.digest ? { realTestDigest: score.digest } : {}) } } : r));
    ({ markdown } = compareRuns(runs));
  }
  const target = absolute(need(a, "md"));
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, markdown);
  const verdict = /^Verdict : .*$/m.exec(markdown)?.[0] ?? "";
  console.log(`compare: ${dirs.length} runs -> ${target}\n${verdict}`);
  return 0;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  if (cmd === "compare") return compare(rest);
  const a = parseArgs(rest);
  if (cmd === "lab") {
    const seed = need(a, "seed");
    const sites = posInt(a, "sites", 1);
    if (a.workers !== undefined) posInt(a, "workers", 1);
    const cls = classifierOptions(a);
    if (cls.kind !== undefined && cls.kind !== "heuristic") classifierInfo(cls.kind, cls.modelDir); // fail early on a missing model
    const out = absolute(join("lab", "out", `${seed}${cls.suffix}`));
    const profiles = a.profiles !== undefined ? posInt(a, "profiles", 1) : 1;
    const env = { LAB_SEED: seed, LAB_SITES: String(sites), LAB_PROFILES: String(profiles), LAB_OUT: out, ...cls.env };
    return runLab(env, out, a.workers, a.report, a, seed, sites);
  }
  if (cmd === "repro") {
    const seed = need(a, "seed");
    const site = posInt(a, "site", 0);
    const cls = classifierOptions(a);
    const out = absolute(join("lab", "out", `${seed}${cls.suffix}`));
    // The world must be the original one: same seed and same site count.
    const worldFile = join(out, "world.json");
    let sites: number;
    if (a.sites !== undefined) sites = posInt(a, "sites", 1);
    else if (existsSync(worldFile)) sites = (JSON.parse(readFileSync(worldFile, "utf8")) as { sites: unknown[] }).sites.length;
    else sites = DEFAULT_SITES;
    if (site >= sites) throw new Error(`--site ${site} is outside the world (${sites} sites; pass --sites for another size)`);
    // A separate directory keeps the original run's results and report intact.
    const reproOut = absolute(join("lab", "out", `${seed}${cls.suffix}-repro-${site}`));
    const profiles = a.profiles !== undefined ? posInt(a, "profiles", 1) : 1;
    return runLab({ LAB_SEED: seed, LAB_SITES: String(sites), LAB_PROFILES: String(profiles), LAB_ONLY: String(site), LAB_OUT: reproOut, ...cls.env }, reproOut, a.workers, a.report, a, seed, sites);
  }
  if (cmd === "dataset") {
    const args = ["--experimental-strip-types", "lab/dataset/build.ts", "--seed", need(a, "seed"), "--forms", String(posInt(a, "forms", 1))];
    if (a.workers !== undefined) args.push("--workers", String(posInt(a, "workers", 1)));
    return spawnSync("node", args, { cwd: EXT_ROOT, stdio: "inherit" }).status ?? 1;
  }
  if (cmd === "report") {
    return writeReport(absolute(need(a, "out")), a.md) > 0 ? 1 : 0;
  }
  console.error("usage: lab --seed <s> --sites <n> [--profiles <n>] [--workers 4] [--report <md>] [--classifier <k> [--model-dir <dir>]] | compare --out <dir> <dir> <dir> --md <file> [--real-rows <jsonl>] | repro --seed <s> --site <i> [--sites <n>] [--profiles <n>] | report --out <dir> [--md <file>] | dataset --seed <s> --forms <n> [--workers <k>]");
  return 2;
}

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (e) {
  console.error(`lab: ${e instanceof Error ? e.message : String(e)}`);
  process.exitCode = 2;
}
