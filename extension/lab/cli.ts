// Command line of the autofill lab (spec 9), run by `node --experimental-strip-types`:
//   lab    --seed <s> [--sites <n>] [--drivers current,smart_fill] [--workers 4] [--report <md>]
//   repro  --seed <s> --site <i> [--sites <n>] [--drivers ...]
//   report --out <dir> [--md <file>]
// `lab` and `repro` run the Playwright lab with the LAB_* variables, then write
// the report; the exit code is 1 when the run is red (a leak, a wrong item or
// an auto-submit outside a sign-in). --sites defaults to 200, --drivers to current.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseDriverGroups } from "./gen/generate.ts";
import { isRed, renderReport, summarize } from "./report.ts";
import type { Result } from "./run/oracle.ts";

const EXT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const DEFAULT_SITES = 200;

type Args = Record<string, string>;

function parseArgs(argv: string[]): Args {
  const out: Args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (!a.startsWith("--")) throw new Error(`unexpected argument ${a}`);
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

/** Write <out>/report.md (and `md` when given); returns whether the run is red. */
function writeReport(out: string, md: string | undefined): boolean {
  const world = JSON.parse(readFileSync(join(out, "world.json"), "utf8")) as { seed: string; sites: unknown[] };
  const summary = summarize(readResults(out));
  const text = renderReport({ seed: world.seed, sites: world.sites.length }, summary, readMeta(out));
  writeFileSync(join(out, "report.md"), text);
  if (md !== undefined) {
    const target = absolute(md);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, text);
  }
  const o = summary.overall;
  const leaks = summary.leaks.length;
  const oc = summary.oneClickTotal;
  console.log(`lab report: ${o.total} scenarios (+${summary.control.total} control), rate ${(o.rate * 100).toFixed(1)} %, ${o.fail} fail, ${leaks} leak, `
    + `${summary.wrongItem.length} wrong_item, ${summary.autoSubmitOutsideLogin.length} auto_submit_outside_login, `
    + `one click current ${oc.current.ok}/${oc.current.total} smart_fill ${oc.smart_fill.ok}/${oc.smart_fill.total} -> ${join(out, "report.md")}`);
  return isRed(summary);
}

function runPlaywright(env: Record<string, string>, workers: string | undefined): number {
  const args = ["playwright", "test", "-c", "lab/run/playwright.config.ts"];
  if (workers !== undefined) args.push("--workers", workers);
  const r = spawnSync("npx", args, { cwd: EXT_ROOT, stdio: "inherit", env: { ...process.env, ...env } });
  return r.status ?? 1;
}

function runLab(env: Record<string, string>, out: string, workers: string | undefined, md: string | undefined): number {
  const started = Date.now();
  const status = runPlaywright(env, workers);
  const minutes = Math.max(1, Math.round((Date.now() - started) / 60_000));
  if (!existsSync(join(out, "results.jsonl"))) {
    console.error("lab: the run produced no results (setup failed?)");
    return 1;
  }
  const meta = { date: new Date().toISOString().slice(0, 10), commit: commit(), durationMin: minutes };
  writeFileSync(join(out, "run-meta.json"), JSON.stringify(meta, null, 2));
  const red = writeReport(out, md);
  return red || status !== 0 ? 1 : 0;
}

function main(argv: string[]): number {
  const [cmd, ...rest] = argv;
  const a = parseArgs(rest);
  if (cmd === "lab") {
    const seed = need(a, "seed");
    const sites = a.sites !== undefined ? posInt(a, "sites", 1) : DEFAULT_SITES;
    if (a.workers !== undefined) posInt(a, "workers", 1);
    const drivers = parseDriverGroups(a.drivers ?? "current").join(",");
    const out = absolute(join("lab", "out", seed));
    return runLab({ LAB_SEED: seed, LAB_SITES: String(sites), LAB_OUT: out, LAB_DRIVERS: drivers }, out, a.workers, a.report);
  }
  if (cmd === "repro") {
    const seed = need(a, "seed");
    const site = posInt(a, "site", 0);
    const out = absolute(join("lab", "out", seed));
    // The world must be the original one: same seed and same site count.
    const worldFile = join(out, "world.json");
    let sites: number;
    if (a.sites !== undefined) sites = posInt(a, "sites", 1);
    else if (existsSync(worldFile)) sites = (JSON.parse(readFileSync(worldFile, "utf8")) as { sites: unknown[] }).sites.length;
    else sites = DEFAULT_SITES;
    if (site >= sites) throw new Error(`--site ${site} is outside the world (${sites} sites; pass --sites for another size)`);
    // A separate directory keeps the original run's results and report intact.
    const reproOut = absolute(join("lab", "out", `${seed}-repro-${site}`));
    const drivers = parseDriverGroups(a.drivers ?? "current").join(",");
    return runLab({ LAB_SEED: seed, LAB_SITES: String(sites), LAB_ONLY: String(site), LAB_OUT: reproOut, LAB_DRIVERS: drivers }, reproOut, a.workers, a.report);
  }
  if (cmd === "report") {
    return writeReport(absolute(need(a, "out")), a.md) ? 1 : 0;
  }
  console.error("usage: lab --seed <s> [--sites <n>] [--drivers current,smart_fill] [--workers 4] [--report <md>] | repro --seed <s> --site <i> [--sites <n>] [--drivers ...] | report --out <dir> [--md <file>]");
  return 2;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (e) {
  console.error(`lab: ${e instanceof Error ? e.message : String(e)}`);
  process.exitCode = 2;
}
