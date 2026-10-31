// Turns the steps exported by the dev-only recorder (popup button, JSON file)
// into corpus Samples under lab/corpus/private/ (git-ignored: recorded flows
// come from the owner's real sessions). Every string goes through sanitize.ts
// (build.ts) before it is written; `filled`, `at` and any unknown key are
// dropped. One Sample per host, its steps in recording order.
// Usage: node --experimental-strip-types lab/corpus/import-recorded.ts <file.json> [--out <dir>]
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { build } from "./build.ts";
import { sanitizeOrigin } from "./sanitize.ts";
import { stableJson } from "./types.ts";
import type { Category, Sample, SampleForm } from "./types.ts";
import { normalizeStep, type RecordedStep } from "../../src/dev/recorder.ts";

export const DEFAULT_OUT = fileURLToPath(new URL("./private/", import.meta.url));

/** The popup export ({version, steps}) or a bare array of steps. */
export function parseExport(text: string): unknown[] {
  const v = JSON.parse(text) as unknown;
  const steps = Array.isArray(v) ? v : (v as { steps?: unknown } | null)?.steps;
  if (!Array.isArray(steps)) throw new Error("not a recorder export: expected an array of steps or {steps: [...]}");
  return steps;
}

function categoryOf(forms: SampleForm[]): Category {
  const roles = new Set(forms.flatMap((f) => f.fields.map((x) => x.role as string)));
  const any = (...r: string[]) => r.some((x) => roles.has(x));
  if (any("cc_number", "cc_csc", "cc_exp", "cc_exp_month", "cc_exp_year", "cc_name")) return "checkout";
  if (any("new_password")) return "signup";
  if (any("password", "username", "email", "otp")) return "login";
  if (any("address_line1", "address_line2", "postal_code", "city", "country")) return "address";
  return "identity";
}

export function importRecorded(raw: unknown[], outDir: string): { hosts: number; steps: number; skipped: number } {
  const byHost = new Map<string, RecordedStep[]>();
  let skipped = 0;
  for (const x of raw) {
    const host = (x as { host?: unknown } | null)?.host;
    // A host that is not a plain lower-case hostname is never a file name.
    const s = typeof host === "string" ? normalizeStep(x, host) : null;
    if (!s) {
      skipped++;
      continue;
    }
    byHost.set(s.host, [...(byHost.get(s.host) ?? []), s]);
  }
  mkdirSync(outDir, { recursive: true });
  let steps = 0;
  for (const [host, list] of byHost) {
    list.sort((a, b) => a.at - b.at);
    const forms: SampleForm[] = [];
    for (const s of list) {
      const base: Sample = { source_url: `https://${host}/`, host, category: "identity", captured_at: "", extractor: 2, status: "ok" };
      const page = { forms: [s.form], framework: "other" as const, iframes: [], shadowFields: 0, truncated: false };
      const one = build(base, page, { providerTexts: [] }, [], "recorded").forms?.[0];
      if (one) forms.push(one);
    }
    steps += forms.length;
    const sample: Sample = {
      source_url: `https://${host}/`,
      host: sanitizeOrigin(`https://${host}`).slice("https://".length),
      category: categoryOf(forms),
      captured_at: new Date(list.at(-1)!.at).toISOString(),
      extractor: 2,
      source: "recorded",
      status: "ok",
      lang: "und",
      steps: forms.map((f) => [f]),
    };
    writeFileSync(`${outDir}/${host}.json`, stableJson(sample));
  }
  return { hosts: byHost.size, steps, skipped };
}

const USAGE = `Usage: node --experimental-strip-types lab/corpus/import-recorded.ts <file.json> [--out <dir>]

Imports the steps exported by the dev-only recorder into private corpus Samples.
  --out   output directory (default lab/corpus/private/, git-ignored)`;

function main(): void {
  const args = process.argv.slice(2);
  const file = args.find((a) => !a.startsWith("--") && args[args.indexOf(a) - 1] !== "--out");
  const o = args.indexOf("--out");
  if (args.includes("--help") || !file) {
    console.log(USAGE);
    process.exitCode = args.includes("--help") ? 0 : 2;
    return;
  }
  const r = importRecorded(parseExport(readFileSync(file, "utf8")), o >= 0 ? (args[o + 1] ?? DEFAULT_OUT) : DEFAULT_OUT);
  console.log(`${r.hosts} hosts, ${r.steps} steps, ${r.skipped} skipped`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
