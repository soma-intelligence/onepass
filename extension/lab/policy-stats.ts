// Password policy results of a lab run: for the signup sites that enforce a
// policy, the scenarios by policy category and how many the site refused with
// the reason `policy` (or `weak_password`). Usage:
//   node --experimental-strip-types lab/policy-stats.ts --out lab/out/<seed>
// Prints a Markdown table; the categories are defined in gen/policy.ts.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { World } from "./gen/model.ts";
import { policyCategory, type PolicyCategory } from "./gen/policy.ts";
import type { Result } from "./run/oracle.ts";

export interface PolicyRow { category: PolicyCategory; scenarios: number; pass: number; policy: number; weak: number; other: number }

const CATEGORIES: PolicyCategory[] = ["attributes", "passwordrules", "hints_readable", "hint_only_unsupported", "none"];

/** Per category: signup scenarios judged (expected failures and lab errors left out), passes, `policy` and `weak_password` refusals. */
export function policyRows(world: Pick<World, "sites">, results: Result[]): PolicyRow[] {
  const rows = new Map<PolicyCategory, PolicyRow>(CATEGORIES.map((c) => [c, { category: c, scenarios: 0, pass: 0, policy: 0, weak: 0, other: 0 }]));
  for (const r of results) {
    const site = world.sites[r.site];
    if (!site || site.flow !== "signup" || r.expect === "nofill" || r.verdict === "lab_error") continue;
    const row = rows.get(policyCategory(site))!;
    row.scenarios++;
    const cause = r.cause ?? "";
    if (cause === "rp_refused:policy") row.policy++;
    else if (cause === "rp_refused:weak_password") row.weak++;
    if (r.verdict === "pass") row.pass++;
    else if (cause !== "rp_refused:policy" && cause !== "rp_refused:weak_password") row.other++;
  }
  return CATEGORIES.map((c) => rows.get(c)!);
}

export function renderRows(rows: PolicyRow[]): string {
  const head = "| Catégorie | Scénarios | Réussis | Refus `policy` | Refus `weak_password` | Autres échecs |\n| --- | --- | --- | --- | --- | --- |";
  return [head, ...rows.map((r) => `| ${r.category} | ${r.scenarios} | ${r.pass} | ${r.policy} | ${r.weak} | ${r.other} |`)].join("\n");
}

if (import.meta.url === `file://${process.argv[1] ?? ""}`) {
  const i = process.argv.indexOf("--out");
  const out = i >= 0 ? process.argv[i + 1] : undefined;
  if (!out) throw new Error("usage: policy-stats.ts --out <dir>");
  const world = JSON.parse(readFileSync(join(out, "world.json"), "utf8")) as World;
  const results = readFileSync(join(out, "results.jsonl"), "utf8").split("\n").filter((l) => l.trim() !== "").map((l) => JSON.parse(l) as Result);
  console.log(renderRows(policyRows(world, results)));
}
