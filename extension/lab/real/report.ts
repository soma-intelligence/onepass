// Outputs of the real-site bench (README "Sorties"): results.jsonl (one line
// per site, step and rule: host, kind, step, rule, verdict, detail, never a
// value) and report.md (violations grouped by rule, then by site, each with
// the screenshot of the card area in shots/).
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import type { Rule, Verdict } from "./oracle.ts";
import type { TargetKind } from "./targets.ts";

export type RowRule = Rule | "-";

export interface ResultRow {
  host: string;
  kind: TargetKind;
  step: string;
  rule: RowRule;
  verdict: Verdict | "error" | "timeout";
  detail: string;
  /** Screenshot of the card area, relative to the output folder. */
  shot?: string;
}

/** Appends rows to `<out>/results.jsonl` as they come (a crashed run keeps what it saw). */
export class ResultsWriter {
  readonly rows: ResultRow[] = [];
  readonly path: string;
  readonly out: string;
  constructor(out: string) {
    this.out = out;
    mkdirSync(out, { recursive: true });
    this.path = join(out, "results.jsonl");
    writeFileSync(this.path, "");
  }
  add(row: ResultRow): void {
    this.rows.push(row);
    appendFileSync(this.path, `${JSON.stringify(row)}\n`);
  }
}

export interface RunMeta {
  startedAt: string;
  finishedAt: string;
  kinds: TargetKind[];
  sites: number;
  managers: string[];
  /** Lines worth reading before the findings (missing modules, skipped kinds). */
  notes: string[];
  vault: { items: number; sites: number; twoAccounts: number; duplicates: number };
}

const RULES: Rule[] = ["R1", "R2", "R3", "R4", "R5"];
const RULE_TITLES: Record<Rule, string> = {
  R1: "R1 card only where needed",
  R2: "R2 everything stays clickable",
  R3: "R3 no redundancy",
  R4: "R4 no clash with another manager",
  R5: "R5 no leak, no send",
};

/** Verdict counts per rule. */
export function countByRule(rows: readonly ResultRow[]): Record<Rule, Record<string, number>> {
  const out = Object.fromEntries(RULES.map((r) => [r, {} as Record<string, number>])) as Record<Rule, Record<string, number>>;
  for (const r of rows) {
    if (r.rule === "-") continue;
    out[r.rule][r.verdict] = (out[r.rule][r.verdict] ?? 0) + 1;
  }
  return out;
}

const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");

/** The Markdown report. `shotBase`: folder the shot paths are relative to (the report's own). */
export function renderReport(rows: readonly ResultRow[], meta: RunMeta): string {
  const lines: string[] = [];
  const sites = new Set(rows.map((r) => `${r.kind}:${r.host}`));
  lines.push("# Real-site bench report", "");
  lines.push(`- Started ${meta.startedAt}, finished ${meta.finishedAt}`);
  lines.push(`- Kinds: ${meta.kinds.join(", ")}; sites asked: ${meta.sites}; sites visited: ${sites.size}`);
  lines.push(`- Other managers: ${meta.managers.length > 0 ? meta.managers.join(", ") : "none"}`);
  lines.push(`- Vault: ${meta.vault.items} fictional logins, ${meta.vault.sites} sites, ${meta.vault.twoAccounts} second accounts, ${meta.vault.duplicates} duplicates`);
  for (const n of meta.notes) lines.push(`- Note: ${n}`);
  lines.push("", "## Counts", "", "| Rule | pass | violation | warn | info | skip |", "| --- | --- | --- | --- | --- | --- |");
  const counts = countByRule(rows);
  for (const r of RULES) {
    const c = counts[r];
    lines.push(`| ${RULE_TITLES[r]} | ${c.pass ?? 0} | ${c.violation ?? 0} | ${c.warn ?? 0} | ${c.info ?? 0} | ${c.skip ?? 0} |`);
  }
  const problems = rows.filter((r) => r.rule === "-" && (r.verdict === "error" || r.verdict === "timeout" || r.verdict === "skip"));
  if (problems.length > 0) {
    lines.push("", "## Sites not fully visited", "", "| Site | Kind | Step | Verdict | Detail |", "| --- | --- | --- | --- | --- |");
    for (const p of problems) lines.push(`| ${p.host} | ${p.kind} | ${p.step} | ${p.verdict} | ${esc(p.detail)} |`);
  }
  for (const rule of RULES) {
    const bad = rows.filter((r) => r.rule === rule && (r.verdict === "violation" || r.verdict === "warn"));
    lines.push("", `## ${RULE_TITLES[rule]}`, "");
    if (bad.length === 0) {
      lines.push("No violation.");
      continue;
    }
    const bySite = new Map<string, ResultRow[]>();
    for (const r of bad) {
      const k = `${r.host} (${r.kind})`;
      bySite.set(k, [...(bySite.get(k) ?? []), r]);
    }
    for (const [site, list] of [...bySite].sort((a, b) => a[0].localeCompare(b[0]))) {
      lines.push(`### ${site}`, "");
      for (const r of list) {
        lines.push(`- **${r.verdict}** at step \`${r.step}\`: ${esc(r.detail)}`);
        if (r.shot) lines.push(`  ![${esc(r.host)} ${r.step}](${r.shot})`);
      }
      lines.push("");
    }
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

export function writeReport(out: string, rows: readonly ResultRow[], meta: RunMeta): string {
  const path = join(out, "report.md");
  writeFileSync(path, renderReport(rows, meta));
  return path;
}

/** A file name for a shot: host, kind, step number, rule; nothing else. */
export function shotName(host: string, kind: TargetKind, stepNo: number, rule: Rule): string {
  return `${host.replace(/[^a-z0-9.-]/gi, "_")}-${kind}-${String(stepNo).padStart(2, "0")}-${rule}.png`;
}

export function shotRel(out: string, file: string): string {
  return relative(out, file);
}
