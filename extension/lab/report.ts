// Report of an autofill lab run (spec 8): folds the per-scenario Results into
// rates and renders a French Markdown report. Results carry field names, hosts
// and verdicts, never a value, so neither does the report. Type-only import:
// this module runs under `node --experimental-strip-types` through cli.ts.
import type { Result } from "./run/oracle.ts";

export interface Rate {
  total: number; pass: number; fail: number; leak: number; xfail: number; xpass: number; flaky: number; labError: number;
  /** (pass + flaky) over total minus xfail, xpass and lab_error; 1 when nothing counts. */
  rate: number;
}

export interface Summary {
  overall: Rate;
  byFlow: Record<string, Rate>;
  byTrait: Record<string, Rate>;
  byLang: Record<string, Rate>;
  byDriver: Record<string, Rate>;
  /** fail and leak verdicts. */
  failures: Result[];
  leaks: Result[];
  /** xfail and xpass verdicts. */
  expected: Result[];
  flaky: Result[];
}

function emptyRate(): Rate {
  return { total: 0, pass: 0, fail: 0, leak: 0, xfail: 0, xpass: 0, flaky: 0, labError: 0, rate: 1 };
}

function add(r: Rate, v: Result["verdict"]): void {
  r.total++;
  switch (v) {
    case "pass": r.pass++; break;
    case "fail": r.fail++; break;
    case "leak": r.leak++; break;
    case "xfail": r.xfail++; break;
    case "xpass": r.xpass++; break;
    case "flaky": r.flaky++; break;
    case "lab_error": r.labError++; break;
  }
}

function finish(r: Rate): Rate {
  const counted = r.total - r.xfail - r.xpass - r.labError;
  r.rate = counted > 0 ? (r.pass + r.flaky) / counted : 1;
  return r;
}

function group(results: Result[], keys: (r: Result) => string[]): Record<string, Rate> {
  const out: Record<string, Rate> = {};
  for (const r of results) {
    for (const k of new Set(keys(r))) add((out[k] ??= emptyRate()), r.verdict);
  }
  for (const k of Object.keys(out)) finish(out[k]!);
  return out;
}

export function summarize(results: Result[]): Summary {
  const overall = emptyRate();
  for (const r of results) add(overall, r.verdict);
  finish(overall);
  return {
    overall,
    byFlow: group(results, (r) => [r.flow]),
    // A site with several traits counts once under each of them.
    byTrait: group(results, (r) => (r.traits.length > 0 ? r.traits : ["(aucun)"])),
    byLang: group(results, (r) => [r.lang]),
    byDriver: group(results, (r) => [r.driver]),
    failures: results.filter((r) => r.verdict === "fail" || r.verdict === "leak"),
    leaks: results.filter((r) => r.verdict === "leak"),
    expected: results.filter((r) => r.verdict === "xfail" || r.verdict === "xpass"),
    flaky: results.filter((r) => r.verdict === "flaky"),
  };
}

const pct = (x: number): string => `${(x * 100).toFixed(1)} %`;

function table(title: string, by: Record<string, Rate>): string[] {
  const rows = Object.entries(by).sort(([a], [b]) => a.localeCompare(b));
  const out = [`### ${title}`, "", "| Clé | Total | Réussis | Échecs | Fuites | Attendus | Inattendus | Instables | Erreurs labo | Taux |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"];
  for (const [k, r] of rows) {
    out.push(`| ${k} | ${r.total} | ${r.pass} | ${r.fail} | ${r.leak} | ${r.xfail} | ${r.xpass} | ${r.flaky} | ${r.labError} | ${pct(r.rate)} |`);
  }
  return [...out, ""];
}

function scenarioLine(r: Result): string {
  const traits = r.traits.length > 0 ? r.traits.join(", ") : "aucun";
  return `- site ${r.site} (${r.flow}, ${r.driver}, traits : ${traits}, langue ${r.lang}) : ${r.cause ?? "sans cause"}. Rejeu : \`${r.repro}\``;
}

function countBy<T>(items: T[], key: (t: T) => string): [string, T[]][] {
  const m = new Map<string, T[]>();
  for (const it of items) {
    const k = key(it);
    m.set(k, [...(m.get(k) ?? []), it]);
  }
  return [...m.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
}

export function renderReport(world: { seed: string; sites: number }, s: Summary, meta: { date: string; commit: string; durationMin: number }): string {
  const o = s.overall;
  const l: string[] = [];
  l.push(`# Rapport du laboratoire d'autofill`, "");
  l.push(`- Graine du monde : \`${world.seed}\``, `- Date : ${meta.date}`, `- Commit : \`${meta.commit}\``, `- Durée : ${meta.durationMin} min`, "");
  l.push("## Résumé", "");
  l.push(`- Sites : ${world.sites}`, `- Scénarios : ${o.total}`);
  l.push(`- Taux de réussite global (hors attendus, inattendus et erreurs du labo) : ${pct(o.rate)}`);
  l.push(`- Réussis : ${o.pass}, échecs : ${o.fail}, instables : ${o.flaky}, échecs attendus : ${o.xfail}, réussites inattendues : ${o.xpass}, erreurs du labo : ${o.labError}`);
  l.push(`- Fuites : ${o.leak}${o.leak > 0 ? " (le passage est rouge)" : ""}`, "");
  l.push("## Taux de réussite", "");
  l.push(...table("Par flux", s.byFlow), ...table("Par trait", s.byTrait), ...table("Par langue", s.byLang), ...table("Par pilote", s.byDriver));

  l.push("## Échecs", "");
  const fails = s.failures.filter((r) => r.verdict === "fail");
  if (fails.length === 0) l.push("Aucun.", "");
  else l.push(...fails.map(scenarioLine), "");

  l.push("## Réussites inattendues", "");
  const xpass = s.expected.filter((r) => r.verdict === "xpass");
  if (xpass.length === 0) l.push("Aucune.", "");
  else l.push("Une capacité attendue manquante est arrivée : retirer l'attente d'échec correspondante.", "", ...xpass.map(scenarioLine), "");

  l.push("## Ce que l'extension ne fait pas encore", "");
  const xfail = s.expected.filter((r) => r.verdict === "xfail");
  if (xfail.length === 0) l.push("Aucun échec attendu dans ce passage.", "");
  else {
    l.push("Échecs attendus, regroupés par cause :", "");
    for (const [cause, rs] of countBy(xfail, (r) => r.cause ?? "sans cause")) {
      const flows = [...new Set(rs.map((r) => r.flow))].sort().join(", ");
      const traits = [...new Set(rs.flatMap((r) => r.traits))].sort().join(", ") || "aucun";
      l.push(`- ${cause} : ${rs.length} scénario(s), flux : ${flows}, traits : ${traits}`);
    }
    l.push("");
  }
  if (fails.length > 0) {
    l.push("Causes d'échec récurrentes (hors attendus) :", "");
    for (const [cause, rs] of countBy(fails, (r) => r.cause ?? "sans cause")) l.push(`- ${cause} : ${rs.length} scénario(s)`);
    l.push("");
  }

  l.push("## Fuites", "");
  if (s.leaks.length === 0) l.push("Aucune.", "");
  else l.push(...s.leaks.map(scenarioLine), "");

  l.push("## Instables", "");
  if (s.flaky.length === 0) l.push("Aucun.", "");
  else l.push("Réussis au second essai, en profil neuf :", "", ...s.flaky.map(scenarioLine), "");
  return l.join("\n");
}
