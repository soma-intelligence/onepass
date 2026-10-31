// Comparison of the three classifier builds on one lab seed (Task 16, spec 1 and 7.3). Reads the
// folders `lab --classifier <k>` left (results.jsonl, world.json, classifier.json), tabulates the
// pass rates per flow, trait, language (and profile), and applies the decision rule in code.
// Run through `node --experimental-strip-types`: relative imports carry their extension.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Rate, Summary } from "./report.ts";
import { summarize } from "./report.ts";
import type { Result } from "./run/oracle.ts";

export type ClassifierKind = "heuristic" | "gbm" | "encoder";
export const KINDS: readonly ClassifierKind[] = ["heuristic", "gbm", "encoder"];
/** Spec 1: inference under 5 ms per form (median, measured in the extension's worker). */
export const MAX_CLASSIFY_MS = 5;

export interface ClassifyTime { forms: number; median: number; p90: number; max: number }

/** What a run knows about its classifier (classifier.json, written by `lab` at run time). */
export interface ClassifierInfo {
  classifier: ClassifierKind;
  /** Bytes of the model files that ship (gbm.onnx; encoder.onnx and tokenizer.json). */
  modelBytes?: number;
  /** Macro F1 on the synthetic test split, from the ml eval JSON next to the model. */
  testMacroF1?: number | null;
  /** Plain macro F1 on real_test; null when it has no rows. */
  realTestMacroF1?: number | null;
  /** Macro F1 on real_test with password, new_password and confirm_password merged (R23): the one criterion (b) uses. */
  realTestMergedF1?: number | null;
  realTestRows?: number;
  /** Digest of the real_test row identifiers both sides were scored on (rowsDigest). */
  realTestDigest?: string;
  /** Build marker checked before the run: classifier kind and sha256 of the model files. */
  buildMarker?: { classifier: ClassifierKind; modelSha256?: string };
  /** "failed" when the classify-time probe did not run to the end. */
  probe?: "ok" | "failed";
  /** Per-form classify time (worker side), models only. */
  classifyMs?: ClassifyTime;
}

export interface RunSide {
  dir: string;
  seed: string;
  sites: number;
  summary: Summary;
  info: ClassifierInfo;
  /** Number of simulated users of the world (1 without profiles). */
  profileCount: number;
}

export interface ModelVerdict { kind: Exclude<ClassifierKind, "heuristic">; eligible: boolean; labRate: number; reasons: string[] }
export interface Decision {
  chosen: ClassifierKind;
  /** True when real_test has no labels, so criterion (b) cannot be judged. */
  provisional: boolean;
  models: ModelVerdict[];
}

function readJson<T>(file: string): T | undefined {
  if (!existsSync(file)) return undefined;
  return JSON.parse(readFileSync(file, "utf8")) as T;
}

export function loadRun(dir: string): RunSide {
  const file = join(dir, "results.jsonl");
  if (!existsSync(file)) throw new Error(`no results file: ${file}`);
  const results = readFileSync(file, "utf8").split("\n").filter((l) => l.trim() !== "").map((l) => JSON.parse(l) as Result);
  const world = readJson<{ seed: string; sites: unknown[]; profiles?: unknown[] }>(join(dir, "world.json"));
  if (!world) throw new Error(`no world file in ${dir}`);
  const info = readJson<ClassifierInfo>(join(dir, "classifier.json"));
  if (!info) throw new Error(`no classifier.json in ${dir} (run it with --classifier)`);
  return { dir, seed: world.seed, sites: world.sites.length, summary: summarize(results), info, profileCount: world.profiles?.length ?? 1 };
}

/** The decision rule of the spec (sections 1 and 7.3). Throws when the runs are not one seed or lack the heuristic run. */
export function decide(runs: RunSide[]): Decision {
  const base = runs.find((r) => r.info.classifier === "heuristic");
  if (!base) throw new Error("the comparison needs the heuristic run");
  if (runs.some((r) => r.seed !== base.seed)) throw new Error("les passages doivent avoir la même graine");
  if (runs.some((r) => r.sites !== base.sites)) throw new Error("les passages doivent avoir le même nombre de sites");
  if (runs.some((r) => r.profileCount !== base.profileCount)) throw new Error("les passages doivent avoir le même nombre de profils");
  if (new Set(runs.map((r) => r.info.classifier)).size !== runs.length) throw new Error("les passages doivent être de classifieurs distincts");
  const models: ModelVerdict[] = [];
  let provisional = false;
  const sizeOf = new Map<string, number>();
  for (const r of runs) {
    if (r.info.classifier === "heuristic") continue;
    const reasons: string[] = [];
    const rate = r.summary.overall.rate;
    if (!(rate > base.summary.overall.rate)) reasons.push(`taux au labo ${pct(rate)} pas au-dessus de l'heuristique (${pct(base.summary.overall.rate)})`);
    const mine = r.info.realTestMergedF1;
    const ref = base.info.realTestMergedF1;
    if (mine == null || ref == null) {
      provisional = true;
      reasons.push("real_test non étiqueté : le critère sur le jeu de test réel ne peut pas être jugé");
    } else if (r.info.realTestDigest === undefined || r.info.realTestDigest !== base.info.realTestDigest || r.info.realTestRows !== base.info.realTestRows) {
      provisional = true;
      reasons.push("real_test non comparable : lignes différentes ou empreinte des lignes inconnue (rejouer l'évaluation du modèle et l'option --real-rows sur le même jeu)");
    } else if (!(mine > ref)) reasons.push(`F1 macro sur real_test (mots de passe fusionnés) ${num(mine)} pas au-dessus de l'heuristique (${num(ref)})`);
    const leaks = r.summary.leaks.length;
    if (leaks > 0) reasons.push(`${leaks} fuite(s) au labo`);
    const ms = r.info.classifyMs;
    if (!ms) reasons.push(r.info.probe === "failed" ? "temps de classement non mesuré : la sonde de mesure a échoué" : "temps de classement non mesuré");
    else if (!(ms.median < MAX_CLASSIFY_MS)) reasons.push(`temps médian ${num(ms.median, 1)} ms par formulaire, au moins ${MAX_CLASSIFY_MS} ms`);
    sizeOf.set(r.info.classifier, r.info.modelBytes ?? Number.POSITIVE_INFINITY);
    models.push({ kind: r.info.classifier as ModelVerdict["kind"], eligible: reasons.length === 0, labRate: rate, reasons });
  }
  const eligible = models.filter((m) => m.eligible).sort((a, b) => b.labRate - a.labRate || sizeOf.get(a.kind)! - sizeOf.get(b.kind)! || a.kind.localeCompare(b.kind));
  return { chosen: eligible[0]?.kind ?? "heuristic", provisional, models };
}

const pct = (x: number): string => `${(x * 100).toFixed(1).replace(".", ",")} %`;
const num = (x: number, digits = 2): string => x.toFixed(digits).replace(".", ",");
const mb = (b: number): string => `${num(b / 1_000_000, 1)} Mo`;

function cell(r: Rate | undefined): string {
  return r === undefined ? "n/a" : `${pct(r.rate)} (${r.pass + r.flaky}/${r.total - r.xfail - r.xpass - r.labError})`;
}

function breakdown(title: string, runs: RunSide[], pick: (s: Summary) => Record<string, Rate>): string[] {
  const keys = [...new Set(runs.flatMap((r) => Object.keys(pick(r.summary))))].sort();
  const head = ["Clé", ...runs.map((r) => r.info.classifier), `Fuites (${runs.map((r) => r.info.classifier).join(" / ")})`];
  const out = [`### ${title}`, "", `| ${head.join(" | ")} |`, `| ${head.map(() => "---").join(" | ")} |`];
  for (const k of keys) {
    const leaks = runs.map((r) => String(pick(r.summary)[k]?.leak ?? 0)).join(" / ");
    out.push(`| ${k} | ${runs.map((r) => cell(pick(r.summary)[k])).join(" | ")} | ${leaks} |`);
  }
  return [...out, ""];
}

function f1(v: number | null | undefined): string {
  if (v === undefined) return "n/a";
  return v === null ? "n/a (0 rows)" : num(v);
}

/** French Markdown of the comparison: summary, tables, offline metrics, verdict with reasons. */
export function renderComparison(runsIn: RunSide[], d: Decision): string {
  const runs = KINDS.map((k) => runsIn.find((r) => r.info.classifier === k)).filter((r): r is RunSide => r !== undefined);
  const l: string[] = ["# Comparaison des classifieurs du formulaire", ""];
  const seed = runs[0]!.seed;
  l.push(`- Graine du monde : \`${seed}\` (${runs[0]!.sites} sites)`, "- Taux : réussis sur scénarios comptés (hors attendus, inattendus et erreurs du labo), entre parenthèses le détail", "");
  l.push("## Synthèse", "");
  l.push("| Classifieur | Taux au labo | Fuites | Médiane par formulaire | Taille du modèle | F1 macro test | F1 macro real_test (mots de passe fusionnés) |", "| --- | --- | --- | --- | --- | --- | --- |");
  for (const r of runs) {
    const i = r.info;
    const model = i.classifier !== "heuristic";
    l.push(`| ${i.classifier} | ${cell(r.summary.overall)} | ${r.summary.leaks.length} | ${model ? (i.classifyMs ? `${num(i.classifyMs.median, 1)} ms (p90 ${num(i.classifyMs.p90, 1)}, ${i.classifyMs.forms} formulaires)` : "non mesurée") : "n/a"} | ${model && i.modelBytes !== undefined ? mb(i.modelBytes) : "n/a"} | ${f1(i.testMacroF1)} | ${f1(i.realTestMergedF1)} |`);
  }
  l.push("");
  l.push("## Taux de réussite", "");
  l.push(...breakdown("Par flux", runs, (s) => s.byFlow), ...breakdown("Par trait", runs, (s) => s.byTrait), ...breakdown("Par langue", runs, (s) => s.byLang));
  if (runs.some((r) => r.profileCount > 1 || Object.keys(r.summary.byProfile).some((k) => k !== "p0"))) l.push(...breakdown("Par profil", runs, (s) => s.byProfile));
  l.push("## Verdict", "");
  l.push(`Verdict : ${d.chosen}${d.provisional ? " (provisoire : real_test non étiqueté)" : ""}`, "");
  l.push("Le critère sur real_test (b) note l'heuristique et les modèles avec `password`, `new_password` et `confirm_password` fusionnés en une seule classe (décision R23) : la production tranche entre mot de passe actuel et nouveau d'après le formulaire, ce que l'heuristique notée champ par champ ne peut pas faire. Les deux scores doivent porter sur les mêmes lignes de real_test (même nombre, même empreinte).", "");
  l.push("Règle (spec, sections 1 et 7.3) : un modèle est retenable s'il fait mieux que l'heuristique au labo sur la même graine et sur real_test, sans aucune fuite, avec un temps médian sous 5 ms par formulaire. Parmi eux, le meilleur taux au labo ; à égalité, le plus petit fichier. Sinon l'heuristique reste.", "");
  for (const m of d.models) l.push(`- ${m.kind} : ${m.eligible ? "retenable" : "écarté"}${m.reasons.length > 0 ? ` (${m.reasons.join(" ; ")})` : ""}`);
  l.push("");
  if (d.provisional) l.push("Le jeu de test réel n'a pas encore d'étiquettes : le critère F1 sur real_test ne peut être rempli par aucun modèle, donc le défaut de construction reste `heuristic`. Le choix sera rejoué quand real_test sera étiqueté.", "");
  return l.join("\n");
}

/** Decides and renders runs already loaded. */
export function compareRuns(runs: RunSide[]): { runs: RunSide[]; decision: Decision; markdown: string } {
  const decision = decide(runs);
  return { runs, decision, markdown: renderComparison(runs, decision) };
}

/** Loads the folders, decides, renders. */
export function compareDirs(dirs: string[]): { runs: RunSide[]; decision: Decision; markdown: string } {
  return compareRuns(dirs.map(loadRun));
}
