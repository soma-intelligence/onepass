// What a lab run records about its classifier (Task 16, classifier.json): model size and the offline
// metrics from the ml eval JSON next to the model, plus the per-form classify time statistics.
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { ClassifierInfo, ClassifierKind, ClassifyTime } from "./compare.ts";

/** Files of a model build, as build.mjs MODEL_FILES. */
const FILES: Record<Exclude<ClassifierKind, "heuristic">, string[]> = { gbm: ["gbm.onnx"], encoder: ["encoder.onnx", "tokenizer.json"] };

interface Split { rows?: number; macro_f1?: number }

export function classifierInfo(kind: ClassifierKind, modelDir?: string): ClassifierInfo {
  if (kind === "heuristic") return { classifier: "heuristic" };
  if (!modelDir) throw new Error(`--classifier ${kind} needs --model-dir`);
  let bytes = 0;
  for (const f of FILES[kind]) {
    const p = join(modelDir, f);
    if (!existsSync(p)) throw new Error(`--model-dir ${modelDir} has no ${f}`);
    bytes += statSync(p).size;
  }
  const info: ClassifierInfo = { classifier: kind, modelBytes: bytes };
  const evalFile = join(modelDir, `${kind}-eval.json`);
  if (existsSync(evalFile)) {
    const e = JSON.parse(readFileSync(evalFile, "utf8")) as { test?: Split | string; real_test?: Split | string };
    const f1 = (s: Split | string | undefined): number | null | undefined => (s === undefined ? undefined : typeof s === "string" || s.macro_f1 === undefined ? null : s.macro_f1);
    info.testMacroF1 = f1(e.test);
    info.realTestMacroF1 = f1(e.real_test);
    info.realTestRows = typeof e.real_test === "object" ? (e.real_test.rows ?? 0) : 0;
  }
  return info;
}

export function quantile(xs: number[], p: number): number {
  return [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor(p * xs.length))]!;
}

export function timeStats(ms: number[]): ClassifyTime {
  return { forms: ms.length, median: quantile(ms, 0.5), p90: quantile(ms, 0.9), max: Math.max(...ms) };
}

export interface ClassifierOptions {
  kind?: ClassifierKind;
  modelDir?: string;
  /** Build variables for build.mjs (ONEPASS_CLASSIFIER, ONEPASS_MODEL_DIR). */
  env: Record<string, string>;
  /** Suffix of the results folder: `lab/out/<seed><suffix>`. */
  suffix: string;
}

/** `--classifier` and `--model-dir` of the command line; without them the run is the historical default build. */
export function classifierOptions(a: Record<string, string>): ClassifierOptions {
  const k = a.classifier;
  if (k === undefined) {
    if (a["model-dir"] !== undefined) throw new Error("--model-dir needs --classifier");
    return { env: {}, suffix: "" };
  }
  if (k !== "heuristic" && k !== "gbm" && k !== "encoder") throw new Error("--classifier must be heuristic|gbm|encoder");
  if (k === "heuristic") return { kind: k, env: { ONEPASS_CLASSIFIER: k }, suffix: `-${k}` };
  if (a["model-dir"] === undefined || a["model-dir"] === "") throw new Error(`--classifier ${k} needs --model-dir`);
  return { kind: k, modelDir: a["model-dir"], env: { ONEPASS_CLASSIFIER: k, ONEPASS_MODEL_DIR: a["model-dir"] }, suffix: `-${k}` };
}
