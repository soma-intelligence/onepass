// @vitest-environment node
// classifier.json of a lab run (Task 16): model size and offline metrics read from the model folder.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { classifierInfo, classifierOptions, quantile, timeStats } from "../../lab/classifier-info.ts";

const tmp: string[] = [];
afterEach(() => { while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true }); });
function modelDir(files: Record<string, string | object>): string {
  const d = mkdtempSync(join(tmpdir(), "ci-"));
  tmp.push(d);
  for (const [n, c] of Object.entries(files)) writeFileSync(join(d, n), typeof c === "string" ? c : JSON.stringify(c));
  return d;
}

describe("classifierInfo", () => {
  it("heuristic_has_no_model_fields", () => {
    expect(classifierInfo("heuristic")).toEqual({ classifier: "heuristic" });
  });

  it("gbm_reads_size_and_eval_json", () => {
    const d = modelDir({ "gbm.onnx": "x".repeat(1000), "gbm-eval.json": { model: "gbm.onnx", test: { rows: 10, macro_f1: 0.9 }, real_test: "n/a (0 rows)" } });
    expect(classifierInfo("gbm", d)).toEqual({ classifier: "gbm", modelBytes: 1000, testMacroF1: 0.9, realTestMacroF1: null, realTestMergedF1: null, realTestRows: 0 });
  });

  it("encoder_size_adds_the_tokenizer_and_real_test_is_read_when_labelled", () => {
    const d = modelDir({ "encoder.onnx": "x".repeat(500), "tokenizer.json": "y".repeat(100), "encoder-eval.json": { test: { rows: 10, macro_f1: 0.8 }, real_test: { rows: 200, macro_f1: 0.7, labels: ["password", "new_password"], confusion_matrix: [[1, 1], [1, 1]] }, real_test_digest: "abc" } });
    expect(classifierInfo("encoder", d)).toEqual({ classifier: "encoder", modelBytes: 600, testMacroF1: 0.8, realTestMacroF1: 0.7, realTestMergedF1: 1, realTestRows: 200, realTestDigest: "abc" });
  });

  it("a_model_without_eval_json_leaves_the_metrics_out", () => {
    const d = modelDir({ "gbm.onnx": "x" });
    const i = classifierInfo("gbm", d);
    expect(i.modelBytes).toBe(1);
    expect(i.testMacroF1).toBeUndefined();
  });

  it("a_model_folder_without_the_model_throws", () => {
    const d = mkdtempSync(join(tmpdir(), "ci-"));
    tmp.push(d);
    mkdirSync(join(d, "x"));
    expect(() => classifierInfo("gbm", d)).toThrow(/gbm.onnx/);
    expect(() => classifierInfo("gbm")).toThrow(/model-dir/);
  });
});

describe("timeStats", () => {
  it("median_p90_max_over_forms", () => {
    expect(quantile([3, 1, 2], 0.5)).toBe(2);
    expect(timeStats([5, 1, 3, 2, 4])).toEqual({ forms: 5, median: 3, p90: 5, max: 5 });
  });
});

describe("classifier options", () => {
  it("no_flag_keeps_the_historical_folder_and_build", () => {
    expect(classifierOptions({})).toEqual({ env: {}, suffix: "" });
  });

  it("heuristic_and_models_name_the_folder_and_pass_the_build_env", () => {
    expect(classifierOptions({ classifier: "heuristic" })).toEqual({ kind: "heuristic", env: { ONEPASS_CLASSIFIER: "heuristic" }, suffix: "-heuristic" });
    const o = classifierOptions({ classifier: "gbm", "model-dir": "/m" });
    expect(o).toMatchObject({ kind: "gbm", suffix: "-gbm", modelDir: "/m" });
    expect(o.env).toEqual({ ONEPASS_CLASSIFIER: "gbm", ONEPASS_MODEL_DIR: "/m" });
  });

  it("refuses_an_unknown_kind_and_a_model_without_its_dir", () => {
    expect(() => classifierOptions({ classifier: "svm" })).toThrow(/heuristic\|gbm\|encoder/);
    expect(() => classifierOptions({ classifier: "encoder" })).toThrow(/--model-dir/);
    expect(() => classifierOptions({ "model-dir": "/m" })).toThrow(/--classifier/);
  });
});
