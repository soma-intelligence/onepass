// @vitest-environment node
// Classifier comparison (Task 16): loads three lab result folders, tabulates the rates per flow, trait and
// language, and applies the spec's decision rule (sections 1 and 7.3) in code.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { type ClassifierInfo, compareDirs, decide, loadRun, renderComparison, type RunSide } from "../../lab/compare.ts";
import { summarize } from "../../lab/report.ts";
import type { Result, Verdict } from "../../lab/run/oracle.ts";

function res(n: number, verdict: Verdict, over: Partial<Result> = {}): Result {
  return {
    worldSeed: "w", site: n, siteSeed: `s${n}`, flow: "login_single", traits: [], lang: "en", labelLang: "en",
    driver: "one_click", expect: "pass", verdict, retried: false, durationMs: 10,
    repro: `npm run lab:repro -- --seed w --site ${n}`, ...over,
  };
}

const tmp: string[] = [];
afterEach(() => { while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true }); });

/** A results folder as `lab` leaves it, plus the classifier.json of Task 16. */
function folder(seed: string, results: Result[], info: ClassifierInfo, sites = 10): string {
  const root = mkdtempSync(join(tmpdir(), "cmp-"));
  tmp.push(root);
  const dir = join(root, `${seed}-${info.classifier}`);
  mkdirSync(dir);
  writeFileSync(join(dir, "results.jsonl"), results.map((r) => JSON.stringify(r)).join("\n") + "\n");
  writeFileSync(join(dir, "world.json"), JSON.stringify({ seed, sites: Array.from({ length: sites }, () => ({})) }));
  writeFileSync(join(dir, "classifier.json"), JSON.stringify(info));
  return dir;
}

const passes = (n: number, fails = 0, extra: Partial<Result> = {}): Result[] =>
  Array.from({ length: n + fails }, (_, i) => res(i, i < n ? "pass" : "fail", { cause: i < n ? undefined : "timeout", ...extra }));

const model = (classifier: "gbm" | "encoder", over: Partial<ClassifierInfo> = {}): ClassifierInfo => ({
  classifier, modelBytes: 1_000_000, testMacroF1: 0.99, realTestMacroF1: 0.8, realTestRows: 200, classifyMs: { forms: 50, median: 0.2, p90: 0.9, max: 1.1 }, ...over,
});
const heuristic: ClassifierInfo = { classifier: "heuristic", testMacroF1: 0.7, realTestMacroF1: 0.6, realTestRows: 200 };

function side(kind: "heuristic" | "gbm" | "encoder", pass: number, fail: number, info: ClassifierInfo, leaks = 0): RunSide {
  const rs = passes(pass, fail);
  for (let i = 0; i < leaks; i++) rs.push(res(100 + i, "leak", { cause: "leak" }));
  return { dir: `d-${kind}`, seed: "w", sites: 10, summary: summarize(rs), info };
}

describe("classifier decision rule", () => {
  it("picks_the_eligible_model_with_the_best_lab_rate", () => {
    const d = decide([side("heuristic", 6, 4, heuristic), side("gbm", 9, 1, model("gbm")), side("encoder", 8, 2, model("encoder", { classifyMs: { forms: 50, median: 2, p90: 3, max: 4 } }))]);
    expect(d.chosen).toBe("gbm");
    expect(d.provisional).toBe(false);
    expect(d.models.map((m) => [m.kind, m.eligible])).toEqual([["gbm", true], ["encoder", true]]);
  });

  it("tie_on_lab_rate_goes_to_the_smaller_model_file", () => {
    const d = decide([side("heuristic", 6, 4, heuristic), side("gbm", 9, 1, model("gbm", { modelBytes: 20_000_000 })), side("encoder", 9, 1, model("encoder", { modelBytes: 1_000_000 }))]);
    expect(d.chosen).toBe("encoder");
  });

  it("a_lab_rate_not_above_the_heuristic_is_not_eligible", () => {
    const d = decide([side("heuristic", 8, 2, heuristic), side("gbm", 8, 2, model("gbm"))]);
    expect(d.chosen).toBe("heuristic");
    expect(d.models[0]!.reasons.join(" ")).toMatch(/taux au labo/);
  });

  it("a_real_test_f1_not_above_the_heuristic_is_not_eligible", () => {
    const d = decide([side("heuristic", 6, 4, heuristic), side("gbm", 9, 1, model("gbm", { realTestMacroF1: 0.6 }))]);
    expect(d.chosen).toBe("heuristic");
    expect(d.provisional).toBe(false);
    expect(d.models[0]!.reasons.join(" ")).toMatch(/real_test/);
  });

  it("any_leak_makes_a_model_not_eligible", () => {
    const d = decide([side("heuristic", 6, 4, heuristic), side("gbm", 9, 1, model("gbm"), 1)]);
    expect(d.chosen).toBe("heuristic");
    expect(d.models[0]!.reasons.join(" ")).toMatch(/fuite/);
  });

  it("a_median_classify_time_of_5_ms_or_more_is_not_eligible", () => {
    const d = decide([side("heuristic", 6, 4, heuristic), side("encoder", 9, 1, model("encoder", { classifyMs: { forms: 50, median: 5, p90: 9, max: 9 } }))]);
    expect(d.chosen).toBe("heuristic");
    expect(d.models[0]!.reasons.join(" ")).toMatch(/5 ms/);
  });

  it("a_missing_classify_time_is_not_eligible", () => {
    const d = decide([side("heuristic", 6, 4, heuristic), side("gbm", 9, 1, model("gbm", { classifyMs: undefined }))]);
    expect(d.chosen).toBe("heuristic");
    expect(d.models[0]!.reasons.join(" ")).toMatch(/non mesur/);
  });

  it("unlabeled_real_test_keeps_the_heuristic_and_the_verdict_is_provisional", () => {
    const d = decide([
      side("heuristic", 6, 4, { classifier: "heuristic", realTestMacroF1: null, realTestRows: 0 }),
      side("gbm", 10, 0, model("gbm", { realTestMacroF1: null, realTestRows: 0 })),
    ]);
    expect(d.chosen).toBe("heuristic");
    expect(d.provisional).toBe(true);
    expect(d.models[0]!.eligible).toBe(false);
    expect(d.models[0]!.reasons.join(" ")).toMatch(/real_test non étiqueté/);
  });

  it("runs_of_different_seeds_are_refused", () => {
    const a = side("heuristic", 6, 4, heuristic);
    const b = { ...side("gbm", 9, 1, model("gbm")), seed: "other" };
    expect(() => decide([a, b])).toThrow(/même graine/);
  });

  it("needs_the_heuristic_run", () => {
    expect(() => decide([side("gbm", 9, 1, model("gbm"))])).toThrow(/heuristic/);
  });
});

describe("classifier comparison report", () => {
  const dirs = () => [
    folder("w", passes(6, 4, { flow: "login_single", traits: ["honeypot"], lang: "fr" }), heuristic),
    folder("w", passes(9, 1, { flow: "login_single", traits: ["honeypot"], lang: "fr" }), model("gbm")),
    folder("w", [...passes(8, 2, { flow: "checkout_card", lang: "en" }), res(50, "leak", { cause: "x", flow: "checkout_card" })], model("encoder", { classifyMs: { forms: 50, median: 70.9, p90: 251, max: 309 }, modelBytes: 16_000_000, realTestMacroF1: null, realTestRows: 0 })),
  ];

  it("loadRun_reads_results_world_and_classifier", () => {
    const [h] = dirs();
    const r = loadRun(h!);
    expect(r.seed).toBe("w");
    expect(r.sites).toBe(10);
    expect(r.info.classifier).toBe("heuristic");
    expect(r.summary.overall.total).toBe(10);
  });

  it("tables_per_flow_trait_language_with_leaks_and_offline_metrics", () => {
    const { markdown, decision } = compareDirs(dirs());
    for (const t of ["### Par flux", "### Par trait", "### Par langue"]) expect(markdown).toContain(t);
    expect(markdown).toContain("| login_single |");
    expect(markdown).toContain("| honeypot |");
    expect(markdown).toContain("| checkout_card |");
    expect(markdown).toMatch(/Fuites/);
    expect(markdown).toMatch(/70[.,]9 ms/);
    expect(markdown).toContain("n/a (0 rows)");
    expect(markdown).toContain("0,99");
    expect(decision.chosen).toBe("gbm");
    expect(markdown).toMatch(/Verdict : gbm/);
  });

  it("is_french_free_of_the_em_dash_and_names_each_model_reasons", () => {
    const { markdown } = compareDirs(dirs());
    expect(markdown).not.toContain("—");
    expect(markdown).toMatch(/## Verdict/);
    expect(markdown).toMatch(/gbm/);
    expect(markdown).toMatch(/encoder/);
    expect(renderComparison(compareDirs(dirs()).runs, compareDirs(dirs()).decision)).toBe(markdown);
  });

  it("profile_table_only_when_a_run_has_other_profiles", () => {
    expect(compareDirs(dirs()).markdown).not.toContain("### Par profil");
    const withProfiles = [
      folder("w", passes(6, 4, { profile: "p1" }), heuristic),
      folder("w", passes(9, 1, { profile: "p1" }), model("gbm")),
    ];
    expect(compareDirs(withProfiles).markdown).toContain("### Par profil");
  });

  it("cli_compare_writes_the_markdown_and_prints_the_verdict", () => {
    const out = mkdtempSync(join(tmpdir(), "cmp-out-"));
    tmp.push(out);
    const [h, g, e] = dirs();
    const rows = join(out, "none.jsonl"); // no rows: heuristic real_test is n/a
    const r = spawnSync("node", ["--experimental-strip-types", "lab/cli.ts", "compare", "--out", h!, g!, e!, "--md", join(out, "cmp.md"), "--real-rows", rows], { cwd: join(import.meta.dirname, "..", ".."), encoding: "utf8" });
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/Verdict : /);
    const md = readFileSync(join(out, "cmp.md"), "utf8");
    expect(md).toContain("provisoire : real_test non étiqueté");
  });
});
