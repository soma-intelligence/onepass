// Heuristic score on the real test rows (Task 16): the existing classifyField run on a DOM rebuilt from a
// row's features, and the macro F1 the ml eval uses (labels with a support or a prediction).
import { describe, expect, it } from "vitest";
import { macroF1 } from "../../lab/dataset/f1.ts";
import { heuristicLabel, heuristicRows } from "../../lab/dataset/heuristic-role.ts";
import type { FieldFeatures } from "../../src/content/detect/features.ts";

const f = (over: Partial<FieldFeatures>): FieldFeatures => ({
  index: 0, tag: "input", hasPattern: false, required: false, depth: 3, siblings: 0, visibility: "visible", width: 0, height: 0, formButtons: [], neighbourLabels: [], ...over,
});

describe("heuristic classifier on feature rows", () => {
  it("rebuilds_the_field_and_maps_roles_to_dataset_labels", () => {
    expect(heuristicLabel(f({ type: "password", name: "password", label: "Password" }))).toBe("password");
    expect(heuristicLabel(f({ type: "email", name: "email", label: "Email address" }))).toBe("email");
    expect(heuristicLabel(f({ type: "text", autocomplete: "cc-number" }))).toBe("cc_number");
    expect(heuristicLabel(f({ type: "text", autocomplete: "bday" }))).toBe("birth_date");
    expect(heuristicLabel(f({ type: "text", autocomplete: "new-password" }))).toBe("new_password");
  });

  it("reads_label_placeholder_and_the_text_before_the_field", () => {
    expect(heuristicLabel(f({ type: "text", placeholder: "Postal code" }))).toBe("postal_code");
    expect(heuristicLabel(f({ type: "text", before: "Your city" }))).toBe("city");
    expect(heuristicLabel(f({ type: "text", ariaLabel: "First name" }))).toBe("given_name");
  });

  it("a_field_with_no_signal_is_none", () => {
    expect(heuristicLabel(f({ type: "text", name: "zzqx" }))).toBe("none");
  });

  it("heuristicRows_scores_only_target_rows_and_reports_n_a_without_rows", () => {
    expect(heuristicRows([])).toEqual({ rows: 0, macroF1: null });
    const r = heuristicRows([
      { ...f({ type: "password", name: "password", label: "Password" }), target: "password" },
      { ...f({ type: "email", name: "email", label: "Email" }), target: "email" },
      { ...f({ type: "text", name: "zzqx" }), target: "none" },
    ]);
    expect(r.rows).toBe(3);
    expect(r.macroF1).toBe(1);
  });
});

describe("macroF1", () => {
  it("averages_f1_over_labels_with_a_support_or_a_prediction", () => {
    // a: tp 1 fp 0 fn 1 -> 2/3 ; b: tp 1 fp 1 fn 0 -> 2/3 ; c never seen
    expect(macroF1(["a", "a", "b"], ["a", "b", "b"])).toBeCloseTo(2 / 3);
    expect(macroF1(["a"], ["a"])).toBe(1);
    expect(macroF1(["a"], ["b"])).toBe(0);
  });
});
