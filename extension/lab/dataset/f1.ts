import { createHash } from "node:crypto";
// Macro F1 as ml/onepass_ml/eval.py computes it: the F1 of every label that has a support or a
// prediction, averaged. Labels nobody has or predicts do not count.
export function macroF1(truth: readonly string[], predicted: readonly string[]): number {
  const tp = new Map<string, number>();
  const support = new Map<string, number>();
  const guessed = new Map<string, number>();
  truth.forEach((t, i) => {
    const p = predicted[i]!;
    support.set(t, (support.get(t) ?? 0) + 1);
    guessed.set(p, (guessed.get(p) ?? 0) + 1);
    if (t === p) tp.set(t, (tp.get(t) ?? 0) + 1);
  });
  const labels = new Set([...support.keys(), ...guessed.keys()]);
  let sum = 0;
  for (const l of labels) sum += (2 * (tp.get(l) ?? 0)) / ((support.get(l) ?? 0) + (guessed.get(l) ?? 0));
  return labels.size === 0 ? 0 : sum / labels.size;
}

/** Ruling R23: for the choice, password, new_password and confirm_password are one class (production resolves them from the form, the heuristic here has no form). */
export const mergeLabel = (l: string): string => (l === "new_password" || l === "confirm_password" ? "password" : l);

export const mergedMacroF1 = (truth: readonly string[], predicted: readonly string[]): number => macroF1(truth.map(mergeLabel), predicted.map(mergeLabel));

/** The same merged macro F1 from a model's confusion matrix (rows truth, columns predicted, in `labels` order). */
export function mergedMacroF1FromConfusion(cm: readonly (readonly number[])[], labels: readonly string[]): number {
  const names = [...new Set(labels.map(mergeLabel))];
  const at = new Map(names.map((n, i) => [n, i]));
  const m = names.map(() => names.map(() => 0));
  cm.forEach((row, i) => row.forEach((n, j) => { m[at.get(mergeLabel(labels[i]!))!]![at.get(mergeLabel(labels[j]!))!]! += n; }));
  let sum = 0;
  let present = 0;
  names.forEach((_, k) => {
    const support = m[k]!.reduce((a, b) => a + b, 0);
    const guessed = m.reduce((a, r) => a + r[k]!, 0);
    if (support + guessed === 0) return;
    present++;
    sum += (2 * m[k]![k]!) / (support + guessed);
  });
  return present === 0 ? 0 : sum / present;
}

/** SHA-256 of the sorted row identifiers `origin, site, step, index` (tab separated, one per line); ml/onepass_ml/eval.py rows_digest is the same recipe. */
export function rowsDigest(rows: readonly { origin: string; site: number; step: number; index: number }[]): string {
  const ids = rows.map((r) => `${r.origin}\t${r.site}\t${r.step}\t${r.index}`).sort();
  return createHash("sha256").update(ids.join("\n"), "utf8").digest("hex");
}
