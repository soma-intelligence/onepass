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
