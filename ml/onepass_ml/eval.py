"""Evaluate an exported ONNX field classifier on the dataset's test and real_test splits.

Usage: uv run python -m onepass_ml.eval <model.onnx> <data dir>
Writes <model dir>/<model stem>-eval.json and prints the headline numbers.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import onnxruntime as ort

from .features import load_matrix
from .labels import LABELS

PREDICT_BATCH = 2_000


def predict(sess: ort.InferenceSession, X) -> np.ndarray:
    """Predicted class indices for a CSR matrix, densified one small batch at a time."""
    out = []
    for start in range(0, X.shape[0], PREDICT_BATCH):
        dense = X[start:start + PREDICT_BATCH].toarray().astype(np.float32)
        out.append(sess.run(["label"], {"features": dense})[0])
    return np.concatenate(out) if out else np.zeros(0, dtype=np.int64)


def metrics(y: np.ndarray, pred: np.ndarray) -> dict[str, Any]:
    n = len(LABELS)
    cm = np.zeros((n, n), dtype=np.int64)
    np.add.at(cm, (y, pred), 1)
    tp = np.diag(cm).astype(float)
    support, predicted = cm.sum(axis=1), cm.sum(axis=0)
    denom = support + predicted
    f1 = np.divide(2 * tp, denom, out=np.zeros(n), where=denom > 0)
    present = denom > 0
    return {
        "rows": int(len(y)),
        "accuracy": float(tp.sum() / len(y)),
        "macro_f1": float(f1[present].mean()),
        "per_role_f1": {LABELS[i]: float(f1[i]) for i in range(n) if present[i]},
        "support": {LABELS[i]: int(support[i]) for i in range(n) if present[i]},
        "labels": list(LABELS),
        "confusion_matrix": cm.tolist(),
    }


def evaluate(model: Path, data: Path) -> dict[str, Any]:
    model, data = Path(model), Path(data)
    sess = ort.InferenceSession(str(model))
    report: dict[str, Any] = {"model": model.name}
    for split in ("test", "real_test"):
        X, y = load_matrix(data / f"{split}.parquet")
        report[split] = metrics(y, predict(sess, X)) if len(y) else "n/a (0 rows)"
    (model.parent / f"{model.stem}-eval.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m onepass_ml.eval <model.onnx> <data dir>", file=sys.stderr)
        return 2
    report = evaluate(Path(argv[0]), Path(argv[1]))
    for split in ("test", "real_test"):
        r = report[split]
        print(f"{split}: {r}" if isinstance(r, str) else f"{split}: rows={r['rows']} accuracy={r['accuracy']:.4f} macro_f1={r['macro_f1']:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
