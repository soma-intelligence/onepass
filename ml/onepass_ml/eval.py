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
        "macro_f1_classes": [LABELS[i] for i in range(n) if present[i]],
        "per_role_f1": {LABELS[i]: float(f1[i]) for i in range(n) if present[i]},
        "support": {LABELS[i]: int(support[i]) for i in range(n) if present[i]},
        "labels": list(LABELS),
        "confusion_matrix": cm.tolist(),
    }


def _encoder_split(sess: ort.InferenceSession, model: Path, path: Path) -> tuple[np.ndarray, np.ndarray]:
    """(y, pred) for model B: serialize text, tokenizer.json next to the model."""
    from tokenizers import Tokenizer

    from .train_encoder import _split, predict_ids

    seqs, y = _split(Tokenizer.from_file(str(model.parent / "tokenizer.json")), path)
    run = lambda ids, mask: sess.run(["probabilities"], {"input_ids": ids, "attention_mask": mask})[0]
    return y, predict_ids(run, seqs)


def evaluate(model: Path, data: Path) -> dict[str, Any]:
    """Model A (vectorizer features) or model B (`model` metadata "encoder", token ids)."""
    model, data = Path(model), Path(data)
    sess = ort.InferenceSession(str(model))
    encoder = sess.get_modelmeta().custom_metadata_map.get("model") == "encoder"
    report: dict[str, Any] = {"model": model.name}
    for split in ("test", "real_test"):
        if encoder:
            y, pred = _encoder_split(sess, model, data / f"{split}.parquet")
        else:
            X, y = load_matrix(data / f"{split}.parquet")
            pred = predict(sess, X) if len(y) else None
        report[split] = metrics(y, pred) if len(y) else "n/a (0 rows)"
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
