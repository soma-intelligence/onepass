"""Retrain model A on lab + bench data and compare it with the shipped heuristic (spec 2026-11-02, 6).

Usage: uv run python -m onepass_ml.bench_compare <lab data dir> <bench rows.jsonl> <out dir>
       [--weight 20] [--n-estimators 300] [--threads 4]

Trains two LightGBM models with the same settings: `lab_only` (lab train split) and `lab_bench`
(lab train plus the bench's bench_train rows, each weighted `--weight`). Each is scored on the
held-out bench origins against the heuristic's in-page labels (gate G1 to G4) and on the lab's
synthetic test split. Writes <out>/compare.json.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
import onnxruntime as ort

from .bench import gate, load_rows, split_rows, to_matrix
from .eval import metrics, predict
from .features import load_matrix
from .labels import LABELS
from .train_gbm import train_gbm


def latency_ms_per_form(model: Path, rows: list[dict], reps: int = 30) -> float:
    """Median time of one ONNX call on the fields of one bench page (native, one thread)."""
    opts = ort.SessionOptions()
    opts.intra_op_num_threads = 1
    sess = ort.InferenceSession(str(model), opts)
    forms: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        forms[r.get("bench_id", r["origin"])].append(r)
    times = []
    for form in forms.values():
        X, _ = to_matrix(form)
        dense = X.toarray().astype(np.float32)
        for _ in range(reps):
            t0 = time.perf_counter()
            sess.run(["label"], {"features": dense})
            times.append((time.perf_counter() - t0) * 1000)
    return float(statistics.median(times)) if times else 0.0


def compare(data: Path, bench_rows: Path, out: Path, *, weight: float = 20.0, n_estimators: int = 300,
            threads: int = 4, seed: int = 1) -> dict[str, Any]:
    data, out = Path(data), Path(out)
    out.mkdir(parents=True, exist_ok=True)
    rows = load_rows(bench_rows)
    train_rows, hold = split_rows(rows)
    Xb, yb = to_matrix(train_rows)
    Xh, _ = to_matrix(hold)
    Xt, yt = load_matrix(data / "test.parquet")
    report: dict[str, Any] = {
        "bench_rows": len(rows),
        "bench_train_rows": len(train_rows),
        "bench_train_origins": sorted({r["origin"] for r in train_rows}),
        "holdout": {"rows": len(hold), "origins": sorted({r["origin"] for r in hold})},
        "weight": weight,
        "models": {},
    }
    for name, extra in (("lab_only", None), ("lab_bench", (Xb, yb, weight))):
        path = train_gbm(data, out / name, seed, num_threads=threads, n_estimators=n_estimators, extra=extra)
        sess = ort.InferenceSession(str(path))
        pred = [LABELS[i] for i in predict(sess, Xh)] if len(hold) else []
        g = gate(hold, pred, size_bytes=path.stat().st_size, latency_ms=latency_ms_per_form(path, hold))
        test = metrics(yt, predict(sess, Xt)) if len(yt) else {"rows": 0}
        report["models"][name] = {
            "gate": g,
            "synthetic_test": {k: test[k] for k in ("rows", "accuracy", "macro_f1") if k in test},
            "holdout_predictions": [
                {"bench_id": r.get("bench_id"), "index": r.get("index"), "target": r["target"],
                 "heuristic": r["heuristic"], "model": p}
                for r, p in zip(hold, pred)
            ],
        }
    (out / "compare.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("data", type=Path)
    ap.add_argument("bench_rows", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--weight", type=float, default=20.0)
    ap.add_argument("--n-estimators", type=int, default=300)
    ap.add_argument("--threads", type=int, default=4)
    a = ap.parse_args(argv)
    r = compare(a.data, a.bench_rows, a.out, weight=a.weight, n_estimators=a.n_estimators, threads=a.threads)
    print(f"bench rows {r['bench_rows']}, train {r['bench_train_rows']}, holdout {r['holdout']['rows']}")
    for name, m in r["models"].items():
        g = m["gate"]
        print(f"{name}: G1 F1 heuristic {g['G1']['heuristic']} model {g['G1']['model']} | "
              f"G2 {g['G2']['heuristic']} vs {g['G2']['model']} | G3 {g['G3']['violations']} | "
              f"G4 {g['G4']['size_bytes']} B {g['G4']['latency_ms']:.3f} ms | synthetic macro F1 "
              f"{m['synthetic_test'].get('macro_f1')} | ship {g['ship']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
