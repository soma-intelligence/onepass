"""Model A: LightGBM multiclass field classifier on the shared vectorizer, exported to ONNX.

Usage: uv run python -m onepass_ml.train_gbm <data dir> <out dir> [--seed N] [--threads N]
       [--num-leaves N] [--n-estimators N] [--learning-rate X]
`data` is the output of onepass_ml.ingest (train/val Parquet + manifest.json). Early stopping on
`val`. Writes <out>/gbm.onnx and <out>/gbm.lgb.txt (the native booster, for equality checks).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import lightgbm as lgb

from .export import export_onnx
from .features import load_matrix
from .labels import LABELS

MAX_BYTES = 2 * 1024 * 1024  # model A target (constraints.md)


def train_gbm(
    data: Path,
    out: Path,
    seed: int = 1,
    *,
    num_threads: int = 4,
    num_leaves: int = 7,
    n_estimators: int = 300,
    learning_rate: float = 0.2,
    early_stopping_rounds: int = 10,
) -> Path:
    data, out = Path(data), Path(out)
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((data / "manifest.json").read_text(encoding="utf-8"))
    X, y = load_matrix(data / "train.parquet")
    Xv, yv = load_matrix(data / "val.parquet")
    params = {
        "objective": "multiclass",
        "num_class": len(LABELS),
        "num_leaves": num_leaves,
        "learning_rate": learning_rate,
        "min_data_in_leaf": 5,
        "feature_fraction": 0.5,
        "lambda_l2": 1.0,
        "seed": seed,
        "num_threads": num_threads,
        "verbosity": -1,
        "deterministic": True,
        "force_row_wise": True,
    }
    train = lgb.Dataset(X, label=y)
    valid = lgb.Dataset(Xv, label=yv, reference=train)
    booster = lgb.train(
        params, train, num_boost_round=n_estimators, valid_sets=[valid],
        callbacks=[lgb.early_stopping(early_stopping_rounds, verbose=False)],
    )
    # Keep only the rounds up to the best one so ONNX and the native file hold the same trees.
    best = booster.best_iteration or booster.current_iteration()
    booster.save_model(str(out / "gbm.lgb.txt"), num_iteration=best)
    booster = lgb.Booster(model_file=str(out / "gbm.lgb.txt"))
    return export_onnx(
        booster, out / "gbm.onnx",
        feature_version=int(manifest["featureVersion"]), dataset_seed=str(manifest["seed"]),
    )


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("data", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--num-leaves", type=int, default=7)
    ap.add_argument("--n-estimators", type=int, default=300)
    ap.add_argument("--learning-rate", type=float, default=0.2)
    a = ap.parse_args(argv)
    t0 = time.time()
    path = train_gbm(
        a.data, a.out, a.seed, num_threads=a.threads, num_leaves=a.num_leaves,
        n_estimators=a.n_estimators, learning_rate=a.learning_rate,
    )
    size = path.stat().st_size
    print(f"{path} {size} bytes, {time.time() - t0:.1f} s")
    if size >= MAX_BYTES:
        print(f"model is {size} bytes, over the {MAX_BYTES} byte target: lower --num-leaves or --n-estimators", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
