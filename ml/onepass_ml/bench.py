"""Rows of the real-site bench (core/onepass-bench, `rows.jsonl`): per-origin split, feature
matrix, and the shipping gate of spec 2026-11-02 section 6.3.

A bench row is a lab DatasetRow (same feature keys) plus `heuristic`, the label the shipped
extension gave the field in the real page, `accept`, the other labels the hand-written truth
accepts, and `bench_id`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
import scipy.sparse as sp

from .labels import LABELS
from .vectorize import VECTOR_DIM, cyrb128, vectorize_sparse

BENCH_SEED = "bench-2026-11-02"
CREDENTIALS = frozenset({"username", "email", "password"})
G1_MARGIN = 0.02
MAX_BYTES = 2 * 1024 * 1024
MAX_LATENCY_MS = 5.0
_INDEX = {label: i for i, label in enumerate(LABELS)}


def load_rows(path: Path) -> list[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def bench_split(origin: str, seed: str = BENCH_SEED) -> str:
    """Half the origins train, half are held out; a login and a signup of one site stay together."""
    return "bench_holdout" if cyrb128(origin + seed)[0] % 2 else "bench_train"


def split_rows(rows: Iterable[dict[str, Any]], seed: str = BENCH_SEED) -> tuple[list[dict], list[dict]]:
    train, hold = [], []
    for r in rows:
        (hold if bench_split(r["origin"], seed) == "bench_holdout" else train).append(r)
    return train, hold


def to_matrix(rows: Sequence[dict[str, Any]]) -> tuple[sp.csr_matrix, np.ndarray]:
    data: list[float] = []
    cols: list[int] = []
    indptr = [0]
    for r in rows:
        for i, x in sorted(vectorize_sparse(r).items()):
            cols.append(i)
            data.append(x)
        indptr.append(len(cols))
    X = sp.csr_matrix(
        (np.array(data, dtype=np.float32), np.array(cols, dtype=np.int32), np.array(indptr, dtype=np.int64)),
        shape=(len(rows), VECTOR_DIM),
    )
    y = np.array([_INDEX[r["target"]] for r in rows], dtype=np.int64)
    return X, y


def family(label: str) -> str:
    return "password" if label == "new_password" else label


def credit(target: str, accept: Sequence[str], pred: str) -> str:
    """`pred` as scored: the target itself when it is in the target's family or an accepted one."""
    ok = {family(target)} | {family(a) for a in accept}
    return target if family(pred) in ok else pred


def merged_macro_f1(truth: Sequence[str], pred: Sequence[str]) -> float | None:
    """Macro F1 over label families (password and new_password merged, lab ruling R23)."""
    if not truth:
        return None
    t = [family(x) for x in truth]
    p = [family(x) for x in pred]
    scores = []
    for c in sorted(set(t) | set(p)):
        tp = sum(a == c and b == c for a, b in zip(t, p))
        fp = sum(a != c and b == c for a, b in zip(t, p))
        fn = sum(a == c and b != c for a, b in zip(t, p))
        scores.append(2 * tp / (2 * tp + fp + fn))
    return float(sum(scores) / len(scores))


def _credential_accuracy(rows: Sequence[dict], pred: Sequence[str]) -> float | None:
    pairs = [(r, p) for r, p in zip(rows, pred) if family(r["target"]) in CREDENTIALS]
    if not pairs:
        return None
    return sum(credit(r["target"], r.get("accept", []), p) == r["target"] for r, p in pairs) / len(pairs)


def gate(rows: Sequence[dict[str, Any]], model_pred: Sequence[str], *, size_bytes: int, latency_ms: float) -> dict[str, Any]:
    """G1 to G4 of spec 6.3 on held-out bench rows. G5 (lab run) is decided after, only if this ships."""
    truth = [r["target"] for r in rows]
    heur = [credit(r["target"], r.get("accept", []), r["heuristic"]) for r in rows]
    model = [credit(r["target"], r.get("accept", []), p) for r, p in zip(rows, model_pred)]
    f_h, f_m = merged_macro_f1(truth, heur), merged_macro_f1(truth, model)
    a_h, a_m = _credential_accuracy(rows, heur), _credential_accuracy(rows, model)
    violations = sum(
        r["target"] == "none" and family(m) in CREDENTIALS and family(r["heuristic"]) not in CREDENTIALS
        for r, m in zip(rows, model_pred)
    )
    g1 = f_h is not None and f_m is not None and f_m >= f_h + G1_MARGIN
    g2 = a_h is not None and a_m is not None and a_m >= a_h
    g4 = size_bytes < MAX_BYTES and latency_ms < MAX_LATENCY_MS
    out = {
        "rows": len(rows),
        "origins": len({r["origin"] for r in rows}),
        "G1": {"heuristic": f_h, "model": f_m, "margin": G1_MARGIN, "pass": bool(g1)},
        "G2": {"heuristic": a_h, "model": a_m, "pass": bool(g2)},
        "G3": {"violations": int(violations), "pass": violations == 0},
        "G4": {"size_bytes": int(size_bytes), "latency_ms": float(latency_ms), "pass": bool(g4)},
    }
    out["ship"] = bool(g1 and g2 and violations == 0 and g4)
    return out
