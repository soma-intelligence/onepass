import json

import pyarrow.parquet as pq

from onepass_ml.bench import BENCH_SEED, bench_split
from onepass_ml.bench_compare import compare


def _bench_rows(mini_data, n_origins=12):
    """Bench-like rows cut from the mini test split, spread over origins on both sides of the split."""
    base = pq.read_table(mini_data / "train.parquet").to_pylist()[:60]
    out = []
    for i, r in enumerate(base):
        r = dict(r)
        r["origin"] = f"site{i % n_origins}.example"
        r["heuristic"] = r["target"] if i % 3 else "none"
        r["accept"] = []
        r["bench_id"] = f"site{i % n_origins}-login"
        r["seed"] = BENCH_SEED
        out.append(r)
    assert {bench_split(r["origin"]) for r in out} == {"bench_train", "bench_holdout"}
    return out


def test_compare_trains_both_models_and_writes_the_gate(mini_data, tmp_path):
    rows_path = tmp_path / "rows.jsonl"
    rows_path.write_text("".join(json.dumps(r) + "\n" for r in _bench_rows(mini_data)))
    report = compare(mini_data, rows_path, tmp_path / "out", weight=5.0, n_estimators=20, threads=2)
    assert set(report["models"]) == {"lab_only", "lab_bench"}
    for m in report["models"].values():
        assert "G1" in m["gate"] and "ship" in m["gate"]
        assert m["synthetic_test"]["rows"] > 0
        assert m["gate"]["G4"]["size_bytes"] > 0
    assert report["holdout"]["rows"] > 0 and report["bench_train_rows"] > 0
    saved = json.loads((tmp_path / "out" / "compare.json").read_text())
    assert saved["models"]["lab_bench"]["gate"] == report["models"]["lab_bench"]["gate"]
    assert (tmp_path / "out" / "lab_bench" / "gbm.onnx").exists()
