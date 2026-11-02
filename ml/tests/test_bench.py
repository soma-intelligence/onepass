import json

import pytest

from onepass_ml.bench import (
    BENCH_SEED,
    bench_split,
    credit,
    gate,
    load_rows,
    merged_macro_f1,
    split_rows,
    to_matrix,
)
from onepass_ml.labels import LABELS
from onepass_ml.vectorize import VECTOR_DIM


def row(origin, target, heuristic, accept=(), **f):
    base = {"index": 0, "tag": "input", "hasPattern": False, "required": False, "depth": 5, "siblings": 1,
            "visibility": "visible", "width": 200, "height": 30, "formButtons": ["sign in"],
            "neighbourLabels": [], "origin": origin, "target": target, "heuristic": heuristic,
            "accept": list(accept), "bench_id": origin.split(".")[0] + "-login", "seed": BENCH_SEED}
    base.update(f)
    return base


def test_split_is_by_origin_stable_and_two_sided():
    origins = [f"site{i}.example" for i in range(200)]
    splits = {o: bench_split(o) for o in origins}
    assert splits == {o: bench_split(o) for o in origins}
    assert set(splits.values()) == {"bench_train", "bench_holdout"}
    share = sum(v == "bench_holdout" for v in splits.values()) / len(origins)
    assert 0.35 < share < 0.65
    rows = [row(o, "password", "password") for o in origins for _ in range(2)]
    train, hold = split_rows(rows)
    assert {r["origin"] for r in train}.isdisjoint({r["origin"] for r in hold})
    assert len(train) + len(hold) == len(rows)


def test_load_rows_skips_blank_lines(tmp_path):
    p = tmp_path / "rows.jsonl"
    p.write_text(json.dumps(row("a.example", "email", "email")) + "\n\n")
    assert len(load_rows(p)) == 1


def test_to_matrix_shapes_and_labels():
    X, y = to_matrix([row("a.example", "email", "email", type="email"), row("a.example", "none", "none")])
    assert X.shape == (2, VECTOR_DIM)
    assert [LABELS[i] for i in y] == ["email", "none"]


def test_credit_accepts_alternatives_and_merges_passwords():
    assert credit("username", ["email"], "email") == "username"
    assert credit("password", [], "new_password") == "password"
    assert credit("new_password", [], "password") == "new_password"
    assert credit("username", [], "email") == "email"


def test_merged_macro_f1():
    t = ["username", "password", "new_password", "none"]
    assert merged_macro_f1(t, t) == pytest.approx(1.0)
    assert merged_macro_f1(t, ["username", "new_password", "password", "none"]) == pytest.approx(1.0)
    # username wrong (email): classes username, email, password, none -> (0 + 0 + 1 + 1) / 4
    assert merged_macro_f1(t, ["email", "password", "password", "none"]) == pytest.approx(0.5)


def _rows():
    return [
        row("a.example", "username", "username", ["email"]),
        row("a.example", "password", "password"),
        row("b.example", "email", "none"),
        row("b.example", "password", "password"),
        row("c.example", "none", "none"),
        row("c.example", "new_password", "password"),
    ]


def test_gate_ships_only_a_clear_win():
    rows = _rows()
    better = ["email", "password", "email", "password", "none", "new_password"]
    g = gate(rows, better, size_bytes=500_000, latency_ms=1.0)
    assert g["G1"]["pass"] and g["G2"]["pass"] and g["G3"]["pass"] and g["G4"]["pass"]
    assert g["ship"] is True
    same = [r["heuristic"] for r in rows]
    g = gate(rows, same, size_bytes=500_000, latency_ms=1.0)
    assert not g["G1"]["pass"] and g["ship"] is False


def test_gate_g3_refuses_a_credential_on_a_none_field():
    rows = _rows()
    pred = ["username", "password", "email", "password", "password", "new_password"]
    g = gate(rows, pred, size_bytes=1, latency_ms=1.0)
    assert g["G3"]["pass"] is False
    assert g["G3"]["violations"] == 1
    assert g["ship"] is False


def test_gate_g4_size_and_latency():
    rows = _rows()
    better = ["email", "password", "email", "password", "none", "new_password"]
    assert gate(rows, better, size_bytes=3 * 1024 * 1024, latency_ms=1.0)["G4"]["pass"] is False
    assert gate(rows, better, size_bytes=1, latency_ms=9.0)["G4"]["pass"] is False


def test_gate_g2_credential_accuracy_may_not_drop():
    rows = _rows()
    # Fixes b's email (G1 up) but breaks a's password.
    pred = ["username", "none", "email", "none", "none", "new_password"]
    g = gate(rows, pred, size_bytes=1, latency_ms=1.0)
    assert g["G2"]["pass"] is False


def test_empty_holdout_never_ships():
    g = gate([], [], size_bytes=1, latency_ms=1.0)
    assert g["ship"] is False
    assert g["G1"]["model"] is None
