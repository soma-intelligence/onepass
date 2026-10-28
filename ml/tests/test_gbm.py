import json
import shutil
from pathlib import Path

import numpy as np
import onnxruntime as ort
import pyarrow.parquet as pq
import pytest

from onepass_ml.eval import evaluate
from onepass_ml.features import load_matrix
from onepass_ml.ingest import ingest
from onepass_ml.labels import LABELS
from onepass_ml.train_gbm import train_gbm
from onepass_ml.vectorize import VECTORIZER_VERSION, VECTOR_DIM

FIXTURE = Path(__file__).parent / "data" / "mini.jsonl.gz"
MANIFEST = {"seed": "mini", "generator": 2, "featureVersion": 1, "rows": 300, "parts": 1}


@pytest.fixture(scope="module")
def data(tmp_path_factory):
    root = tmp_path_factory.mktemp("gbm")
    src = root / "src"
    src.mkdir()
    shutil.copy(FIXTURE, src / "part-0000.jsonl.gz")
    (src / "manifest.json").write_text(json.dumps(MANIFEST))
    ingest(src, root / "data")
    return root / "data"


@pytest.fixture(scope="module")
def trained(data, tmp_path_factory):
    out = tmp_path_factory.mktemp("out")
    path = train_gbm(data, out, seed=1, num_threads=2, n_estimators=40)
    return path, out


def test_trains_and_exports(trained):
    path, out = trained
    assert path == out / "gbm.onnx"
    assert path.exists()
    assert path.stat().st_size < 2 * 1024 * 1024


def test_onnx_reloads_with_contract(trained):
    path, _ = trained
    sess = ort.InferenceSession(str(path))
    inp = sess.get_inputs()[0]
    assert inp.name == "features" and inp.shape[1] == VECTOR_DIM
    outs = {o.name: o for o in sess.get_outputs()}
    assert set(outs) == {"label", "probabilities"}
    assert outs["label"].type == "tensor(int64)"
    assert outs["probabilities"].type == "tensor(float)"
    meta = sess.get_modelmeta().custom_metadata_map
    assert meta["feature_version"] == "1"
    assert meta["vector_dim"] == str(VECTOR_DIM)
    assert json.loads(meta["labels"]) == list(LABELS)
    assert meta["vectorizer_version"] == str(VECTORIZER_VERSION)
    assert meta["dataset_seed"] == "mini"
    assert meta["model"] == "gbm"


def test_onnx_matches_lightgbm_on_50_rows(trained, data):
    import lightgbm as lgb

    path, out = trained
    booster = lgb.Booster(model_file=str(out / "gbm.lgb.txt"))
    X, _ = load_matrix(data / "train.parquet")
    X = X[:50]
    assert X.shape[0] == 50
    dense = X.toarray().astype(np.float32)
    sess = ort.InferenceSession(str(path))
    label, proba = sess.run(None, {"features": dense})
    ref = booster.predict(dense)
    assert proba.shape == ref.shape
    assert np.abs(proba - ref).max() < 1e-5
    assert (label == ref.argmax(axis=1)).all()


def test_evaluate_reports_and_real_test_empty(trained, data):
    path, out = trained
    report = evaluate(path, data)
    t = report["test"]
    assert 0.0 <= t["accuracy"] <= 1.0
    assert 0.0 <= t["macro_f1"] <= 1.0
    assert t["macro_f1_classes"] == sorted(t["per_role_f1"], key=LABELS.index)
    assert set(t["per_role_f1"]) <= set(LABELS)
    cm = np.array(t["confusion_matrix"])
    assert cm.shape == (len(LABELS), len(LABELS))
    assert cm.sum() == t["rows"]
    assert report["real_test"] == "n/a (0 rows)"
    written = json.loads((out / "gbm-eval.json").read_text())
    assert written["real_test"] == "n/a (0 rows)"
    assert written["test"]["macro_f1"] == t["macro_f1"]


def test_target_is_not_a_feature(data):
    X, y = load_matrix(data / "train.parquet")
    rows = pq.read_table(data / "train.parquet").to_pylist()
    assert X.shape == (len(rows), VECTOR_DIM)
    assert [LABELS[i] for i in y] == [r["target"] for r in rows]


def test_train_raises_and_removes_file_over_size(data, tmp_path, monkeypatch):
    import onepass_ml.train_gbm as t

    monkeypatch.setattr(t, "MAX_BYTES", 1000)
    with pytest.raises(ValueError, match="over"):
        train_gbm(data, tmp_path, n_estimators=5, num_threads=2)
    assert not (tmp_path / "gbm.onnx").exists()
