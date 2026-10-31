"""Model B: tiny config (2 layers, 50 steps, CPU) for the default run; real size marked slow."""

import json

import numpy as np
import onnxruntime as ort
import pyarrow.parquet as pq
import pytest
import torch

from onepass_ml import tokenizer as ref
from onepass_ml.eval import evaluate
from onepass_ml.labels import LABELS
from onepass_ml.train_encoder import BASE, BASE_REVISION, MAX_BYTES, batch_inputs, load_torch, train_encoder
from onepass_ml.vectorize import VECTORIZER_VERSION, serialize


@pytest.fixture(scope="module")
def trained(mini_data, tmp_path_factory):
    out = tmp_path_factory.mktemp("enc")
    path = train_encoder(mini_data, out, epochs=1, seed=1, layers=2, max_steps=50, device="cpu", threads=1)
    return path, out


def _rows(data, split="test"):
    return pq.read_table(data / f"{split}.parquet").to_pylist()


def _inputs(out, rows):
    tok = ref.load(out / "tokenizer.json")
    return batch_inputs([ref.encode(tok, serialize(r)) for r in rows], tok.pad_id)


def test_exports_files(trained):
    path, out = trained
    assert path == out / "encoder.onnx"
    for name in ("encoder.onnx", "encoder.fp32.onnx", "tokenizer.json"):
        assert (out / name).exists(), name
    assert path.stat().st_size < (out / "encoder.fp32.onnx").stat().st_size


@pytest.mark.parametrize("name", ["encoder.onnx", "encoder.fp32.onnx"])
def test_onnx_contract_and_metadata(trained, name):
    _, out = trained
    sess = ort.InferenceSession(str(out / name))
    ins = {i.name: i for i in sess.get_inputs()}
    assert set(ins) == {"input_ids", "attention_mask"}
    assert all(i.type == "tensor(int64)" and len(i.shape) == 2 for i in ins.values())
    outs = sess.get_outputs()
    assert [o.name for o in outs] == ["probabilities"]
    assert outs[0].type == "tensor(float)" and outs[0].shape[1] == len(LABELS)
    meta = sess.get_modelmeta().custom_metadata_map
    assert meta["feature_version"] == "1"
    assert meta["vector_dim"] == "128"  # max sequence length for this model
    assert json.loads(meta["labels"]) == list(LABELS)
    assert meta["dataset_seed"] == "mini"
    assert meta["model"] == "encoder"
    assert meta["vectorizer_version"] == str(VECTORIZER_VERSION)
    assert meta["base_model"] == BASE
    assert meta["base_revision"] == BASE_REVISION


def test_fp32_onnx_matches_pytorch(trained, mini_data):
    _, out = trained
    ids, mask = _inputs(out, _rows(mini_data))
    model = load_torch(out).eval()
    with torch.no_grad():
        want = model(torch.from_numpy(ids), torch.from_numpy(mask)).numpy()
    got = ort.InferenceSession(str(out / "encoder.fp32.onnx")).run(None, {"input_ids": ids, "attention_mask": mask})[0]
    assert got.shape == (len(ids), len(LABELS))
    assert np.abs(got - want).max() < 1e-3
    assert np.allclose(got.sum(axis=1), 1.0, atol=1e-4)


def test_int8_argmax_agrees_with_fp32(trained, mini_data):
    _, out = trained
    rows = _rows(mini_data, "train") + _rows(mini_data, "test")
    ids, mask = _inputs(out, rows)
    feed = {"input_ids": ids, "attention_mask": mask}
    fp = ort.InferenceSession(str(out / "encoder.fp32.onnx")).run(None, feed)[0]
    q = ort.InferenceSession(str(out / "encoder.onnx")).run(None, feed)[0]
    assert (fp.argmax(1) == q.argmax(1)).mean() >= 0.95


def test_padding_does_not_change_the_output(trained, mini_data):
    _, out = trained
    rows = _rows(mini_data)[:4]
    sess = ort.InferenceSession(str(out / "encoder.fp32.onnx"))
    ids, mask = _inputs(out, rows)
    together = sess.run(None, {"input_ids": ids, "attention_mask": mask})[0]
    for k, r in enumerate(rows):
        i1, m1 = _inputs(out, [r])
        alone = sess.run(None, {"input_ids": i1, "attention_mask": m1})[0]
        assert np.abs(alone[0] - together[k]).max() < 1e-4


def test_evaluate_reads_encoder(trained, mini_data):
    path, out = trained
    report = evaluate(path, mini_data)
    t = report["test"]
    assert 0.0 <= t["macro_f1"] <= 1.0
    assert np.array(t["confusion_matrix"]).sum() == t["rows"]
    assert report["real_test"] == "n/a (0 rows)"
    assert (out / "encoder-eval.json").exists()


def test_over_size_raises_and_removes(mini_data, tmp_path, monkeypatch):
    import onepass_ml.train_encoder as t

    monkeypatch.setattr(t, "MAX_BYTES", 1000)
    with pytest.raises(ValueError, match="over"):
        train_encoder(mini_data, tmp_path, epochs=1, layers=1, max_steps=2, device="cpu", threads=1)
    assert not (tmp_path / "encoder.onnx").exists()


@pytest.mark.slow
def test_real_size_under_30_mb(mini_data, tmp_path):
    path = train_encoder(mini_data, tmp_path, epochs=1, max_steps=5, device="cpu", threads=1)
    assert path.stat().st_size < MAX_BYTES == 30 * 1024 * 1024
    assert ort.InferenceSession(str(path)).get_modelmeta().custom_metadata_map["vector_dim"] == "128"
