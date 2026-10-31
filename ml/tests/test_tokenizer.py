"""Pruned encoder tokenizer: the pure-Python reference (onepass_ml.tokenizer, the spec Task 15
ports to TypeScript) must give the same ids as the Hugging Face tokenizer on the same JSON."""

import json
import unicodedata
from pathlib import Path

import pyarrow.parquet as pq
import pytest
from tokenizers import Tokenizer

from onepass_ml import tokenizer as ref
from onepass_ml.train_encoder import BASE, BASE_REVISION, build_tokenizer, full_tokenizer, train_texts
from onepass_ml.vectorize import serialize

VECTORS = Path(__file__).parents[2] / "extension" / "test" / "vectors" / "vectorize.json"
BENCH = Path(__file__).parents[1] / "out" / "bench" / "train.parquet"
MAX_LEN = 128


@pytest.fixture(scope="module")
def built(mini_data, tmp_path_factory):
    out = tmp_path_factory.mktemp("tok") / "tokenizer.json"
    texts = train_texts(mini_data / "train.parquet")
    old_ids = build_tokenizer(texts, out, BASE, BASE_REVISION, MAX_LEN)
    return out, texts, old_ids


def _hf(path: Path) -> Tokenizer:
    return Tokenizer.from_file(str(path))


def _same(path: Path, texts: list[str]) -> None:
    hf, tok = _hf(path), ref.load(path)
    for t in texts:
        assert ref.encode(tok, t) == hf.encode(t).ids, t


def test_json_is_the_restricted_format(built):
    path, _, old_ids = built
    j = json.loads(path.read_text(encoding="utf-8"))
    assert j["normalizer"] == {"type": "NFKC"}
    assert j["model"]["type"] == "Unigram"
    assert j["truncation"]["max_length"] == MAX_LEN
    pieces = [p for p, _ in j["model"]["vocab"]]
    assert pieces[:4] == ["<s>", "<pad>", "</s>", "<unk>"]
    assert j["model"]["unk_id"] == 3
    assert len(old_ids) == len(pieces) and old_ids[:4] == [0, 1, 2, 3]
    assert "<mask>" not in pieces
    # Pruned: a few thousand pieces, not 250k.
    assert 500 < len(pieces) < 60_000


def test_single_characters_of_present_scripts_kept(built):
    path, texts, _ = built
    pieces = {p for p, _ in json.loads(path.read_text(encoding="utf-8"))["model"]["vocab"]}
    # Every Latin letter of the base vocab survives even if train never used it alone.
    for c in "abcdefghijklmnopqrstuvwxyz":
        assert c in pieces or "▁" + c in pieces
    assert any(unicodedata.name(p[-1], "").startswith("LATIN") for p in pieces)


def test_reference_equals_hf_on_shared_vectors(built):
    cases = json.loads(VECTORS.read_text(encoding="utf-8"))["cases"]
    _same(built[0], [c["serialize"] for c in cases])


def test_reference_equals_hf_on_fixture_rows(mini_data, built):
    texts = []
    for split in ("train", "val", "test"):
        texts += [serialize(r) for r in pq.read_table(mini_data / f"{split}.parquet").to_pylist()]
    assert len(texts) >= 250
    _same(built[0], texts)


@pytest.mark.skipif(not BENCH.exists(), reason="ml/out/bench not ingested on this machine")
def test_reference_equals_hf_on_500_dataset_rows(built):
    rows = pq.read_table(BENCH).slice(0, 500).to_pylist()
    assert len(rows) == 500
    _same(built[0], [serialize(r) for r in rows])


def test_reference_equals_hf_on_edge_cases(built):
    _same(built[0], [
        "", " ", "a", "type=email |  name=x　y\t z", "<s>inside</s> and <unk><pad>",
        "＜ｓ＞ fullwidth", "▁meta▁space", "\U0001f600 emoji அஆ tamil",
        "مرحبا пароль パスワード 비밀번호 密码",
        "zzqxw " * 200,  # truncation
    ])


def test_pruning_keeps_train_segmentation(built):
    """On train strings the pruned vocab yields the same pieces as the full base vocab."""
    path, texts, _ = built
    full, pruned = full_tokenizer(BASE, BASE_REVISION, MAX_LEN), _hf(path)
    for t in texts:
        assert pruned.encode(t).tokens == full.encode(t).tokens, t
