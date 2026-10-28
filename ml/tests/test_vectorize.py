"""Shared vectorizer: asserts the cases written by the TypeScript side
(extension/test/vectors/vectorize.json) so training and the extension see the same input."""

import json
from pathlib import Path

import pytest

from onepass_ml.vectorize import (
    FEATURE_KEYS,
    HASH_DIM,
    INDICATORS,
    NUM_INDICATORS,
    VECTOR_DIM,
    cyrb128,
    normalize_text,
    serialize,
    tokenize,
    vectorize,
    vectorize_sparse,
)

FILE = Path(__file__).parents[2] / "extension" / "test" / "vectors" / "vectorize.json"
DATA = json.loads(FILE.read_text(encoding="utf8"))


def test_layout():
    assert VECTOR_DIM == 4096
    assert HASH_DIM + NUM_INDICATORS == VECTOR_DIM
    assert INDICATORS[-1][1] + INDICATORS[-1][2] == VECTOR_DIM
    assert len(vectorize({"tag": "input"})) == VECTOR_DIM


def test_at_least_20_cases():
    assert len(DATA["cases"]) >= 20


@pytest.mark.parametrize("case", DATA["cases"], ids=lambda c: c["name"])
def test_matches_typescript(case):
    got = vectorize_sparse(case["features"])
    assert [[i, v] for i, v in sorted(got.items())] == case["nonzero"]
    assert serialize(case["features"]) == case["serialize"]


def test_hash_words_match_typescript():
    for h in DATA["hashes"]:
        assert list(cyrb128(h["input"])) == h["words"], h["input"]


def test_row_extras_never_change_the_vector():
    feats = DATA["cases"][0]["features"]
    base = vectorize_sparse(feats)
    row = {**feats, "target": "email", "split": "train", "origin": "synthetic:1", "seed": "s", "lab": "password", "width": 3, "height": 4, "pageTitle": "zzz"}
    assert vectorize_sparse(row) == base
    assert serialize(row) == serialize(feats)
    # Only the listed keys are read.
    assert vectorize_sparse(row, keys=[]) != base
    assert "target" not in FEATURE_KEYS and "lab" not in FEATURE_KEYS
    assert not {"width", "height", "pageTitle"} & set(FEATURE_KEYS)


def test_none_equals_missing():
    a = vectorize_sparse({"tag": "input", "label": None, "maxlength": None, "formButtons": None})
    b = vectorize_sparse({"tag": "input"})
    assert a == b


def test_tokenize():
    assert tokenize("E-mail address 2") == ["e", "mail", "address", "2"]
    assert tokenize("メールアドレス") == ["メー", "ール", "ルア", "アド", "ドレ", "レス"]
    assert tokenize("姓") == ["姓"]
    assert tokenize("email地址x") == ["email", "地址", "x"]
    assert tokenize("") == []


def test_normalize_matches_js_rules():
    assert normalize_text("İSMİNİZ") == "i̇smi̇ni̇z"
    assert normalize_text("ΟΔΥΣΣΕΥΣ") == "οδυσσευς"
    assert normalize_text("STRAẞE") == "straße"
    assert normalize_text("a  b﻿ c\x1cd ") == "a b c\x1cd"
