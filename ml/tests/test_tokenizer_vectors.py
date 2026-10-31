"""Shared tokenizer vectors (extension/test/vectors/tokenizer.json), asserted by this side and by
extension/test/background/tokenizer.test.ts: the TypeScript port of onepass_ml.tokenizer must give
the same ids on the same tokenizer JSON.

The file embeds its own tokenizer: a subset of the bench encoder's tokenizer.json (the special
tokens plus every piece that can match inside the test texts, in the bench order), so it stays
small, committed and independent of ml/out. Regenerate it from this side (needs the bench encoder,
ml/out/bench-encoder/tokenizer.json) with:
    UPDATE_VECTORS=1 uv run pytest tests/test_tokenizer_vectors.py
"""

import json
import os
import unicodedata
from pathlib import Path

import pytest
from tokenizers import Tokenizer

from onepass_ml import tokenizer as ref
from onepass_ml.vectorize import serialize

ROOT = Path(__file__).parents[2]
FILE = ROOT / "extension" / "test" / "vectors" / "tokenizer.json"
VECTORIZE = ROOT / "extension" / "test" / "vectors" / "vectorize.json"
BENCH = Path(__file__).parents[1] / "out" / "bench-encoder" / "tokenizer.json"


def _f(**kw) -> dict:
    base = {"index": 0, "tag": "input", "hasPattern": False, "required": False, "depth": 3, "siblings": 0,
            "visibility": "visible", "width": 0, "height": 0, "formButtons": [], "neighbourLabels": []}
    return {**base, **kw}


# Scripts and code point cases the TypeScript port must get right (indices are code points).
EXTRA = {
    "emoji_label": _f(type="password", name="pw", label="mot de passe 🔐🔑", formButtons=["entrer ✅"]),
    "astral_cjk_ext_b": _f(type="text", name="user", label="𠮷野家 ユーザー名", placeholder="𠀋𡈽𡌛"),
    "math_fraktur_nfkc": _f(type="email", name="𝔢𝔪𝔞𝔦𝔩", label="𝐄𝐦𝐚𝐢𝐥 address"),
    "arabic": _f(type="password", name="password", label="كلمة المرور", formButtons=["تسجيل الدخول"]),
    "hebrew_rtl_mark": _f(type="text", name="user", label="‏שם משתמש", placeholder="דוא״ל"),
    "chinese": _f(type="text", name="phone", label="手机号码", placeholder="请输入手机号", formButtons=["获取验证码", "登录"]),
    "korean": _f(type="password", name="pw", label="비밀번호", before="아이디 로그인"),
    "japanese": _f(type="email", name="mail", label="メールアドレス", after="パスワードを忘れた"),
    "thai": _f(type="text", name="otp", label="รหัสยืนยัน", inputmode="numeric", maxlength=6),
    "devanagari_marks": _f(type="text", name="naam", label="पूरा नाम", placeholder="उपयोगकर्ता"),
    "cyrillic": _f(type="password", name="pass", label="Пароль", formButtons=["Войти"]),
    "greek_accents": _f(type="email", name="email", label="Ηλεκτρονικό ταχυδρομείο"),
    "unicode_spaces": _f(type="text", name="a b", label="nom　complet ici", placeholder="x y"),
    "special_token_literal": _f(type="text", name="<s>", label="a </s> b <unk><pad>", placeholder="<s><s>"),
    "zwj_family_emoji": _f(type="text", name="nick", label="👨‍👩‍👧 family", placeholder="🇫🇷 flag"),
    "combining_sequences": _f(type="text", name="nom", label="élève café", placeholder="Å Ω ﬁ"),
    "long_truncated": _f(type="text", name="x" * 40, label=" ".join(f"word{i}" for i in range(200))),
    "empty": _f(type="text"),
}


def _texts() -> list[tuple[str, str, dict | None]]:
    cases = json.loads(VECTORIZE.read_text(encoding="utf-8"))["cases"]
    out: list[tuple[str, str, dict | None]] = [(f"vectorize_{c['name']}", c["serialize"], None) for c in cases]
    out += [(name, serialize(f), f) for name, f in EXTRA.items()]
    # Raw strings, not serialize output: leading/trailing and only whitespace, specials only.
    out += [("raw_whitespace_only", " \t　 ", None), ("raw_specials_only", "<s></s>", None),
            ("raw_leading_space", "  hello world  ", None), ("raw_meta_char", "a▁b ▁c", None)]
    return out


def _subset(full: dict, texts: list[str]) -> dict:
    tok = ref.load(BENCH)
    keep: set[str] = set(tok.specials)
    for t in texts:
        for seg in ref._split_specials(tok, t):
            if isinstance(seg, int):
                continue
            for piece in ref._pre_tokenize(unicodedata.normalize("NFKC", seg)):
                for i in range(len(piece)):
                    for j in range(i + 1, min(len(piece), i + tok.max_piece) + 1):
                        if piece[i:j] in tok.index:
                            keep.add(piece[i:j])
    vocab = [v for v in full["model"]["vocab"] if v[0] in keep]
    ids = {v[0]: i for i, v in enumerate(vocab)}
    out = json.loads(json.dumps(full))
    out["model"]["vocab"] = vocab
    out["model"]["unk_id"] = ids["<unk>"]
    for t in out["added_tokens"]:
        t["id"] = ids[t["content"]]
    for k, v in out["post_processor"].get("special_tokens", {}).items():
        v["ids"] = [ids[k]]
    return out


def _write() -> None:
    full = json.loads(BENCH.read_text(encoding="utf-8"))
    texts = _texts()
    sub = _subset(full, [t for _, t, _ in texts])
    tmp = FILE.with_suffix(".tok.tmp")
    tmp.write_text(json.dumps(sub, ensure_ascii=False), encoding="utf-8")
    tok = ref.load(tmp)
    tmp.unlink()
    cases = []
    for name, text, f in texts:
        c = {"name": name, "text": text, "ids": ref.encode(tok, text)}
        if f is not None:
            c["features"] = f
        cases.append(c)
    data = {"source": "subset of ml/out/bench-encoder/tokenizer.json", "tokenizer": sub, "cases": cases}
    FILE.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


if os.environ.get("UPDATE_VECTORS"):
    if not BENCH.exists():
        raise RuntimeError(f"UPDATE_VECTORS needs the bench encoder tokenizer at {BENCH}")
    _write()

DATA = json.loads(FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def tok_path(tmp_path_factory) -> Path:
    p = tmp_path_factory.mktemp("tokvec") / "tokenizer.json"
    p.write_text(json.dumps(DATA["tokenizer"], ensure_ascii=False), encoding="utf-8")
    return p


def test_reference_gives_the_recorded_ids(tok_path):
    tok = ref.load(tok_path)
    for c in DATA["cases"]:
        assert ref.encode(tok, c["text"]) == c["ids"], c["name"]


def test_hugging_face_agrees_on_the_embedded_tokenizer(tok_path):
    hf = Tokenizer.from_file(str(tok_path))
    for c in DATA["cases"]:
        assert hf.encode(c["text"]).ids == c["ids"], c["name"]


def test_serialize_matches_the_recorded_text():
    for c in DATA["cases"]:
        if "features" in c:
            assert serialize(c["features"]) == c["text"], c["name"]


def test_cases_cover_astral_code_points_unk_and_truncation(tok_path):
    tok = ref.load(tok_path)
    texts = {c["name"]: c for c in DATA["cases"]}
    assert any(ord(ch) > 0xFFFF for c in DATA["cases"] for ch in c["text"])
    assert tok.unk_id in texts["emoji_label"]["ids"]
    assert len(texts["long_truncated"]["ids"]) == tok.max_length
    assert texts["raw_specials_only"]["ids"] == [tok.bos_id, tok.bos_id, tok.eos_id, tok.eos_id]
