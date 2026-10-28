"""ANY change to the layout (namespaces, indicator order, TEXT_CAP, tokenization, hashing) must bump
VECTORIZER_VERSION and regenerate extension/test/vectors/vectorize.json (UPDATE_VECTORS=1 on the
TypeScript side), and the same bump goes in vectorize.ts. Models carry it as ONNX `vectorizer_version`.

Shared field vectorizer: exact Python port of extension/src/content/detect/vectorize.ts.

The model is trained here and runs in the extension, so a field must become the same vector and the
same text on both sides. extension/test/vectors/vectorize.json (written by the TypeScript side) is
asserted by both test suites.

Only FieldFeatures keys are read (FEATURE_KEYS). `target`, `split`, `origin`, `seed`, `lab` and,
per ruling R16, width, height and pageTitle never influence the output. None is the same as missing.

Layout (VECTOR_DIM = 4096): [0, HASH_DIM) hashed token counts, then the numeric indicators in the
order of INDICATORS (name, absolute offset, size). A token adds 1 at
cyrb128(f"{namespace}:{token}")[0] % HASH_DIM. Values are small integers or k/16 fractions, exact in
float32.

Text: normalize_text, capped to TEXT_CAP code points. Tokens are maximal runs of code points whose
unicodedata category starts with L, M or N (JS: \\p{L}\\p{M}\\p{N}). Inside a run Han, Hiragana,
Katakana and Hangul code points (CJK_RANGES) form segments that become overlapping bigrams (a lone
code point stays a unigram); other segments are one token. Python 3.12 has Unicode 15.0 tables;
code points assigned later may classify differently from Node's ICU.
"""

from __future__ import annotations

import re
import unicodedata
from array import array
from typing import Any, Iterable, Mapping, Sequence

VECTORIZER_VERSION = 1
VECTOR_DIM = 4096
TEXT_CAP = 256

TYPES = (
    "text", "email", "password", "tel", "number", "url", "search", "date", "datetime-local", "month",
    "week", "time", "color", "range", "select", "textarea", "other",
)
KNOWN_AUTOCOMPLETE = frozenset((
    "name", "honorific-prefix", "given-name", "additional-name", "family-name", "honorific-suffix",
    "nickname", "username", "new-password", "current-password", "one-time-code", "organization-title",
    "organization", "street-address", "address-line1", "address-line2", "address-line3",
    "address-level1", "address-level2", "address-level3", "address-level4", "country", "country-name",
    "postal-code", "cc-name", "cc-given-name", "cc-additional-name", "cc-family-name", "cc-number",
    "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc", "cc-type", "transaction-currency",
    "transaction-amount", "language", "bday", "bday-day", "bday-month", "bday-year", "sex", "url",
    "photo", "email", "tel", "tel-country-code", "tel-national", "tel-area-code", "tel-local",
    "tel-extension", "impp", "webauthn",
))
VISIBILITIES = ("visible", "display_none", "offscreen", "opacity", "zero_size")
MAXLENGTH_BOUNDS = (2, 4, 8, 16, 64)
INPUTMODES = ("", "text", "numeric", "tel", "email", "url", "search", "decimal")

# Every FieldFeatures key the vectorizer may read. Nothing else is ever looked at.
FEATURE_KEYS = (
    "index", "tag", "type", "name", "id", "autocomplete", "inputmode", "maxlength", "hasPattern",
    "required", "label", "placeholder", "ariaLabel", "before", "after", "depth", "siblings",
    "visibility", "formButtons", "neighbourLabels",
)

_blocks = [
    ("type", len(TYPES)), ("known_autocomplete", 1), ("visibility", len(VISIBILITIES)),
    ("maxlength", len(MAXLENGTH_BOUNDS) + 2), ("depth", 1), ("index", 1), ("siblings", 1),
    ("has_pattern", 1), ("required", 1), ("inputmode", len(INPUTMODES) + 1),
]
NUM_INDICATORS = sum(n for _, n in _blocks)
HASH_DIM = VECTOR_DIM - NUM_INDICATORS
INDICATORS: tuple[tuple[str, int, int], ...] = ()
_at = HASH_DIM
for _name, _size in _blocks:
    INDICATORS += ((_name, _at, _size),)
    _at += _size
_OFFSET = {name: off for name, off, _ in INDICATORS}

# JS \s and String.prototype.trim: WhiteSpace and LineTerminator. Python's \s differs (it has
# \x1c-\x1f and lacks ﻿), so the set is explicit.
_WS = "\t\n\v\f\r                  　﻿"
_WS_RUN = re.compile("[" + _WS + "]+")
_CJK_RANGES = (
    (0x3040, 0x309F), (0x30A0, 0x30FF), (0x31F0, 0x31FF), (0x3400, 0x4DBF), (0x4E00, 0x9FFF),
    (0xAC00, 0xD7AF), (0xF900, 0xFAFF), (0x20000, 0x2A6DF), (0x2A700, 0x2EBEF), (0x30000, 0x323AF),
)


def normalize_text(s: str) -> str:
    """NFKC, lower case, whitespace folded: same as normalizeText in features.ts."""
    return _WS_RUN.sub(" ", unicodedata.normalize("NFKC", s).lower()).strip(_WS)


def cyrb128(s: str) -> tuple[int, int, int, int]:
    """Port of src/shared/hash.ts: UTF-16 code units, 32-bit unsigned Math.imul arithmetic."""
    m = 0xFFFFFFFF
    h1, h2, h3, h4 = 1779033703, 3144134277, 1013904242, 2773480762
    raw = s.encode("utf-16-le", "surrogatepass")
    for i in range(0, len(raw), 2):
        k = raw[i] | (raw[i + 1] << 8)
        h1 = h2 ^ (((h1 ^ k) * 597399067) & m)
        h2 = h3 ^ (((h2 ^ k) * 2869860233) & m)
        h3 = h4 ^ (((h3 ^ k) * 951274213) & m)
        h4 = h1 ^ (((h4 ^ k) * 2716044179) & m)
    h1 = ((h3 ^ (h1 >> 18)) * 597399067) & m
    h2 = ((h4 ^ (h2 >> 22)) * 2869860233) & m
    h3 = ((h1 ^ (h3 >> 17)) * 951274213) & m
    h4 = ((h2 ^ (h4 >> 19)) * 2716044179) & m
    return ((h1 ^ h2 ^ h3 ^ h4) & m, (h2 ^ h1) & m, (h3 ^ h1) & m, (h4 ^ h1) & m)


def _is_cjk(c: str) -> bool:
    cp = ord(c)
    return any(a <= cp <= b for a, b in _CJK_RANGES)


def _clean(s: Any) -> str:
    if s is None:
        return ""
    return normalize_text(str(s))[:TEXT_CAP].rstrip(" ")


def tokenize(s: str | None) -> list[str]:
    out: list[str] = []

    def segment(seg: list[str], cjk: bool) -> None:
        if not seg:
            return
        if not cjk:
            out.append("".join(seg))
        elif len(seg) == 1:
            out.append(seg[0])
        else:
            out.extend(seg[i] + seg[i + 1] for i in range(len(seg) - 1))

    def flush(run: list[str]) -> None:
        seg: list[str] = []
        seg_cjk = False
        for c in run:
            k = _is_cjk(c)
            if seg and k != seg_cjk:
                segment(seg, seg_cjk)
                seg = []
            seg_cjk = k
            seg.append(c)
        segment(seg, seg_cjk)

    run: list[str] = []
    for c in _clean(s):
        if unicodedata.category(c)[0] in "LMN":
            run.append(c)
        else:
            flush(run)
            run = []
    flush(run)
    return out


def _features(row: Mapping[str, Any], keys: Iterable[str]) -> dict[str, Any]:
    allowed = set(FEATURE_KEYS)
    return {k: row.get(k) for k in keys if k in allowed}


def _effective_type(f: Mapping[str, Any]) -> str:
    if _clean(f.get("tag")) == "select":
        return "select"
    t = f.get("type")
    return _clean(t if t is not None else f.get("tag"))


def vectorize_sparse(row: Mapping[str, Any], keys: Sequence[str] = FEATURE_KEYS) -> dict[int, float]:
    """Non-zero entries of the vector. `row` may be a whole dataset row: only `keys` are read."""
    f = _features(row, keys)
    v: dict[int, float] = {}

    def add(ns: str, tok: str) -> None:
        i = cyrb128(f"{ns}:{tok}")[0] % HASH_DIM
        v[i] = v.get(i, 0.0) + 1.0

    def add_all(ns: str, s: str | None) -> None:
        for t in tokenize(s):
            add(ns, t)

    typ = _effective_type(f)
    if typ:
        add("type", typ)
    tag = _clean(f.get("tag"))
    if tag:
        add("tag", tag)
    for ns, s in (("name", f.get("name")), ("id", f.get("id"))):
        add_all(ns, s)
        whole = _clean(s)
        if whole:
            add(f"{ns}_full", whole)
    ac_tokens = [t for t in _clean(f.get("autocomplete")).split(" ") if t]
    for t in ac_tokens:
        add("ac", t)
    add_all("label", f.get("label"))
    add_all("ph", f.get("placeholder"))
    add_all("aria", f.get("ariaLabel"))
    add_all("before", f.get("before"))
    add_all("after", f.get("after"))
    for s in f.get("neighbourLabels") or []:
        add_all("near", s)
    for s in f.get("formButtons") or []:
        add_all("btn", s)

    v[_OFFSET["type"] + (TYPES.index(typ) if typ in TYPES else len(TYPES) - 1)] = 1.0
    if any(t in KNOWN_AUTOCOMPLETE for t in ac_tokens):
        v[_OFFSET["known_autocomplete"]] = 1.0
    vis = f.get("visibility")
    if vis in VISIBILITIES:
        v[_OFFSET["visibility"] + VISIBILITIES.index(vis)] = 1.0
    ml = f.get("maxlength")
    mb = 0
    if ml is not None and ml > 0:
        mb = next((i for i, b in enumerate(MAXLENGTH_BOUNDS) if ml <= b), len(MAXLENGTH_BOUNDS)) + 1
    v[_OFFSET["maxlength"] + mb] = 1.0
    for name, key, cap in (("depth", "depth", 16), ("index", "index", 15), ("siblings", "siblings", 15)):
        val = min(max(f.get(key) or 0, 0), cap) / 16
        if val:
            v[_OFFSET[name]] = val
    if f.get("hasPattern"):
        v[_OFFSET["has_pattern"]] = 1.0
    if f.get("required"):
        v[_OFFSET["required"]] = 1.0
    im = _clean(f.get("inputmode"))
    v[_OFFSET["inputmode"] + (INPUTMODES.index(im) if im in INPUTMODES else len(INPUTMODES))] = 1.0
    return v


def vectorize(row: Mapping[str, Any], keys: Sequence[str] = FEATURE_KEYS) -> array:
    """Dense float32 vector of VECTOR_DIM entries."""
    out = array("f", bytes(4 * VECTOR_DIM))
    for i, x in vectorize_sparse(row, keys).items():
        out[i] = x
    return out


def serialize(row: Mapping[str, Any], keys: Sequence[str] = FEATURE_KEYS) -> str:
    """Text for the encoder, same format as serialize in vectorize.ts."""
    f = _features(row, keys)

    def join(xs: list[str] | None) -> str:
        return "; ".join(_clean(x) for x in (xs or []))

    return " | ".join((
        f"type={_effective_type(f)}", f"name={_clean(f.get('name'))}", f"id={_clean(f.get('id'))}", f"ac={_clean(f.get('autocomplete'))}", f"label={_clean(f.get('label'))}",
        f"ph={_clean(f.get('placeholder'))}", f"aria={_clean(f.get('ariaLabel'))}",
        f"before={_clean(f.get('before'))}", f"after={_clean(f.get('after'))}",
        f"near={join(f.get('neighbourLabels'))}", f"buttons={join(f.get('formButtons'))}",
    ))
