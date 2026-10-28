"""Pure-Python reference of the encoder tokenizer: reads only out/encoder/tokenizer.json.

The JSON is a Hugging Face `tokenizers` file restricted to the pieces this module implements, so
the same file loads in `tokenizers.Tokenizer.from_file` (tests assert equality) and in the
TypeScript port of this module (Task 15). No transformers, no sentencepiece, no tokenizers here.

Pipeline, in order (each step names the JSON field it reads):
1. added_tokens: the special tokens (`<s>`, `<pad>`, `</s>`, `<unk>`) are cut out of the raw text
   (leftmost, longest match first) and map straight to their id.
2. normalizer {"type": "NFKC"}: each remaining segment is NFKC normalized.
3. pre_tokenizer Sequence[WhitespaceSplit, Metaspace]: split on Unicode White_Space, then each
   word gets U+2581 prepended (prepend_scheme "always") and is split before every U+2581.
4. model {"type": "Unigram"}: Viterbi over each piece with the vocab scores (float64 sums,
   candidates scanned by increasing start then increasing length, strictly better wins). A code
   point no piece covers becomes `<unk>` scored min(vocab score) - 10; consecutive `<unk>` fuse.
5. truncation.max_length: keep the first max_length - 2 tokens, then post_processor wraps them as
   `<s> ... </s>`.
Padding is the caller's: pad id is `pad_id`, attention mask 1 on real tokens.
"""

from __future__ import annotations

import json
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

META = "▁"
UNK_PENALTY = 10.0
# Unicode White_Space, the set Rust char::is_whitespace uses (Python's str.split differs).
WHITE_SPACE = frozenset(
    "\t\n\v\f\r \x85\xa0           "
    "     　"
)


@dataclass
class RefTokenizer:
    pieces: list[str]
    scores: list[float]
    unk_id: int
    bos_id: int
    eos_id: int
    pad_id: int
    max_length: int
    specials: dict[str, int]
    index: dict[str, int] = field(default_factory=dict)
    max_piece: int = 0
    unk_score: float = 0.0

    def __post_init__(self) -> None:
        self.index = {p: i for i, p in enumerate(self.pieces)}
        self.max_piece = max(len(p) for p in self.pieces)
        self.unk_score = min(self.scores) - UNK_PENALTY


def load(path: Path) -> RefTokenizer:
    j = json.loads(Path(path).read_text(encoding="utf-8"))
    assert j["normalizer"] == {"type": "NFKC"}, j["normalizer"]
    pre = j["pre_tokenizer"]
    assert pre["type"] == "Sequence" and [p["type"] for p in pre["pretokenizers"]] == ["WhitespaceSplit", "Metaspace"]
    ms = pre["pretokenizers"][1]
    assert ms["replacement"] == META and ms["prepend_scheme"] == "always" and ms["split"] is True
    m = j["model"]
    assert m["type"] == "Unigram" and not m.get("byte_fallback")
    single = j["post_processor"]["single"]
    assert [next(iter(s)) for s in single] == ["SpecialToken", "Sequence", "SpecialToken"]
    pieces = [p for p, _ in m["vocab"]]
    specials = {t["content"]: t["id"] for t in j["added_tokens"] if t["special"]}
    return RefTokenizer(
        pieces=pieces,
        scores=[float(s) for _, s in m["vocab"]],
        unk_id=m["unk_id"],
        bos_id=specials[single[0]["SpecialToken"]["id"]],
        eos_id=specials[single[2]["SpecialToken"]["id"]],
        pad_id=specials["<pad>"],
        max_length=j["truncation"]["max_length"],
        specials=specials,
    )


def _split_specials(tok: RefTokenizer, text: str) -> list[str | int]:
    """Text segments and special token ids, in order (leftmost match, longest on ties)."""
    out: list[str | int] = []
    names = sorted(tok.specials, key=len, reverse=True)
    i = start = 0
    while i < len(text):
        hit = next((n for n in names if text.startswith(n, i)), None)
        if hit is None:
            i += 1
            continue
        if start < i:
            out.append(text[start:i])
        out.append(tok.specials[hit])
        i = start = i + len(hit)
    if start < len(text):
        out.append(text[start:])
    return out


def _pre_tokenize(s: str) -> list[str]:
    words: list[str] = []
    cur: list[str] = []
    for c in s:
        if c in WHITE_SPACE:
            if cur:
                words.append("".join(cur))
                cur = []
        else:
            cur.append(c)
    if cur:
        words.append("".join(cur))
    out: list[str] = []
    for w in words:
        w = w.replace(" ", META)
        if not w.startswith(META):
            w = META + w
        cut = 0
        for k in range(1, len(w)):
            if w[k] == META:
                out.append(w[cut:k])
                cut = k
        out.append(w[cut:])
    return out


def _viterbi(tok: RefTokenizer, s: str) -> list[int]:
    n = len(s)
    best = [float("-inf")] * (n + 1)
    back: list[tuple[int, int] | None] = [None] * (n + 1)  # (start, id)
    best[0] = 0.0
    for start in range(n):
        if back[start] is None and start:
            continue
        here = best[start]
        single = False
        for end in range(start + 1, min(n, start + tok.max_piece) + 1):
            i = tok.index.get(s[start:end])
            if i is None:
                continue
            if end == start + 1:
                single = True
            cand = here + tok.scores[i]
            if back[end] is None or cand > best[end]:
                best[end], back[end] = cand, (start, i)
        if not single:
            cand = here + tok.unk_score
            end = start + 1
            if back[end] is None or cand > best[end]:
                best[end], back[end] = cand, (start, tok.unk_id)
    ids: list[int] = []
    end = n
    while end > 0:
        start, i = back[end]  # type: ignore[misc]
        if not (i == tok.unk_id and ids and ids[-1] == tok.unk_id):
            ids.append(i)
        end = start
    return ids[::-1]


def encode(tok: RefTokenizer, text: str) -> list[int]:
    """Token ids with `<s>`/`</s>`, truncated to max_length."""
    ids: list[int] = []
    for seg in _split_specials(tok, text):
        if isinstance(seg, int):
            ids.append(seg)
            continue
        for piece in _pre_tokenize(unicodedata.normalize("NFKC", seg)):
            ids.extend(_viterbi(tok, piece))
    return [tok.bos_id, *ids[: tok.max_length - 2], tok.eos_id]
