"""Model B: small multilingual encoder field classifier, exported to ONNX for onnxruntime-web.

Usage: uv run python -m onepass_ml.train_encoder <data dir> <out dir> [--epochs N] [--seed N]
       [--layers N] [--max-steps N] [--device cpu|mps] [--threads N] [--batch-size N] [--lr X]
`data` is the output of onepass_ml.ingest. Input text is serialize(row) (vectorize.py), target is
the `target` column (R14), labels from labels.py.

Ruling R19, what this does to the base model (BASE at BASE_REVISION, Hugging Face cache):
- Vocabulary pruned to the pieces the train split uses, plus the specials and every single-character
  piece of the scripts present in train (any non-letter single character is kept too). The
  embedding rows are copied for the kept pieces, `<mask>` is dropped, other words map to `<unk>`.
- Depth: `layers` of the 12 kept, evenly spaced and ending on the last one (6 = 1,3,5,...,11),
  then fine-tuned. No teacher distillation.
- Head: masked mean pooling, dropout, linear; softmax inside the exported graph.
Writes <out>/tokenizer.json (see onepass_ml/tokenizer.py for the format), encoder.fp32.onnx,
encoder.onnx (dynamic 8-bit weights, the shipped model), encoder.pt (PyTorch weights, for checks).
Early stopping on val macro F1.
"""

from __future__ import annotations

import argparse
import copy
import json
import random
import sys
import time
import unicodedata
from pathlib import Path

import numpy as np
import onnx
import pyarrow.parquet as pq
import torch
from torch import nn

from .labels import LABELS
from .vectorize import VECTORIZER_VERSION, serialize

BASE = "microsoft/Multilingual-MiniLM-L12-H384"
BASE_REVISION = "6e8c1ec6b4ec4e3fc6eb7d2cd834fcd582b61daf"
MAX_LENGTH = 128  # p100 of the bench serialize strings is 122 tokens with the base vocab
MAX_BYTES = 30 * 1024 * 1024  # model B target (constraints.md), on the quantized file
SPECIALS = ("<s>", "<pad>", "</s>", "<unk>")
PAD_ID = 1
_INDEX = {label: i for i, label in enumerate(LABELS)}


# ---------------------------------------------------------------- tokenizer

def train_texts(path: Path) -> list[str]:
    return [serialize(r) for r in pq.read_table(path).to_pylist()]


def _base_json(base: str, revision: str) -> dict:
    from transformers import AutoTokenizer

    tok = AutoTokenizer.from_pretrained(base, revision=revision)
    j = json.loads(tok.backend_tokenizer.to_str())
    vocab = j["model"]["vocab"]
    assert [p for p, _ in vocab[:4]] == list(SPECIALS), vocab[:4]
    return j


def _assemble(vocab: list[list], max_length: int):
    """HF tokenizer with only the steps onepass_ml.tokenizer implements (no precompiled charsmap)."""
    from tokenizers import Tokenizer

    meta = {"type": "Metaspace", "replacement": "▁", "prepend_scheme": "always", "split": True}
    j = {
        "version": "1.0",
        "truncation": None,
        "padding": None,
        "added_tokens": [
            {"id": i, "content": s, "single_word": False, "lstrip": False, "rstrip": False,
             "normalized": False, "special": True}
            for i, s in enumerate(SPECIALS)
        ],
        "normalizer": {"type": "NFKC"},
        "pre_tokenizer": {"type": "Sequence", "pretokenizers": [{"type": "WhitespaceSplit"}, meta]},
        "post_processor": {
            "type": "TemplateProcessing",
            "single": [{"SpecialToken": {"id": "<s>", "type_id": 0}}, {"Sequence": {"id": "A", "type_id": 0}},
                       {"SpecialToken": {"id": "</s>", "type_id": 0}}],
            "pair": [{"SpecialToken": {"id": "<s>", "type_id": 0}}, {"Sequence": {"id": "A", "type_id": 0}},
                     {"SpecialToken": {"id": "</s>", "type_id": 0}}, {"Sequence": {"id": "B", "type_id": 0}},
                     {"SpecialToken": {"id": "</s>", "type_id": 0}}],
            "special_tokens": {
                "<s>": {"id": "<s>", "ids": [0], "tokens": ["<s>"]},
                "</s>": {"id": "</s>", "ids": [2], "tokens": ["</s>"]},
            },
        },
        "decoder": meta,
        "model": {"type": "Unigram", "unk_id": 3, "vocab": vocab, "byte_fallback": False},
    }
    tok = Tokenizer.from_str(json.dumps(j))
    tok.enable_truncation(max_length)
    return tok


def full_tokenizer(base: str = BASE, revision: str = BASE_REVISION, max_length: int = MAX_LENGTH):
    """The base vocab (minus `<mask>`, same ids) behind the restricted pipeline: pruning reference."""
    vocab = [v for v in _base_json(base, revision)["model"]["vocab"] if v[0] != "<mask>"]
    return _assemble(vocab, max_length)


def _script(c: str) -> str | None:
    """Script key of a letter (first word of its Unicode name: LATIN, CJK, HANGUL...); None otherwise."""
    if not unicodedata.category(c).startswith("L"):
        return None
    return unicodedata.name(c, "?").split(" ")[0]


def build_tokenizer(texts: list[str], out: Path, base: str = BASE, revision: str = BASE_REVISION,
                    max_length: int = MAX_LENGTH) -> list[int]:
    """Writes the pruned tokenizer.json; returns, per new id, the base vocab id it came from."""
    vocab = _base_json(base, revision)["model"]["vocab"]
    full = _assemble([v for v in vocab if v[0] != "<mask>"], max_length)
    used = {i for e in full.encode_batch(texts) for i in e.ids}
    scripts = {s for t in texts for c in set(t) if (s := _script(c))}
    keep = []
    for i, (piece, _) in enumerate(vocab):
        if piece == "<mask>":
            continue
        bare = piece[1:] if piece.startswith("▁") else piece
        single = len(bare) == 1 and (_script(bare) is None or _script(bare) in scripts)
        if i < len(SPECIALS) or i in used or piece == "▁" or single:
            keep.append(i)
    tok = _assemble([vocab[i] for i in keep], max_length)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tok.save(str(out))
    return keep


# ---------------------------------------------------------------- model

class FieldEncoder(nn.Module):
    """input_ids, attention_mask (int64 [N, L]) -> probabilities [N, C]."""

    def __init__(self, config, n_labels: int = len(LABELS)):
        super().__init__()
        from transformers import BertModel

        self.bert = BertModel(config, add_pooling_layer=False)
        self.dropout = nn.Dropout(config.hidden_dropout_prob)
        self.head = nn.Linear(config.hidden_size, n_labels)

    def logits(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        h = self.bert(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state
        m = attention_mask.unsqueeze(-1).to(h.dtype)
        pooled = (h * m).sum(1) / m.sum(1).clamp(min=1.0)
        return self.head(self.dropout(pooled))

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        return torch.softmax(self.logits(input_ids, attention_mask), dim=-1)


def kept_layers(layers: int, total: int = 12) -> list[int]:
    return [round((i + 1) * total / layers) - 1 for i in range(layers)]


def _student(keep: list[int], layers: int, base: str, revision: str) -> FieldEncoder:
    from transformers import BertModel

    teacher = BertModel.from_pretrained(base, revision=revision, add_pooling_layer=False)
    config = copy.deepcopy(teacher.config)
    config.num_hidden_layers = layers
    config.vocab_size = len(keep)
    config.pad_token_id = PAD_ID
    config._attn_implementation = "eager"  # plain MatMul/Softmax ops for the ONNX export
    model = FieldEncoder(config)
    s, t = model.bert, teacher
    with torch.no_grad():
        s.embeddings.word_embeddings.weight.copy_(t.embeddings.word_embeddings.weight[torch.tensor(keep)])
        s.embeddings.position_embeddings.load_state_dict(t.embeddings.position_embeddings.state_dict())
        s.embeddings.token_type_embeddings.load_state_dict(t.embeddings.token_type_embeddings.state_dict())
        s.embeddings.LayerNorm.load_state_dict(t.embeddings.LayerNorm.state_dict())
        for j, i in enumerate(kept_layers(layers, t.config.num_hidden_layers)):
            s.encoder.layer[j].load_state_dict(t.encoder.layer[i].state_dict())
    return model


def load_torch(out: Path) -> FieldEncoder:
    from transformers import BertConfig

    saved = torch.load(Path(out) / "encoder.pt", map_location="cpu", weights_only=True)
    config = BertConfig.from_dict(json.loads(saved["config"]))
    config._attn_implementation = "eager"
    model = FieldEncoder(config, int(saved["n_labels"]))
    model.load_state_dict(saved["state"])
    return model


def batch_inputs(seqs: list[list[int]], pad_id: int = PAD_ID) -> tuple[np.ndarray, np.ndarray]:
    """Pad to the longest sequence: (input_ids, attention_mask), both int64 [N, L]."""
    n = max((len(s) for s in seqs), default=0)
    ids = np.full((len(seqs), n), pad_id, dtype=np.int64)
    mask = np.zeros((len(seqs), n), dtype=np.int64)
    for k, s in enumerate(seqs):
        ids[k, :len(s)] = s
        mask[k, :len(s)] = 1
    return ids, mask


def _split(tok, path: Path) -> tuple[list[list[int]], np.ndarray]:
    rows = pq.read_table(path).to_pylist()
    enc = tok.encode_batch([serialize(r) for r in rows]) if rows else []
    return [e.ids for e in enc], np.array([_INDEX[r["target"]] for r in rows], dtype=np.int64)


def predict_ids(fn, seqs: list[list[int]], batch: int = 256) -> np.ndarray:
    """Argmax of fn(ids, mask) -> probabilities, batched by similar length."""
    order = np.argsort([len(s) for s in seqs], kind="stable")
    pred = np.zeros(len(seqs), dtype=np.int64)
    for start in range(0, len(seqs), batch):
        idx = order[start:start + batch]
        ids, mask = batch_inputs([seqs[i] for i in idx])
        pred[idx] = np.asarray(fn(ids, mask)).argmax(axis=1)
    return pred


# ---------------------------------------------------------------- export

def _metadata(path: Path, meta: dict[str, str]) -> None:
    m = onnx.load(str(path))
    del m.metadata_props[:]
    for k, v in meta.items():
        p = m.metadata_props.add()
        p.key, p.value = k, v
    onnx.save(m, str(path))


def export_encoder(model: FieldEncoder, out: Path, meta: dict[str, str]) -> tuple[Path, Path]:
    from onnxruntime.quantization import QuantType, quantize_dynamic

    model = model.cpu().eval()
    fp32, q8 = out / "encoder.fp32.onnx", out / "encoder.onnx"
    ids = torch.tensor([[0, 5, 6, 2], [0, 7, 2, PAD_ID]], dtype=torch.int64)
    mask = (ids != PAD_ID).to(torch.int64)
    axes = {"input_ids": {0: "N", 1: "L"}, "attention_mask": {0: "N", 1: "L"}, "probabilities": {0: "N"}}
    torch.onnx.export(
        model, (ids, mask), str(fp32), input_names=["input_ids", "attention_mask"],
        output_names=["probabilities"], dynamic_axes=axes, opset_version=17, dynamo=False,
    )
    _metadata(fp32, meta)
    # Weights to signed 8 bits, activations quantized to uint8 at run time (DynamicQuantizeLinear +
    # MatMulInteger<uint8, int8>, both CPU kernels onnxruntime-web ships). On this Mac QInt8 runs at
    # 5.0 ms/field single thread against 8.4 for QUInt8, same size. Gather covers the embedding.
    quantize_dynamic(fp32, q8, op_types_to_quantize=["MatMul", "Gather"], weight_type=QuantType.QInt8)
    _metadata(q8, meta)
    return fp32, q8


# ---------------------------------------------------------------- training

def _device(name: str | None) -> torch.device:
    if name:
        return torch.device(name)
    return torch.device("mps" if torch.backends.mps.is_available() else "cpu")


def train_encoder(
    data: Path,
    out: Path,
    base: str = BASE,
    epochs: int = 3,
    seed: int = 1,
    *,
    revision: str = BASE_REVISION,
    layers: int = 6,
    max_length: int = MAX_LENGTH,
    max_steps: int | None = None,
    device: str | None = None,
    threads: int = 4,
    batch_size: int = 32,
    lr: float = 1e-4,
    eval_every: int = 500,
    patience: int = 3,
    log=None,
) -> Path:
    from tokenizers import Tokenizer

    from .eval import metrics

    data, out = Path(data), Path(out)
    out.mkdir(parents=True, exist_ok=True)
    torch.set_num_threads(threads)
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    manifest = json.loads((data / "manifest.json").read_text(encoding="utf-8"))

    keep = build_tokenizer(train_texts(data / "train.parquet"), out / "tokenizer.json", base, revision, max_length)
    tok = Tokenizer.from_file(str(out / "tokenizer.json"))
    X, y = _split(tok, data / "train.parquet")
    Xv, yv = _split(tok, data / "val.parquet")
    dev = _device(device)
    model = _student(keep, layers, base, revision).to(dev)

    per_epoch = max(1, -(-len(X) // batch_size))
    total = min(max_steps, epochs * per_epoch) if max_steps else epochs * per_epoch
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    warm = max(1, total // 16)
    sched = torch.optim.lr_scheduler.LambdaLR(
        opt, lambda s: min((s + 1) / warm, max(0.0, (total - s) / max(1, total - warm))))
    loss_fn = nn.CrossEntropyLoss()
    gen = torch.Generator().manual_seed(seed)

    def val_f1() -> float:
        model.eval()
        with torch.no_grad():
            fn = lambda i, m: model(torch.from_numpy(i).to(dev), torch.from_numpy(m).to(dev)).cpu().numpy()
            f1 = metrics(yv, predict_ids(fn, Xv))["macro_f1"] if len(yv) else 0.0
        model.train()
        return f1

    best, best_state, bad, step = -1.0, None, 0, 0
    model.train()
    done = False
    while not done:
        for idx in torch.randperm(len(X), generator=gen).split(batch_size):
            ids, mask = batch_inputs([X[i] for i in idx.tolist()])
            logits = model.logits(torch.from_numpy(ids).to(dev), torch.from_numpy(mask).to(dev))
            loss = loss_fn(logits, torch.from_numpy(y[idx.numpy()]).to(dev))
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            step += 1
            if step % eval_every == 0 or step == total:
                f1 = val_f1()
                if log:
                    log(f"step {step}/{total} loss {loss.item():.4f} val_macro_f1 {f1:.4f}")
                if f1 > best:
                    best, bad = f1, 0
                    best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
                else:
                    bad += 1
                if bad >= patience:
                    done = True
            if step >= total or done:
                done = True
                break

    model = model.cpu()
    if best_state is not None:
        model.load_state_dict(best_state)
    torch.save({"config": model.bert.config.to_json_string(), "n_labels": len(LABELS), "state": model.state_dict()},
               out / "encoder.pt")
    meta = {
        "feature_version": str(manifest["featureVersion"]),
        # For this model vector_dim is the max sequence length in tokens (specials included),
        # not a feature vector width: the input is token ids, truncated to this length.
        "vector_dim": str(max_length),
        "vectorizer_version": str(VECTORIZER_VERSION),
        "labels": json.dumps(list(LABELS)),
        "dataset_seed": str(manifest["seed"]),
        "model": "encoder",
        "base_model": base,
        "base_revision": revision,
    }
    _, path = export_encoder(model, out, meta)
    size = path.stat().st_size
    if size >= MAX_BYTES:
        path.unlink()
        raise ValueError(f"quantized model is {size} bytes, over the {MAX_BYTES} byte target: lower --layers")
    return path


def latency_ms_per_field(model: Path, data: Path, batch: int = 20, reps: int = 50, threads: int = 1) -> float:
    """onnxruntime CPU, batches of `batch` test fields, median ms per field."""
    import onnxruntime as ort
    from tokenizers import Tokenizer

    opts = ort.SessionOptions()
    opts.intra_op_num_threads = threads
    sess = ort.InferenceSession(str(model), opts, providers=["CPUExecutionProvider"])
    tok = Tokenizer.from_file(str(Path(model).parent / "tokenizer.json"))
    seqs, _ = _split(tok, Path(data) / "test.parquet")
    times = []
    for r in range(reps + 3):
        start = (r * batch) % max(1, len(seqs) - batch)
        ids, mask = batch_inputs(seqs[start:start + batch])
        t0 = time.perf_counter()
        sess.run(None, {"input_ids": ids, "attention_mask": mask})
        if r >= 3:
            times.append((time.perf_counter() - t0) * 1000 / len(ids))
    return float(np.median(times))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("data", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--layers", type=int, default=6)
    ap.add_argument("--max-steps", type=int, default=None)
    ap.add_argument("--device", default=None)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--eval-every", type=int, default=500)
    a = ap.parse_args(argv)
    t0 = time.time()
    path = train_encoder(
        a.data, a.out, epochs=a.epochs, seed=a.seed, layers=a.layers, max_steps=a.max_steps,
        device=a.device, threads=a.threads, batch_size=a.batch_size, lr=a.lr, eval_every=a.eval_every,
        log=lambda s: print(s, flush=True),
    )
    vocab = len(json.loads((a.out / "tokenizer.json").read_text(encoding="utf-8"))["model"]["vocab"])
    print(f"{path} {path.stat().st_size} bytes (fp32 {(a.out / 'encoder.fp32.onnx').stat().st_size}), "
          f"vocab {vocab}, {time.time() - t0:.1f} s")
    for th in (1, 4):
        print(f"latency {latency_ms_per_field(path, a.data, threads=th):.3f} ms/field (batch 20, {th} thread)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
