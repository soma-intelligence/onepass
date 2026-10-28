"""Convert the dataset builder's gzip JSONL parts into Parquet splits.

Input: a directory of `part-*.jsonl.gz` plus `manifest.json` (written by
extension/lab/dataset/build.ts). Output: `train`, `val`, `test` and `real_test`
Parquet files with the columns of `DatasetRow` (rows.ts). Parts are streamed in
batches, so memory stays flat whatever the dataset size.

Usage: uv run python -m onepass_ml.ingest <src> <dst>
"""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path
from typing import Any, Iterator

import pyarrow as pa
import pyarrow.parquet as pq

SPLITS = ("train", "val", "test", "real_test")
BATCH_ROWS = 50_000

_S = pa.large_string()
_L = pa.list_(pa.large_string())

# Same names and order as DatasetRow (FieldFeatures without `lab`, then the row fields).
SCHEMA = pa.schema(
    [
        ("index", pa.int32()),
        ("tag", _S),
        ("type", _S),
        ("name", _S),
        ("id", _S),
        ("autocomplete", _S),
        ("inputmode", _S),
        ("maxlength", pa.int32()),
        ("hasPattern", pa.bool_()),
        ("required", pa.bool_()),
        ("label", _S),
        ("placeholder", _S),
        ("ariaLabel", _S),
        ("before", _S),
        ("after", _S),
        ("depth", pa.int32()),
        ("siblings", pa.int32()),
        ("visibility", _S),
        ("width", pa.int32()),
        ("height", pa.int32()),
        ("formButtons", _L),
        ("pageTitle", _S),
        ("neighbourLabels", _L),
        ("seed", _S),
        ("generator", pa.int32()),
        ("featureVersion", pa.int32()),
        ("site", pa.int32()),
        ("step", pa.int32()),
        ("source", _S),
        ("origin", _S),
        ("split", _S),
        ("lang", _S),
        ("framework", _S),
        ("traits", _L),
        ("target", _S),
    ]
)

Manifest = dict[str, Any]


def _rows(src: Path) -> Iterator[dict[str, Any]]:
    parts = sorted(src.glob("part-*.jsonl.gz"))
    if not parts:
        raise FileNotFoundError(f"no part-*.jsonl.gz in {src}")
    for part in parts:
        with gzip.open(part, "rt", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)


def _table(rows: list[dict[str, Any]], schema: pa.Schema) -> pa.Table:
    return pa.Table.from_pylist(rows, schema=schema)


def ingest(src: Path, dst: Path, batch_rows: int = BATCH_ROWS) -> Manifest:
    """Write dst/{train,val,test,real_test}.parquet and dst/manifest.json, return the manifest."""
    src, dst = Path(src), Path(dst)
    manifest_path = src / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(manifest_path)
    source = json.loads(manifest_path.read_text(encoding="utf-8"))
    dst.mkdir(parents=True, exist_ok=True)

    meta = {
        "seed": str(source["seed"]),
        "generator": str(source["generator"]),
        "featureVersion": str(source["featureVersion"]),
    }
    schema = SCHEMA.with_metadata(meta)
    known = set(SCHEMA.names)
    writers = {s: pq.ParquetWriter(dst / f"{s}.parquet", schema, compression="zstd") for s in SPLITS}
    buffers: dict[str, list[dict[str, Any]]] = {s: [] for s in SPLITS}
    counts = {s: 0 for s in SPLITS}
    origins = {s: set() for s in SPLITS}

    def flush(split: str) -> None:
        if buffers[split]:
            writers[split].write_table(_table(buffers[split], schema))
            buffers[split] = []

    try:
        for row in _rows(src):
            if "lab" in row:
                raise ValueError("row carries the `lab` mark column; the builder must strip it")
            extra = set(row) - known
            if extra:
                raise ValueError(f"unknown columns: {sorted(extra)}")
            split = row.get("split")
            if split not in counts:
                raise ValueError(f"unknown split {split!r}")
            buffers[split].append(row)
            counts[split] += 1
            origins[split].add(row["origin"])
            if len(buffers[split]) >= batch_rows:
                flush(split)
        for s in SPLITS:
            flush(s)
    finally:
        for w in writers.values():
            w.close()

    shared = origins["real_test"] & (origins["train"] | origins["val"] | origins["test"])
    if shared:
        raise ValueError(f"origin shared between real_test and synthetic splits: {sorted(shared)[:3]}")

    manifest: Manifest = {**source, "rows": sum(counts.values()), "splits": counts}
    (dst / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: uv run python -m onepass_ml.ingest <src> <dst>", file=sys.stderr)
        return 2
    m = ingest(Path(argv[0]), Path(argv[1]))
    print(json.dumps({"rows": m["rows"], "splits": m["splits"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
