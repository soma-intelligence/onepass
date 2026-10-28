import gzip
import json
import os
import shutil
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from onepass_ml.ingest import SCHEMA, ingest

FIXTURE = Path(__file__).parent / "data" / "mini.jsonl.gz"
MANIFEST = {"seed": "mini", "generator": 2, "featureVersion": 1, "rows": 300, "parts": 1}


def make_src(tmp_path: Path, rows: list[dict] | None = None, manifest: dict | None = MANIFEST) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    if rows is None:
        shutil.copy(FIXTURE, src / "part-0000.jsonl.gz")
    else:
        with gzip.open(src / "part-0000.jsonl.gz", "wt", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
    if manifest is not None:
        (src / "manifest.json").write_text(json.dumps(manifest))
    return src


def fixture_rows() -> list[dict]:
    with gzip.open(FIXTURE, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def test_writes_four_files(tmp_path):
    ingest(make_src(tmp_path), tmp_path / "dst")
    names = sorted(p.name for p in (tmp_path / "dst").glob("*.parquet"))
    assert names == ["real_test.parquet", "test.parquet", "train.parquet", "val.parquet"]


def test_row_counts_match_splits(tmp_path):
    rows = fixture_rows()
    assert len(rows) == 300
    ingest(make_src(tmp_path), tmp_path / "dst")
    for split in ("train", "val", "test"):
        want = sum(1 for r in rows if r["split"] == split)
        assert want > 0
        assert pq.read_table(tmp_path / "dst" / f"{split}.parquet").num_rows == want


def test_no_lab_column(tmp_path):
    ingest(make_src(tmp_path), tmp_path / "dst")
    for p in (tmp_path / "dst").glob("*.parquet"):
        assert "lab" not in pq.read_schema(p).names


def test_lab_in_input_is_rejected(tmp_path):
    rows = fixture_rows()
    rows[0]["lab"] = "3"
    with pytest.raises(ValueError, match="lab"):
        ingest(make_src(tmp_path, rows), tmp_path / "dst")


def test_schema_types_and_names(tmp_path):
    ingest(make_src(tmp_path), tmp_path / "dst")
    schema = pq.read_schema(tmp_path / "dst" / "train.parquet")
    assert schema.names == SCHEMA.names
    for name in ("tag", "label", "target", "split", "origin", "seed", "lang"):
        assert schema.field(name).type == pa.large_string()
    for name in ("formButtons", "neighbourLabels", "traits"):
        assert schema.field(name).type == pa.list_(pa.large_string())
    assert schema.field("depth").type == pa.int32()
    assert schema.field("hasPattern").type == pa.bool_()
    assert schema.field("maxlength").type == pa.int32()


def test_label_text_and_target_kept_apart(tmp_path):
    ingest(make_src(tmp_path), tmp_path / "dst")
    t = pq.read_table(tmp_path / "dst" / "train.parquet").to_pylist()
    assert any(r["label"] for r in t)
    assert any(r["target"] not in (None, "none") for r in t)
    assert {r["target"] for r in t} != {r["label"] for r in t}


def test_absent_optionals_become_null(tmp_path):
    ingest(make_src(tmp_path), tmp_path / "dst")
    t = pq.read_table(tmp_path / "dst" / "train.parquet")
    assert t.column("maxlength").null_count > 0
    assert t.column("target").null_count == 0


def test_metadata_from_manifest(tmp_path):
    ingest(make_src(tmp_path), tmp_path / "dst")
    for p in (tmp_path / "dst").glob("*.parquet"):
        md = pq.read_schema(p).metadata
        assert md[b"seed"] == b"mini"
        assert md[b"generator"] == b"2"
        assert md[b"featureVersion"] == b"1"


def test_returns_manifest_with_counts(tmp_path):
    m = ingest(make_src(tmp_path), tmp_path / "dst")
    assert m["seed"] == "mini" and m["rows"] == 300
    assert m["splits"]["real_test"] == 0
    assert sum(m["splits"].values()) == 300
    assert json.loads((tmp_path / "dst" / "manifest.json").read_text())["splits"] == m["splits"]


def test_empty_real_test_has_full_schema(tmp_path):
    ingest(make_src(tmp_path), tmp_path / "dst")
    t = pq.read_table(tmp_path / "dst" / "real_test.parquet")
    assert t.num_rows == 0
    assert t.schema.names == SCHEMA.names


def test_no_shared_origin_between_train_and_real_test(tmp_path):
    rows = fixture_rows()
    for r in rows:
        if r["split"] == "test":
            r["split"] = "real_test"
            r["origin"] = "real:" + r["origin"]
    ingest(make_src(tmp_path, rows), tmp_path / "dst")
    real = pq.read_table(tmp_path / "dst" / "real_test.parquet", columns=["origin"])
    assert real.num_rows > 0
    train = pq.read_table(tmp_path / "dst" / "train.parquet", columns=["origin"])
    assert not set(real.column("origin").to_pylist()) & set(train.column("origin").to_pylist())


def test_origin_overlap_raises(tmp_path):
    rows = fixture_rows()
    rows[0]["split"] = "real_test"  # same origin still appears in train rows of that site
    train_origin = rows[0]["origin"]
    assert any(r["origin"] == train_origin and r["split"] == "train" for r in rows[1:])
    with pytest.raises(ValueError, match="origin"):
        ingest(make_src(tmp_path, rows), tmp_path / "dst")


def test_streams_in_small_batches(tmp_path):
    src = make_src(tmp_path)
    shutil.copy(FIXTURE, src / "part-0001.jsonl.gz")
    (src / "manifest.json").write_text(json.dumps({**MANIFEST, "rows": 600}))
    m = ingest(src, tmp_path / "dst", batch_rows=7)
    assert m["rows"] == 600
    assert pq.read_table(tmp_path / "dst" / "train.parquet").num_rows == m["splits"]["train"]


def test_unknown_split_raises(tmp_path):
    rows = fixture_rows()
    rows[0]["split"] = "dev"
    with pytest.raises(ValueError, match="split"):
        ingest(make_src(tmp_path, rows), tmp_path / "dst")


def test_missing_manifest_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        ingest(make_src(tmp_path, manifest=None), tmp_path / "dst")


def _no_output(tmp_path):
    dst = tmp_path / "dst"
    assert not list(dst.glob("*.parquet")) if dst.exists() else True
    assert not (tmp_path / "dst.tmp").exists()


def test_failures_leave_no_output(tmp_path):
    rows = fixture_rows()
    rows[0]["split"] = "real_test"
    with pytest.raises(ValueError, match="origin"):
        ingest(make_src(tmp_path, rows), tmp_path / "dst")
    _no_output(tmp_path)


def test_unknown_split_leaves_no_output(tmp_path):
    rows = fixture_rows()
    rows[5]["split"] = "dev"
    with pytest.raises(ValueError, match="split"):
        ingest(make_src(tmp_path, rows), tmp_path / "dst")
    _no_output(tmp_path)


@pytest.mark.parametrize("key", ["target", "index", "hasPattern", "origin", "split"])
def test_missing_required_key_names_key_and_part(tmp_path, key):
    rows = fixture_rows()
    del rows[3][key]
    with pytest.raises(ValueError, match=rf"part-0000.jsonl.gz.*'{key}'"):
        ingest(make_src(tmp_path, rows), tmp_path / "dst")
    _no_output(tmp_path)


def test_required_fields_not_nullable():
    assert not SCHEMA.field("target").nullable
    assert not SCHEMA.field("index").nullable
    assert SCHEMA.field("maxlength").nullable


@pytest.mark.parametrize("key", ["seed", "generator", "featureVersion"])
def test_manifest_missing_key(tmp_path, key):
    m = {k: v for k, v in MANIFEST.items() if k != key}
    with pytest.raises(ValueError, match=key):
        ingest(make_src(tmp_path, manifest=m), tmp_path / "dst")


def test_row_count_mismatch(tmp_path):
    rows = fixture_rows()[:250]
    with pytest.raises(ValueError, match="300.*250"):
        ingest(make_src(tmp_path, rows), tmp_path / "dst")
    _no_output(tmp_path)


def test_replaces_existing_output(tmp_path):
    ingest(make_src(tmp_path), tmp_path / "dst")
    m = ingest(tmp_path / "src", tmp_path / "dst")
    assert m["rows"] == 300 and not (tmp_path / "dst.tmp").exists()


def test_failed_swap_keeps_previous_output(tmp_path, monkeypatch):
    src = make_src(tmp_path)
    dst = tmp_path / "dst"
    ingest(src, dst)
    before = {f.name: f.read_bytes() for f in dst.iterdir()}
    calls = []
    real = os.rename

    def flaky(a, b):
        calls.append(1)
        if len(calls) == 2:
            raise OSError("boom")
        return real(a, b)

    monkeypatch.setattr(os, "rename", flaky)
    with pytest.raises(OSError, match="boom"):
        ingest(src, dst)
    monkeypatch.undo()
    assert {f.name: f.read_bytes() for f in dst.iterdir()} == before
    assert not (tmp_path / "dst.tmp").exists() and not (tmp_path / "dst.old").exists()


def test_manifest_without_rows(tmp_path):
    m = {k: v for k, v in MANIFEST.items() if k != "rows"}
    with pytest.raises(ValueError, match="rows"):
        ingest(make_src(tmp_path, manifest=m), tmp_path / "dst")


def test_writers_closed_when_second_fails(tmp_path, monkeypatch):
    opened = []
    real = pq.ParquetWriter

    class W(real):
        def __init__(self, *a, **k):
            if len(opened) == 1:
                raise OSError("second writer")
            super().__init__(*a, **k)
            opened.append(self)

    monkeypatch.setattr(pq, "ParquetWriter", W)
    with pytest.raises(OSError, match="second writer"):
        ingest(make_src(tmp_path), tmp_path / "dst")
    assert opened and opened[0].is_open is False
