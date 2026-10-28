import json
import shutil
from pathlib import Path

# LightGBM (Homebrew libomp) and torch (its own libomp) put two OpenMP runtimes in one pytest
# process. Measured on this Mac: importing lightgbm first and keeping torch on one thread is the
# only order that neither hangs nor crashes. Training runs (separate processes) are unaffected.
import lightgbm  # noqa: F401  (must load before torch)
import pytest
import torch

torch.set_num_threads(1)

from onepass_ml.ingest import ingest

FIXTURE = Path(__file__).parent / "data" / "mini.jsonl.gz"
MANIFEST = {"seed": "mini", "generator": 2, "featureVersion": 1, "rows": 300, "parts": 1}


@pytest.fixture(scope="session")
def mini_data(tmp_path_factory) -> Path:
    """The 300-row fixture ingested to train/val/test/real_test Parquet."""
    root = tmp_path_factory.mktemp("mini")
    src = root / "src"
    src.mkdir()
    shutil.copy(FIXTURE, src / "part-0000.jsonl.gz")
    (src / "manifest.json").write_text(json.dumps(MANIFEST))
    ingest(src, root / "data")
    return root / "data"
