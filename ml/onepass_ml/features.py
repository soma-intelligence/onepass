"""Parquet split to sparse feature matrix, in batches (the full train set is never densified)."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
import scipy.sparse as sp

from .labels import LABELS
from .vectorize import VECTOR_DIM, vectorize_sparse

BATCH_ROWS = 20_000
_INDEX = {label: i for i, label in enumerate(LABELS)}


def load_matrix(path: Path, batch_rows: int = BATCH_ROWS) -> tuple[sp.csr_matrix, np.ndarray]:
    """(X, y): float32 CSR [rows, VECTOR_DIM] and int64 class indices from the `target` column.

    Rows go through to_pylist (not pandas): vectorize treats None as missing and `x or []` would
    raise on numpy arrays. Only FEATURE_KEYS are read, so `target`, `split`, `origin` and `seed`
    never reach the features.
    """
    blocks: list[sp.csr_matrix] = []
    ys: list[int] = []
    for batch in pq.ParquetFile(path).iter_batches(batch_size=batch_rows):
        data: list[float] = []
        cols: list[int] = []
        indptr = [0]
        for row in batch.to_pylist():
            ys.append(_INDEX[row["target"]])
            for i, x in sorted(vectorize_sparse(row).items()):
                cols.append(i)
                data.append(x)
            indptr.append(len(cols))
        blocks.append(sp.csr_matrix(
            (np.array(data, dtype=np.float32), np.array(cols, dtype=np.int32), np.array(indptr, dtype=np.int64)),
            shape=(len(indptr) - 1, VECTOR_DIM),
        ))
    X = sp.vstack(blocks, format="csr") if blocks else sp.csr_matrix((0, VECTOR_DIM), dtype=np.float32)
    return X, np.array(ys, dtype=np.int64)
