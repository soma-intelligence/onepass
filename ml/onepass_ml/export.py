"""LightGBM booster to ONNX for onnxruntime-web (Task 15 loads this file)."""

from __future__ import annotations

import json
from pathlib import Path

import lightgbm as lgb
from onnxmltools import convert_lightgbm
from onnxmltools.convert.common.data_types import FloatTensorType
import onnx

from .labels import LABELS
from .vectorize import VECTOR_DIM


def export_onnx(booster: lgb.Booster, path: Path, *, feature_version: int, dataset_seed: str, model: str = "gbm") -> Path:
    """Float input [N, VECTOR_DIM] `features`; outputs `label` (int64) and `probabilities` [N, C]
    (plain float tensor, no ZipMap, so onnxruntime-web can read it)."""
    onx = convert_lightgbm(
        booster,
        initial_types=[("features", FloatTensorType([None, VECTOR_DIM]))],
        zipmap=False,
        target_opset=15,
    )
    meta = {
        "feature_version": str(feature_version),
        "vector_dim": str(VECTOR_DIM),
        "labels": json.dumps(list(LABELS)),
        "dataset_seed": str(dataset_seed),
        "model": model,
    }
    for o in onx.graph.output:  # the converter declares label as shape [1]; it is [N]
        if o.name == "label":
            d = o.type.tensor_type.shape.dim
            del d[:]
            d.add().dim_param = "N"
    del onx.metadata_props[:]
    for k, v in meta.items():
        p = onx.metadata_props.add()
        p.key, p.value = k, v
    path = Path(path)
    onnx.save(onx, str(path))
    return path
