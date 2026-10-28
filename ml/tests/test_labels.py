import re
from pathlib import Path

from onepass_ml.labels import LABELS, ROLES

MODEL_TS = Path(__file__).parents[2] / "extension" / "lab" / "gen" / "model.ts"


def test_roles_match_model_ts_in_order():
    src = MODEL_TS.read_text(encoding="utf-8")
    m = re.search(r"export type Role\s*=([^;]+);", src)
    assert m, "Role type not found in model.ts"
    assert tuple(re.findall(r'"([a-z0-9_]+)"', m.group(1))) == ROLES


def test_labels_are_roles_then_none():
    assert LABELS == ROLES + ("none",)
    assert len(set(LABELS)) == len(LABELS)
