"""Regenerates dhash-vectors.json: python3 -I scripts/testdata/make_dhash_vectors.py"""
import base64
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import icon_pack  # noqa: E402


def make(width, height, pixel):
    rows = [b"".join(bytes(pixel(x, y)) for x in range(width)) for y in range(height)]
    return icon_pack.png_from_rgba(width, height, rows)


def disc(x, y):
    inside = (x - 31.5) ** 2 + (y - 31.5) ** 2 <= 26 ** 2
    return (220, 60, 40, 255) if inside else (0, 0, 0, 0)


def mark(x, y):
    if 8 <= x < 56 and 8 <= y < 56:
        return (20, 90, 200, 128 if (x // 8 + y // 8) % 2 else 255)
    return (255, 255, 255, 0)


def faint(x, y):
    if 8 <= x < 56 and 8 <= y < 56:
        return (200, 40, 90, 1 + (x // 8 + y // 8) * 3 % 20)
    return (0, 0, 0, 0)


noise = random.Random(14)
noise_px = [tuple(noise.getrandbits(8) for _ in range(3)) + (255,) for _ in range(256 * 256)]

VECTORS = [
    ("solid-white", make(32, 32, lambda x, y: (255, 255, 255, 255))),
    ("solid-black", make(32, 32, lambda x, y: (0, 0, 0, 255))),
    ("horizontal-gradient", make(64, 64, lambda x, y: (x * 4, x * 4, x * 4, 255))),
    ("vertical-gradient", make(64, 64, lambda x, y: (y * 4, y * 4, y * 4, 255))),
    ("checkerboard", make(48, 48, lambda x, y: (0, 0, 0, 255) if (x // 6 + y // 6) % 2 else (255, 255, 255, 255))),
    ("transparent-disc", make(64, 64, disc)),
    ("one-pixel", make(1, 1, lambda x, y: (10, 200, 30, 255))),
    ("non-square-40x16", make(40, 16, lambda x, y: ((x * 37 + y * 11) % 256, (x * 5) % 256, (y * 16) % 256, 255))),
    ("noise-256", make(256, 256, lambda x, y: noise_px[y * 256 + x])),
    ("partial-alpha-mark", make(64, 64, mark)),
    ("low-alpha-mark", make(64, 64, faint)),
]

out = [{"name": n, "png": base64.b64encode(p).decode(), "hash": "%016x" % icon_pack.dhash(p)} for n, p in VECTORS]
(HERE / "dhash-vectors.json").write_text(json.dumps(out, indent=1) + "\n")
for v in out:
    print(v["name"], v["hash"])
