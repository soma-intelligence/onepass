"""The iPhone and iPad app icon family: the Lattice mark (render.mjs) on ten grounds.

    python3 docs/assets/brand/family.py [--sheet PATH]

Needs Pillow and numpy. Draws the same mark as render.mjs (a 2 x 3 lattice of dots and one bar on a
100 x 100 grid, 56 % of the tile) and writes:
- apple/App/Resources/Assets.xcassets/AppIcon.appiconset/AppIcon-ios*.png: the primary icon, violet,
  with its dark and tinted appearances (the Mac sizes in that set and the Watch and visionOS icons stay
  render.mjs's);
- one AppIcon-<slug>.appiconset per alternate (iOS only, light, dark and tinted). The app target builds
  every app icon set as an alternate on iOS (ASSETCATALOG_COMPILER_INCLUDE_ALL_APPICON_ASSETS);
- AppIconPreviews/IconPreview-<slug>.imageset: the picture Settings > General > App Icon draws (an app
  icon set cannot be loaded as an image), light and dark.

Auto follows the phone's appearance: violet mark on white by day, white mark on charcoal at night. The
other grounds stay the same in both. Add a ground here, run the script, then add its slug to
AppIconChoice.all in apple/App/Settings/AppIconSettings.swift.
"""
import json
import pathlib
import sys

import numpy as np
from PIL import Image, ImageDraw, ImageFilter

ROOT = pathlib.Path(__file__).resolve().parents[3]
ASSETS = ROOT / "apple/App/Resources/Assets.xcassets"
PREVIEWS = ASSETS / "AppIconPreviews"
N = 1024
SS = 4  # supersampling for the mark's edges
PREVIEW_PX = 192  # the picker draws 64 pt at @3x

DOTS = [(cx, cy) for cx in (23.5, 49.5) for cy in (24, 50, 76)]
DOT_R, DOT_OPACITY = 9, 0.55
BAR = (67.5, 15, 18, 70)
SCALE = 0.56

VIOLET = (88, 86, 214)  # Theme.accent, #5856D6
VIOLET_LIGHT = (150, 148, 248)
WHITE = (255, 255, 255)


def linear(top, bottom, mid=None):
    t = np.linspace(0, 1, N)[:, None, None]
    if mid is None:
        a = np.array(top) * (1 - t) + np.array(bottom) * t
    else:
        a = np.where(t < 0.45,
                     np.array(top) + (np.array(mid) - np.array(top)) * (t / 0.45),
                     np.array(mid) + (np.array(bottom) - np.array(mid)) * ((t - 0.45) / 0.55))
    return Image.fromarray(np.repeat(a, N, 1).astype(np.uint8)).convert("RGBA")


def radial(inner, outer):
    y, x = np.mgrid[0:N, 0:N]
    r = np.clip(np.hypot(x - N * 0.3, y - N * 0.12) / (N * 1.15), 0, 1)[..., None]
    return Image.fromarray((np.array(inner) * (1 - r) + np.array(outer) * r).astype(np.uint8)).convert("RGBA")


def blueprint():
    g = linear((34, 74, 150), (20, 48, 108))
    d = ImageDraw.Draw(g)
    for i in range(0, N, 64):
        d.line([(i, 0), (i, N)], fill=(255, 255, 255, 28), width=2)
        d.line([(0, i), (N, i)], fill=(255, 255, 255, 28), width=2)
    return g


def mark(color, outline=False):
    m = N * SS * SCALE
    o = (N * SS - m) / 2
    k = m / 100
    layer = Image.new("RGBA", (N * SS, N * SS), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    dot, solid, width = color + (int(255 * DOT_OPACITY),), color + (255,), int(2.2 * k)
    for cx, cy in DOTS:
        box = [o + (cx - DOT_R) * k, o + (cy - DOT_R) * k, o + (cx + DOT_R) * k, o + (cy + DOT_R) * k]
        if outline:
            d.ellipse(box, outline=solid, width=width)
        else:
            d.ellipse(box, fill=dot)
    x, y, w, h = BAR
    box = [o + x * k, o + y * k, o + (x + w) * k, o + (y + h) * k]
    if outline:
        d.rounded_rectangle(box, radius=w / 2 * k, outline=solid, width=width)
    else:
        d.rounded_rectangle(box, radius=w / 2 * k, fill=solid)
    return layer.resize((N, N), Image.LANCZOS)


def tile(ground, color, outline=False):
    out = ground.copy()
    m = mark(color, outline)
    if color == WHITE and not outline:
        # The soft shadow of render.mjs's Mac tile, under a white mark only.
        shadow = Image.new("RGBA", (N, N), (27, 26, 74, 0))
        shadow.putalpha(m.getchannel("A").point(lambda v: int(v * 0.3)))
        shadow = shadow.transform((N, N), Image.AFFINE, (1, 0, 0, 0, 1, -12)).filter(ImageFilter.GaussianBlur(14))
        out.alpha_composite(shadow)
    out.alpha_composite(m)
    return out.convert("RGB")


def tinted(outline=False):
    """The tinted appearance: a grey mark on black, which iOS colours with the user's tint."""
    out = Image.new("RGBA", (N, N), (0, 0, 0, 255))
    out.alpha_composite(mark((235, 235, 235), outline))
    return out.convert("RGB")


# slug: (ground, mark colour, outline)
GROUNDS = {
    "violet": (lambda: linear((110, 108, 240), (63, 61, 184), VIOLET), WHITE, False),
    "white": (lambda: linear((255, 255, 255), (244, 244, 247)), VIOLET, False),
    "paper": (lambda: linear((248, 244, 234), (236, 229, 214)), VIOLET, False),
    "grey": (lambda: linear((232, 233, 237), (214, 216, 222)), VIOLET, False),
    "lavender": (lambda: linear((238, 233, 255), (212, 202, 250)), VIOLET, False),
    "charcoal": (lambda: linear((46, 46, 50), (16, 16, 18)), WHITE, False),
    "black": (lambda: linear((6, 6, 8), (0, 0, 0)), WHITE, False),
    "navy": (lambda: linear((22, 28, 58), (8, 10, 26)), WHITE, False),
    "dusk": (lambda: radial((255, 160, 140), (76, 52, 150)), WHITE, False),
    "blueprint": (blueprint, WHITE, True),
}


def looks():
    """slug: (light, dark, tinted). 'violet' is the primary, 'auto' follows the appearance."""
    fixed = {s: tile(g(), c, o) for s, (g, c, o) in GROUNDS.items()}
    plain, lines = tinted(), tinted(outline=True)
    out = {s: (im, im, lines if s == "blueprint" else plain) for s, im in fixed.items()}
    # The primary's dark appearance: the violet mark, lighter, on near black.
    out["violet"] = (fixed["violet"], tile(linear((30, 29, 44), (10, 10, 14)), VIOLET_LIGHT), plain)
    out["auto"] = (fixed["white"], fixed["charcoal"], plain)
    return out


def write_set(directory, files):
    directory.mkdir(parents=True, exist_ok=True)
    for name, image in files.items():
        image.save(directory / name, optimize=True)


def appearance_images(stem):
    return [
        {"filename": f"{stem}.png", "idiom": "universal", "platform": "ios", "size": "1024x1024"},
        {"appearances": [{"appearance": "luminosity", "value": "dark"}], "filename": f"{stem}-dark.png",
         "idiom": "universal", "platform": "ios", "size": "1024x1024"},
        {"appearances": [{"appearance": "luminosity", "value": "tinted"}], "filename": f"{stem}-tinted.png",
         "idiom": "universal", "platform": "ios", "size": "1024x1024"},
    ]


def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def main():
    all_looks = looks()
    info = {"author": "xcode", "version": 1}

    # The primary: its iOS images, next to render.mjs's Mac sizes in the same set.
    primary = ASSETS / "AppIcon.appiconset"
    light, dark, tint = all_looks["violet"]
    write_set(primary, {"AppIcon-ios.png": light, "AppIcon-ios-dark.png": dark, "AppIcon-ios-tinted.png": tint})
    contents = json.loads((primary / "Contents.json").read_text())
    mac = [i for i in contents["images"] if i.get("idiom") == "mac"]
    dump(primary / "Contents.json", {"images": appearance_images("AppIcon-ios") + mac, "info": info})

    PREVIEWS.mkdir(exist_ok=True)
    dump(PREVIEWS / "Contents.json", {"info": info})
    for slug, (light, dark, tint) in all_looks.items():
        if slug != "violet":
            directory = ASSETS / f"AppIcon-{slug}.appiconset"
            for old in directory.glob("*.png"):
                old.unlink()
            write_set(directory, {f"{slug}.png": light, f"{slug}-dark.png": dark, f"{slug}-tinted.png": tint})
            dump(directory / "Contents.json", {"images": appearance_images(slug), "info": info})
        preview = PREVIEWS / f"IconPreview-{slug}.imageset"
        write_set(preview, {
            f"{slug}.png": light.resize((PREVIEW_PX, PREVIEW_PX), Image.LANCZOS),
            f"{slug}-dark.png": dark.resize((PREVIEW_PX, PREVIEW_PX), Image.LANCZOS),
        })
        dump(preview / "Contents.json", {"images": [
            {"filename": f"{slug}.png", "idiom": "universal"},
            {"appearances": [{"appearance": "luminosity", "value": "dark"}], "filename": f"{slug}-dark.png",
             "idiom": "universal"}], "info": info})

    if "--sheet" in sys.argv:
        sheet(all_looks, pathlib.Path(sys.argv[sys.argv.index("--sheet") + 1]))
    print("done", len(all_looks), "icons")


def sheet(all_looks, path):
    """Every icon at 60 pt, masked, on a light and on a dark wallpaper."""
    cell, pad, size = 214, 30, 180
    order = ["violet", "auto"] + [s for s in GROUNDS if s != "violet"]
    width = pad * 2 + len(order) * cell
    canvas = Image.new("RGB", (width, 480))
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, size - 1, size - 1], radius=42, fill=255)
    for row, (background, index) in enumerate((((232, 234, 240), 0), ((20, 22, 30), 1))):
        y = row * 240
        ImageDraw.Draw(canvas).rectangle([0, y, width, y + 240], fill=background)
        for i, slug in enumerate(order):
            canvas.paste(all_looks[slug][index].resize((size, size), Image.LANCZOS), (pad + i * cell, y + 30), mask)
    canvas.save(path)


if __name__ == "__main__":
    main()
