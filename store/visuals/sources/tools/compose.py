"""Compose App Store slides: a real simulator screenshot in a drawn device frame, a headline and a
background. Rendered with headless Chromium at the exact pixel size, then flattened to RGB (no alpha).

    python3 compose.py            # every slide in SLIDES
    python3 compose.py iphone69   # one set
"""
import glob, json, pathlib, sys, subprocess
from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parents[2]          # store/visuals
SRC = ROOT / "sources"
SHOTS = SRC / "shots"
AI = SRC / "ai"
HTML = SRC / "html"
EXE = glob.glob("/Users/quentin/Library/Caches/ms-playwright/chromium_headless_shell-1217/*/chrome-headless-shell")[0]

INK = "#16161d"
ACCENT = "#4b44c8"

FONT = "-apple-system, 'SF Pro Display', 'Helvetica Neue', sans-serif"


def bg_css(kind):
    if kind == "wall":
        return f"background:#e9e3d9 url('{(AI/'wall-light-portrait.png').as_uri()}') center top/cover no-repeat;"
    if kind == "wall-land":
        return f"background:#e9e3d9 url('{(AI/'wall-light-landscape.png').as_uri()}') center/cover no-repeat;"
    if kind == "dusk":
        return f"background:#0d1320 url('{(AI/'dusk-wall-landscape.png').as_uri()}') left center/cover no-repeat;"
    if kind == "paper":
        return "background:#f2efe9;"
    if kind == "ink":
        return "background:#101118;"
    raise ValueError(kind)


def phone(shot, width, kind="iphone", dark=False):
    """A drawn phone around the real screenshot. width = outer width in px."""
    from PIL import Image
    w, h = Image.open(shot).size
    bezel = round(width * 0.028)
    sw = width - 2 * bezel
    sh = round(sw * h / w)
    if kind == "iphone":
        r_screen = round(sw * 0.142)
        island = (f"<div style='position:absolute;left:50%;top:{bezel + round(sh*0.0143)}px;transform:translateX(-50%);"
                  f"width:{round(sw*0.287)}px;height:{round(sh*0.0385)}px;border-radius:999px;background:#000'></div>")
    else:  # ipad
        r_screen = round(sw * 0.0185)
        island = ""
    r_outer = r_screen + bezel
    return f"""
<div style="position:relative;width:{width}px;height:{sh + 2*bezel}px;border-radius:{r_outer}px;
  background:#121214;box-shadow:0 0 0 {max(2, round(width*0.0022))}px {'#55555c' if dark else '#3a3a3e'} inset,{' 0 0 0 2px rgba(255,255,255,.10),' if dark else ''} 0 {round(width*0.05)}px {round(width*0.12)}px rgba(40,30,20,.22), 0 {round(width*0.01)}px {round(width*0.03)}px rgba(40,30,20,.18);">
  <img src="{shot.as_uri()}" style="position:absolute;left:{bezel}px;top:{bezel}px;width:{sw}px;height:{sh}px;border-radius:{r_screen}px;display:block">
  {island}

</div>"""


def page(W, H, background, body, dark=False):
    color = "#f4f2ee" if dark else INK
    sub = "rgba(244,242,238,.72)" if dark else "rgba(22,22,29,.62)"
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
html,body{{margin:0;width:{W}px;height:{H}px;overflow:hidden}}
body::before{{content:'';position:absolute;inset:0;background:{'rgba(250,247,241,.30)' if background.startswith('wall') else 'transparent'}}}
body{{{bg_css(background)} font-family:{FONT};color:{color};-webkit-font-smoothing:antialiased;position:relative}}
.h{{text-wrap:balance;font-weight:700;letter-spacing:-0.025em;line-height:1.04;margin:0}}
.s{{text-wrap:balance;font-weight:400;color:{sub};letter-spacing:-0.005em;line-height:1.3;margin:0}}
.mark{{color:{ACCENT if not dark else '#a9a4ff'}}}
</style></head><body>{body}</body></html>"""


def portrait_slide(W, H, shot, head, sub, background="wall", device="iphone", dark=False):
    s = W / 1320
    if device == "iphone":
        dev_w = round(W * 0.74)
        top_text = round(150 * s)
        h_size, s_size = round(104 * s), round(46 * s)
    else:
        dev_w = round(W * 0.80)
        top_text = round(150 * s * 0.75)
        h_size, s_size = round(96 * s * 0.72), round(44 * s * 0.72)
    text = (f"<div style='position:absolute;left:0;right:0;top:{top_text}px;text-align:center;padding:0 {round(W*0.08)}px'>"
            f"<p class='h' style='font-size:{h_size}px'>{head}</p>"
            + (f"<p class='s' style='font-size:{s_size}px;margin-top:{round(h_size*0.32)}px'>{sub}</p>" if sub else "")
            + "</div>")
    dev = phone(shot, dev_w, device, dark)
    # device anchored to the bottom with a margin, so every slide of a set lines up
    from PIL import Image
    w, h = Image.open(shot).size
    bezel = round(dev_w * 0.028)
    dev_h = round((dev_w - 2 * bezel) * h / w) + 2 * bezel
    bottom = round(H * 0.045)
    top = H - bottom - dev_h
    body = text + f"<div style='position:absolute;left:{(W-dev_w)//2}px;top:{top}px'>{dev}</div>"
    return page(W, H, background, body, dark)


def mac_slide(W, H, shot, head, sub, background="wall-land", dark=False):
    from PIL import Image
    w, h = Image.open(shot).size
    win_w = round(W * 0.72)
    win_h = round(win_w * h / w)
    h_size, s_size = 96, 42
    top = 112
    text = (f"<div style='position:absolute;left:0;right:0;top:{top}px;text-align:center'>"
            f"<p class='h' style='font-size:{h_size}px'>{head}</p>"
            + (f"<p class='s' style='font-size:{s_size}px;margin-top:22px'>{sub}</p>" if sub else "") + "</div>")
    y = H - win_h - 72
    img = (f"<img src='{shot.as_uri()}' style='position:absolute;left:{(W-win_w)//2}px;top:{y}px;width:{win_w}px;height:{win_h}px;"
           f"filter:drop-shadow(0 30px 60px rgba(30,24,16,.28)) drop-shadow(0 4px 12px rgba(30,24,16,.18))'>"
           f"<div style='position:absolute;left:{(W-win_w)//2}px;top:{y}px;width:{win_w}px;height:{win_h}px;border-radius:{round(win_w*0.0115)}px;"
           f"box-shadow:0 0 0 {2 if dark else 1}px {'rgba(255,255,255,.14)' if dark else 'rgba(0,0,0,.10)'}'></div>")
    return page(W, H, background, text + img, dark)


def render(html, out, W, H):
    out.parent.mkdir(parents=True, exist_ok=True)
    HTML.mkdir(parents=True, exist_ok=True)
    src = HTML / (out.parent.name + "-" + out.stem + ".html")
    src.write_text(html)
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=EXE, args=["--allow-file-access-from-files"])
        pg = b.new_page(viewport={"width": W, "height": H}, device_scale_factor=1)
        pg.goto(src.as_uri())
        pg.wait_for_timeout(400)
        pg.screenshot(path=str(out), full_page=False)
        b.close()
    from PIL import Image
    im = Image.open(out)
    if im.mode != "RGB":
        im.convert("RGB").save(out)
    print(out.relative_to(ROOT), Image.open(out).size, Image.open(out).mode)


if __name__ == "__main__":
    import slides
    only = sys.argv[1:]
    for set_name, (W, H, kind, items) in slides.SETS.items():
        if only and set_name not in only:
            continue
        for i, it in enumerate(items, 1):
            shot = SHOTS / it["shot"]
            if kind == "mac":
                html = mac_slide(W, H, shot, it["head"], it.get("sub"), it.get("bg", "wall-land"), it.get("dark", False))
            else:
                html = portrait_slide(W, H, shot, it["head"], it.get("sub"), it.get("bg", "wall"), kind, it.get("dark", False))
            render(html, ROOT / set_name / f"{i:02d}-{it['name']}.png", W, H)
