"""README hero: real captures of the Mac, iPad, iPhone and Watch apps on one calm wall (2400 x 1200)."""
import pathlib
from compose import phone, page, render, SHOTS, ROOT

W, H = 2400, 1200


def watch(shot, width):
    from PIL import Image
    w, h = Image.open(shot).size
    pad = round(width * 0.075)
    sw = width - 2 * pad
    sh = round(sw * h / w)
    return f"""<div style="position:relative;width:{width}px;height:{sh+2*pad}px;border-radius:{round(width*0.24)}px;background:#1b1b1e;
      box-shadow:0 0 0 3px #4a4a50 inset,0 0 0 1px rgba(0,0,0,.25),0 30px 60px rgba(40,30,20,.25)">
      <img src="{shot.as_uri()}" style="position:absolute;left:{pad}px;top:{pad}px;width:{sw}px;height:{sh}px;border-radius:{round(sw*0.17)}px"></div>"""


def main():
    mac = SHOTS / "mac-detail.png"
    mw = 1500
    mh = round(mw * 1640 / 2560)
    mac_html = (f"<img src='{mac.as_uri()}' style='position:absolute;left:{(W-mw)//2 - 40}px;top:{H - mh - 120}px;width:{mw}px;height:{mh}px;"
                f"filter:drop-shadow(0 30px 60px rgba(30,24,16,.28)) drop-shadow(0 4px 12px rgba(30,24,16,.18))'>")
    pad_html = f"<div style='position:absolute;left:150px;top:{H-860}px'>{phone(SHOTS/'pad-watchtower.png', 600, 'ipad')}</div>"
    ph_html = f"<div style='position:absolute;left:{W-640}px;top:{H-1000}px'>{phone(SHOTS/'p69-home.png', 420, 'iphone')}</div>"
    w_html = f"<div style='position:absolute;left:{W-300}px;top:{H-380}px'>{watch(SHOTS/'watch-list.png', 230)}</div>"
    body = pad_html + mac_html + ph_html + w_html
    render(page(W, H, "wall-land", body), ROOT / "readme-hero.png", W, H)


if __name__ == "__main__":
    main()
