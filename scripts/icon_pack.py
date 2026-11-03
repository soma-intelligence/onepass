#!/usr/bin/env python3
"""OnePass site icon pack: brand icons from open sets, keyed by domain, in one signed file.

    icon_pack.py build --simple-icons DIR --logos DIR --twofa DIR --sources FILE
                       --version N --out DIR [--size 256] [--jobs N] [--domains FILE]
                       [--resvg PATH] [--cwebp PATH]
        Reads the three upstream checkouts (untrusted data: SVG text is checked before it is
        drawn, nothing in them runs), rasterizes each kept icon to a square WebP at --size
        pixels, and writes DIR/onepass-icons-<N>.bin (the pack), DIR/icon-pack-manifest.json
        (version, size and SHA-256 of the pack, the upstream commits) and DIR/report.json.
        --sources is a JSON object {"simple-icons": {"commit": ..., "archive_sha256": ...}, ...}.
    icon_pack.py sign --manifest FILE
        Writes FILE.sig: the Ed25519 signature (base64) of the manifest's exact bytes, with the
        key in ICON_PACK_ED_PRIVATE_KEY (a 32-byte seed, base64; never generated here).
    icon_pack.py verify --manifest FILE --pack FILE --public-key B64
        Checks the signature, the pack's size and hash, and that the pack parses.
    icon_pack.py public-key
        Prints the public key of ICON_PACK_ED_PRIVATE_KEY.

The app never asks anyone for one site's icon (that would tell a third party which sites a
person has): it ships a baseline pack and may replace it with a newer whole pack downloaded
from the project's GitHub releases, the same bytes for everyone, accepted only when the
manifest is signed by the key the app trusts.

Pack format 1 (all integers big-endian):
    b"OPIP" | u8 format (1) | u32 index length | index (UTF-8 JSON) | icon bytes
    index = {"format": 1, "version": N, "size": px,
             "icons": [[offset, length, flags], ...],   offsets into the icon bytes
             "domains": {"withings.com": icon number, ...}}
    flags: bit 0 = one color mark (drawn in the text color by the app).

Sources and licenses (docs/icon-pack.md): Simple Icons (CC0-1.0, icons carrying another
license are kept only when it is permissive and needs no attribution in the UI), gilbarbara/logos
(CC0-1.0), 2FA Directory (MIT). Logos stay trademarks of their owners.

Rasterizer: resvg (no scripting, no network; --resources-dir is an empty folder so no local
file is read). WebP: cwebp -lossless. Standard library only otherwise.
"""

import argparse
import base64
import concurrent.futures
import datetime
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import threading
import unicodedata
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import appcast  # noqa: E402  (Ed25519 through OpenSSL, the same code as the signed appcast)

MAGIC = b"OPIP"
FORMAT = 1
FLAG_MONO = 1
MAX_SVG_BYTES = 512 * 1024
# Marks within this width to height ratio fit a square tile; wider ones are wordmarks.
SQUARE = (0.6, 1.6)

# Simple Icons entries that carry their own license are kept only under these.
PERMISSIVE = {"CC0-1.0", "MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "Unlicense", "ISC"}

# Multi-label public suffixes and shared hosting suffixes: never a pack key (mirrors
# SiteIconLoader.multiLabelSuffixes, the app's own list).
SHARED_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "ac.uk", "gov.uk", "nhs.uk", "police.uk",
    "gouv.fr", "asso.fr", "com.fr", "nom.fr", "tm.fr", "prd.fr", "co.at", "or.at", "gv.at", "ac.at",
    "com.es", "org.es", "nom.es", "gob.es", "com.pt", "gov.pt", "com.pl", "net.pl", "org.pl", "gov.pl",
    "com.gr", "gov.gr", "co.hu", "com.ro", "com.ua", "gov.ua", "com.tr", "gov.tr", "org.tr", "co.il",
    "org.il", "gov.il", "ac.il", "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "co.nz",
    "net.nz", "org.nz", "govt.nz", "ac.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "gr.jp",
    "ad.jp", "co.kr", "or.kr", "go.kr", "ac.kr", "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.hk", "org.hk", "gov.hk", "com.tw", "org.tw", "gov.tw", "com.sg", "gov.sg", "edu.sg", "com.my",
    "gov.my", "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in", "co.id", "or.id", "go.id",
    "ac.id", "co.th", "in.th", "go.th", "ac.th", "com.ph", "gov.ph", "com.vn", "gov.vn", "com.pk",
    "gov.pk", "com.bd", "com.br", "net.br", "org.br", "gov.br", "edu.br", "com.mx", "gob.mx", "org.mx",
    "com.ar", "gob.ar", "com.co", "gov.co", "com.pe", "gob.pe", "com.ec", "com.ve", "com.uy", "cl.cl",
    "gob.cl", "co.za", "org.za", "gov.za", "ac.za", "com.eg", "gov.eg", "com.sa", "gov.sa", "com.ng",
    "gov.ng", "co.ke", "or.ke", "co.ma", "gov.ma", "com.tn", "ac.ma", "github.io", "gitlab.io",
    "vercel.app", "netlify.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "appspot.com",
    "herokuapp.com", "azurewebsites.net", "cloudfront.net", "blogspot.com", "s3.amazonaws.com",
    "onrender.com", "fly.dev", "ngrok.io", "ngrok-free.app",
}

# Hosts that hold many brands' files: a Simple Icons `source` there says nothing of the brand's site.
GENERIC_SOURCE_HOSTS = {
    "github.com", "gitlab.com", "wikipedia.org", "wikimedia.org", "commons.wikimedia.org", "brandfolder.com",
    "figma.com", "dribbble.com", "behance.net", "twitter.com", "x.com", "facebook.com", "youtube.com",
    "medium.com", "google.com", "drive.google.com", "docs.google.com", "apple.com", "play.google.com",
    "apps.apple.com", "npmjs.com", "pypi.org", "bitbucket.org", "dropbox.com", "frontify.com",
    "brandfetch.com", "seeklogo.com", "worldvectorlogo.com", "svgrepo.com", "iconify.design",
}

# Ranks, best first. A colored square mark from a CC0 set beats a one color mark.
RANK_LOGOS_ICON = 0
RANK_TWOFA_COLOR = 1
RANK_SIMPLE = 2
RANK_LOGOS_SQUARE = 3
RANK_TWOFA_MONO = 4

UNSAFE_SVG = re.compile(
    rb"<!doctype|<!entity|<script|<foreignobject|<image|<text|<iframe|<embed|<object|<use[^>]*href\s*=\s*[\"'][^#]"
    rb"|@import|javascript:|data:|url\(\s*[\"']?[^#\s\"')]",
    re.I,
)
HREF = re.compile(rb"(?:xlink:)?href\s*=\s*[\"']([^\"']*)[\"']", re.I)


class IconPackError(Exception):
    pass


# --- Names ---------------------------------------------------------------

def normalized_domain(text):
    """A pack key: lower case host without `www.`, at least two labels, never a shared suffix."""
    if not text:
        return None
    host = text.strip().lower()
    host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", host)
    host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split(":", 1)[0].rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+", host):
        return None
    if host in SHARED_SUFFIXES or "." not in host:
        return None
    if re.fullmatch(r"[0-9.]+", host):
        return None
    return host


def registrable(host):
    labels = host.split(".")
    suffix = 1
    for n in range(len(labels), 1, -1):
        if ".".join(labels[-n:]) in SHARED_SUFFIXES:
            suffix = n
            break
    if len(labels) <= suffix:
        return None
    return ".".join(labels[-(suffix + 1):])


def squash(text):
    """Letters and digits only, accents dropped: "Air Canada" and "aircanada" meet."""
    text = unicodedata.normalize("NFD", text.lower().replace("&", "and"))
    return re.sub(r"[^a-z0-9]", "", text)


def simple_icons_slug(entry):
    if entry.get("slug"):
        return entry["slug"]
    title = entry["title"].lower()
    for a, b in {"+": "plus", ".": "dot", "&": "and", "đ": "d", "ħ": "h", "ı": "i", "ĸ": "k", "ŀ": "l",
                 "ł": "l", "ß": "ss", "ŧ": "t", "ø": "o"}.items():
        title = title.replace(a, b)
    return re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFD", title))


# --- SVG -----------------------------------------------------------------

def is_safe_svg(data):
    """Markup with an <svg> root that draws without reading anything else: no DOCTYPE or entity,
    no script, no embedded or external image, no text (fonts differ between machines), and every
    reference inside the document."""
    if len(data) > MAX_SVG_BYTES:
        return False
    head = data.lstrip()[:200].lower()
    if not (head.startswith(b"<svg") or head.startswith(b"<?xml") or head.startswith(b"<!--")):
        return False
    if b"<svg" not in data.lower() or UNSAFE_SVG.search(data):
        return False
    return all(ref.startswith(b"#") for ref in HREF.findall(data))


ROOT_TAG = re.compile(rb"<svg\b[^>]*>", re.I)
NUMBER = rb"(-?[0-9]*\.?[0-9]+(?:e-?[0-9]+)?)"


def view_box(root):
    m = re.search(rb"viewBox\s*=\s*[\"']\s*" + NUMBER + rb"[\s,]+" + NUMBER + rb"[\s,]+" + NUMBER + rb"[\s,]+"
                  + NUMBER + rb"\s*[\"']", root, re.I)
    if m:
        x, y, w, h = (float(v) for v in m.groups())
        return (x, y, w, h) if w > 0 and h > 0 else None
    w = re.search(rb"\swidth\s*=\s*[\"']\s*" + NUMBER + rb"(?:px)?\s*[\"']", root, re.I)
    h = re.search(rb"\sheight\s*=\s*[\"']\s*" + NUMBER + rb"(?:px)?\s*[\"']", root, re.I)
    if w and h and float(w.group(1)) > 0 and float(h.group(1)) > 0:
        return (0.0, 0.0, float(w.group(1)), float(h.group(1)))
    return None


def aspect(data):
    root = ROOT_TAG.search(data)
    box = view_box(root.group(0)) if root else None
    return box[2] / box[3] if box else None


def squared(data, size, fill=None):
    """The SVG with its root made a `size` pixel square around the drawing (centered), and
    `fill` set on the root for a one color set whose paths carry no color."""
    root = ROOT_TAG.search(data)
    if not root:
        raise IconPackError("no <svg> root")
    tag = root.group(0)
    box = view_box(tag)
    if not box:
        raise IconPackError("no viewBox or size")
    x, y, w, h = box
    side = max(w, h)
    x -= (side - w) / 2
    y -= (side - h) / 2
    cleaned = re.sub(rb"\s(?:width|height|viewBox|preserveAspectRatio|x|y)\s*=\s*(\"[^\"]*\"|'[^']*')", b"", tag,
                     flags=re.I)
    if fill:
        cleaned = re.sub(rb"\sfill\s*=\s*(\"[^\"]*\"|'[^']*')", b"", cleaned, flags=re.I)
    closing = b"/>" if cleaned.endswith(b"/>") else b">"
    body = cleaned[: -len(closing)].rstrip()
    attributes = f' width="{size}" height="{size}" viewBox="{x:g} {y:g} {side:g} {side:g}"'
    attributes += ' preserveAspectRatio="xMidYMid meet"'
    if fill:
        attributes += f' fill="#{fill}"'
    return data[: root.start()] + body + attributes.encode() + closing + data[root.end():]


def colors_in(data):
    found = set()
    for m in re.finditer(rb"#([0-9a-f]{6}|[0-9a-f]{3})\b", data, re.I):
        c = m.group(1).decode().lower()
        found.add(c if len(c) == 6 else "".join(ch * 2 for ch in c))
    for m in re.finditer(rb"rgba?\(([^)]*)\)", data, re.I):
        found.add(m.group(1).decode().replace(" ", ""))
    return found


# --- PNG (resvg's output: 8-bit RGBA, not interlaced) ---------------------

def png_rgba(data):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise IconPackError("not a PNG")
    pos, idat, width = 8, b"", None
    while pos < len(data):
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        chunk = data[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            width, height, depth, color, _, _, interlace = struct.unpack(">IIBBBBB", chunk)
            if depth != 8 or color != 6 or interlace:
                raise IconPackError("unexpected PNG layout")
        elif kind == b"IDAT":
            idat += chunk
        pos += 12 + length
    raw = zlib.decompress(idat)
    stride = width * 4
    out = bytearray(stride * height)
    prev = bytearray(stride)
    for row in range(height):
        f = raw[row * (stride + 1)]
        line = bytearray(raw[row * (stride + 1) + 1:(row + 1) * (stride + 1)])
        for i in range(stride):
            a = line[i - 4] if i >= 4 else 0
            b = prev[i]
            c = prev[i - 4] if i >= 4 else 0
            if f == 1:
                line[i] = (line[i] + a) & 255
            elif f == 2:
                line[i] = (line[i] + b) & 255
            elif f == 3:
                line[i] = (line[i] + (a + b) // 2) & 255
            elif f == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        out[row * stride:(row + 1) * stride] = line
        prev = line
    return width, height, bytes(out)


def coverage(width, height, pixels):
    """Share of the square with ink (alpha over 50%)."""
    opaque = sum(1 for i in range(3, len(pixels), 4 * 3) if pixels[i] > 127)
    return opaque / (width * height / 3)


def ink_aspect(width, height, pixels):
    """Width over height of the box around the ink (alpha over 50%)."""
    xs, ys = [], []
    for y in range(height):
        row = pixels[y * width * 4:(y + 1) * width * 4]
        inked = [x for x in range(width) if row[x * 4 + 3] > 127]
        if inked:
            xs += (inked[0], inked[-1])
            ys.append(y)
    if not xs:
        return 1.0
    return (max(xs) - min(xs) + 1) / (max(ys) - min(ys) + 1)


# --- Candidates -----------------------------------------------------------

class Candidate:
    def __init__(self, rank, source, svg, fill=None, mono=False, name=""):
        self.rank, self.source, self.svg, self.fill, self.mono, self.name = rank, source, svg, fill, mono, name


def twofa_entries(root):
    """{domain: (name, image path or None, extra domains)} from 2FA Directory's entries/."""
    out = {}
    for path in sorted((root / "entries").glob("*/*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        for name, entry in data.items():
            if not isinstance(entry, dict):
                continue
            domain = normalized_domain(entry.get("domain") or "")
            if not domain:
                continue
            img_name = entry.get("img") or f"{entry.get('domain')}.svg"
            if "/" in img_name or img_name.startswith("."):
                img_name = ""
            image = root / "img" / img_name[:1].lower() / img_name if img_name else None
            extra = [d for d in (normalized_domain(x) for x in entry.get("additional-domains") or []) if d]
            out[domain] = (str(name), image if image and image.is_file() else None, extra)
    return out


def collect(simple_root, logos_root, twofa_root, log):
    """{domain: [Candidate, ...]} from the three sets."""
    found = {}

    def add(domain, candidate):
        if domain:
            found.setdefault(domain, []).append(candidate)

    twofa = twofa_entries(twofa_root)
    by_name = {}
    for domain, (name, _, extra) in twofa.items():
        by_name.setdefault(squash(re.sub(r"\s*\[.*?\]\s*", "", name)), []).extend([domain, *extra])

    # 2FA Directory: its own image when square (wordmarks are left out: a long word shrunk into a
    # tile reads as noise).
    for domain, (name, image, extra) in twofa.items():
        if not image or image.suffix.lower() != ".svg":
            continue
        data = image.read_bytes()
        if not is_safe_svg(data):
            log("unsafe", f"2fa {image.name}")
            continue
        ratio = aspect(data)
        if not ratio or not SQUARE[0] <= ratio <= SQUARE[1]:
            continue
        colored = len(colors_in(data) - {"ffffff", "000000"}) >= 2
        for d in [domain, *extra]:
            add(d, Candidate(RANK_TWOFA_COLOR if colored else RANK_TWOFA_MONO, "2fa-directory", data,
                             name=f"2fa:{image.name}"))

    # gilbarbara/logos: the square "-icon" variant first, the main file when it is square.
    logos = json.loads((logos_root / "logos.json").read_text(encoding="utf-8"))
    for entry in logos:
        domain = normalized_domain(entry.get("url") or "")
        if not domain or registrable(domain) in GENERIC_SOURCE_HOSTS and squash(entry.get("name", "")) not in squash(domain):
            continue
        files = [f for f in entry.get("files") or [] if re.fullmatch(r"[a-z0-9._-]+\.svg", f)]
        short = entry.get("shortname", "")
        chosen = None
        if f"{short}-icon.svg" in files:
            chosen = (RANK_LOGOS_ICON, f"{short}-icon.svg")
        elif f"{short}.svg" in files:
            chosen = (RANK_LOGOS_SQUARE, f"{short}.svg")
        if not chosen:
            continue
        path = logos_root / "logos" / chosen[1]
        if not path.is_file():
            continue
        data = path.read_bytes()
        if not is_safe_svg(data):
            log("unsafe", f"logos {chosen[1]}")
            continue
        ratio = aspect(data)
        if not ratio or not SQUARE[0] <= ratio <= SQUARE[1]:
            continue
        add(domain, Candidate(chosen[0], "logos", data, name=f"logos:{chosen[1]}"))

    # Simple Icons: one color marks, drawn in the brand's color. The domain is 2FA Directory's for
    # the same name, else the `source` host when its name is the brand's.
    data = json.loads((simple_root / "data" / "simple-icons.json").read_text(encoding="utf-8"))
    entries = data if isinstance(data, list) else data.get("icons", [])
    for entry in entries:
        license_type = (entry.get("license") or {}).get("type")
        if license_type and license_type not in PERMISSIVE:
            log("license", f"simple-icons {entry.get('title')} ({license_type})")
            continue
        hex_color = str(entry.get("hex", "")).upper()
        if not re.fullmatch(r"[0-9A-F]{6}", hex_color):
            continue
        slug = simple_icons_slug(entry)
        path = simple_root / "icons" / f"{slug}.svg"
        if not re.fullmatch(r"[a-z0-9_]+", slug) or not path.is_file():
            continue
        svg = path.read_bytes()
        if not is_safe_svg(svg):
            log("unsafe", f"simple-icons {slug}")
            continue
        title = squash(entry["title"])
        # Exact names first: "GitHub" owns github.com, "GitHub Actions" only reaches it when
        # nothing better does.
        domains = {d: 0.0 for d in by_name.get(title, [])}
        source = normalized_domain(entry.get("source") or "")
        reg = registrable(source) if source else None
        label = (reg or "").split(".")[0]
        if reg and len(label) >= 3 and reg not in domains:
            if label in (title, slug):
                domains[reg] = 0.0
            elif reg not in GENERIC_SOURCE_HOSTS and (
                    (len(title) >= 4 and title in label) or (len(label) >= 4 and label in title)):
                domains[reg] = 0.5
        r, g, b = (int(hex_color[i:i + 2], 16) / 255 for i in (0, 2, 4))
        lum = 0.2126 * r + 0.7152 * g + 0.0722 * b
        mono = max(r, g, b) - min(r, g, b) < 0.12 and (lum < 0.25 or lum > 0.85)
        for d, penalty in sorted(domains.items()):
            add(d, Candidate(RANK_SIMPLE + penalty, "simple-icons", svg, fill="000000" if mono else hex_color, mono=mono,
                             name=f"simple-icons:{slug}"))
    return found


# --- Rendering ------------------------------------------------------------

def render(candidate, size, resvg, cwebp, work):
    svg = squared(candidate.svg, size, candidate.fill)
    source = work / "in.svg"
    png = work / "out.png"
    webp = work / "out.webp"
    source.write_bytes(svg)
    for f in (png, webp):
        if f.exists():
            f.unlink()
    empty = work / "resources"
    empty.mkdir(exist_ok=True)
    result = subprocess.run([resvg, "--resources-dir", str(empty), "--skip-system-fonts", str(source), str(png)],
                            capture_output=True, timeout=60)
    if result.returncode != 0 or not png.exists():
        raise IconPackError("resvg failed: " + result.stderr.decode(errors="replace").strip()[:200])
    # The ink check reads a small copy: decoding the full size in Python would dominate the build.
    small = work / "small.png"
    result = subprocess.run([resvg, "--resources-dir", str(empty), "--skip-system-fonts", "-w", "64", "-h", "64",
                             str(source), str(small)], capture_output=True, timeout=60)
    if result.returncode != 0:
        raise IconPackError("resvg failed on the small copy")
    width, height, pixels = png_rgba(small.read_bytes())
    if coverage(width, height, pixels) < 0.02:
        raise IconPackError("almost empty")
    # A square SVG may still hold a wordmark ("gusto" on a 24 px box): a long word shrunk into a
    # tile reads as noise, the site's own icon or a monogram does better.
    ratio = ink_aspect(width, height, pixels)
    if not SQUARE[0] <= ratio <= SQUARE[1] * 1.4:
        raise IconPackError(f"wordmark (ink {ratio:.2f} wide for 1 high)")
    if png.read_bytes()[16:24] != struct.pack(">II", size, size):
        raise IconPackError("rendered at the wrong size")
    result = subprocess.run([cwebp, "-quiet", "-lossless", "-z", "9", "-exact", "-metadata", "none", str(png), "-o",
                             str(webp)], capture_output=True, timeout=120)
    if result.returncode != 0 or not webp.exists():
        raise IconPackError("cwebp failed: " + result.stderr.decode(errors="replace").strip()[:200])
    return webp.read_bytes()


def pack_bytes(version, size, icons, domains):
    """icons: [(bytes, flags)], domains: {domain: index}."""
    offsets, blob, position = [], bytearray(), 0
    for data, flags in icons:
        offsets.append([position, len(data), flags])
        blob += data
        position += len(data)
    index = json.dumps({"format": FORMAT, "version": version, "size": size, "icons": offsets,
                        "domains": dict(sorted(domains.items()))}, separators=(",", ":"), sort_keys=True).encode()
    return MAGIC + bytes([FORMAT]) + struct.pack(">I", len(index)) + index + bytes(blob)


def read_pack(data):
    """(index, icon bytes) of a pack, every offset checked."""
    if len(data) < 9 or data[:4] != MAGIC or data[4] != FORMAT:
        raise IconPackError("not an icon pack of format 1")
    (length,) = struct.unpack(">I", data[5:9])
    if 9 + length > len(data):
        raise IconPackError("index runs past the end")
    index = json.loads(data[9:9 + length].decode())
    blob = data[9 + length:]
    for offset, size, _ in index["icons"]:
        if offset < 0 or size <= 0 or offset + size > len(blob):
            raise IconPackError("icon runs past the end")
    for number in index["domains"].values():
        if not 0 <= number < len(index["icons"]):
            raise IconPackError("domain points past the icons")
    return index, blob


def build(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    sources = json.loads(Path(args.sources).read_text(encoding="utf-8"))
    skipped = {}

    def log(kind, what):
        skipped.setdefault(kind, []).append(what)

    found = collect(Path(args.simple_icons), Path(args.logos), Path(args.twofa), log)
    if args.domains:
        keep = {d for d in (normalized_domain(x) for x in Path(args.domains).read_text().split()) if d}
        found = {d: c for d, c in found.items() if d in keep}
    # Each domain's best candidate is drawn; a domain whose candidate fails moves to its next one.
    queues = {d: sorted(c, key=lambda c: (c.rank, c.name)) for d, c in found.items()}
    results = {}  # (svg sha, fill) -> (webp bytes, flags) or None
    icons, numbers, domains, chosen = [], {}, {}, {}

    def key_of(candidate):
        return (hashlib.sha256(candidate.svg).hexdigest(), candidate.fill)

    with tempfile.TemporaryDirectory() as tmp:
        local = threading.local()

        def draw(candidate):
            if not hasattr(local, "work"):
                local.work = Path(tempfile.mkdtemp(dir=tmp))
            try:
                return render(candidate, args.size, args.resvg, args.cwebp, local.work), None
            except (IconPackError, subprocess.TimeoutExpired) as error:
                return None, f"{candidate.name}: {error}"

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            while queues:
                wanted = {}
                for domain, queue in queues.items():
                    k = key_of(queue[0])
                    if k not in results:
                        wanted.setdefault(k, queue[0])
                for k, (data, error) in zip(wanted, pool.map(draw, wanted.values())):
                    results[k] = (data, FLAG_MONO if wanted[k].mono else 0) if data else None
                    if error:
                        log("render", error)
                for domain in sorted(queues):
                    queue = queues[domain]
                    k = key_of(queue[0])
                    if results[k] is None:
                        queue.pop(0)
                        if not queue:
                            del queues[domain]
                        continue
                    if k not in numbers:
                        numbers[k] = len(icons)
                        icons.append(results[k])
                    domains[domain] = numbers[k]
                    chosen[domain] = queue[0].name
                    del queues[domain]
    pack = pack_bytes(args.version, args.size, icons, domains)
    read_pack(pack)
    name = f"onepass-icons-{args.version}.bin"
    (out / name).write_bytes(pack)
    manifest = {
        "format": FORMAT,
        "version": args.version,
        "created": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
        "pack": {"file": name, "size": len(pack), "sha256": hashlib.sha256(pack).hexdigest()},
        "icons": len(icons),
        "domains": len(domains),
        "pixels": args.size,
        "sources": sources,
    }
    (out / "icon-pack-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    report = {"chosen": dict(sorted(chosen.items())), "skipped": {k: sorted(v) for k, v in skipped.items()}}
    (out / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(f"{len(domains)} domains, {len(icons)} icons, {len(pack)} bytes -> {out / name}")
    return 0


def seed_from_environment():
    value = os.environ.get("ICON_PACK_ED_PRIVATE_KEY")
    if not value:
        raise IconPackError("ICON_PACK_ED_PRIVATE_KEY is not set")
    try:
        return appcast.load_seed(value)
    except appcast.AppcastError as error:
        raise IconPackError(str(error)) from None


def verify_files(manifest_path, pack_path, public_b64):
    manifest_bytes = Path(manifest_path).read_bytes()
    signature = base64.b64decode(Path(str(manifest_path) + ".sig").read_text().strip(), validate=True)
    public = base64.b64decode(public_b64, validate=True)
    if not appcast.verify(public, manifest_bytes, signature):
        raise IconPackError("the manifest signature does not verify")
    manifest = json.loads(manifest_bytes)
    pack = Path(pack_path).read_bytes()
    if len(pack) != manifest["pack"]["size"] or hashlib.sha256(pack).hexdigest() != manifest["pack"]["sha256"]:
        raise IconPackError("the pack does not match the manifest")
    index, _ = read_pack(pack)
    if index["version"] != manifest["version"]:
        raise IconPackError("the pack's version is not the manifest's")
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--simple-icons", required=True)
    b.add_argument("--logos", required=True)
    b.add_argument("--twofa", required=True)
    b.add_argument("--sources", required=True)
    b.add_argument("--version", required=True, type=int)
    b.add_argument("--size", type=int, default=256)
    b.add_argument("--out", required=True)
    b.add_argument("--resvg", default="resvg")
    b.add_argument("--cwebp", default="cwebp")
    b.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    b.add_argument("--domains", help="a file of domains: build only those (previews)")
    s = sub.add_parser("sign")
    s.add_argument("--manifest", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--manifest", required=True)
    v.add_argument("--pack", required=True)
    v.add_argument("--public-key", required=True)
    sub.add_parser("public-key")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            if not 64 <= args.size <= 1024:
                raise IconPackError("--size must be 64 to 1024")
            return build(args)
        if args.command == "sign":
            seed = seed_from_environment()
            signature = appcast.sign(seed, Path(args.manifest).read_bytes())
            Path(args.manifest + ".sig").write_text(base64.b64encode(signature).decode() + "\n")
            return 0
        if args.command == "verify":
            manifest = verify_files(args.manifest, args.pack, args.public_key)
            print(f"ok: version {manifest['version']}, {manifest['domains']} domains")
            return 0
        if args.command == "public-key":
            print(base64.b64encode(appcast.public_key(seed_from_environment())).decode())
            return 0
    except (IconPackError, appcast.AppcastError, OSError, ValueError) as error:
        print(f"icon_pack: {error}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
