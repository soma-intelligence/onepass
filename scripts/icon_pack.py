#!/usr/bin/env python3
"""OnePass site icon pack: brand icons from open sets, keyed by domain, in one signed file.

    icon_pack.py build --simple-icons DIR --logos DIR --twofa DIR --sources FILE
                       --version N --out DIR [--size 256] [--jobs N] [--sites DIR]
                       [--domains FILE]... [--blocklist FILE]
                       [--platforms FILE] [--wikidata DIR] [--resvg PATH] [--cwebp PATH]
        Reads the three upstream checkouts (untrusted data: SVG text is checked before it is
        drawn, nothing in them runs), rasterizes each kept icon to a square WebP at --size
        pixels, and writes DIR/onepass-icons-<N>.bin (the pack), DIR/icon-pack-manifest.json
        (version, size and SHA-256 of the pack, the upstream commits) and DIR/report.json.
        --sources is a JSON object {"simple-icons": {"commit": ..., "archive_sha256": ...}, ...}.
    icon_pack.py sites [--curated FILE] [--domains FILE]... [--blocklist FILE] [--platforms FILE] --out DIR
        Fetches, at build time only, the icon of every curated brand that uses its site and, with
        --domains, of every popular domain listed (plain text, one per line), at least 128 px, into DIR (domains in DIR/domains and DIR/domains.json),
        and the icon of every hosting platform (--platforms, default scripts/icon-pack-platforms.txt)
        into DIR/platforms and DIR/platforms.json.
    icon_pack.py wikidata --out DIR [--blocklist FILE] [--platforms FILE] [--page-size N] [--max-pages N]
                          [--dry-run]
        Asks Wikidata (SPARQL, paged, build time only) for items with an official website (P856)
        and a logo (P154), keeps each item's current logo and each domain's item with the most
        sitelinks, and downloads from Wikimedia Commons the public domain and CC0 files (SHA-1
        checked) into DIR/files, with DIR/wikidata.json. `build --wikidata DIR` uses them after
        the curated list and before the open sets. --dry-run prints the query and fetches nothing.
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
    optional keys: "names", "tenants", and "rejects": dHashes (16 lowercase hex digits, sorted) of
    hosting-platform icons (a gym portal serving its software vendor's favicon), which the app
    never shows as a site's icon; "platforms": sorted icon numbers of hosting platforms (an icon
    with a domain of --platforms, or a subdomain of one), which the app never shows as another
    site's parent brand (its own domain still gets it).
    flags: bit 0 = one color mark (drawn in the text color by the app);
           bit 1 (value 2) = a 128 px icon from a popular-domain list (--domains), the others
           being `size` px.

Sources and licenses (docs/icon-pack.md): Simple Icons (CC0-1.0, icons carrying another
license are kept only when it is permissive and needs no attribution in the UI), gilbarbara/logos
(CC0-1.0), 2FA Directory (MIT). Logos stay trademarks of their owners.

Rasterizer: resvg (no scripting, no network; --resources-dir is an empty folder so no local
file is read). WebP: cwebp -lossless; an icon over --max-icon-bytes (MAX_ICON_BYTES) is encoded
again with loss; a Wikidata logo still over it is refused, so the domain moves to its next
candidate (an icon from any other source is kept with loss). Standard library only otherwise.
"""

import argparse
import base64
import concurrent.futures
import datetime
import hashlib
import html
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
FLAG_DOMAIN_LIST = 2
# Icons from a popular-domain list are smaller than the hand-picked and open-set ones.
DOMAIN_SIZE = 128
MIN_DOMAIN_PIXELS = 128
MAX_SVG_BYTES = 512 * 1024
# The pack ships inside the app: 25,000 icons fit about 60 MB only at about 6 KB each. A detailed
# crest or a photo is over it, and reads poorly in a small tile anyway.
MAX_ICON_BYTES = 6 * 1024
LOSSY = ["-q", "80", "-alpha_q", "90", "-m", "6", "-sharp_yuv"]
# Marks within this width to height ratio fit a square tile; wider ones are wordmarks.
SQUARE = (0.6, 1.6)
# A hand-picked wordmark ("Aēsop") may be this wide for 1 high, no wider.
WORDMARK_MAX = 4.5

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
RANK_DOMAIN_LIST = 9

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


def cropped(data, view):
    """The SVG with its root's box set to `view` ("x y width height"): the part of a logo that
    is the mark, without what sits beside it (a registered sign that is noise at list size)."""
    numbers = view.split() if isinstance(view, str) else []
    try:
        x, y, w, h = (float(n) for n in numbers)
    except ValueError:
        raise IconPackError(f"bad view {view!r}") from None
    if w <= 0 or h <= 0:
        raise IconPackError(f"bad view {view!r}")
    root = ROOT_TAG.search(data)
    if not root:
        raise IconPackError("no <svg> root")
    tag = root.group(0)
    cleaned = re.sub(rb"\s(?:width|height|viewBox|preserveAspectRatio|x|y)\s*=\s*(\"[^\"]*\"|'[^']*')", b"", tag,
                     flags=re.I)
    closing = b"/>" if cleaned.endswith(b"/>") else b">"
    body = cleaned[: -len(closing)].rstrip() + f' viewBox="{x:g} {y:g} {w:g} {h:g}"'.encode() + closing
    return data[: root.start()] + body + data[root.end():]


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


DHASH_MAX_SIDE = 4096


def dhash(rgba_png):
    """64-bit difference hash of a PNG, identical to VaultKit's IconHash.dHash.

    Composite over white (straight alpha), gray = 0.299 R + 0.587 G + 0.114 B,
    area-average to 9 columns x 8 rows (each cell averages the source pixels it
    overlaps, weighted by overlap), then bit = cell[row][x] > cell[row][x + 1] + 1e-9
    (the margin keeps flat images at 0 despite rounding noise), row by row, first
    bit most significant. Raises IconPackError for anything but a sane 8-bit RGBA PNG
    (at most 4096 x 4096), so callers can skip the icon."""
    if len(rgba_png) < 33 or rgba_png[:8] != b"\x89PNG\r\n\x1a\n" or rgba_png[12:16] != b"IHDR":
        raise IconPackError("not a PNG")
    w, h = struct.unpack(">II", rgba_png[16:24])
    if not (0 < w <= DHASH_MAX_SIDE and 0 < h <= DHASH_MAX_SIDE):
        raise IconPackError("PNG too large to hash")
    try:
        width, height, px = png_rgba(rgba_png)
    except (struct.error, zlib.error, IndexError) as error:
        raise IconPackError("unreadable PNG: %s" % error)
    if len(px) != width * height * 4:
        raise IconPackError("unreadable PNG")
    gray = []
    for i in range(0, width * height * 4, 4):
        a = float(px[i + 3])
        r, g, b = (float(px[i + k]) * a / 255.0 + 255.0 * (1.0 - a / 255.0) for k in range(3))
        gray.append(0.299 * r + 0.587 * g + 0.114 * b)

    def spans(count, cells):
        out = []
        for c in range(cells):
            lo, hi = float(c * count) / float(cells), float((c + 1) * count) / float(cells)
            first, last = int(lo), min(count - 1, int(hi))
            out.append((lo, hi, [(i, min(float(i + 1), hi) - max(float(i), lo)) for i in range(first, last + 1)
                                  if min(float(i + 1), hi) - max(float(i), lo) > 0.0]))
        return out

    cols, rows = spans(width, 9), spans(height, 8)
    cells = []
    for ylo, yhi, ys in rows:
        line = []
        for xlo, xhi, xs in cols:
            total = 0.0
            for y, wy in ys:
                acc = 0.0
                for x, wx in xs:
                    acc += gray[y * width + x] * wx
                total += acc * wy
            line.append(total / ((xhi - xlo) * (yhi - ylo)))
        cells.append(line)
    bits = 0
    for line in cells:
        for x in range(8):
            bits = (bits << 1) | (1 if line[x] > line[x + 1] + 1e-9 else 0)
    return bits


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
    def __init__(self, rank, source, svg, fill=None, mono=False, name="", brand="", tile=None, curated=False):
        self.rank, self.source, self.svg, self.fill, self.mono, self.name = rank, source, svg, fill, mono, name
        # brand: the brand's name in its set (a title with no URL finds its icon by it); tile: a
        # background color drawn under the mark; curated: chosen by hand (scripts/icon-pack-curated.json).
        self.brand, self.tile, self.curated = brand, tile, curated
        # wordmark: a hand-picked brand whose whole name is its mark ("Aēsop"), kept wider than a tile.
        self.wordmark = False
        # size: pixels this candidate is drawn at (None: the build's --size); flags: extra index flags.
        self.size, self.flags = None, 0
        # license: the file's own license when the source names one per icon (Wikidata/Commons).
        self.license = None


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
                             name=f"2fa:{image.name}", brand=name))

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
        add(domain, Candidate(chosen[0], "logos", data, name=f"logos:{chosen[1]}", brand=entry.get("name", "")))

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
                             name=f"simple-icons:{slug}", brand=entry["title"]))
    return found


RANK_CURATED = -1
LICENSES = {"simple-icons": "CC0-1.0", "logos": "CC0-1.0", "2fa-directory": "MIT",
            "brand": "trademark of its owner, the brand's own icon (app or site) as a browser or the App Store shows it",
            "commons": "public domain (Wikimedia Commons, PD-textlogo), trademark of its owner",
            "wikidata": "public domain or CC0 (Wikimedia Commons file named by Wikidata P154), trademark of its owner"}


def simple_icon(simple_root, slug):
    data = json.loads((simple_root / "data" / "simple-icons.json").read_text(encoding="utf-8"))
    for entry in data if isinstance(data, list) else data.get("icons", []):
        if simple_icons_slug(entry) == slug:
            return entry
    return None


def curated_candidates(curated, roots, sites, log):
    """{domain: Candidate} for the hand-picked brands: they beat every automatic match. A brand
    whose source is missing (a site that was not fetched) is left to the automatic match."""
    simple_root, logos_root, twofa_root = roots
    out = {}
    for entry in curated.get("brands", []):
        use, domains = entry.get("use", ""), [d for d in (normalized_domain(x) for x in entry.get("domains", [])) if d]
        if not domains or use == "none":
            continue
        kind, _, ref = use.partition(":")
        candidate = None
        if kind == "commons":
            # A vector logo from Wikimedia Commons, fetched by `sites` (hash pinned there).
            path = sites / domains[0] if sites else None
            data = path.read_bytes() if path and path.is_file() else b""
            if not data:
                log("curated", f"{domains[0]}: no fetched icon")
                continue
            if not is_safe_svg(data):
                log("curated", f"{domains[0]}: fetched file is not a safe SVG")
                continue
            candidate = Candidate(RANK_CURATED, "commons", data, name=f"brand:{domains[0]}")
        elif kind == "site":
            path = sites / domains[0] if sites else None
            if path and path.is_file():
                data = path.read_bytes()
                if is_safe_svg(data):
                    svg = data
                elif raster_mime(data) and raster_size(data):
                    svg = raster_svg(data)
                else:
                    log("curated", f"{domains[0]}: fetched file is neither a safe SVG nor an image")
                    continue
                candidate = Candidate(RANK_CURATED, "brand", svg, name=f"brand:{domains[0]}")
            else:
                log("curated", f"{domains[0]}: no fetched icon")
        elif kind in ("simple-icons", "logos", "2fa") and re.fullmatch(r"[a-z0-9._-]+", ref):
            if kind == "simple-icons":
                meta = simple_icon(simple_root, ref)
                path = simple_root / "icons" / f"{ref}.svg"
            elif kind == "logos":
                meta, path = {}, logos_root / "logos" / ref
            else:
                meta, path = {}, twofa_root / "img" / ref[:1] / ref
            data = path.read_bytes() if path.is_file() else b""
            if not data or not is_safe_svg(data) or (kind == "simple-icons" and not meta):
                log("curated", f"{domains[0]}: {use} missing or unsafe")
                continue
            fill, mono = None, False
            if kind == "simple-icons":
                fill = str(meta["hex"]).upper()
                r, g, b = (int(fill[i:i + 2], 16) / 255 for i in (0, 2, 4))
                lum = 0.2126 * r + 0.7152 * g + 0.0722 * b
                mono = max(r, g, b) - min(r, g, b) < 0.12 and (lum < 0.25 or lum > 0.85)
                fill = "000000" if mono else fill
            source = {"2fa": "2fa-directory"}.get(kind, kind)
            candidate = Candidate(RANK_CURATED, source, data, fill=fill, mono=mono, name=use)
        else:
            log("curated", f"{domains[0]}: unknown source {use!r}")
            continue
        if candidate:
            candidate.brand, candidate.curated = entry.get("name", ""), True
            view = entry.get("view")
            if view:
                try:
                    candidate.svg = cropped(candidate.svg, view)
                except IconPackError as error:
                    log("curated", f"{domains[0]}: {error}")
                    continue
            if entry.get("mono") is True:
                # A black mark drawn in the text color by the app, like a one color Simple Icons mark.
                candidate.fill, candidate.mono = "000000", True
            candidate.wordmark = entry.get("wordmark") is True
            tile = entry.get("tile")
            if tile and re.fullmatch(r"[0-9A-Fa-f]{6}", tile):
                candidate.tile, candidate.mono = tile.upper(), False
            for d in domains:
                out[d] = candidate
    return out


# --- Brand sites (curated list, fetched at build time only) ----------------

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
LINK_TAG = re.compile(r"<link\b[^>]*>", re.I)
ATTR = re.compile(r"""([a-z:-]+)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""", re.I)
MIN_SITE_PIXELS = 180


def raster_size(data):
    """(width, height) of a PNG, JPEG or WebP from its header, else None."""
    if data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
        return struct.unpack(">II", data[16:24])
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP" and len(data) >= 30:
        kind = data[12:16]
        if kind == b"VP8X":
            return (1 + int.from_bytes(data[24:27], "little"), 1 + int.from_bytes(data[27:30], "little"))
        if kind == b"VP8L":
            bits = int.from_bytes(data[21:25], "little")
            return (1 + (bits & 0x3FFF), 1 + ((bits >> 14) & 0x3FFF))
        if kind == b"VP8 ":
            return (int.from_bytes(data[26:28], "little") & 0x3FFF, int.from_bytes(data[28:30], "little") & 0x3FFF)
        return None
    if data[:2] == b"\xff\xd8":
        pos = 2
        while pos + 9 < len(data):
            if data[pos] != 0xFF:
                return None
            marker = data[pos + 1]
            length = int.from_bytes(data[pos + 2:pos + 4], "big")
            if marker in (0xC0, 0xC1, 0xC2):
                h, w = struct.unpack(">HH", data[pos + 5:pos + 9])
                return (w, h)
            pos += 2 + length
    return None


def png_from_rgba(width, height, rows):
    """An 8-bit RGBA PNG of `rows` (top-down, width * 4 bytes each)."""
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + row for row in rows)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def ico_largest(data):
    """The largest image of a .ico as PNG bytes: its own PNG, or its 32-bit bitmap converted. None
    when it holds neither."""
    if data[:4] != b"\x00\x00\x01\x00" or len(data) < 6:
        return None
    count = struct.unpack("<H", data[4:6])[0]
    best = None
    for i in range(min(count, 64)):
        entry = data[6 + 16 * i:22 + 16 * i]
        if len(entry) < 16:
            break
        side = entry[0] or 256
        size, offset = struct.unpack("<II", entry[8:16])
        if offset + size <= len(data) and (not best or side > best[0]):
            best = (side, data[offset:offset + size])
    if not best:
        return None
    payload = best[1]
    if payload[:8] == b"\x89PNG\r\n\x1a\n":
        return payload
    if len(payload) < 40:
        return None
    header, width, height, _, bits = struct.unpack("<IiiHH", payload[:16])
    height //= 2
    if bits != 32 or width <= 0 or height <= 0 or width > 1024 or height > 1024:
        return None
    start = header
    if start + width * height * 4 > len(payload):
        return None
    rows = []
    for y in range(height - 1, -1, -1):  # bottom-up BGRA
        row = payload[start + y * width * 4:start + (y + 1) * width * 4]
        rows.append(b"".join(bytes((row[i + 2], row[i + 1], row[i], row[i + 3])) for i in range(0, len(row), 4)))
    return png_from_rgba(width, height, rows)


def raster_mime(data):
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[:2] == b"\xff\xd8":
        return "image/jpeg"
    return None


def raster_svg(data):
    """An SVG of the raster image alone, so resvg scales it like any mark (the build's own markup:
    the image arrives as base64 data, never as a reference)."""
    w, h = raster_size(data)
    uri = f"data:{raster_mime(data)};base64,{base64.b64encode(data).decode()}"
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}">'
            f'<image width="{w}" height="{h}" href="{uri}"/></svg>').encode()


def icon_links(html, base):
    """Icon URLs a page declares (apple-touch-icon and icon links, the web app manifest), with the
    size each declares (0 when it does not say)."""
    import urllib.parse
    found, manifest = [], None
    for tag in LINK_TAG.findall(html):
        attrs = {k.lower(): v.strip("\"'") for k, v in ATTR.findall(tag)}
        rel = attrs.get("rel", "").lower().split()
        href = attrs.get("href")
        if not href:
            continue
        url = urllib.parse.urljoin(base, href)
        if "manifest" in rel:
            manifest = url
        elif "apple-touch-icon" in rel or "apple-touch-icon-precomposed" in rel or "icon" in rel:
            sizes = [int(n) for n in re.findall(r"(\d+)x\d+", attrs.get("sizes", ""))]
            touch = "apple-touch-icon" in " ".join(rel)
            found.append((url, max(sizes) if sizes else (180 if touch else 0)))
    return found, manifest


def fetch_url(url, limit, headers=None, timeout=20):
    """(bytes, final URL after redirects), https only. `headers` replace or add to the defaults."""
    import http.client
    import urllib.request
    if not url.startswith("https://"):
        raise IconPackError("not https")
    request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            final = response.geturl()
            if not final.startswith("https://"):
                raise IconPackError("redirected off https")
            data = response.read(limit + 1)
    except http.client.HTTPException as error:
        # A cut or malformed response (IncompleteRead, BadStatusLine...) is a connection error:
        # callers skip the site, and Wikimedia requests are retried.
        raise ConnectionError(f"bad HTTP response: {type(error).__name__}") from error
    if len(data) > limit:
        raise IconPackError("too large")
    return data, final


def fetch(url, limit):
    return fetch_url(url, limit)[0]


def site_icon(page, fetcher=None, google=True, min_pixels=MIN_SITE_PIXELS, hosts=None):
    """The largest icon of a brand's own site: PNG, JPEG or WebP of at least `min_pixels`, or a
    safe square SVG. Returns (url, bytes, pixels) or raises. `fetcher(url, limit)` returns
    (bytes, final URL) (default fetch_url; tests point it at a local server); `google` allows the
    copy Google keeps; `hosts`, a set, collects the host the page itself ended on after redirects."""
    import urllib.parse
    fetcher = fetcher or fetch_url

    def get(url, limit):
        return fetcher(url, limit)[0]

    candidates, final = [], page
    try:
        data, final = fetcher(page, 3 * 1024 * 1024)
        if hosts is not None:
            hosts.add(urllib.parse.urlsplit(final).hostname or "")
        html = data.decode("utf-8", "replace")
        links, manifest = icon_links(html, final)
        candidates += links
        if manifest:
            try:
                data = json.loads(get(manifest, 512 * 1024))
                for icon in data.get("icons") or []:
                    sizes = [int(n) for n in re.findall(r"(\d+)x\d+", str(icon.get("sizes", "")))]
                    if icon.get("src") and "monochrome" not in str(icon.get("purpose", "")):
                        candidates.append((urllib.parse.urljoin(manifest, icon["src"]), max(sizes) if sizes else 0))
            except (OSError, ValueError, IconPackError):
                pass
    except (OSError, ValueError, IconPackError):
        pass
    parts = urllib.parse.urlsplit(final)
    root = f"{parts.scheme}://{parts.netloc}/"
    candidates += [(root + "apple-touch-icon.png", 180), (root + "apple-touch-icon-precomposed.png", 180),
                   (root + "favicon.ico", 1)]
    # Google's copy of the site's own icon (at build time only, never from the app): many sites
    # turn scripts away (403, 429) or list only a small favicon in their markup. It returns the
    # icon at its own size, never scaled up, so the size check below still holds.
    if google:
        candidates.append(("https://t1.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL"
                           f"&url={urllib.parse.quote(root, safe='')}&size=256", 2))
    best = None
    for url, declared in sorted(set(candidates), key=lambda c: -c[1]):
        if best and declared and declared < best[2]:
            continue
        try:
            data = get(url, 2 * 1024 * 1024)
        except (OSError, ValueError, IconPackError):
            continue
        if data[:4] == b"\x00\x00\x01\x00":
            data = ico_largest(data) or b""
        if data.lstrip()[:5].lower() in (b"<svg ", b"<?xml") and is_safe_svg(data):
            ratio = aspect(data)
            if ratio and 0.9 <= ratio <= 1.1:
                return url, data, 10000
            continue
        size = raster_size(data) if raster_mime(data) else None
        if not size or min(size) < min_pixels or not 0.9 <= size[0] / size[1] <= 1.1:
            continue
        if not best or min(size) > best[2]:
            best = (url, data, min(size))
    if not best:
        raise IconPackError(f"no icon of {min_pixels} px or more on {page}")
    return best


def app_icon(track_id, seller):
    """The brand's own App Store icon (its iOS app, by track id), 256 px PNG, when the app's
    seller is the brand (`seller`, case-insensitive substring)."""
    import urllib.parse
    data = json.loads(fetch("https://itunes.apple.com/lookup?" + urllib.parse.urlencode({"id": int(track_id)}),
                            512 * 1024))
    results = data.get("results") or []
    if not results:
        raise IconPackError(f"no app {track_id}")
    app = results[0]
    if seller.lower() not in str(app.get("sellerName", "")).lower():
        raise IconPackError(f"app {track_id} is sold by {app.get('sellerName')!r}, not {seller!r}")
    art = str(app.get("artworkUrl512") or "")
    if not re.fullmatch(r"https://[a-z0-9.-]+\.mzstatic\.com/[^?#]+/512x512bb\.(jpg|png)", art):
        raise IconPackError(f"app {track_id}: unexpected artwork URL")
    url = art.rsplit("/", 1)[0] + "/256x256bb.png"
    image = fetch(url, 2 * 1024 * 1024)
    size = raster_size(image) if raster_mime(image) else None
    if not size or min(size) < MIN_SITE_PIXELS:
        raise IconPackError(f"app {track_id}: artwork too small")
    return url, image, min(size)


COMMONS_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _().,'-]*\.svg")
COMMONS_UPLOAD = re.compile(r"https://upload\.wikimedia\.org/wikipedia/commons/[0-9a-f]/[0-9a-f]{2}/[^?#/]+\.svg")


def commons_svg(name, sha1):
    """A logo file of Wikimedia Commons (a text logo there is public domain), pinned by the SHA-1
    Commons lists for it: a new upload of the file is refused until someone looks at it and moves
    the pin. Returns (url, bytes)."""
    import urllib.parse
    if not COMMONS_FILE.fullmatch(name) or not re.fullmatch(r"[0-9a-f]{40}", sha1 or ""):
        raise IconPackError(f"commons:{name}: needs a file name and its sha1")
    query = urllib.parse.urlencode({"action": "query", "titles": "File:" + name, "prop": "imageinfo",
                                    "iiprop": "url|sha1", "format": "json"})
    pages = json.loads(fetch("https://commons.wikimedia.org/w/api.php?" + query, 512 * 1024))["query"]["pages"]
    info = (list(pages.values())[0].get("imageinfo") or [{}])[0]
    url = str(info.get("url", "")).split("?")[0]
    if not COMMONS_UPLOAD.fullmatch(url):
        raise IconPackError(f"commons:{name}: unexpected file URL")
    data = fetch(url, MAX_SVG_BYTES)
    if hashlib.sha1(data).hexdigest() != sha1:
        raise IconPackError(f"commons:{name}: the file changed on Commons (sha1 pin)")
    if not is_safe_svg(data):
        raise IconPackError(f"commons:{name}: not a safe SVG")
    return url, data


def fetch_sites(curated, out, log):
    """Fetches the icon of every curated entry that uses its site, into `out` (one file per entry
    and sites.json: where each came from, its hash and size)."""
    out.mkdir(parents=True, exist_ok=True)
    record = {}
    for entry in curated["brands"]:
        if not entry.get("domains"):
            continue
        key = entry["domains"][0]
        if str(entry.get("use", "")).startswith("commons:"):
            try:
                url, data = commons_svg(entry["use"].partition(":")[2], entry.get("sha1", ""))
            except (IconPackError, OSError, ValueError, KeyError) as error:
                log("site", f"{key}: {error}")
                continue
            (out / key).write_bytes(data)
            record[key] = {"url": url, "sha256": hashlib.sha256(data).hexdigest(), "license": LICENSES["commons"],
                           "fetched": datetime.date.today().isoformat()}
            print(f"{key}: {url} (vector)")
            continue
        if entry.get("use") != "site":
            continue
        got, errors = None, []
        # The brand's own app icon first (square, made for a tile), then its site's icon.
        if entry.get("app"):
            try:
                got = app_icon(entry["app"], entry["seller"])
            except (IconPackError, OSError, ValueError) as error:
                errors.append(str(error))
        if not got and entry.get("site"):
            try:
                got = site_icon(entry["site"])
            except (IconPackError, OSError, ValueError) as error:
                errors.append(str(error))
        if not got:
            log("site", f"{key}: {'; '.join(errors) or 'no app and no site'}")
            continue
        url, data, pixels = got
        (out / key).write_bytes(data)
        record[key] = {"url": url, "sha256": hashlib.sha256(data).hexdigest(), "pixels": pixels,
                       "fetched": datetime.date.today().isoformat()}
        print(f"{key}: {url} ({pixels} px)")
    (out / "sites.json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")
    return record


# --- Popular domains (a list, fetched at build time only) ------------------

DEFAULT_BLOCKLIST = Path(__file__).resolve().parent / "icon-pack-blocklist.txt"


def read_domain_lists(paths):
    """[domain, ...] from plain text list files (one domain per line, `#` comments). Each entry
    becomes its registrable domain (the app finds a subdomain's icon through its parent), once, in
    list order. A line with a comma (a ranked CSV) is refused: no list records its provenance."""
    seen, out = set(), []
    for path in paths:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if "," in line:
                raise IconPackError(f"{Path(path).name}: one domain per line, no CSV")
            host = normalized_domain(line)
            domain = registrable(host) if host else None
            if domain and domain not in seen:
                seen.add(domain)
                out.append(domain)
    return out


class Blocklist:
    """Domains that never get an icon. A line is a domain (`bad.example`, `www.` ignored: it and every
    subdomain of it, so m.bad.example is blocked too) or `*.suffix` (the suffix itself and every host
    under it, so `*.xxx` is a whole top-level domain)."""

    def __init__(self, exact=(), suffixes=()):
        self.exact, self.suffixes = frozenset(exact), tuple(suffixes)

    @staticmethod
    def _host(text):
        host = text.strip().lower().rstrip(".")
        return host[4:] if host.startswith("www.") else host

    def blocks(self, host):
        host = self._host(host or "")
        if not host:
            return False
        labels = host.split(".")
        # The host and each parent name (m.shop.co.uk, shop.co.uk): a multi-part public suffix such as
        # co.uk is only blocked if a line names it.
        if any(".".join(labels[i:]) in self.exact for i in range(len(labels))):
            return True
        return any(host == s or host.endswith("." + s) for s in self.suffixes)


def load_blocklist(path):
    exact, suffixes = set(), set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        if line.startswith("*."):
            suffixes.add(line[2:])
        else:
            exact.add(Blocklist._host(line))
    return Blocklist(exact, suffixes)


def curated_domains(curated):
    """Every domain the hand-picked list names, `use: none` included (curated always wins)."""
    return {d for entry in curated.get("brands", []) for d in (normalized_domain(x) for x in entry.get("domains", [])) if d}


def fetch_domains(domains, skip, blocklist, out, log, fetcher=None, google=True, jobs=8, folder="domains",
                  min_pixels=MIN_DOMAIN_PIXELS):
    """Fetches each listed domain's own icon (at least `min_pixels`) into out/<folder>/<domain>
    and out/<folder>.json. The icon belongs to the domain as listed, whatever the site redirects to.
    A listed domain, or the host its page ends on, that the blocklist names is dropped. Returns
    (record, blocked domains)."""
    (out / folder).mkdir(parents=True, exist_ok=True)

    def one(domain):
        hosts = set()
        try:
            url, data, pixels = site_icon(f"https://{domain}/", fetcher, google, min_pixels, hosts)
        except (IconPackError, OSError, ValueError) as error:
            return domain, None, str(error), hosts
        return domain, (url, data, pixels), None, hosts

    todo, blocked = [], []
    for domain in domains:
        if domain in skip:
            continue
        (blocked if blocklist.blocks(domain) else todo).append(domain)
    record = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        for domain, got, error, hosts in pool.map(one, todo):
            if any(blocklist.blocks(h) for h in hosts):
                blocked.append(domain)
                continue
            if not got:
                log("domain", f"{domain}: {error}")
                continue
            url, data, pixels = got
            (out / folder / domain).write_bytes(data)
            record[domain] = {"url": url, "sha256": hashlib.sha256(data).hexdigest(), "pixels": pixels,
                              "final_hosts": sorted(hosts),
                              "fetched": datetime.date.today().isoformat()}
    (out / f"{folder}.json").write_text(json.dumps({"fetched": record, "blocked": sorted(blocked)}, indent=1, sort_keys=True) + "\n")
    return record, sorted(blocked)


# --- Hosting platforms (their icons are never a brand's logo) --------------

DEFAULT_PLATFORMS = Path(__file__).resolve().parent / "icon-pack-platforms.txt"
# A platform's favicon may be small: the app keeps site icons from 32 px on.
MIN_PLATFORM_PIXELS = 32
# Two icons whose dHashes differ in at most this many bits are the same icon (the app uses the same).
REJECT_DISTANCE = 6
# An icon shared by this many different brands (registrable domains with different names) belongs to
# the platform that hosts them, not to any of them.
SHARED_BRANDS = 3
# Side of the PNG each site icon is drawn at to be hashed.
HASH_PIXELS = 128
# A dHash with fewer or more bits set says little about the icon (a flat tile hashes 0): it is never a
# reject and never matches one (IconPack.minHashBits / maxHashBits in the app).
MIN_HASH_BITS = 8
MAX_HASH_BITS = 56


def fetch_platforms(platforms, out, log, fetcher=None, google=True, jobs=8):
    """Fetches the own icon of every hosting platform (daxko.com, okta.com, wix.com...) into
    out/platforms/<domain> and out/platforms.json, with the same fetcher as the brands. Returns the
    record."""
    record, _ = fetch_domains(platforms, set(), Blocklist(), out, log, fetcher, google, jobs, folder="platforms",
                              min_pixels=MIN_PLATFORM_PIXELS)
    return record


def source_svg(data):
    """The SVG resvg draws for a fetched icon: the file itself when it is a safe SVG, else the raster
    image embedded (`raster_svg`); None for anything else."""
    if is_safe_svg(data):
        return data
    if raster_mime(data) and raster_size(data):
        return raster_svg(data)
    return None


def platform_svgs(sites, platforms):
    """{platform domain: SVG} for the platform icons `sites` fetched into sites/platforms."""
    out = {}
    for domain in platforms:
        file = sites / "platforms" / domain
        if file.is_file():
            svg = source_svg(file.read_bytes())
            if svg:
                out[domain] = svg
    return out


def icon_hash(svg, resvg, work):
    """dHash of `svg` drawn by resvg in a HASH_PIXELS square (the rendered PNG, never the raw
    download: the app hashes its own normalized copy too)."""
    try:
        source, png = work / "hash.svg", work / "hash.png"
        source.write_bytes(squared(svg, HASH_PIXELS))
        if png.exists():
            png.unlink()
        empty = work / "resources"
        empty.mkdir(exist_ok=True)
        result = subprocess.run([resvg, "--resources-dir", str(empty), "--skip-system-fonts", str(source), str(png)],
                                capture_output=True, timeout=60)
        if result.returncode != 0 or not png.exists():
            raise IconPackError("resvg failed: " + result.stderr.decode(errors="replace").strip()[:200])
        return dhash(png.read_bytes())
    except (OSError, subprocess.TimeoutExpired) as error:
        raise IconPackError(f"cannot hash: {error}") from None


def distance(a, b):
    return bin(a ^ b).count("1")


def informative(value):
    """A hash with enough structure to identify an icon: MIN_HASH_BITS to MAX_HASH_BITS bits set."""
    return MIN_HASH_BITS <= bin(value).count("1") <= MAX_HASH_BITS


def brand_label(domain):
    """The brand a domain names: its registrable domain's first label, squashed (brand.com and
    brand.co.uk give "brand")."""
    reg = registrable(domain) or domain
    return squash(reg.split(".")[0])


def find_rejects(icons, platform_hashes=()):
    """Sorted hashes of platform icons: every platform's own icon, plus each site icon hash that
    SHARED_BRANDS or more different brands serve (icons within REJECT_DISTANCE, counted by
    `brand_label`, so one brand's own domains count once). icons: [(domain, hash)]. A hash that is
    not `informative` (a flat tile) is left out on both sides."""
    labels = {}
    for domain, value in icons:
        if informative(value):
            labels.setdefault(value, set()).add(brand_label(domain))
    rejects = {value for value in platform_hashes if informative(value)}
    values = list(labels)
    for value in values:
        near = set()
        for other in values:
            if distance(value, other) <= REJECT_DISTANCE:
                near |= labels[other]
        if len(near) >= SHARED_BRANDS:
            rejects.add(value)
    return sorted(rejects)


def is_rejected(value, rejects):
    return informative(value) and any(informative(r) and distance(value, r) <= REJECT_DISTANCE for r in rejects)


# Candidates that are a site's own icon, fetched by `sites` (curated `site` brands, domain lists).
SITE_SOURCES = {"brand", "domain-list"}


def reject_platform_icons(found, sites, platforms, resvg, jobs, log):
    """Hashes every fetched site icon among the candidates and every platform icon (each drawn by
    resvg, `icon_hash`), finds the rejects (`find_rejects`), and drops from `found` each site icon
    that matches one: it must not ship as a brand's logo. A platform's own domain keeps its icon.
    Returns (rejects, dropped domains)."""
    digest = {}

    def key(svg):
        k = digest.get(id(svg))
        if k is None:
            k = digest[id(svg)] = hashlib.sha256(svg).hexdigest()
        return k

    owners = {}  # one entry per fetched file: a curated brand's candidate serves all its domains
    for domain, candidates in found.items():
        for c in candidates:
            if c.source in SITE_SOURCES and id(c) not in owners:
                owners[id(c)] = (c.name.partition(":")[2] or domain, c)
    shared = platform_svgs(sites, platforms)
    todo = {key(c.svg): c.svg for _, c in owners.values()}
    todo.update({key(svg): svg for svg in shared.values()})
    hashes = {}
    with tempfile.TemporaryDirectory() as tmp:
        local = threading.local()

        def one(item):
            k, svg = item
            if not hasattr(local, "work"):
                local.work = Path(tempfile.mkdtemp(dir=tmp))
            try:
                return k, icon_hash(svg, resvg, local.work), None
            except IconPackError as error:
                return k, None, str(error)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
            for k, value, error in pool.map(one, sorted(todo.items())):
                if value is None:
                    log("hash", f"{k[:12]}: {error}")
                else:
                    hashes[k] = value
    icons = [(owner, hashes[key(c.svg)]) for owner, c in owners.values() if key(c.svg) in hashes]
    rejects = find_rejects(icons, [hashes[key(svg)] for svg in shared.values() if key(svg) in hashes])
    own = {registrable(d) or d for d in platforms}
    dropped = set()
    for domain in sorted(found):
        kept = []
        for c in found[domain]:
            value = hashes.get(key(c.svg)) if c.source in SITE_SOURCES else None
            if value is not None and is_rejected(value, rejects) and (registrable(domain) or domain) not in own:
                dropped.add(domain)
                log("platform-icon", f"{domain}: {c.name}")
                continue
            kept.append(c)
        if kept:
            found[domain] = kept
        else:
            del found[domain]
    return rejects, sorted(dropped)


def domain_candidates(listed, skip, blocklist, sites, log):
    """({domain: Candidate}, stats) for the listed domains `sites` fetched: icons drawn at DOMAIN_SIZE
    with FLAG_DOMAIN_LIST. Skipped: curated domains, blocklisted ones (listed domain or recorded final
    host), sources under MIN_DOMAIN_PIXELS."""
    path = sites / "domains.json"
    recorded = json.loads(path.read_text(encoding="utf-8")).get("fetched", {}) if path.is_file() else {}
    out, stats = {}, {"fetched": 0, "kept": 0, "blocked": 0}
    for domain in listed:
        file = sites / "domains" / domain
        if domain in skip or not file.is_file():
            continue
        stats["fetched"] += 1
        meta = recorded.get(domain, {})
        hosts = list(meta.get("final_hosts") or []) + ([meta["final_host"]] if meta.get("final_host") else [])
        if blocklist.blocks(domain) or any(blocklist.blocks(h) for h in hosts):
            stats["blocked"] += 1
            log("domain-blocked", domain)
            continue
        data = file.read_bytes()
        if is_safe_svg(data):
            svg = data
        elif raster_mime(data) and raster_size(data):
            if min(raster_size(data)) < MIN_DOMAIN_PIXELS:
                log("domain-small", f"{domain}: source under {MIN_DOMAIN_PIXELS} px")
                continue
            svg = raster_svg(data)
        else:
            log("domain", f"{domain}: neither a safe SVG nor an image")
            continue
        candidate = Candidate(RANK_DOMAIN_LIST, "domain-list", svg, name=f"domain:{domain}")
        candidate.size, candidate.flags = DOMAIN_SIZE, FLAG_DOMAIN_LIST
        out[domain] = candidate
    return out, stats


# --- Wikidata + Wikimedia Commons (fetched at build time only) ---------------

WIKIDATA_SPARQL = "https://query.wikidata.org/sparql"
COMMONS_API = "https://commons.wikimedia.org/w/api.php"
# Polite and generic: names the tool and its public repository, nothing about who runs it.
WIKI_UA = "OnePass icon pack builder (https://github.com/soma-intelligence/onepass)"
# Between the hand-picked list and the open sets.
RANK_WIKIDATA = -0.5
# A Wikidata logo wider than this for 1 high is a wordmark: dropped (only the curated list keeps one).
WIKIDATA_WORDMARK = 2.6
WIKIDATA_PAGE = 2000
WIKIDATA_MAX_PAGES = 200
SPARQL_LIMIT = 64 * 1024 * 1024
COMMONS_BATCH = 50
COMMONS_JSON_LIMIT = 4 * 1024 * 1024
# The per-icon download caps of the other sources: SVG text, and a raster image as `site_icon` takes it.
MAX_RASTER_BYTES = 2 * 1024 * 1024
RETRY_ATTEMPTS = 5
WIKI_TIMEOUT = 60
RETRY_MAX_WAIT = 300
# Commons LicenseShortName values kept: public domain and CC0 only (no per-icon attribution).
KEPT_LICENSE = re.compile(r"public domain|pd|pd-[a-z0-9._-]+|cc0|cc0[ -]1\.0", re.I)
COMMONS_TITLE = re.compile(r"[^/\\#<>\[\]{}|:\x00-\x1f\x7f]{1,240}\.(svg|png|jpe?g|webp)", re.I)
FILE_PATH = re.compile(r"https?://commons\.wikimedia\.org/wiki/Special:FilePath/(.+)")
COMMONS_ORIGINAL = re.compile(r"https://upload\.wikimedia\.org/wikipedia/commons/[0-9a-f]/[0-9a-f]{2}/[^?#/]+")
WIKIDATA_FILE = re.compile(r"files/[0-9a-f]{40}\.(svg|png|jpg|webp)")
FORMATS = {"image/svg+xml": "svg", "image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}
# An official website on these hosts is a page about the brand on someone else's service, not the
# brand's own site: social networks, app stores, link hubs, code and file hosts (plus the platform list).
NOT_A_BRAND_SITE = {
    "facebook.com", "fb.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "youtube.com", "youtu.be",
    "tiktok.com", "pinterest.com", "reddit.com", "tumblr.com", "vk.com", "ok.ru", "weibo.com", "weibo.cn", "t.me",
    "telegram.me", "threads.net", "threads.com", "snapchat.com", "mastodon.social", "bsky.app", "discord.gg",
    "discord.com", "twitch.tv", "flickr.com", "soundcloud.com", "bandcamp.com", "myspace.com", "vimeo.com",
    "medium.com", "substack.com", "patreon.com",
    "apps.apple.com", "itunes.apple.com", "play.google.com", "apps.microsoft.com", "chrome.google.com",
    "chromewebstore.google.com", "appgallery.huawei.com", "galaxystore.samsung.com", "f-droid.org",
    "linktr.ee", "beacons.ai", "lnk.bio", "bio.link", "carrd.co", "about.me", "campsite.bio", "taplink.cc",
    "solo.to", "linkin.bio", "allmylinks.com", "flow.page", "bit.ly", "tinyurl.com", "goo.gl", "linkfly.to",
    "sourceforge.net", "codeberg.org", "sites.google.com", "archive.org", "web.archive.org",
} | GENERIC_SOURCE_HOSTS


def kept_license(short_name):
    """True for a Commons LicenseShortName that is public domain or CC0."""
    text = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]*>", "", str(short_name or "")))).strip()
    return bool(KEPT_LICENSE.fullmatch(text))


def license_name(short_name):
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]*>", "", str(short_name or "")))).strip() or "(none)"


def retry_after(error):
    try:
        value = int(str(error.headers.get("Retry-After", "")).strip())
    except (AttributeError, ValueError):
        return None
    return value if value >= 0 else None


def with_retries(call, sleep=None, attempts=RETRY_ATTEMPTS):
    """call() again after 429 or 5xx (Retry-After when the server sends seconds, else 2, 4, 8... s), and
    after a connection error or a timeout (2, 4, 8... s), at most `attempts` calls in all."""
    import socket
    import time
    import urllib.error
    sleep = sleep or time.sleep
    for attempt in range(attempts):
        try:
            return call()
        except urllib.error.HTTPError as error:
            if (error.code != 429 and not 500 <= error.code <= 599) or attempt == attempts - 1:
                raise
            wait = retry_after(error)
            sleep(min(RETRY_MAX_WAIT, wait if wait is not None else 2 ** (attempt + 1)))
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError):
            if attempt == attempts - 1:
                raise
            sleep(min(RETRY_MAX_WAIT, 2 ** (attempt + 1)))
    raise IconPackError("unreachable")


def wiki_get(url, limit, accept="*/*", sleep=None):
    """GET from a Wikimedia host through `fetch_url` (https only), with WIKI_UA and retries."""
    # A SPARQL page can take tens of seconds on a busy endpoint.
    return with_retries(lambda: fetch_url(url, limit, {"User-Agent": WIKI_UA, "Accept": accept}, WIKI_TIMEOUT)[0], sleep)


def wikidata_query(limit, offset):
    """One page of items with an official website (P856) and a logo (P154): every statement with its
    rank, the logo's start and end time qualifiers, the item's sitelink count and label."""
    limit, offset = int(limit), int(offset)
    return (
        "SELECT ?item ?itemLabel ?sitelinks ?logoStatement ?logo ?logoRank ?logoStart ?logoEnd\n"
        "       ?siteStatement ?site ?siteRank WHERE {\n"
        "  { SELECT DISTINCT ?item WHERE { ?item wdt:P154 ?anyLogo ; wdt:P856 ?anySite . }\n"
        f"    ORDER BY ?item LIMIT {limit} OFFSET {offset} }}\n"
        "  ?item wikibase:sitelinks ?sitelinks .\n"
        "  ?item p:P154 ?logoStatement .\n"
        "  ?logoStatement ps:P154 ?logo ; wikibase:rank ?logoRank .\n"
        "  OPTIONAL { ?logoStatement pq:P580 ?logoStart . }\n"
        "  OPTIONAL { ?logoStatement pq:P582 ?logoEnd . }\n"
        "  ?item p:P856 ?siteStatement .\n"
        "  ?siteStatement ps:P856 ?site ; wikibase:rank ?siteRank .\n"
        '  SERVICE wikibase:label { bd:serviceParam wikibase:language "en,mul,fr". }\n'
        "}"
    )


def sparql_url(query):
    import urllib.parse
    return WIKIDATA_SPARQL + "?" + urllib.parse.urlencode({"query": query, "format": "json"})


def _binding(row, name):
    value = row.get(name)
    return str(value.get("value", "")) if isinstance(value, dict) else ""


def _rank(uri):
    return {"PreferredRank": "preferred", "NormalRank": "normal", "DeprecatedRank": "deprecated"}.get(
        uri.rsplit("#", 1)[-1], "deprecated")


def _time(text):
    """(year, month, day) of an xsd:dateTime, None for anything else (an unknown value)."""
    m = re.match(r"([+-]?\d{1,16})-(\d{2})-(\d{2})T", text or "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def commons_title(value):
    """The Commons file title of a P154 value (a Special:FilePath URL), None when it is not a plain
    image file name. The title is only ever sent as a query parameter, never used as a path."""
    import urllib.parse
    m = FILE_PATH.fullmatch(value or "")
    if not m:
        return None
    title = urllib.parse.unquote(m.group(1)).replace("_", " ").strip()
    if title.startswith(".") or not COMMONS_TITLE.fullmatch(title):
        return None
    return title


def wikidata_items(bindings, items=None):
    """{Q id: {"label", "sitelinks", "logos": {statement: {...}}, "sites": {statement: {...}}}} from
    SPARQL result rows (one row per logo statement, site statement and qualifier value)."""
    items = {} if items is None else items
    for row in bindings:
        qid = _binding(row, "item").rsplit("/", 1)[-1]
        if not re.fullmatch(r"Q[1-9][0-9]*", qid):
            continue
        item = items.setdefault(qid, {"label": "", "sitelinks": 0, "logos": {}, "sites": {}})
        label = _binding(row, "itemLabel").strip()
        if label and label != qid:
            item["label"] = label
        try:
            item["sitelinks"] = max(item["sitelinks"], int(_binding(row, "sitelinks") or 0))
        except ValueError:
            pass
        logo = _binding(row, "logo")
        if logo:
            statement = item["logos"].setdefault(_binding(row, "logoStatement") or logo, {
                "file": commons_title(logo), "rank": _rank(_binding(row, "logoRank")), "starts": [], "ended": False})
            start = _time(_binding(row, "logoStart"))
            if start and start not in statement["starts"]:
                statement["starts"].append(start)
            # Any end time, an unknown one too, means the logo is no longer in use.
            if "logoEnd" in row:
                statement["ended"] = True
        site = _binding(row, "site")
        if site:
            item["sites"].setdefault(_binding(row, "siteStatement") or site,
                                     {"url": site, "rank": _rank(_binding(row, "siteRank"))})
    return items


def current_logo(logos):
    """The item's current logo file: deprecated statements and ended ones (P582) left out, preferred
    rank first, then the latest start time (P580); file name order settles the rest."""
    live = sorted((s for s in logos.values() if s["file"] and s["rank"] != "deprecated" and not s["ended"]),
                  key=lambda s: s["file"])
    pool = [s for s in live if s["rank"] == "preferred"] or live
    if not pool:
        return None
    return max(pool, key=lambda s: (1, max(s["starts"])) if s["starts"] else (0, (0, 0, 0)))["file"]


def site_domains(item, refuse):
    """[(domain, None)] or [(None, reason)]: each non-deprecated official website's host, lower case
    without `www.`. refuse(host) gives a reason to leave a host out, or None."""
    out = []
    for statement in item["sites"].values():
        if statement["rank"] == "deprecated":
            continue
        url = statement["url"]
        domain = normalized_domain(url) if re.match(r"https?://", url, re.I) else None
        if not domain:
            out.append((None, "bad-domain", url))
            continue
        reason = refuse(domain)
        out.append((None, reason, domain) if reason else (domain, None, domain))
    return out


def wikidata_refusal(blocklist, platforms):
    hubs = Blocklist(NOT_A_BRAND_SITE)
    hosted = Blocklist(platforms)

    def refuse(domain):
        if hubs.blocks(domain):
            return "not-a-brand-site"
        if hosted.blocks(domain):
            return "platform"
        if blocklist.blocks(domain):
            return "blocklist"
        return None
    return refuse


def fetch_wikidata(out, blocklist, platforms, fetcher=None, page_size=WIKIDATA_PAGE, max_pages=WIKIDATA_MAX_PAGES,
                   now=None):
    """Queries Wikidata for items with an official website and a logo, picks each item's current logo
    and each domain's item (most sitelinks; the others are conflicts), asks Commons for each file's
    URL, SHA-1, size and license, and downloads the public domain and CC0 ones into out/files
    (named by SHA-1) with out/wikidata.json. fetcher(url, limit, accept) -> bytes (default wiki_get).
    Returns the record written."""
    import urllib.parse
    fetcher = fetcher or wiki_get
    now = now or datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    dropped = {}

    def drop(reason, what):
        dropped.setdefault(reason, []).append(what)

    page_errors = []

    def read_json(url, limit, accept, what):
        """The parsed response, asked twice at most when it is cut short (bad JSON on a 200), over
        the cap or not answered after the fetcher's own retries (timeout, connection); None (and a
        page error) when the second answer is no better."""
        for attempt in range(2):
            try:
                # strict=False: labels on Wikidata may hold raw control characters (tabs, newlines).
                return json.loads(fetcher(url, limit, accept), strict=False)
            except (ValueError, IconPackError, OSError) as error:
                if attempt == 1:
                    page_errors.append(f"{what}: {str(error)[:200]}")
        return None

    items, failed = {}, 0
    for page in range(max(1, int(max_pages))):
        data = read_json(sparql_url(wikidata_query(page_size, page * page_size)), SPARQL_LIMIT,
                         "application/sparql-results+json", f"sparql offset {page * page_size}")
        try:
            bindings = data["results"]["bindings"] if data is not None else None
            if not isinstance(bindings, list):
                raise TypeError
        except (KeyError, TypeError):
            if data is not None:
                page_errors.append(f"sparql offset {page * page_size}: no results")
            failed += 1
            if failed >= 2:
                break  # two pages in a row lost: the endpoint is not answering, stop asking
            continue
        failed = 0
        # A page is full when it holds page_size distinct items; an item seen on an earlier page may
        # come back (the order is only stable per query), so it is counted, not taken as the end.
        distinct = {_binding(row, "item") for row in bindings if isinstance(row, dict)} - {""}
        before = len(items)
        wikidata_items(bindings, items)
        if len(distinct) < page_size or len(items) == before:
            break
    else:
        drop("page-limit", f"stopped after {max_pages} pages")

    refuse = wikidata_refusal(blocklist, platforms)
    claims = {}  # domain -> [(sitelinks, qid)]
    logo_of = {}
    for qid in sorted(items, key=lambda q: int(q[1:])):
        item = items[qid]
        logo = current_logo(item["logos"])
        if not logo:
            drop("no-current-logo", qid)
            continue
        domains = []
        for domain, reason, what in site_domains(item, refuse):
            if reason:
                drop(reason, f"{qid} {what}")
            elif domain not in domains:
                domains.append(domain)
        if not domains:
            continue
        logo_of[qid] = logo
        for domain in domains:
            claims.setdefault(domain, []).append((item["sitelinks"], qid))
    owner, conflicts = {}, {}
    for domain, entries in sorted(claims.items()):
        entries.sort(key=lambda e: (-e[0], int(e[1][1:])))
        owner[domain] = entries[0][1]
        if len(entries) > 1:
            conflicts[domain] = {"kept": entries[0][1], "others": [q for _, q in entries[1:]]}

    titles = sorted({logo_of[q] for q in set(owner.values())})
    info = {}
    for start in range(0, len(titles), COMMONS_BATCH):
        batch = titles[start:start + COMMONS_BATCH]
        query = urllib.parse.urlencode({
            "action": "query", "format": "json", "formatversion": "2", "prop": "imageinfo",
            "iiprop": "url|sha1|size|mime|extmetadata", "iiextmetadatafilter": "LicenseShortName",
            "titles": "|".join("File:" + t for t in batch)})
        data = read_json(COMMONS_API + "?" + query, COMMONS_JSON_LIMIT, "application/json",
                         f"commons batch {start // COMMONS_BATCH + 1}")
        if not isinstance(data, dict):
            continue
        names = {n.get("to"): n.get("from") for n in (data.get("query") or {}).get("normalized") or []}
        pages = (data.get("query") or {}).get("pages") or []
        for page in pages.values() if isinstance(pages, dict) else pages:
            title = str(page.get("title", ""))
            title = names.get(title, title)
            title = title[5:] if title.startswith("File:") else title
            if page.get("missing") or not page.get("imageinfo"):
                continue
            info[title.replace("_", " ")] = page["imageinfo"][0]

    licenses, files = {}, {}
    for title in titles:
        meta = info.get(title)
        if not meta:
            drop("missing-on-commons", title)
            continue
        short = ((meta.get("extmetadata") or {}).get("LicenseShortName") or {}).get("value")
        name = license_name(short)
        counts = licenses.setdefault(name, {"kept": 0, "dropped": 0})
        if not kept_license(short):
            counts["dropped"] += 1
            drop("license", f"{title} ({name})")
            continue
        try:
            files[title] = commons_file(title, meta, fetcher, out)
            files[title]["license"] = name
            counts["kept"] += 1
        except IconPackError as error:
            reason, _, detail = str(error).partition(": ")
            counts["dropped"] += 1
            drop(reason, f"{title}: {detail}" if detail else title)
        except (OSError, ValueError) as error:
            counts["dropped"] += 1
            drop("download", f"{title}: {error}")

    domains = {}
    for domain, qid in sorted(owner.items()):
        got = files.get(logo_of[qid])
        if got:
            domains[domain] = dict(got, item=qid, label=items[qid]["label"], sitelinks=items[qid]["sitelinks"],
                                   file=logo_of[qid])
    record = {"queried": now.isoformat(), "endpoint": WIKIDATA_SPARQL, "user_agent": WIKI_UA,
              "items": len(items), "domains": domains, "licenses": dict(sorted(licenses.items())),
              "dropped": {k: sorted(v) for k, v in sorted(dropped.items())}, "conflicts": conflicts,
              "page_errors": page_errors}
    out.mkdir(parents=True, exist_ok=True)
    (out / "wikidata.json").write_text(json.dumps(record, indent=1, sort_keys=True, ensure_ascii=False) + "\n",
                                       encoding="utf-8")
    return record


def commons_original(url):
    """The file URL without the tracking query Commons now appends (utm_source, utm_campaign...).
    Any other query or a fragment is left in place, so the URL check refuses it."""
    import urllib.parse
    parts = urllib.parse.urlsplit(url)
    if parts.query and not parts.fragment:
        keys = [key for key, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)]
        if keys and all(key.startswith("utm_") for key in keys):
            return urllib.parse.urlunsplit(parts._replace(query=""))
    return url


def commons_file(title, meta, fetcher, out):
    """Downloads one Commons original after its checks (format, size, shape, URL, then SHA-1 of the
    bytes, SVG safety or raster header) into out/files/<sha1>.<ext>. Raises IconPackError
    "<reason>: <detail>"."""
    kind = FORMATS.get(str(meta.get("mime", "")))
    if not kind:
        raise IconPackError(f"format: {meta.get('mime')}")
    limit = MAX_SVG_BYTES if kind == "svg" else MAX_RASTER_BYTES
    size, width, height = (int(meta.get(k) or 0) for k in ("size", "width", "height"))
    if size > limit:
        raise IconPackError(f"too-large: {size} bytes")
    if width and height and width / height > WIKIDATA_WORDMARK:
        raise IconPackError(f"wordmark: {width / height:.2f} wide for 1 high")
    if kind != "svg" and width and height and min(width, height) < MIN_SITE_PIXELS:
        raise IconPackError(f"small: {width}x{height}")
    url = commons_original(str(meta.get("url", "")))
    sha1 = str(meta.get("sha1", "")).lower()
    if not COMMONS_ORIGINAL.fullmatch(url):
        raise IconPackError(f"url: {url[:120]}")
    if not re.fullmatch(r"[0-9a-f]{40}", sha1):
        raise IconPackError("sha1: missing")
    data = fetcher(url, limit, "*/*")
    if len(data) > limit:
        raise IconPackError("too-large: over the cap")
    if hashlib.sha1(data).hexdigest() != sha1:
        raise IconPackError("sha1: the bytes are not the file Commons lists")
    if kind == "svg":
        if not is_safe_svg(data):
            raise IconPackError("unsafe-svg")
        ratio = aspect(data)
        if not ratio:
            raise IconPackError("unsafe-svg: no viewBox or size")
    else:
        dims = raster_size(data) if raster_mime(data) else None
        if not dims or min(dims) < MIN_SITE_PIXELS:
            raise IconPackError("small: not an image of %d px or more" % MIN_SITE_PIXELS)
        ratio = dims[0] / dims[1]
    if ratio > WIKIDATA_WORDMARK:
        raise IconPackError(f"wordmark: {ratio:.2f} wide for 1 high")
    path = f"files/{sha1}.{kind}"
    (out / "files").mkdir(parents=True, exist_ok=True)
    (out / path).write_bytes(data)
    return {"path": path, "sha1": sha1, "sha256": hashlib.sha256(data).hexdigest(), "url": url}


def wikidata_candidates(folder, skip, blocklist, platforms, log):
    """({domain: Candidate}, record, drops) from the folder `wikidata` wrote. Every file is checked
    again (path shape, SHA-256, SVG safety or raster header, shape): the folder is build input.
    Skipped: curated domains (curated wins), hosts refused since (blocklist, platforms)."""
    record = json.loads((folder / "wikidata.json").read_text(encoding="utf-8"))
    refuse = wikidata_refusal(blocklist, platforms)
    curated_parent = Blocklist(skip)
    out, drops, shared = {}, {}, {}

    def drop(reason, what):
        drops[reason] = drops.get(reason, 0) + 1
        log("wikidata", f"{what}: {reason}")

    for domain, entry in sorted((record.get("domains") or {}).items()):
        if normalized_domain(domain) != domain or not isinstance(entry, dict):
            drop("bad-domain", domain)
            continue
        if domain in skip:
            drop("curated", domain)
            continue
        if curated_parent.blocks(domain):
            # The app finds a subdomain's icon through its parent: this one would hide the curated icon.
            drop("subdomain-of-curated", domain)
            continue
        reason = refuse(domain)
        if reason:
            drop(reason, domain)
            continue
        path = str(entry.get("path", ""))
        qid = str(entry.get("item", ""))
        if not WIKIDATA_FILE.fullmatch(path) or not re.fullmatch(r"Q[1-9][0-9]*", qid):
            drop("bad-record", domain)
            continue
        file = folder / path
        data = file.read_bytes() if file.is_file() else b""
        if not data or hashlib.sha256(data).hexdigest() != entry.get("sha256"):
            drop("file-changed", domain)
            continue
        if path.endswith(".svg"):
            if not is_safe_svg(data):
                drop("unsafe-svg", domain)
                continue
            svg, ratio = data, aspect(data)
        elif raster_mime(data) and raster_size(data):
            w, h = raster_size(data)
            svg, ratio = raster_svg(data), (w / h if h else None)
        else:
            drop("format", domain)
            continue
        if not ratio or ratio > WIKIDATA_WORDMARK:
            drop("wordmark", domain)
            continue
        candidate = shared.get(path)
        if candidate is None:
            candidate = shared[path] = Candidate(RANK_WIKIDATA, "wikidata", svg, name=f"wikidata:{qid}",
                                                 brand=str(entry.get("label") or ""))
            candidate.license = str(entry.get("license") or "")
        out[domain] = candidate
    return out, record, drops


# --- Rendering ------------------------------------------------------------

def tiled(svg, size, color):
    """`svg` (already squared to `size`) drawn at 62% in the middle of a full square of `color`:
    an app icon, for a mark that only reads on its brand color (Snapchat's ghost on yellow)."""
    inner = size * 0.62
    offset = (size - inner) / 2
    root = ROOT_TAG.search(svg)
    body = svg[root.start():]
    body = re.sub(rb'\swidth="[^"]*"\sheight="[^"]*"', f' x="{offset:g}" y="{offset:g}" width="{inner:g}" height="{inner:g}"'.encode(),
                  body[:root.end() - root.start()], count=1) + body[root.end() - root.start():]
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
            f'<rect width="{size}" height="{size}" fill="#{color}"/>').encode() + body + b"</svg>"


def render(candidate, size, resvg, cwebp, work, max_bytes=None):
    svg = squared(candidate.svg, size, candidate.fill)
    if candidate.tile:
        svg = tiled(svg, size, candidate.tile)
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
    # A hand-picked mark may be a short word ("hue"); a long one is still refused, unless the
    # whole name is the brand's mark (curated `wordmark`), set wide in the tile by the app.
    low, high = (0.4, 2.6) if candidate.curated else (SQUARE[0], SQUARE[1] * 1.4)
    if candidate.curated and candidate.wordmark:
        high = WORDMARK_MAX
    if not low <= ratio <= high:
        raise IconPackError(f"wordmark (ink {ratio:.2f} wide for 1 high)")
    if png.read_bytes()[16:24] != struct.pack(">II", size, size):
        raise IconPackError("rendered at the wrong size")
    result = subprocess.run([cwebp, "-quiet", "-lossless", "-z", "9", "-exact", "-metadata", "none", str(png), "-o",
                             str(webp)], capture_output=True, timeout=120)
    if result.returncode != 0 or not webp.exists():
        raise IconPackError("cwebp failed: " + result.stderr.decode(errors="replace").strip()[:200])
    data = webp.read_bytes()
    if max_bytes is None or len(data) <= max_bytes:
        return data
    webp.unlink()
    result = subprocess.run([cwebp, "-quiet", *LOSSY, "-metadata", "none", str(png), "-o", str(webp)],
                            capture_output=True, timeout=120)
    if result.returncode != 0 or not webp.exists():
        raise IconPackError("cwebp failed: " + result.stderr.decode(errors="replace").strip()[:200])
    lossy = webp.read_bytes()
    if len(lossy) > max_bytes and candidate.source == "wikidata":
        raise IconPackError(f"too-heavy: {len(lossy)} bytes with loss, over {max_bytes}")
    return min(data, lossy, key=len)


def brand_names(picked, domains):
    """{squashed brand name: icon number}: an item with no web address finds its icon by its
    title ("Reddit"). A name two different icons claim is left out, unless a hand-picked brand
    or a domain named after it settles it."""
    claims = {}
    for domain, candidate in picked.items():
        name = squash(re.sub(r"\s*\[.*?\]\s*", "", candidate.brand or ""))
        if len(name) < 3:
            continue
        label = domain.split(".")[0]
        weight = 2 if candidate.curated else 1 if label == name else 0
        claims.setdefault(name, []).append((weight, domains[domain]))
    out = {}
    for name, entries in claims.items():
        best = max(w for w, _ in entries)
        numbers = {n for w, n in entries if w == best}
        if len(numbers) == 1:
            out[name] = numbers.pop()
    return dict(sorted(out.items()))


def platform_icons(domains, platforms):
    """Sorted icon numbers of hosting platforms: every icon one of whose `domains` is a platform
    domain (`platforms`) or a subdomain of one."""
    listed = {p.lower().strip(".") for p in platforms if p}
    out = set()
    for domain, number in domains.items():
        name = domain.lower().strip(".")
        if any(name == p or name.endswith("." + p) for p in listed):
            out.add(number)
    return sorted(out)


def platform_tenants(domains, curated_tenants, platforms):
    """Sorted tenant domains: the curated tenants and every hosting platform domain (`platforms`)
    with an icon in `domains`. A tenant's subdomains never inherit its icon (a club's portal at
    club.clubautomation.com is the club's, not Club Automation's); the bare domain keeps it."""
    listed = (normalized_domain(x) for x in list(curated_tenants) + list(platforms))
    return sorted({d for d in listed if d and d in domains})


def pack_bytes(version, size, icons, domains, names=None, tenants=None, rejects=None, platforms=None):
    """icons: [(bytes, flags)], domains: {domain: index}, names: {squashed brand name: index},
    tenants: domains whose icon is not inherited by their subdomains (acme.zendesk.com is Acme's),
    rejects: dHashes of platform icons (ints), written as 16 hex digits, sorted, once each,
    platforms: icon numbers of hosting platforms (`platform_icons`), sorted, once each."""
    offsets, blob, position = [], bytearray(), 0
    for data, flags in icons:
        offsets.append([position, len(data), flags])
        blob += data
        position += len(data)
    index = {"format": FORMAT, "version": version, "size": size, "icons": offsets, "domains": dict(sorted(domains.items()))}
    if names:
        index["names"] = dict(sorted(names.items()))
    if tenants:
        index["tenants"] = sorted(tenants)
    if rejects:
        index["rejects"] = sorted({"%016x" % r for r in rejects})
    if platforms:
        index["platforms"] = sorted(set(platforms))
    index = json.dumps(index, separators=(",", ":"), sort_keys=True).encode()
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
    for number in list(index["domains"].values()) + list(index.get("names", {}).values()):
        if not 0 <= number < len(index["icons"]):
            raise IconPackError("domain points past the icons")
    for value in index.get("rejects", []):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{16}", value):
            raise IconPackError("a reject is not 16 lowercase hex digits")
    for number in index.get("platforms", []):
        if not isinstance(number, int) or isinstance(number, bool) or not 0 <= number < len(index["icons"]):
            raise IconPackError("a platform points past the icons")
    return index, blob


def build(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    sources = json.loads(Path(args.sources).read_text(encoding="utf-8"))
    skipped = {}

    def log(kind, what):
        skipped.setdefault(kind, []).append(what)

    roots = (Path(args.simple_icons), Path(args.logos), Path(args.twofa))
    found = collect(*roots, log)
    curated = json.loads(Path(args.curated).read_text(encoding="utf-8")) if args.curated else {}
    sites = Path(args.sites) if args.sites else None
    for domain, candidate in curated_candidates(curated, roots, sites, log).items():
        found.setdefault(domain, []).append(candidate)
    fetched = json.loads((sites / "sites.json").read_text(encoding="utf-8")) if sites and (sites / "sites.json").is_file() else {}
    stats = {"fetched": 0, "kept": 0, "blocked": 0}
    if args.domains:
        if not sites:
            raise IconPackError("--domains needs --sites (the folder `sites --domains` wrote)")
        listed = read_domain_lists(args.domains)
        extra, stats = domain_candidates(listed, curated_domains(curated), load_blocklist(args.blocklist), sites, log)
        for domain, candidate in extra.items():
            found.setdefault(domain, []).append(candidate)
    wikidata = None
    if args.wikidata:
        # Wikidata logos (the `wikidata` command's folder): after the curated list, before the open sets.
        platforms = read_domain_lists([args.platforms]) if args.platforms else []
        extra, wd_record, wd_drops = wikidata_candidates(Path(args.wikidata), curated_domains(curated),
                                                         load_blocklist(args.blocklist), platforms, log)
        open_sets = {"logos", "2fa-directory", "simple-icons"}
        overrides = sorted(d for d in extra if any(
            any(c.source in open_sets for c in found.get(parent, []))
            for parent in (".".join(d.split(".")[i:]) for i in range(1, len(d.split(".")) - 1))))
        for domain, candidate in extra.items():
            found.setdefault(domain, []).append(candidate)
        wikidata = {"record": wd_record, "drops": wd_drops, "candidates": len(extra), "overrides": overrides}
    rejects, dropped = [], []
    if sites:
        # Hosting-platform icons (a gym portal serving its software vendor's favicon): shipped as
        # `rejects` for the app, and never kept as a brand's icon here.
        platforms = read_domain_lists([args.platforms]) if args.platforms else []
        rejects, dropped = reject_platform_icons(found, sites, platforms, args.resvg, args.jobs, log)
    # Each domain's best candidate is drawn; a domain whose candidate fails moves to its next one.
    queues = {d: sorted(c, key=lambda c: (c.rank, c.name)) for d, c in found.items()}
    results = {}  # (svg sha, fill) -> (webp bytes, flags) or None
    icons, numbers, domains, chosen, picked = [], {}, {}, {}, {}

    def key_of(candidate):
        return (hashlib.sha256(candidate.svg).hexdigest(), candidate.fill, candidate.tile, candidate.curated,
                candidate.size)

    with tempfile.TemporaryDirectory() as tmp:
        local = threading.local()

        def draw(candidate):
            if not hasattr(local, "work"):
                local.work = Path(tempfile.mkdtemp(dir=tmp))
            try:
                return render(candidate, candidate.size or args.size, args.resvg, args.cwebp, local.work,
                              args.max_icon_bytes or None), None
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
                    results[k] = (data, (FLAG_MONO if wanted[k].mono else 0) | wanted[k].flags) if data else None
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
                    picked[domain] = queue[0]
                    del queues[domain]
    stats["kept"] = sum(1 for c in picked.values() if c.rank == RANK_DOMAIN_LIST)
    names = brand_names(picked, domains)
    # Icons of hosting platforms: never another site's parent brand in the app.
    platform_list = read_domain_lists([args.platforms]) if args.platforms else []
    platforms = platform_icons(domains, platform_list)
    tenants = platform_tenants(domains, curated.get("tenants", []), platform_list)
    pack = pack_bytes(args.version, args.size, icons, domains, names=names, tenants=tenants, rejects=rejects,
                      platforms=platforms)
    used = {name.partition(":")[2] for name in chosen.values() if name.startswith("brand:")}
    if used:
        # Where each brand icon in the pack came from (URL, hash, size, date): the per-icon record.
        sources = dict(sources, **{"brand-sites": {
            "license": LICENSES["brand"], "icons": {k: v for k, v in sorted(fetched.items()) if k in used}}})
    if stats["kept"]:
        sources = dict(sources, **{"domain-list": {
            "license": LICENSES["brand"], "icons": stats["kept"], "pixels": DOMAIN_SIZE,
            "lists": [Path(x).name for x in args.domains]}})
    wd_used = {d: c for d, c in picked.items() if c.source == "wikidata"}
    if wikidata:
        wd_domains = wikidata["record"].get("domains") or {}
        sources = dict(sources, **{"wikidata": {
            "license": LICENSES["wikidata"], "queried": wikidata["record"].get("queried"),
            "endpoint": wikidata["record"].get("endpoint"),
            "icons": {d: {k: wd_domains[d].get(k) for k in ("item", "file", "sha1", "license", "url")}
                      for d in sorted(wd_used)}}})
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
    if rejects:
        manifest["rejects"] = len(rejects)
    if wikidata:
        manifest["wikidata_queried"] = wikidata["record"].get("queried")
    (out / "icon-pack-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    licenses = {d: c.license or LICENSES.get(c.source, "") for d, c in sorted(picked.items())}
    report = {"chosen": dict(sorted(chosen.items())), "licenses": licenses, "names": len(names),
              "domains_fetched": stats["fetched"], "domains_kept": stats["kept"], "domains_blocked": stats["blocked"],
              "rejects": len(rejects), "platform_icons_dropped": dropped,
              "skipped": {k: sorted(v) for k, v in skipped.items()}}
    if wikidata:
        record = wikidata["record"]
        drops = {k: len(v) for k, v in (record.get("dropped") or {}).items()}
        for k, v in wikidata["drops"].items():
            drops[k] = drops.get(k, 0) + v
        per_license = {}
        for name_, counts in (record.get("licenses") or {}).items():
            per_license[name_] = dict(counts, in_pack=sum(1 for c in wd_used.values() if c.license == name_))
        report["wikidata"] = {"queried": record.get("queried"), "items": record.get("items"),
                              "domains": len(record.get("domains") or {}), "candidates": wikidata["candidates"],
                              "in_pack": len(wd_used), "licenses": dict(sorted(per_license.items())),
                              "dropped": dict(sorted(drops.items())), "conflicts": record.get("conflicts") or {},
                              # Subdomains given their own Wikidata logo under a parent the open sets cover
                              # (aws.amazon.com under amazon.com): kept, listed for review.
                              "subdomain-override": wikidata["overrides"],
                              "page_errors": record.get("page_errors") or []}
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
    b.add_argument("--max-icon-bytes", type=int, default=MAX_ICON_BYTES, help="0 keeps every icon lossless")
    b.add_argument("--out", required=True)
    b.add_argument("--resvg", default="resvg")
    b.add_argument("--cwebp", default="cwebp")
    b.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    b.add_argument("--domains", action="append",
                   help="a popular-domain list (plain text, one per line; repeatable): its icons, fetched by "
                        "`sites --domains`, are drawn at 128 px with index flag 2")
    b.add_argument("--blocklist", default=str(DEFAULT_BLOCKLIST),
                   help="domains and *.suffix lines that never get an icon (default scripts/icon-pack-blocklist.txt)")
    b.add_argument("--curated", default=str(Path(__file__).resolve().parent / "icon-pack-curated.json"),
                   help="hand-picked brands (default scripts/icon-pack-curated.json; empty string for none)")
    b.add_argument("--sites", help="the folder `sites` wrote (brand icons fetched at build time)")
    b.add_argument("--platforms", default=str(DEFAULT_PLATFORMS),
                   help="hosting platforms whose icons are rejects (default scripts/icon-pack-platforms.txt; "
                        "empty string for none)")
    b.add_argument("--wikidata", help="the folder `wikidata` wrote (logos named by Wikidata, files from Commons)")
    w = sub.add_parser("wikidata")
    w.add_argument("--out", required=True)
    w.add_argument("--blocklist", default=str(DEFAULT_BLOCKLIST))
    w.add_argument("--platforms", default=str(DEFAULT_PLATFORMS),
                   help="hosting platforms: an official website on one of them is left out (empty string for none)")
    w.add_argument("--page-size", type=int, default=WIKIDATA_PAGE)
    w.add_argument("--max-pages", type=int, default=WIKIDATA_MAX_PAGES)
    w.add_argument("--dry-run", action="store_true",
                   help="print the endpoint, the User-Agent and the first page's query, fetch nothing")
    st = sub.add_parser("sites")
    st.add_argument("--curated", default=str(Path(__file__).resolve().parent / "icon-pack-curated.json"))
    st.add_argument("--out", required=True)
    st.add_argument("--domains", action="append", help="a popular-domain list (plain text, one per line; repeatable)")
    st.add_argument("--blocklist", default=str(DEFAULT_BLOCKLIST))
    st.add_argument("--jobs", type=int, default=8)
    st.add_argument("--platforms", default=str(DEFAULT_PLATFORMS),
                    help="hosting platforms whose icons are fetched into OUT/platforms (empty string for none)")
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
        if args.command == "wikidata":
            if not 1 <= args.page_size <= 10000 or args.max_pages < 1:
                raise IconPackError("--page-size must be 1 to 10000 and --max-pages at least 1")
            if args.dry_run:
                print(f"endpoint: {WIKIDATA_SPARQL}\nuser-agent: {WIKI_UA}\npage size: {args.page_size}, "
                      f"at most {args.max_pages} pages\nCommons: {COMMONS_API} (imageinfo, {COMMONS_BATCH} files "
                      f"per request)\n\n{wikidata_query(args.page_size, 0)}")
                return 0
            platforms = read_domain_lists([args.platforms]) if args.platforms else []
            record = fetch_wikidata(Path(args.out), load_blocklist(args.blocklist), platforms,
                                    page_size=args.page_size, max_pages=args.max_pages)
            print(f"{record['items']} items, {len(record['domains'])} domains with a kept logo, "
                  f"{len(record['conflicts'])} conflicts -> {Path(args.out) / 'wikidata.json'}")
            return 0
        if args.command == "sites":
            curated = json.loads(Path(args.curated).read_text(encoding="utf-8"))
            failed = []
            out = Path(args.out)
            fetch_sites(curated, out, lambda kind, what: failed.append(what))
            if args.domains:
                listed = read_domain_lists(args.domains)
                record, blocked = fetch_domains(listed, curated_domains(curated), load_blocklist(args.blocklist), out,
                                                lambda kind, what: failed.append(what), jobs=args.jobs)
                print(f"{len(record)} domain icons, {len(blocked)} blocked")
            if args.platforms:
                platforms = read_domain_lists([args.platforms])
                record = fetch_platforms(platforms, out, lambda kind, what: failed.append(what), jobs=args.jobs)
                print(f"{len(record)} platform icons")
            for line in failed:
                print(f"icon_pack: {line}", file=sys.stderr)
            return 0
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
