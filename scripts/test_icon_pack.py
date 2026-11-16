#!/usr/bin/env python3
"""Tests of scripts/icon_pack.py.

Run: python3 -I scripts/test_icon_pack.py   (the signing test needs OpenSSL 3 or later on PATH,
or OPENSSL=/path/to/openssl; the rendering test needs resvg and cwebp, RESVG=/path/to/resvg).
"""

import base64
import hashlib
import json
import os
import struct
import zlib
import shutil
import sys
import functools
import http.client
import http.server
import tempfile
import threading
import unittest
import urllib.request
import urllib.parse
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import appcast  # noqa: E402
import icon_pack  # noqa: E402

# RFC 8032, section 7.1, TEST 1.
RFC_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC_PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

SQUARE_SVG = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M2 2h20v20H2z"/></svg>'
COLOR_SVG = (b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><path fill="#ff0000" d="M0 0h5v10H0z"/>'
             b'<path fill="#0000ff" d="M5 0h5v10H5z"/></svg>')
WIDE_SVG = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 20"><path d="M0 0h100v20H0z"/></svg>'


def has_openssl():
    try:
        appcast.openssl()
        return True
    except appcast.AppcastError:
        return False


class Names(unittest.TestCase):
    def test_domains(self):
        n = icon_pack.normalized_domain
        self.assertEqual(n("https://www.Withings.com/fr/"), "withings.com")
        self.assertEqual(n("accounts.firefox.com"), "accounts.firefox.com")
        self.assertIsNone(n("co.uk"))
        self.assertIsNone(n("github.io"))
        self.assertIsNone(n("localhost"))
        self.assertIsNone(n("192.168.1.1"))
        self.assertIsNone(n("exa mple.com"))
        self.assertEqual(icon_pack.registrable("a.b.service.gov.uk"), "service.gov.uk")
        self.assertEqual(icon_pack.registrable("www.aircanada.com"), "aircanada.com")

    def test_slugs(self):
        s = icon_pack.simple_icons_slug
        self.assertEqual(s({"title": "AT&T"}), "atandt")
        self.assertEqual(s({"title": "Air Canada"}), "aircanada")
        self.assertEqual(s({"title": ".ENV"}), "dotenv")
        self.assertEqual(s({"title": "Backstage", "slug": "backstage_casting"}), "backstage_casting")


class Svg(unittest.TestCase):
    def test_safety(self):
        self.assertTrue(icon_pack.is_safe_svg(SQUARE_SVG))
        self.assertTrue(icon_pack.is_safe_svg(b'<svg><defs><path id="a"/></defs><use href="#a"/></svg>'))
        for bad in [
            b'<!DOCTYPE svg [<!ENTITY x "y">]><svg/>',
            b'<svg><script>alert(1)</script></svg>',
            b'<svg><image href="file:///etc/passwd"/></svg>',
            b'<svg><use href="other.svg#a"/></svg>',
            b'<svg><use xlink:href="https://x.test/a.svg#a"/></svg>',
            b'<svg><rect style="fill:url(https://x.test/p)"/></svg>',
            b'<svg><style>@import "x.css";</style></svg>',
            b'<svg><text>Brand</text></svg>',
            b'<svg><foreignObject/></svg>',
            b'<html><svg/></html>',
            b"<svg>" + b" " * (icon_pack.MAX_SVG_BYTES + 1) + b"</svg>",
        ]:
            self.assertFalse(icon_pack.is_safe_svg(bad), bad[:60])

    def test_squared_centers_and_sets_fill(self):
        out = icon_pack.squared(WIDE_SVG, 256, "F01428")
        root = icon_pack.ROOT_TAG.search(out).group(0)
        self.assertIn(b'width="256" height="256"', root)
        self.assertIn(b'viewBox="0 -40 100 100"', root)
        self.assertIn(b'fill="#F01428"', root)
        self.assertEqual(root.count(b"viewBox"), 1)
        self.assertAlmostEqual(icon_pack.aspect(WIDE_SVG), 5.0)
        sized = b'<svg xmlns="http://www.w3.org/2000/svg" width="32px" height="32px"><path d="M0 0h1v1z"/></svg>'
        self.assertIn(b'viewBox="0 0 32 32"', icon_pack.squared(sized, 64))

    def test_ink_aspect_spots_wordmarks(self):
        width, height = 8, 8
        pixels = bytearray(width * height * 4)
        for x in range(0, 8):
            for y in (3, 4):
                pixels[(y * width + x) * 4 + 3] = 255
        self.assertAlmostEqual(icon_pack.ink_aspect(width, height, bytes(pixels)), 4.0)
        self.assertEqual(icon_pack.ink_aspect(width, height, bytes(width * height * 4)), 1.0)

    def test_colors(self):
        self.assertEqual(icon_pack.colors_in(COLOR_SVG), {"ff0000", "0000ff"})


class Raster(unittest.TestCase):
    def test_sizes_and_ico(self):
        png = icon_pack.png_from_rgba(3, 2, [b"\xff\x00\x00\xff" * 3, b"\x00\x00\xff\x80" * 3])
        self.assertEqual(icon_pack.raster_size(png), (3, 2))
        self.assertEqual(icon_pack.raster_mime(png), "image/png")
        self.assertEqual(icon_pack.png_rgba(png)[2][:4], b"\xff\x00\x00\xff")
        jpeg = b"\xff\xd8\xff\xe0\x00\x04ab\xff\xc0\x00\x11\x08\x00\xc8\x01\x2c" + b"\x00" * 12
        self.assertEqual(icon_pack.raster_size(jpeg), (300, 200))
        self.assertIsNone(icon_pack.raster_mime(b"<svg/>"))
        # A .ico holding a 2x2 32-bit bitmap (bottom-up BGRA, then the AND mask).
        bmp = struct.pack("<IiiHHIIiiII", 40, 2, 4, 1, 32, 0, 0, 0, 0, 0, 0)
        bmp += b"\x00\x00\xff\xff" * 2 + b"\xff\x00\x00\xff" * 2 + b"\x00" * 8
        ico = b"\x00\x00\x01\x00\x01\x00" + struct.pack("<BBBBHHII", 2, 2, 0, 0, 1, 32, len(bmp), 22) + bmp
        out = icon_pack.ico_largest(ico)
        width, height, pixels = icon_pack.png_rgba(out)
        self.assertEqual((width, height), (2, 2))
        self.assertEqual(pixels[:4], b"\x00\x00\xff\xff")  # top row is the bitmap's last: blue
        self.assertEqual(pixels[8:12], b"\xff\x00\x00\xff")
        self.assertIsNone(icon_pack.ico_largest(b"not an ico"))

    def test_raster_svg_embeds_the_image(self):
        png = icon_pack.png_from_rgba(1, 1, [b"\x00\x00\x00\xff"])
        svg = icon_pack.raster_svg(png)
        self.assertIn(b'viewBox="0 0 1 1"', svg)
        self.assertIn(b"data:image/png;base64,", svg)

    def test_icon_links(self):
        html = ('<link rel="icon" href="/f.ico"><link rel="apple-touch-icon" sizes="180x180" href="/t.png">'
                '<link rel=manifest href="/m.json">')
        links, manifest = icon_pack.icon_links(html, "https://brand.test/a/")
        self.assertIn(("https://brand.test/t.png", 180), links)
        self.assertIn(("https://brand.test/f.ico", 0), links)
        self.assertEqual(manifest, "https://brand.test/m.json")

    def test_tiled_draws_a_square_under_the_mark(self):
        out = icon_pack.tiled(icon_pack.squared(SQUARE_SVG, 100), 100, "FFFC00")
        self.assertIn(b'<rect width="100" height="100" fill="#FFFC00"/>', out)
        self.assertIn(b'x="19" y="19" width="62" height="62"', out)


class Pack(unittest.TestCase):
    def test_round_trip_and_bounds(self):
        data = icon_pack.pack_bytes(3, 256, [(b"aaa", 0), (b"bb", 1)], {"b.com": 1, "a.com": 0})
        index, blob = icon_pack.read_pack(data)
        self.assertEqual(index["version"], 3)
        offset, length, flags = index["icons"][index["domains"]["b.com"]]
        self.assertEqual((blob[offset:offset + length], flags), (b"bb", 1))
        with self.assertRaises(icon_pack.IconPackError):
            icon_pack.read_pack(data[:-1])
        with self.assertRaises(icon_pack.IconPackError):
            icon_pack.read_pack(b"XXXX" + data[4:])
        bad = icon_pack.pack_bytes(3, 256, [(b"a", 0)], {"a.com": 4})
        with self.assertRaises(icon_pack.IconPackError):
            icon_pack.read_pack(bad)
        bad = icon_pack.pack_bytes(3, 256, [(b"a", 0)], {"a.com": 0}, names={"brand": 2})
        with self.assertRaises(icon_pack.IconPackError):
            icon_pack.read_pack(bad)

    def test_names_and_tenants(self):
        data = icon_pack.pack_bytes(3, 256, [(b"a", 0)], {"zendesk.com": 0}, names={"zendesk": 0},
                                    tenants=["zendesk.com"])
        index, _ = icon_pack.read_pack(data)
        self.assertEqual(index["names"], {"zendesk": 0})
        self.assertEqual(index["tenants"], ["zendesk.com"])
        plain, _ = icon_pack.read_pack(icon_pack.pack_bytes(3, 256, [(b"a", 0)], {"a.com": 0}))
        self.assertNotIn("names", plain)

    def test_brand_names(self):
        C = icon_pack.Candidate
        picked = {"reddit.com": C(0, "logos", b"", brand="Reddit"),
                  "redd.it": C(0, "logos", b"", brand="Reddit"),
                  "box.com": C(0, "logos", b"", brand="Box"),
                  "boxhq.net": C(0, "logos", b"", brand="Box"),
                  "a.com": C(0, "logos", b"", brand="Same"), "b.com": C(0, "logos", b"", brand="Same"),
                  "x.com": C(0, "logos", b"", brand="X")}
        domains = {"reddit.com": 0, "redd.it": 0, "box.com": 1, "boxhq.net": 2, "a.com": 3, "b.com": 4, "x.com": 5}
        names = icon_pack.brand_names(picked, domains)
        self.assertEqual(names["reddit"], 0)
        self.assertEqual(names["box"], 1)  # the domain named after the brand settles it
        self.assertNotIn("same", names)  # two icons, nothing settles it
        self.assertNotIn("x", names)  # too short


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())


class Collect(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        si, logos, twofa = self.tmp / "si", self.tmp / "logos", self.tmp / "2fa"
        write(si / "data/simple-icons.json", json.dumps([
            {"title": "Withings", "hex": "00A2E0", "source": "https://www.withings.com/press"},
            {"title": "Apple", "hex": "000000", "source": "https://www.apple.com"},
            {"title": "Dotenv", "hex": "ECD53F", "source": "https://github.com/motdotla/dotenv"},
            {"title": "Restricted", "hex": "112233", "source": "https://restricted.com",
             "license": {"type": "CC-BY-NC-4.0"}},
            {"title": "Air Canada", "hex": "F01428", "source": "https://brand.example.org"},
        ]))
        for slug in ["withings", "apple", "dotenv", "restricted", "aircanada"]:
            write(si / f"icons/{slug}.svg", SQUARE_SVG)
        write(logos / "logos.json", json.dumps([
            {"name": "Withings", "shortname": "withings", "url": "https://www.withings.com/",
             "files": ["withings-icon.svg", "withings.svg"]},
            {"name": "Wide", "shortname": "wide", "url": "https://wide.com/", "files": ["wide.svg"]},
        ]))
        write(logos / "logos/withings-icon.svg", COLOR_SVG)
        write(logos / "logos/wide.svg", WIDE_SVG)
        write(twofa / "entries/a/aircanada.com.json", json.dumps(
            {"Air Canada": {"domain": "aircanada.com", "additional-domains": ["aeroplan.com"]}}))
        write(twofa / "entries/u/unsafe.com.json", json.dumps({"Unsafe": {"domain": "unsafe.com"}}))
        write(twofa / "img/u/unsafe.com.svg", b"<svg><script/></svg>")
        self.roots = (si, logos, twofa)

    def test_ranks_and_mapping(self):
        log = []
        found = icon_pack.collect(*self.roots, lambda kind, what: log.append((kind, what)))
        best = {d: min(c, key=lambda c: c.rank) for d, c in found.items()}
        self.assertEqual(best["withings.com"].source, "logos")
        self.assertEqual(best["apple.com"].fill, "000000")
        self.assertTrue(best["apple.com"].mono)
        self.assertEqual(best["aircanada.com"].fill, "F01428")
        self.assertIn("aeroplan.com", found)
        self.assertNotIn("github.com", found)
        self.assertNotIn("restricted.com", found)
        self.assertNotIn("wide.com", found)
        self.assertNotIn("unsafe.com", found)
        self.assertIn(("license", "simple-icons Restricted (CC-BY-NC-4.0)"), log)
        self.assertIn(("unsafe", "2fa unsafe.com.svg"), log)

    def test_curated_beats_the_automatic_match(self):
        sites = self.tmp / "sites"
        write(sites / "brand.test", icon_pack.png_from_rgba(1, 1, [b"\x00\x00\x00\xff"]))
        curated = {"brands": [
            {"name": "Withings", "domains": ["withings.com", "account.withings.com"], "use": "simple-icons:withings",
             "tile": "FFFC00"},
            {"name": "Brand", "domains": ["brand.test"], "use": "site"},
            {"name": "Missing", "domains": ["missing.test"], "use": "site"},
            {"name": "None", "domains": [], "use": "none"},
        ]}
        log = []
        out = icon_pack.curated_candidates(curated, self.roots, sites, lambda k, w: log.append((k, w)))
        self.assertEqual(out["withings.com"].rank, icon_pack.RANK_CURATED)
        self.assertEqual(out["withings.com"].fill, "00A2E0")
        self.assertEqual(out["withings.com"].tile, "FFFC00")
        self.assertTrue(out["withings.com"].curated)
        self.assertIs(out["account.withings.com"], out["withings.com"])
        self.assertEqual(out["brand.test"].source, "brand")
        self.assertIn(b"data:image/png;base64,", out["brand.test"].svg)
        self.assertNotIn("missing.test", out)
        self.assertIn(("curated", "missing.test: no fetched icon"), log)

    def test_curated_commons_wordmark(self):
        sites = self.tmp / "sites"
        # A 4 by 1 wordmark with a registered sign to its right, outside the cropped view.
        logo = (b'<svg xmlns="http://www.w3.org/2000/svg" width="500" height="100" viewBox="0 0 500 100">'
                b'<path fill="#000" d="M0 30h400v40H0z"/><path d="M450 40h20v20h-20z"/></svg>')
        write(sites / "wordmark.test", logo)
        write(sites / "unsafe.test", b"<svg><script/></svg>")
        curated = {"brands": [
            {"name": "Wordmark", "domains": ["wordmark.test"], "use": "commons:Wordmark.svg", "mono": True,
             "wordmark": True, "view": "0 0 410 100"},
            {"name": "Unsafe", "domains": ["unsafe.test"], "use": "commons:Unsafe.svg"},
            {"name": "Bad view", "domains": ["wordmark.test"], "use": "commons:Wordmark.svg", "view": "0 0 -1"},
        ]}
        log = []
        out = icon_pack.curated_candidates(curated, self.roots, sites, lambda k, w: log.append((k, w)))
        mark = out["wordmark.test"]
        self.assertEqual((mark.source, mark.fill, mark.mono, mark.wordmark, mark.curated),
                         ("commons", "000000", True, True, True))
        root = icon_pack.ROOT_TAG.search(mark.svg).group(0)
        self.assertIn(b'viewBox="0 0 410 100"', root)
        self.assertNotIn(b"width=", root)
        self.assertNotIn("unsafe.test", out)
        self.assertIn(("curated", "unsafe.test: fetched file is not a safe SVG"), log)
        self.assertIn(("curated", "wordmark.test: bad view '0 0 -1'"), log)
        with self.assertRaises(icon_pack.IconPackError):
            icon_pack.commons_svg("../x.svg", "0" * 40)
        with self.assertRaises(icon_pack.IconPackError):
            icon_pack.commons_svg("Aesop_logo_2013.svg", "")

    @unittest.skipUnless((os.environ.get("RESVG") or shutil.which("resvg")) and shutil.which("cwebp"),
                         "needs resvg and cwebp")
    def test_wordmark_renders_only_when_marked(self):
        resvg = os.environ.get("RESVG") or shutil.which("resvg")
        logo = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 100"><path d="M0 0h400v100H0z"/></svg>'
        work = self.tmp / "work"
        work.mkdir()
        mark = icon_pack.Candidate(icon_pack.RANK_CURATED, "commons", logo, fill="000000", mono=True, curated=True)
        with self.assertRaises(icon_pack.IconPackError):
            icon_pack.render(mark, 128, resvg, shutil.which("cwebp"), work)
        mark.wordmark = True
        self.assertEqual(icon_pack.render(mark, 128, resvg, shutil.which("cwebp"), work)[:4], b"RIFF")

    @unittest.skipUnless((os.environ.get("RESVG") or shutil.which("resvg")) and shutil.which("cwebp"),
                         "needs resvg and cwebp")
    def test_heavy_icon_is_encoded_with_loss_then_refused(self):
        resvg, cwebp = os.environ.get("RESVG") or shutil.which("resvg"), shutil.which("cwebp")
        noisy = (b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><defs>'
                 b'<linearGradient id="a" x2="1" y2="1"><stop offset="0" stop-color="#e33"/>'
                 b'<stop offset=".5" stop-color="#3a7"/><stop offset="1" stop-color="#36e"/></linearGradient>'
                 b'<radialGradient id="b" cx=".3" cy=".7" r=".8"><stop offset="0" stop-color="#ff0"/>'
                 b'<stop offset="1" stop-color="#0ff" stop-opacity="0"/></radialGradient></defs>'
                 b'<rect width="48" height="48" fill="url(#a)"/><circle cx="24" cy="24" r="22" fill="url(#b)"/></svg>')
        work = self.tmp / "work"
        work.mkdir()
        mark = icon_pack.Candidate(icon_pack.RANK_WIKIDATA, "wikidata", noisy, name="wikidata:Q1")
        lossless = icon_pack.render(mark, 256, resvg, cwebp, work)
        self.assertEqual(lossless[12:16], b"VP8L")
        lossy = icon_pack.render(mark, 256, resvg, cwebp, work, max_bytes=len(lossless) - 1)
        self.assertLess(len(lossy), len(lossless))
        self.assertNotIn(b"VP8L", lossy[:64])
        with self.assertRaisesRegex(icon_pack.IconPackError, "too-heavy"):
            icon_pack.render(mark, 256, resvg, cwebp, work, max_bytes=100)
        mark.curated = True
        self.assertEqual(icon_pack.render(mark, 256, resvg, cwebp, work, max_bytes=100), lossy)

    @unittest.skipUnless((os.environ.get("RESVG") or shutil.which("resvg")) and shutil.which("cwebp"),
                         "needs resvg and cwebp")
    def test_build_end_to_end(self):
        sources = self.tmp / "sources.json"
        sources.write_text("{}")
        out = self.tmp / "out"
        code = icon_pack.main(["build", "--simple-icons", str(self.roots[0]), "--logos", str(self.roots[1]),
                               "--twofa", str(self.roots[2]), "--sources", str(sources), "--version", "42",
                               "--size", "128", "--out", str(out), "--curated", "",
                               "--resvg", os.environ.get("RESVG") or shutil.which("resvg")])
        self.assertEqual(code, 0)
        manifest = json.loads((out / "icon-pack-manifest.json").read_text())
        pack = (out / manifest["pack"]["file"]).read_bytes()
        self.assertEqual(hashlib.sha256(pack).hexdigest(), manifest["pack"]["sha256"])
        index, blob = icon_pack.read_pack(pack)
        self.assertEqual(index["size"], 128)
        offset, length, flags = index["icons"][index["domains"]["apple.com"]]
        self.assertEqual(blob[offset:offset + 4], b"RIFF")
        self.assertEqual(flags, icon_pack.FLAG_MONO)


def png(size):
    return icon_pack.png_from_rgba(size, size, [b"\x20\x40\xc0\xff" * size] * size)


class DomainList(unittest.TestCase):
    """Domains from a list: fetched from a local server (the fetcher maps https://<domain>/x to
    http://127.0.0.1:<port>/<domain>/x), never the network, never Google's copy."""

    def setUp(self):
        Collect.setUp(self)  # the three upstream folders in self.roots, self.tmp
        self.web = self.tmp / "web"
        self.web.mkdir()
        self.redirects = {}
        redirects = self.redirects

        class Handler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path in redirects:
                    self.send_response(302)
                    self.send_header("Location", redirects[self.path])
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                super().do_GET()

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=str(self.web)))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]
        self.log = []
        self.none = icon_pack.Blocklist()

    def fetcher(self, url, limit):
        parts = urllib.parse.urlsplit(url)
        local = f"http://127.0.0.1:{self.port}/{parts.netloc}{parts.path}"
        with urllib.request.urlopen(local, timeout=10) as response:
            final = urllib.parse.urlsplit(response.geturl())
            data = response.read(limit + 1)
        host, _, rest = final.path.lstrip("/").partition("/")
        return data, f"https://{host}/{rest}"

    def site(self, domain, pixels):
        write(self.web / domain / "index.html", '<html><link rel="apple-touch-icon" href="icon.png"></html>')
        write(self.web / domain / "icon.png", png(pixels))

    def fetch(self, domains, blocklist=None, skip=()):
        return icon_pack.fetch_domains(domains, set(skip), blocklist or self.none, self.tmp / "sites",
                                       lambda k, w: self.log.append((k, w)), fetcher=self.fetcher, google=False, jobs=2)

    def build(self, listfile, extra=(), curated=None, flags=None):
        sources = self.tmp / "sources.json"
        sources.write_text("{}")
        curated_path = self.tmp / "curated.json"
        curated_path.write_text(json.dumps(curated or {"brands": []}))
        sizes = {}

        def fake(candidate, size, resvg, cwebp, work, max_bytes=None):
            sizes[candidate.name] = size
            return b"RIFF" + candidate.name.encode()

        out = self.tmp / "out"
        with mock.patch.object(icon_pack, "render", side_effect=fake):
            code = icon_pack.main(["build", "--simple-icons", str(self.roots[0]), "--logos", str(self.roots[1]),
                                   "--twofa", str(self.roots[2]), "--sources", str(sources), "--version", "7",
                                   "--out", str(out), "--curated", str(curated_path), "--sites", str(self.tmp / "sites"),
                                   "--domains", str(listfile), "--blocklist", str(self.tmp / "block.txt"), *extra])
        self.assertEqual(code, 0)
        manifest = json.loads((out / "icon-pack-manifest.json").read_text())
        index, _ = icon_pack.read_pack((out / manifest["pack"]["file"]).read_bytes())
        report = json.loads((out / "report.json").read_text())
        return manifest, index, report, sizes

    def test_cut_response_skips_the_site_and_is_retried(self):
        class Cut:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def geturl(self):
                return "https://cut.test/"

            def read(self, n):
                raise http.client.IncompleteRead(b"x" * 10)

        with mock.patch("urllib.request.urlopen", return_value=Cut()):
            with self.assertRaises(ConnectionError):
                icon_pack.fetch_url("https://cut.test/", 100)
            record, _ = icon_pack.fetch_domains(["cut.test"], set(), self.none, self.tmp / "sites",
                                                lambda k, w: self.log.append((k, w)), google=False, jobs=1)
            self.assertNotIn("cut.test", record)
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) == 1:
                raise ConnectionError("bad HTTP response: IncompleteRead")
            return b"ok"

        self.assertEqual(icon_pack.with_retries(flaky, sleep=lambda s: None), b"ok")

    def test_lists_plain_and_comments(self):
        a, b, c = self.tmp / "a.txt", self.tmp / "b.txt", self.tmp / "c.csv"
        write(a, "# banks\nWww.Plain.test\n\nhttps://sub.shop.test/path  # inline\nplain.test\nco.uk\n")
        write(b, "google.com\nmail.plain.test\ngithub.io\n")
        write(c, "1,google.com\n")
        self.assertEqual(icon_pack.read_domain_lists([a]), ["plain.test", "shop.test"])
        self.assertEqual(icon_pack.read_domain_lists([a, b]), ["plain.test", "shop.test", "google.com"])
        # A ranked CSV is refused: no list records its provenance.
        with self.assertRaises(icon_pack.IconPackError):
            icon_pack.read_domain_lists([c])

    def test_blocklist_exact_and_suffix(self):
        write(self.tmp / "b.txt", "# header\nbad.test  # why\n\n*.adult\n*.Evil.example\n")
        block = icon_pack.load_blocklist(self.tmp / "b.txt")
        for host in ["bad.test", "www.bad.test", "x.adult", "adult", "evil.example", "a.b.evil.example",
                     "sub.bad.test", "m.bad.test", "a.b.bad.test"]:
            self.assertTrue(block.blocks(host), host)
        for host in ["notbad.test", "good.example", "bad.test.example", "co.uk", "", None]:
            self.assertFalse(block.blocks(host), host)
        shipped = icon_pack.load_blocklist(ROOT / "scripts" / "icon-pack-blocklist.txt")
        self.assertTrue(shipped.suffixes)
        self.assertLess(len((ROOT / "scripts" / "icon-pack-blocklist.txt").read_text().splitlines()), 60)

    def test_shipped_french_list(self):
        listed = icon_pack.read_domain_lists([ROOT / "scripts" / "icon-pack-domains-fr.txt"])
        text = (ROOT / "scripts" / "icon-pack-domains-fr.txt").read_text()
        self.assertGreater(len(listed), 250)
        self.assertEqual(len(listed), len(set(listed)))
        self.assertNotIn("\u2014", text)
        shipped = icon_pack.load_blocklist(ROOT / "scripts" / "icon-pack-blocklist.txt")
        self.assertEqual([d for d in listed if shipped.blocks(d)], [])

    def test_domains_icon_kept_at_128_with_flag(self):
        self.site("plain.test", 200)
        record, blocked = self.fetch(["plain.test"])
        self.assertEqual((sorted(record), blocked), (["plain.test"], []))
        self.assertEqual(record["plain.test"]["pixels"], 200)
        write(self.tmp / "list.txt", "plain.test\n")
        write(self.tmp / "block.txt", "# none\n")
        manifest, index, report, sizes = self.build(self.tmp / "list.txt")
        self.assertEqual(sizes["domain:plain.test"], 128)
        offset, length, flags = index["icons"][index["domains"]["plain.test"]]
        self.assertEqual(flags, icon_pack.FLAG_DOMAIN_LIST)
        self.assertEqual(flags, 2)
        self.assertEqual((report["domains_fetched"], report["domains_kept"], report["domains_blocked"]), (1, 1, 0))
        self.assertNotIn("tranco", manifest)

    def test_csv_list_is_refused(self):
        self.site("plain.test", 200)
        self.fetch(["plain.test"])
        write(self.tmp / "list.csv", "1,plain.test\n")
        write(self.tmp / "block.txt", "")
        write(self.tmp / "s.json", "{}")
        with mock.patch.object(icon_pack, "render", return_value=b"RIFF"):
            code = icon_pack.main(["build", "--simple-icons", str(self.roots[0]), "--logos", str(self.roots[1]),
                                   "--twofa", str(self.roots[2]), "--sources", str(self.tmp / "s.json"),
                                   "--version", "7", "--out", str(self.tmp / "out"), "--curated", "",
                                   "--sites", str(self.tmp / "sites"), "--domains", str(self.tmp / "list.csv"),
                                   "--blocklist", str(self.tmp / "block.txt")])
        self.assertEqual(code, 1)

    def test_redirect_keyed_to_listed_domain(self):
        self.site("new.test", 200)
        self.redirects["/old.test/"] = "/new.test/"
        record, blocked = self.fetch(["old.test"])
        self.assertEqual((sorted(record), blocked), (["old.test"], []))
        self.assertEqual(record["old.test"]["final_hosts"], ["new.test"])
        self.assertTrue((self.tmp / "sites" / "domains" / "old.test").is_file())
        self.assertFalse((self.tmp / "sites" / "domains" / "new.test").exists())
        write(self.tmp / "list.txt", "old.test\n")
        write(self.tmp / "block.txt", "")
        _, index, _, _ = self.build(self.tmp / "list.txt")
        self.assertIn("old.test", index["domains"])
        self.assertNotIn("new.test", index["domains"])

    def test_blocklisted_final_host_dropped(self):
        self.site("bad.test", 200)
        self.site("fine.test", 200)
        self.site("listed.test", 200)
        self.redirects["/front.test/"] = "/bad.test/"
        block = icon_pack.Blocklist(["bad.test", "listed.test"])
        record, blocked = self.fetch(["front.test", "fine.test", "listed.test"], block)
        self.assertEqual(sorted(record), ["fine.test"])
        self.assertEqual(blocked, ["front.test", "listed.test"])
        self.assertFalse((self.tmp / "sites" / "domains" / "front.test").exists())
        # The build checks again, from the recorded final host (a blocklist may grow after `sites`).
        self.site("later.test", 200)
        self.redirects["/shop.test/"] = "/later.test/"
        self.fetch(["shop.test", "fine.test"])
        write(self.tmp / "list.txt", "shop.test\nfine.test\n")
        write(self.tmp / "block.txt", "later.test\n")
        _, index, report, _ = self.build(self.tmp / "list.txt")
        self.assertIn("fine.test", index["domains"])
        self.assertNotIn("shop.test", index["domains"])
        self.assertEqual((report["domains_fetched"], report["domains_kept"], report["domains_blocked"]), (2, 1, 1))

    def test_exact_entry_blocks_subdomains_with_public_suffix(self):
        block = icon_pack.Blocklist(["shop.co.uk"])
        self.assertTrue(block.blocks("m.shop.co.uk"))
        self.assertTrue(block.blocks("shop.co.uk"))
        self.assertFalse(block.blocks("other.co.uk"))
        self.assertFalse(block.blocks("co.uk"))

    def test_redirect_to_subdomain_of_blocked_dropped(self):
        self.site("m.bad.test", 200)
        self.redirects["/front.test/"] = "/m.bad.test/"
        record, blocked = self.fetch(["front.test"], icon_pack.Blocklist(["bad.test"]))
        self.assertEqual((record, blocked), ({}, ["front.test"]))
        self.assertFalse((self.tmp / "sites" / "domains" / "front.test").exists())

    def test_every_recorded_final_host_is_checked(self):
        write(self.tmp / "sites" / "domains" / "multi.test", png(200))
        write(self.tmp / "sites" / "domains" / "old.test", png(200))
        write(self.tmp / "sites" / "domains.json", json.dumps({"fetched": {
            "multi.test": {"final_hosts": ["a.test", "b.test"]},
            "old.test": {"final_host": "b.test"}}}))
        block = icon_pack.Blocklist(["b.test"])
        out, stats = icon_pack.domain_candidates(["multi.test", "old.test"], set(), block, self.tmp / "sites",
                                                 lambda k, w: self.log.append((k, w)))
        self.assertEqual((out, stats["blocked"]), ({}, 2))

    def test_flags_two_and_one_combine(self):
        self.site("plain.test", 200)
        self.fetch(["plain.test"])
        write(self.tmp / "list.txt", "plain.test\n")
        write(self.tmp / "block.txt", "")
        real = icon_pack.domain_candidates

        def mono(*args):
            out, stats = real(*args)
            for c in out.values():
                c.mono, c.fill = True, "000000"
            return out, stats

        with mock.patch.object(icon_pack, "domain_candidates", side_effect=mono):
            _, index, _, _ = self.build(self.tmp / "list.txt")
        self.assertEqual(index["icons"][index["domains"]["plain.test"]][2], 3)

    def test_small_source_dropped(self):
        self.site("tiny.test", 100)
        record, _ = self.fetch(["tiny.test"])
        self.assertEqual(record, {})
        self.assertEqual(self.log[0][0], "domain")
        # A small file already in the sites folder is dropped by the build as well.
        write(self.tmp / "sites" / "domains" / "tiny.test", png(100))
        out, stats = icon_pack.domain_candidates(["tiny.test"], set(), self.none, self.tmp / "sites",
                                                 lambda k, w: self.log.append((k, w)))
        self.assertEqual((out, stats["fetched"]), ({}, 1))
        self.assertEqual(self.log[-1][0], "domain-small")

    def test_curated_icon_stays_256(self):
        self.site("plain.test", 200)
        self.site("apple.com", 200)
        self.fetch(["plain.test", "apple.com"])
        write(self.tmp / "list.txt", "apple.com\nplain.test\n")
        write(self.tmp / "block.txt", "")
        curated = {"brands": [{"name": "Apple", "domains": ["apple.com"], "use": "simple-icons:apple"}]}
        _, index, report, sizes = self.build(self.tmp / "list.txt", curated=curated)
        self.assertEqual(sizes["simple-icons:apple"], 256)
        self.assertEqual(sizes["domain:plain.test"], 128)
        self.assertNotIn("domain:apple.com", sizes)
        self.assertEqual(index["icons"][index["domains"]["apple.com"]][2], icon_pack.FLAG_MONO)
        self.assertEqual(index["icons"][index["domains"]["plain.test"]][2], icon_pack.FLAG_DOMAIN_LIST)
        self.assertEqual((report["domains_fetched"], report["domains_kept"]), (1, 1))

    def test_curated_domains_are_skipped_when_fetching(self):
        self.site("plain.test", 200)
        record, _ = self.fetch(["plain.test", "apple.com"], skip=["apple.com"])
        self.assertEqual(sorted(record), ["plain.test"])
        self.assertEqual(icon_pack.curated_domains({"brands": [{"domains": ["WWW.Apple.com"], "use": "none"}]}), {"apple.com"})


def pattern(seed, size=128):
    """A PNG of 9 x 8 gray blocks drawn from `seed`: different seeds hash far apart."""
    import random
    rng = random.Random(seed)
    grid = [[rng.randrange(256) for _ in range(9)] for _ in range(8)]
    rows = []
    for y in range(size):
        line = grid[y * 8 // size]
        rows.append(b"".join(bytes((line[x * 9 // size],) * 3 + (255,)) for x in range(size)))
    return icon_pack.png_from_rgba(size, size, rows)


def embedded_hash(svg, resvg, work):
    """icon_hash without resvg: the dHash of the PNG `raster_svg` embedded."""
    import re
    return icon_pack.dhash(base64.b64decode(re.search(rb"base64,([^\"]+)", svg).group(1)))


class Platforms(unittest.TestCase):
    """Hosting-platform icons: rejects in the index, and never shipped as a brand's icon."""

    def setUp(self):
        DomainList.setUp(self)
        write(self.tmp / "block.txt", "")
        write(self.tmp / "none.txt", "")

    fetcher = DomainList.fetcher
    fetch = DomainList.fetch

    def serve(self, domain, image):
        write(self.web / domain / "index.html", '<html><link rel="apple-touch-icon" href="icon.png"></html>')
        write(self.web / domain / "icon.png", image)

    def build(self, domains, platforms="none.txt"):
        write(self.tmp / "list.txt", "\n".join(domains) + "\n")
        with mock.patch.object(icon_pack, "icon_hash", side_effect=embedded_hash):
            return DomainList.build(self, self.tmp / "list.txt", ["--platforms", str(self.tmp / platforms)])

    def test_icon_shared_by_three_sites_is_a_reject(self):
        for domain in ("gym-one.test", "club-two.test", "studio-three.test"):
            self.serve(domain, pattern(1))
        self.serve("own.test", pattern(2))
        domains = ["gym-one.test", "club-two.test", "studio-three.test", "own.test"]
        self.fetch(domains)
        manifest, index, report, _ = self.build(domains)
        self.assertEqual(index["rejects"], ["%016x" % icon_pack.dhash(pattern(1))])
        for domain in domains[:3]:
            self.assertNotIn(domain, index["domains"])
        self.assertIn("own.test", index["domains"])
        self.assertEqual(report["platform_icons_dropped"], sorted(domains[:3]))
        self.assertEqual((report["rejects"], manifest["rejects"]), (1, 1))

    def test_platform_list_icon_is_a_reject(self):
        self.serve("vendor.test", pattern(3))
        self.serve("portal.test", pattern(3))
        self.serve("other.test", pattern(4))
        write(self.tmp / "platforms.txt", "# gym software\nvendor.test\n")
        record = icon_pack.fetch_platforms(["vendor.test"], self.tmp / "sites", lambda k, w: self.log.append((k, w)),
                                           fetcher=self.fetcher, google=False, jobs=1)
        self.assertEqual(sorted(record), ["vendor.test"])
        self.assertTrue((self.tmp / "sites" / "platforms" / "vendor.test").is_file())
        self.assertIn("vendor.test", json.loads((self.tmp / "sites" / "platforms.json").read_text())["fetched"])
        domains = ["portal.test", "other.test", "vendor.test"]
        self.fetch(domains)
        _, index, report, _ = self.build(domains, platforms="platforms.txt")
        self.assertEqual(index["rejects"], ["%016x" % icon_pack.dhash(pattern(3))])
        self.assertNotIn("portal.test", index["domains"])
        self.assertIn("other.test", index["domains"])
        # The platform's own domain keeps its own icon, as a tenant: its subdomains (a club's
        # portal on the platform) never inherit it.
        self.assertIn("vendor.test", index["domains"])
        self.assertIn("vendor.test", index["tenants"])
        self.assertEqual(report["platform_icons_dropped"], ["portal.test"])

    def test_platform_domains_with_an_icon_are_tenants(self):
        domains = {"clubautomation.com": 0, "zendesk.com": 1, "acme.com": 2}
        self.assertEqual(
            icon_pack.platform_tenants(domains, ["zendesk.com", "gone.com"],
                                       ["clubautomation.com", "www.clubautomation.com", "wix.com"]),
            ["clubautomation.com", "zendesk.com"])
        self.assertEqual(icon_pack.platform_tenants(domains, [], []), [])

    def test_one_brand_on_its_own_domains_is_not_a_reject(self):
        domains = ["brand.com", "brand.fr", "brand.de", "brand.co.uk"]
        for domain in domains:
            self.serve(domain, pattern(5))
        self.fetch(domains)
        _, index, report, _ = self.build(domains)
        self.assertNotIn("rejects", index)
        for domain in domains:
            self.assertIn(domain, index["domains"])
        self.assertEqual((report["rejects"], report["platform_icons_dropped"]), (0, []))

    def test_flat_tiles_of_unrelated_brands_are_not_a_reject(self):
        domains = ["alpha.test", "bravo.test", "charlie.test"]
        for domain, color in zip(domains, (b"\x20\x40\xc0\xff", b"\xc0\x20\x20\xff", b"\x10\x90\x30\xff")):
            self.serve(domain, icon_pack.png_from_rgba(128, 128, [color * 128] * 128))
        self.fetch(domains)
        _, index, report, _ = self.build(domains)
        self.assertNotIn("rejects", index)
        for domain in domains:
            self.assertIn(domain, index["domains"])
        self.assertEqual(report["platform_icons_dropped"], [])
        self.assertEqual(icon_pack.find_rejects([("a.test", 0), ("b.test", 0), ("c.test", 0)], [0, (1 << 64) - 1]), [])
        self.assertFalse(icon_pack.is_rejected(0, [0]))

    def test_near_duplicates_cluster_and_far_ones_do_not(self):
        base = 0x0F0F_F0F0_3C3C_A5A5
        near = base ^ 0b111111  # 6 bits away
        far = base ^ 0b1111111  # 7 bits away
        self.assertEqual(icon_pack.find_rejects([("a.test", base), ("b.test", near), ("c.test", base)]), sorted({base, near}))
        self.assertEqual(icon_pack.find_rejects([("a.test", base), ("b.test", base), ("c.test", far)]), [])
        self.assertEqual(icon_pack.find_rejects([("a.test", base), ("b.test", base)], [far]), [far])
        self.assertTrue(icon_pack.is_rejected(near, [base]))
        self.assertFalse(icon_pack.is_rejected(far, [base]))

    def test_rejects_in_the_index(self):
        data = icon_pack.pack_bytes(3, 256, [(b"a", 0)], {"a.com": 0}, rejects=[255, 1, 255])
        index, _ = icon_pack.read_pack(data)
        self.assertEqual(index["rejects"], ["0000000000000001", "00000000000000ff"])
        bad = data.replace(b'"0000000000000001"', b'"000000000000000G"')
        with self.assertRaises(icon_pack.IconPackError):
            icon_pack.read_pack(bad)

    def test_platform_icons_in_the_index(self):
        domains = {"daxko.com": 0, "members.daxko.com": 0, "login.okta.com": 1, "bayclubs.com": 2,
                   "notdaxko.com": 3, "acme.com": 4}
        self.assertEqual(icon_pack.platform_icons(domains, ["daxko.com", "okta.com", "wix.com"]), [0, 1])
        icons = [(b"a", 0), (b"b", 0), (b"c", 0), (b"d", 0), (b"e", 0)]
        data = icon_pack.pack_bytes(3, 256, icons, domains, platforms=[1, 0, 1])
        index, _ = icon_pack.read_pack(data)
        self.assertEqual(index["platforms"], [0, 1])
        plain, _ = icon_pack.read_pack(icon_pack.pack_bytes(3, 256, icons, domains))
        self.assertNotIn("platforms", plain)
        with self.assertRaises(icon_pack.IconPackError):
            icon_pack.read_pack(icon_pack.pack_bytes(3, 256, icons, domains, platforms=[9]))

    def test_shipped_platform_list(self):
        path = ROOT / "scripts" / "icon-pack-platforms.txt"
        listed = icon_pack.read_domain_lists([path])
        self.assertGreaterEqual(len(listed), 35)
        self.assertEqual(len(listed), len(set(listed)))
        self.assertNotIn("\u2014", path.read_text())
        for domain in ("daxko.com", "clubautomation.com", "force.com", "salesforce.com", "okta.com", "shopify.com",
                       "wix.com", "squarespace.com", "wordpress.com", "zendesk.com"):
            self.assertIn(domain, listed)

    @unittest.skipUnless(os.environ.get("RESVG") or shutil.which("resvg"), "needs resvg")
    def test_icon_hash_draws_then_hashes(self):
        work = self.tmp / "work"
        work.mkdir()
        image = pattern(6, 256)
        value = icon_pack.icon_hash(icon_pack.raster_svg(image), os.environ.get("RESVG") or shutil.which("resvg"), work)
        self.assertLessEqual(icon_pack.distance(value, icon_pack.dhash(image)), 2)


WIKIDATA_DATA = ROOT / "scripts" / "testdata" / "wikidata"


class Wikidata(unittest.TestCase):
    """Wikidata + Commons as a build source, from recorded-format fixtures (scripts/testdata/wikidata):
    the network helper is replaced, nothing leaves the machine."""

    def setUp(self):
        Collect.setUp(self)
        self.calls = []
        write(self.tmp / "block.txt", "")
        write(self.tmp / "platforms.txt", "shopify.test\n")

    def fetcher(self, url, limit, accept="*/*"):
        self.calls.append((url, limit, accept))
        if url.startswith(icon_pack.WIKIDATA_SPARQL + "?"):
            return (WIKIDATA_DATA / "sparql-page.json").read_bytes()
        if url.startswith(icon_pack.COMMONS_API + "?"):
            return (WIKIDATA_DATA / "commons-imageinfo.json").read_bytes()
        if url.startswith("https://upload.wikimedia.org/"):
            return (WIKIDATA_DATA / "files" / urllib.parse.unquote(url.rsplit("/", 1)[1])).read_bytes()
        raise AssertionError(f"unexpected URL {url}")

    def test_commons_tracking_query_is_dropped_any_other_is_kept(self):
        base = "https://upload.wikimedia.org/wikipedia/commons/8/84/Acme_logo_2015.svg"
        self.assertEqual(icon_pack.commons_original(base + "?utm_source=commons.wikimedia.org&utm_campaign=index"), base)
        self.assertEqual(icon_pack.commons_original(base), base)
        for kept in (base + "?utm_source=x&download=1", base + "?utm_source=x#y", base + "?a"):
            self.assertEqual(icon_pack.commons_original(kept), kept)
            self.assertIsNone(icon_pack.COMMONS_ORIGINAL.fullmatch(icon_pack.commons_original(kept)))

    def query(self, block=None):
        when = icon_pack.datetime.datetime(2026, 11, 14, 9, 30, tzinfo=icon_pack.datetime.timezone.utc)
        return icon_pack.fetch_wikidata(self.tmp / "wikidata", block or icon_pack.Blocklist(), ["shopify.test"],
                                        fetcher=self.fetcher, now=when)

    def build(self, curated=None, extra=()):
        sources = self.tmp / "sources.json"
        sources.write_text("{}")
        curated_path = self.tmp / "curated.json"
        curated_path.write_text(json.dumps(curated or {"brands": []}))
        out = self.tmp / "out"
        with mock.patch.object(icon_pack, "render", side_effect=lambda c, *a: b"RIFF" + c.name.encode()):
            code = icon_pack.main(["build", "--simple-icons", str(self.roots[0]), "--logos", str(self.roots[1]),
                                   "--twofa", str(self.roots[2]), "--sources", str(sources), "--version", "9",
                                   "--out", str(out), "--curated", str(curated_path), "--wikidata",
                                   str(self.tmp / "wikidata"), "--blocklist", str(self.tmp / "block.txt"),
                                   "--platforms", str(self.tmp / "platforms.txt"), *extra])
        self.assertEqual(code, 0)
        manifest = json.loads((out / "icon-pack-manifest.json").read_text())
        index, blob = icon_pack.read_pack((out / manifest["pack"]["file"]).read_bytes())
        report = json.loads((out / "report.json").read_text())
        return manifest, index, blob, report

    def icon(self, index, blob, domain):
        offset, length, _ = index["icons"][index["domains"][domain]]
        return blob[offset:offset + length]

    def test_licenses(self):
        for kept in ("Public domain", "public DOMAIN", "PD", "PD-textlogo", "PD-ineligible", "PD-shape", "pd-us",
                     "CC0", "CC0 1.0", "cc0-1.0", " <span>Public domain</span> "):
            self.assertTrue(icon_pack.kept_license(kept), kept)
        for dropped in ("CC BY-SA 4.0", "CC BY 3.0", "GFDL", "Copyrighted free use", "Attribution", "PDF", "",
                        None, "Public domain; CC BY-SA", "pd-", "CC0 2.0 BY", "PD-textlogo and CC BY-SA 4.0",
                        "PD-self cc-by-sa-4.0", "pd-  by-nc"):
            self.assertFalse(icon_pack.kept_license(dropped), dropped)

    def test_current_logo(self):
        def s(file, rank="normal", starts=(), ended=False):
            return {"file": file, "rank": rank, "starts": list(starts), "ended": ended}
        pick = icon_pack.current_logo
        self.assertEqual(pick({1: s("old.svg", starts=[(2001, 1, 1)], ended=True), 2: s("new.svg", starts=[(2015, 1, 1)]),
                               3: s("bad.svg", "deprecated", starts=[(2020, 1, 1)])}), "new.svg")
        self.assertEqual(pick({1: s("pref.svg", "preferred"), 2: s("later.svg", starts=[(2024, 1, 1)])}), "pref.svg")
        self.assertEqual(pick({1: s("a.svg", starts=[(2010, 5, 1)]), 2: s("b.svg", starts=[(2010, 6, 1)]),
                               3: s("c.svg")}), "b.svg")
        self.assertEqual(pick({1: s("z.svg"), 2: s("y.svg")}), "y.svg")
        self.assertIsNone(pick({1: s("x.svg", "deprecated"), 2: s("w.svg", ended=True), 3: s(None)}))
        self.assertIsNone(icon_pack.commons_title("http://commons.wikimedia.org/wiki/Special:FilePath/..%2F..%2Fx.svg"))
        self.assertIsNone(icon_pack.commons_title("http://commons.wikimedia.org/wiki/Special:FilePath/x.exe"))
        self.assertIsNone(icon_pack.commons_title("https://example.org/x.svg"))
        self.assertEqual(icon_pack.commons_title("http://commons.wikimedia.org/wiki/Special:FilePath/A%C4%93sop_logo.svg"),
                         "Aēsop logo.svg")

    def test_query_downloads_and_drops(self):
        record = self.query()
        # Polite to the endpoints: one query page, one Commons batch, then one download per candidate file.
        sparql = [c for c in self.calls if c[0].startswith(icon_pack.WIKIDATA_SPARQL)]
        self.assertEqual(len(sparql), 1)
        self.assertEqual(sparql[0][2], "application/sparql-results+json")
        self.assertIn("OFFSET+0", sparql[0][0])
        self.assertTrue(all(c[0].startswith("https://") for c in self.calls))
        domains = record["domains"]
        self.assertEqual(sorted(domains), ["acme.test", "aircanada.com", "withings.com"])
        acme = domains["acme.test"]
        self.assertEqual((acme["item"], acme["label"], acme["file"], acme["license"]),
                         ("Q100", "Acme", "Acme logo 2015.svg", "Public domain"))
        self.assertEqual(acme["path"], "files/%s.svg" % acme["sha1"])
        self.assertEqual((self.tmp / "wikidata" / acme["path"]).read_bytes(),
                         (WIKIDATA_DATA / "files" / "Acme_logo_2015.svg").read_bytes())
        self.assertEqual(domains["aircanada.com"]["path"].rsplit(".", 1)[1], "png")
        self.assertEqual(record["conflicts"], {"acme.test": {"kept": "Q100", "others": ["Q200"]}})
        dropped = record["dropped"]
        self.assertEqual(dropped["license"], ["Sharealike.svg (CC BY-SA 4.0)"])
        self.assertEqual(dropped["wordmark"], ["Widemark.svg: 5.00 wide for 1 high"])
        self.assertEqual(dropped["unsafe-svg"], ["unsafe.svg"])
        self.assertEqual(dropped["sha1"], ["Tampered.svg: the bytes are not the file Commons lists"])
        self.assertEqual(dropped["platform"], ["Q800 hosted.shopify.test"])
        self.assertEqual(sorted(dropped["not-a-brand-site"]), ["Q100 facebook.com", "Q1000 linktr.ee"])
        self.assertNotIn("old.acme.test", json.dumps(record))
        self.assertEqual(record["licenses"]["CC BY-SA 4.0"], {"kept": 0, "dropped": 1})
        self.assertEqual(record["licenses"]["Public domain"], {"kept": 1, "dropped": 2})
        self.assertEqual(record["licenses"]["PD-shape"], {"kept": 1, "dropped": 0})
        self.assertEqual(record["queried"], "2026-11-14T09:30:00+00:00")
        self.assertEqual(record["user_agent"], icon_pack.WIKI_UA)
        # The rejected files never land in the folder; only SHA-1 named files do.
        names = sorted(p.name for p in (self.tmp / "wikidata" / "files").iterdir())
        self.assertEqual(len(names), 3)
        self.assertTrue(all(icon_pack.WIKIDATA_FILE.fullmatch("files/" + n) for n in names))
        # A blocklisted domain is never queried on Commons.
        self.calls.clear()
        record = self.query(icon_pack.Blocklist(["acme.test"]))
        self.assertNotIn("acme.test", record["domains"])
        self.assertIn("Q100 acme.test", record["dropped"]["blocklist"])

    def test_download_cap_and_url(self):
        meta = json.loads((WIKIDATA_DATA / "commons-imageinfo.json").read_text())["query"]["pages"][0]["imageinfo"][0]
        out = self.tmp / "w"
        big = dict(meta, size=icon_pack.MAX_SVG_BYTES + 1)
        with self.assertRaisesRegex(icon_pack.IconPackError, "^too-large"):
            icon_pack.commons_file("Acme logo 2015.svg", big, self.fetcher, out)
        moved = dict(meta, url="https://evil.example/Acme_logo_2015.svg")
        with self.assertRaisesRegex(icon_pack.IconPackError, "^url"):
            icon_pack.commons_file("Acme logo 2015.svg", moved, self.fetcher, out)
        gif = dict(meta, mime="image/gif")
        with self.assertRaisesRegex(icon_pack.IconPackError, "^format"):
            icon_pack.commons_file("Acme logo 2015.svg", gif, self.fetcher, out)
        self.calls.clear()
        icon_pack.commons_file("Acme logo 2015.svg", meta, self.fetcher, out)
        self.assertEqual(self.calls[0][1], icon_pack.MAX_SVG_BYTES)

    def test_paging_stops_on_a_short_page(self):
        def row(n):
            e = "http://www.wikidata.org/entity/"
            return {"item": {"type": "uri", "value": f"{e}Q{n}"}, "site": {"type": "uri", "value": f"https://s{n}.test/"},
                    "siteRank": {"type": "uri", "value": "http://wikiba.se/ontology#NormalRank"}}
        pages = [[row(1), row(2)], [row(3), row(4)], [row(5)]]
        seen = []

        def fetcher(url, limit, accept="*/*"):
            if url.startswith(icon_pack.WIKIDATA_SPARQL):
                seen.append(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["query"][0])
                return json.dumps({"results": {"bindings": pages[len(seen) - 1]}}).encode()
            return b'{"query": {"pages": []}}'
        record = icon_pack.fetch_wikidata(self.tmp / "w", icon_pack.Blocklist(), [], fetcher=fetcher, page_size=2)
        self.assertEqual(len(seen), 3)
        self.assertIn("LIMIT 2 OFFSET 4", seen[2])
        self.assertEqual(record["items"], 5)
        self.assertEqual(len(record["dropped"]["no-current-logo"]), 5)
        seen.clear()
        record = icon_pack.fetch_wikidata(self.tmp / "w", icon_pack.Blocklist(), [], fetcher=fetcher, page_size=2,
                                          max_pages=1)
        self.assertEqual(len(seen), 1)
        self.assertIn("page-limit", record["dropped"])

    def test_network_helper_user_agent_and_retries(self):
        import urllib.error
        attempts, waits = [], []

        def flaky(url, limit, headers=None, timeout=20):
            attempts.append(headers)
            self.assertEqual(timeout, icon_pack.WIKI_TIMEOUT)
            if len(attempts) == 1:
                raise urllib.error.HTTPError(url, 429, "slow down", {"Retry-After": "7"}, None)
            if len(attempts) == 2:
                raise urllib.error.HTTPError(url, 503, "busy", {}, None)
            return b"ok", url

        with mock.patch.object(icon_pack, "fetch_url", side_effect=flaky):
            self.assertEqual(icon_pack.wiki_get("https://query.wikidata.org/sparql?x", 10, "application/json",
                                                sleep=waits.append), b"ok")
        self.assertEqual(waits, [7, 4])
        self.assertEqual(icon_pack.WIKI_UA, "OnePass icon pack builder (https://github.com/soma-intelligence/onepass)")
        self.assertEqual(attempts[0], {"User-Agent": icon_pack.WIKI_UA, "Accept": "application/json"})
        # A dropped connection or a timeout is retried with the same bounded backoff.
        import socket
        errors = [urllib.error.URLError("reset"), socket.timeout("slow"), TimeoutError("slow")]

        def shaky(url, limit, headers=None, timeout=20):
            if errors:
                raise errors.pop(0)
            return b"fine", url
        waits.clear()
        with mock.patch.object(icon_pack, "fetch_url", side_effect=shaky):
            self.assertEqual(icon_pack.wiki_get("https://query.wikidata.org/sparql", 10, sleep=waits.append), b"fine")
        self.assertEqual(waits, [2, 4, 8])

        def down(url, limit, headers=None, timeout=20):
            raise urllib.error.URLError("no route")
        waits.clear()
        with mock.patch.object(icon_pack, "fetch_url", side_effect=down):
            with self.assertRaises(urllib.error.URLError):
                icon_pack.wiki_get("https://query.wikidata.org/sparql", 10, sleep=waits.append)
        self.assertEqual(len(waits), icon_pack.RETRY_ATTEMPTS - 1)
        waits.clear()

        def missing(url, limit, headers=None, timeout=20):
            raise urllib.error.HTTPError(url, 404, "gone", {}, None)
        with mock.patch.object(icon_pack, "fetch_url", side_effect=missing):
            with self.assertRaises(urllib.error.HTTPError):
                icon_pack.wiki_get("https://commons.wikimedia.org/w/api.php", 10, sleep=waits.append)
        self.assertEqual(waits, [])  # a 404 is not retried
        # fetch_url sends the caller's User-Agent and refuses plain http.
        captured = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def geturl(self):
                return "https://query.wikidata.org/sparql"

            def read(self, n):
                return b"{}"

        def urlopen(request, timeout):
            captured.append(request)
            return Response()
        with mock.patch("urllib.request.urlopen", side_effect=urlopen):
            icon_pack.fetch_url("https://query.wikidata.org/sparql", 10, {"User-Agent": icon_pack.WIKI_UA})
        self.assertEqual(captured[0].get_header("User-agent"), icon_pack.WIKI_UA)
        with self.assertRaises(icon_pack.IconPackError):
            icon_pack.fetch_url("http://query.wikidata.org/sparql", 10)

    def test_paging_counts_distinct_items_not_new_ones(self):
        def row(n, site="NormalRank"):
            e = "http://www.wikidata.org/entity/"
            return {"item": {"type": "uri", "value": f"{e}Q{n}"}, "site": {"type": "uri", "value": f"https://s{n}.test/"},
                    "siteRank": {"type": "uri", "value": "http://wikiba.se/ontology#" + site}}
        # Q2 comes back on page 2 (two rows for one item on page 1 too): the run goes on to page 3.
        pages = [[row(1), row(1, "DeprecatedRank"), row(2)], [row(2), row(3)], [row(4)]]
        seen = []

        def fetcher(url, limit, accept="*/*"):
            if url.startswith(icon_pack.WIKIDATA_SPARQL):
                seen.append(url)
                return json.dumps({"results": {"bindings": pages[len(seen) - 1]}}).encode()
            return b'{"query": {"pages": []}}'
        record = icon_pack.fetch_wikidata(self.tmp / "w", icon_pack.Blocklist(), [], fetcher=fetcher, page_size=2)
        self.assertEqual((len(seen), record["items"]), (3, 4))
        # A full page that brings nothing new ends the run.
        pages[:] = [[row(1), row(2)], [row(1), row(2)], [row(9)]]
        seen.clear()
        icon_pack.fetch_wikidata(self.tmp / "w", icon_pack.Blocklist(), [], fetcher=fetcher, page_size=2)
        self.assertEqual(len(seen), 2)

    def test_raw_control_characters_in_labels_do_not_lose_a_page(self):
        page = b'{"results": {"bindings": [{"itemLabel": {"type": "literal", "value": "Tab\tLabel"}}]}}'

        def fetcher(url, limit, accept="*/*"):
            return page if url.startswith(icon_pack.WIKIDATA_SPARQL) else b'{"query": {"pages": []}}'
        record = icon_pack.fetch_wikidata(self.tmp / "w", icon_pack.Blocklist(), [], fetcher=fetcher, page_size=2)
        self.assertEqual(record["page_errors"], [])

    def test_cut_or_oversized_answers_become_page_errors(self):
        good = json.dumps({"results": {"bindings": []}}).encode()
        answers = [b'{"results": {"bindi', icon_pack.IconPackError("too large"), b"[1", TimeoutError("timed out")]
        calls = []

        def fetcher(url, limit, accept="*/*"):
            calls.append(url)
            answer = answers.pop(0) if answers else good
            if isinstance(answer, Exception):
                raise answer
            return answer
        # Page 1: cut, then too large: an error. Page 2: cut, then timed out: an error, two in a row, so the run
        # stops and still writes its record.
        record = icon_pack.fetch_wikidata(self.tmp / "w", icon_pack.Blocklist(), [], fetcher=fetcher, page_size=2)
        self.assertEqual(len(calls), 4)
        self.assertEqual(record["page_errors"], ["sparql offset 0: too large",
                                                 "sparql offset 2: timed out"])
        # One retry is enough when the second answer is whole.
        answers[:] = [b'{"results": {"bindi', good]
        calls.clear()
        record = icon_pack.fetch_wikidata(self.tmp / "w", icon_pack.Blocklist(), [], fetcher=fetcher, page_size=2)
        self.assertEqual((len(calls), record["page_errors"]), (2, []))
        self.assertTrue((self.tmp / "w" / "wikidata.json").is_file())

    def test_subdomain_of_curated_dropped_and_open_set_parent_overridden(self):
        self.query()
        record = json.loads((self.tmp / "wikidata" / "wikidata.json").read_text())
        acme = record["domains"]["acme.test"]
        # store.withings.com: withings.com is curated. miles.aeroplan.com: aeroplan.com only has the open sets.
        record["domains"]["store.withings.com"] = dict(acme, item="Q101")
        record["domains"]["miles.aeroplan.com"] = dict(acme, item="Q102")
        (self.tmp / "wikidata" / "wikidata.json").write_text(json.dumps(record))
        curated = {"brands": [{"name": "Withings", "domains": ["withings.com"], "use": "simple-icons:withings"}]}
        _, index, blob, report = self.build(curated)
        self.assertNotIn("store.withings.com", index["domains"])
        self.assertEqual(report["wikidata"]["dropped"]["subdomain-of-curated"], 1)
        self.assertIn("store.withings.com: subdomain-of-curated", report["skipped"]["wikidata"])
        self.assertEqual(self.icon(index, blob, "miles.aeroplan.com"), b"RIFFwikidata:Q100")
        self.assertNotIn(b"wikidata", self.icon(index, blob, "aeroplan.com"))
        self.assertEqual(report["wikidata"]["subdomain-override"], ["miles.aeroplan.com"])
        # A curated `use: none` parent counts as curated too.
        log = []
        out, _, drops = icon_pack.wikidata_candidates(self.tmp / "wikidata", {"aeroplan.com"}, icon_pack.Blocklist(),
                                                      [], lambda k, w: log.append(w))
        self.assertNotIn("miles.aeroplan.com", out)
        self.assertEqual(drops["subdomain-of-curated"], 1)

    def test_dry_run_prints_the_query_and_fetches_nothing(self):
        import contextlib
        import io
        printed = io.StringIO()
        with mock.patch.object(icon_pack, "fetch_url", side_effect=AssertionError("network")), \
                contextlib.redirect_stdout(printed):
            code = icon_pack.main(["wikidata", "--out", str(self.tmp / "w"), "--dry-run", "--page-size", "500"])
        self.assertEqual(code, 0)
        self.assertIn("wdt:P154", printed.getvalue())
        self.assertIn("LIMIT 500 OFFSET 0", printed.getvalue())
        self.assertIn("user-agent: OnePass icon pack builder (https://github.com/soma-intelligence/onepass)",
                      printed.getvalue())
        self.assertFalse((self.tmp / "w").exists())

    def test_build_priority_names_and_report(self):
        self.query()
        curated = {"brands": [{"name": "Withings", "domains": ["withings.com"], "use": "simple-icons:withings"}]}
        manifest, index, blob, report = self.build(curated)
        # Wikidata beats the open sets (Air Canada is in 2FA Directory and Simple Icons too) ...
        self.assertEqual(self.icon(index, blob, "aircanada.com"), b"RIFFwikidata:Q700")
        self.assertEqual(self.icon(index, blob, "acme.test"), b"RIFFwikidata:Q100")
        # ... and loses to the curated list.
        self.assertEqual(self.icon(index, blob, "withings.com"), b"RIFFsimple-icons:withings")
        # The item label reaches `names`.
        self.assertEqual(index["names"]["acme"], index["domains"]["acme.test"])
        self.assertEqual(index["names"]["aircanada"], index["domains"]["aircanada.com"])
        self.assertEqual(manifest["wikidata_queried"], "2026-11-14T09:30:00+00:00")
        self.assertEqual(manifest["sources"]["wikidata"]["queried"], "2026-11-14T09:30:00+00:00")
        self.assertEqual(sorted(manifest["sources"]["wikidata"]["icons"]), ["acme.test", "aircanada.com"])
        self.assertEqual(manifest["sources"]["wikidata"]["icons"]["acme.test"]["license"], "Public domain")
        wd = report["wikidata"]
        self.assertEqual((wd["in_pack"], wd["domains"], wd["candidates"]), (2, 3, 2))
        self.assertEqual(wd["licenses"]["Public domain"], {"kept": 1, "dropped": 2, "in_pack": 1})
        self.assertEqual(wd["licenses"]["CC BY-SA 4.0"]["dropped"], 1)
        self.assertEqual((wd["dropped"]["curated"], wd["dropped"]["license"], wd["dropped"]["wordmark"],
                          wd["dropped"]["unsafe-svg"]), (1, 1, 1, 1))
        self.assertEqual(wd["conflicts"], {"acme.test": {"kept": "Q100", "others": ["Q200"]}})
        self.assertEqual(report["licenses"]["acme.test"], "Public domain")
        self.assertEqual(report["licenses"]["aircanada.com"], "PD-shape")

    def test_build_checks_the_files_again(self):
        self.query()
        record = json.loads((self.tmp / "wikidata" / "wikidata.json").read_text())
        acme = record["domains"]["acme.test"]
        # A file swapped after the query, an unsafe one with a matching hash, a path outside the folder.
        unsafe = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><image href="https://x.test/a.png"/></svg>'
        (self.tmp / "wikidata" / acme["path"]).write_bytes(unsafe)
        record["domains"]["swapped.test"] = dict(acme, sha256=hashlib.sha256(b"other").hexdigest())
        acme["sha256"] = hashlib.sha256(unsafe).hexdigest()
        record["domains"]["escape.test"] = dict(acme, path="../../sources.json")
        wide = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 300 100"><path d="M0 0h300v100H0z"/></svg>'
        wide_path = "files/%s.svg" % ("e" * 40)
        (self.tmp / "wikidata" / wide_path).write_bytes(wide)
        record["domains"]["wide.test"] = dict(acme, path=wide_path, sha256=hashlib.sha256(wide).hexdigest())
        (self.tmp / "wikidata" / "wikidata.json").write_text(json.dumps(record))
        write(self.tmp / "block.txt", "aircanada.com\n")
        log = []
        out, _, drops = icon_pack.wikidata_candidates(self.tmp / "wikidata", set(),
                                                      icon_pack.load_blocklist(self.tmp / "block.txt"),
                                                      ["shopify.test"], lambda k, w: log.append(w))
        self.assertEqual(sorted(out), ["withings.com"])
        self.assertEqual(drops, {"unsafe-svg": 1, "file-changed": 1, "bad-record": 1, "wordmark": 1, "blocklist": 1})

    def test_rejects_never_drop_a_wikidata_logo(self):
        # Three unrelated sites serve one icon: a platform reject. Acme's Wikidata logo is that same
        # image, yet it is a logo, not a site icon, and stays.
        DomainList.setUp(self)  # a local web server, in a new self.tmp
        write(self.tmp / "block.txt", "")
        write(self.tmp / "platforms.txt", "shopify.test\n")
        image = pattern(1, 256)
        for domain in ("gym-one.test", "club-two.test", "studio-three.test"):
            write(self.web / domain / "index.html", '<html><link rel="apple-touch-icon" href="icon.png"></html>')
            write(self.web / domain / "icon.png", image)
        icon_pack.fetch_domains(["gym-one.test", "club-two.test", "studio-three.test"], set(), icon_pack.Blocklist(),
                                self.tmp / "sites", lambda k, w: None, google=False, jobs=1,
                                fetcher=lambda url, limit: DomainList.fetcher(self, url, limit))
        self.query()
        record = json.loads((self.tmp / "wikidata" / "wikidata.json").read_text())
        path = "files/%s.png" % hashlib.sha1(image).hexdigest()
        (self.tmp / "wikidata" / path).write_bytes(image)
        record["domains"]["acme.test"].update(path=path, sha256=hashlib.sha256(image).hexdigest())
        (self.tmp / "wikidata" / "wikidata.json").write_text(json.dumps(record))
        write(self.tmp / "list.txt", "gym-one.test\nclub-two.test\nstudio-three.test\n")
        with mock.patch.object(icon_pack, "icon_hash", side_effect=embedded_hash):
            _, index, blob, report = self.build(extra=["--sites", str(self.tmp / "sites"),
                                                       "--domains", str(self.tmp / "list.txt")])
        self.assertEqual(index["rejects"], ["%016x" % icon_pack.dhash(image)])
        self.assertEqual(report["platform_icons_dropped"], ["club-two.test", "gym-one.test", "studio-three.test"])
        self.assertEqual(self.icon(index, blob, "acme.test"), b"RIFFwikidata:Q100")


@unittest.skipUnless(has_openssl(), "needs OpenSSL 3")
class Signing(unittest.TestCase):
    def test_sign_then_verify(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        pack = icon_pack.pack_bytes(9, 256, [(b"x", 0)], {"a.com": 0})
        (tmp / "onepass-icons-9.bin").write_bytes(pack)
        manifest = tmp / "icon-pack-manifest.json"
        manifest.write_text(json.dumps({"format": 1, "version": 9, "pack": {
            "file": "onepass-icons-9.bin", "size": len(pack), "sha256": hashlib.sha256(pack).hexdigest()}}))
        os.environ["ICON_PACK_ED_PRIVATE_KEY"] = base64.b64encode(RFC_SEED).decode()
        self.addCleanup(os.environ.pop, "ICON_PACK_ED_PRIVATE_KEY", None)
        self.assertEqual(icon_pack.main(["sign", "--manifest", str(manifest)]), 0)
        public = base64.b64encode(RFC_PUBLIC).decode()
        self.assertEqual(icon_pack.verify_files(manifest, tmp / "onepass-icons-9.bin", public)["version"], 9)
        (tmp / "onepass-icons-9.bin").write_bytes(pack + b"!")
        with self.assertRaises(icon_pack.IconPackError):
            icon_pack.verify_files(manifest, tmp / "onepass-icons-9.bin", public)
        manifest.write_text(manifest.read_text().replace('"version": 9', '"version": 10'))
        with self.assertRaises(icon_pack.IconPackError):
            icon_pack.verify_files(manifest, tmp / "onepass-icons-9.bin", public)


class DHash(unittest.TestCase):
    def test_shared_vectors(self):
        vectors = json.loads((ROOT / "scripts" / "testdata" / "dhash-vectors.json").read_text())
        self.assertEqual(len(vectors), 11)
        for v in vectors:
            png = base64.b64decode(v["png"])
            # Python is the reference and matches exactly. The Swift test allows a distance of at most 2
            # for "low-alpha-mark" only: CoreGraphics premultiplies to 8 bits, which at alpha 1 to 20
            # cannot be undone exactly.
            self.assertEqual("%016x" % icon_pack.dhash(png), v["hash"], v["name"])

    def test_refuses_what_it_cannot_hash(self):
        def png(width, height, body=b""):
            def chunk(kind, data):
                return (struct.pack(">I", len(data)) + kind + data
                        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))
            return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
                    + chunk(b"IDAT", body) + chunk(b"IEND", b""))
        for bad in (b"", b"not a png at all, just text bytes", png(100000, 100000), png(0, 4),
                    png(4, 4, b"garbage")):
            with self.assertRaises(icon_pack.IconPackError):
                icon_pack.dhash(bad)

    def test_distinguishes_images(self):
        vectors = {v["name"]: icon_pack.dhash(base64.b64decode(v["png"]))
                   for v in json.loads((ROOT / "scripts" / "testdata" / "dhash-vectors.json").read_text())}
        self.assertEqual(vectors["solid-white"], vectors["solid-black"])
        self.assertGreater(bin(vectors["checkerboard"] ^ vectors["noise-256"]).count("1"), 8)


if __name__ == "__main__":
    unittest.main()
