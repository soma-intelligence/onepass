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
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
