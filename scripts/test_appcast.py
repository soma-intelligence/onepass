#!/usr/bin/env python3
"""Tests of scripts/appcast.py and apple/scripts/check-update-key.sh.

Run: python3 -I scripts/test_appcast.py   (needs OpenSSL 3 or later on PATH,
or OPENSSL=/path/to/openssl; LibreSSL cannot sign Ed25519).
"""

import base64
import io
import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import appcast  # noqa: E402

SPARKLE_NS = "http://www.andymatuschak.org/xml-namespaces/sparkle"
CHECK_KEY = ROOT / "apple" / "scripts" / "check-update-key.sh"

# RFC 8032, section 7.1, TEST 1 (empty message).
RFC_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC_PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
RFC_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)

SEED = bytes(range(32))
OTHER_SEED = bytes(range(1, 33))
FEED = "https://github.com/soma-intelligence/onepass/releases/latest/download/appcast.xml"


def info_plist(public_key, **overrides):
    info = {
        "CFBundleIdentifier": "me.somalabs.onepass",
        "CFBundleShortVersionString": "0.3.0",
        "CFBundleVersion": "0.3.0",
        "LSMinimumSystemVersion": "26.0",
        "SUFeedURL": FEED,
        "SUPublicEDKey": public_key,
        "SURequireSignedFeed": True,
        "SUVerifyUpdateBeforeExtraction": True,
        "SUEnableSystemProfiling": False,
    }
    info.update(overrides)
    return {k: v for k, v in info.items() if v is not None}


def make_zip(path, info):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("OnePass.app/Contents/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        z.writestr("OnePass.app/Contents/MacOS/OnePass", b"\xcf\xfa\xed\xfe binary")


def split_feed(data):
    """The signed content and its signing block, read the way Sparkle reads them
    (SPUExtractAppcastContent: the last prefix, then the first suffix after it)."""
    prefix = b"<!-- sparkle-signatures:\n"
    start = data.rfind(prefix)
    assert start >= 0, "no signing block"
    end = data.find(b"-->", start + len(prefix))
    block = data[start + len(prefix):end].decode()
    fields = {}
    for line in block.splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return data[:start], fields


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_vector(self):
        self.assertEqual(appcast.public_key(RFC_SEED), RFC_PUBLIC)
        self.assertEqual(appcast.sign(RFC_SEED, b""), RFC_SIGNATURE)
        self.assertTrue(appcast.verify(RFC_PUBLIC, b"", RFC_SIGNATURE))

    def test_tampered_data_is_refused(self):
        signature = appcast.sign(SEED, b"OnePass archive")
        pub = appcast.public_key(SEED)
        self.assertTrue(appcast.verify(pub, b"OnePass archive", signature))
        self.assertFalse(appcast.verify(pub, b"OnePass archivE", signature))
        self.assertFalse(appcast.verify(appcast.public_key(OTHER_SEED), b"OnePass archive", signature))

    def test_seed_must_be_32_bytes(self):
        for bad in (b"", bytes(31), bytes(64), bytes(96)):
            with self.assertRaises(appcast.AppcastError):
                appcast.load_seed(base64.b64encode(bad).decode())
        with self.assertRaises(appcast.AppcastError):
            appcast.load_seed("not base64 at all!")
        self.assertEqual(appcast.load_seed(" " + base64.b64encode(SEED).decode() + "\n"), SEED)

    def test_libressl_is_not_accepted(self):
        self.assertFalse(appcast.is_usable_openssl_version("LibreSSL 3.3.6"))
        self.assertTrue(appcast.is_usable_openssl_version("OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13)"))
        self.assertTrue(appcast.is_usable_openssl_version("OpenSSL 4.0.3 29 Sep 2026"))
        self.assertFalse(appcast.is_usable_openssl_version("OpenSSL 1.1.1w  11 Sep 2023"))


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.zip = self.dir / "OnePass-0.3.0-mac.zip"
        self.pub_b64 = base64.b64encode(appcast.public_key(SEED)).decode()

    def build(self, version="0.3.0", **plist_overrides):
        make_zip(self.zip, info_plist(self.pub_b64, **plist_overrides))
        return appcast.build_appcast(
            seed=SEED,
            version=version,
            archive=self.zip,
            download_url="https://github.com/soma-intelligence/onepass/releases/download/v0.3.0/OnePass-0.3.0-mac.zip",
            release_url="https://github.com/soma-intelligence/onepass/releases/tag/v0.3.0",
            source_date_epoch=1793577600,
        )

    def test_feed_is_signed_and_names_the_signed_archive(self):
        data = self.build()
        content, fields = split_feed(data)
        pub = appcast.public_key(SEED)
        self.assertEqual(int(fields["length"]), len(content))
        self.assertTrue(appcast.verify(pub, content, base64.b64decode(fields["edSignature"])))

        item = ET.fromstring(content).find("channel/item")
        self.assertEqual(item.findtext(f"{{{SPARKLE_NS}}}version"), "0.3.0")
        self.assertEqual(item.findtext(f"{{{SPARKLE_NS}}}shortVersionString"), "0.3.0")
        self.assertEqual(item.findtext(f"{{{SPARKLE_NS}}}minimumSystemVersion"), "26.0")
        self.assertEqual(item.findtext(f"{{{SPARKLE_NS}}}hardwareRequirements"), "arm64")
        self.assertEqual(item.find("description").get(f"{{{SPARKLE_NS}}}format"), "plain-text")
        self.assertEqual(item.findtext("link"), "https://github.com/soma-intelligence/onepass/releases/tag/v0.3.0")
        enclosure = item.find("enclosure")
        archive = self.zip.read_bytes()
        self.assertEqual(enclosure.get("url"), "https://github.com/soma-intelligence/onepass/releases/download/v0.3.0/OnePass-0.3.0-mac.zip")
        self.assertEqual(int(enclosure.get(f"{{{SPARKLE_NS}}}length") or enclosure.get("length")), len(archive))
        signature = base64.b64decode(enclosure.get(f"{{{SPARKLE_NS}}}edSignature"))
        self.assertTrue(appcast.verify(pub, archive, signature))
        self.assertEqual(item.findtext("pubDate"), "Mon, 02 Nov 2026 00:00:00 GMT")

    def test_verify_command_checks_both_signatures(self):
        data = self.build()
        feed = self.dir / "appcast.xml"
        feed.write_bytes(data)
        appcast.verify_appcast(feed, self.zip, appcast.public_key(SEED))
        # A feed edited after signing.
        feed.write_bytes(data.replace(b"OnePass 0.3.0", b"OnePass 9.9.9", 1))
        with self.assertRaises(appcast.AppcastError):
            appcast.verify_appcast(feed, self.zip, appcast.public_key(SEED))
        # An archive swapped after signing.
        feed.write_bytes(data)
        with zipfile.ZipFile(self.zip, "a") as z:
            z.writestr("OnePass.app/Contents/Resources/extra", b"x")
        with self.assertRaises(appcast.AppcastError):
            appcast.verify_appcast(feed, self.zip, appcast.public_key(SEED))

    def test_dry_run_version_uses_its_numeric_core(self):
        content, _ = split_feed(self.build(version="0.3.0-dryrun.abcdef123456"))
        self.assertIn(b"<sparkle:version>0.3.0</sparkle:version>", content)

    def test_refuses_an_app_that_trusts_another_key(self):
        other = base64.b64encode(appcast.public_key(OTHER_SEED)).decode()
        with self.assertRaisesRegex(appcast.AppcastError, "SUPublicEDKey"):
            self.build(SUPublicEDKey=other)
        with self.assertRaisesRegex(appcast.AppcastError, "SUPublicEDKey"):
            self.build(SUPublicEDKey="")

    def test_refuses_wrong_version_numbers(self):
        with self.assertRaisesRegex(appcast.AppcastError, "CFBundleShortVersionString"):
            self.build(CFBundleShortVersionString="0.2.0")
        with self.assertRaisesRegex(appcast.AppcastError, "CFBundleVersion"):
            self.build(CFBundleVersion="1")

    def test_refuses_weak_update_settings(self):
        with self.assertRaisesRegex(appcast.AppcastError, "SUFeedURL"):
            self.build(SUFeedURL="http://github.com/x/appcast.xml")
        with self.assertRaisesRegex(appcast.AppcastError, "SURequireSignedFeed"):
            self.build(SURequireSignedFeed=False)
        with self.assertRaisesRegex(appcast.AppcastError, "SUVerifyUpdateBeforeExtraction"):
            self.build(SUVerifyUpdateBeforeExtraction=None)
        with self.assertRaisesRegex(appcast.AppcastError, "SUEnableSystemProfiling"):
            self.build(SUEnableSystemProfiling=True)

    def test_refuses_a_zip_without_exactly_one_app(self):
        with zipfile.ZipFile(self.zip, "w") as z:
            z.writestr("README", b"no app")
        with self.assertRaises(appcast.AppcastError):
            appcast.read_app_info(self.zip)

    def test_key_file_is_private_and_removed(self):
        seen = []
        real = appcast._run_openssl

        def spy(args, **kwargs):
            for a in args:
                p = Path(a)
                if p.name == "key.der" and p.exists():
                    seen.append((oct(p.stat().st_mode & 0o777), oct(p.parent.stat().st_mode & 0o777), p))
            return real(args, **kwargs)

        appcast._run_openssl = spy
        try:
            appcast.sign(SEED, b"data")
        finally:
            appcast._run_openssl = real
        self.assertTrue(seen)
        for mode, dir_mode, path in seen:
            self.assertEqual(mode, "0o600")
            self.assertEqual(dir_mode, "0o700")
            self.assertFalse(path.exists())


class CheckUpdateKeyTests(unittest.TestCase):
    def run_check(self, **env):
        base = {"PATH": os.environ["PATH"], "PLATFORM_NAME": "macosx",
                "CODE_SIGN_IDENTITY": "Developer ID Application",
                "ONEPASS_SPARKLE_PUBLIC_KEY": base64.b64encode(bytes(32)).decode(),
                "ONEPASS_UPDATE_FEED_URL": FEED}
        base.update(env)
        return subprocess.run(["bash", str(CHECK_KEY)], env=base, capture_output=True, text=True)

    def test_developer_id_build_needs_a_valid_key(self):
        self.assertEqual(self.run_check().returncode, 0)
        for bad in ("", "abc", base64.b64encode(bytes(31)).decode(), base64.b64encode(bytes(33)).decode()):
            result = self.run_check(ONEPASS_SPARKLE_PUBLIC_KEY=bad)
            self.assertEqual(result.returncode, 1, bad)
            self.assertIn("ONEPASS_SPARKLE_PUBLIC_KEY", result.stderr)

    def test_developer_id_build_needs_an_https_feed(self):
        result = self.run_check(ONEPASS_UPDATE_FEED_URL="http://github.com/appcast.xml")
        self.assertEqual(result.returncode, 1)
        self.assertIn("ONEPASS_UPDATE_FEED_URL", result.stderr)

    def test_other_builds_pass_without_a_key(self):
        self.assertEqual(self.run_check(ONEPASS_SPARKLE_PUBLIC_KEY="", CODE_SIGN_IDENTITY="-").returncode, 0)
        self.assertEqual(self.run_check(ONEPASS_SPARKLE_PUBLIC_KEY="", CODE_SIGN_IDENTITY="Apple Development").returncode, 0)
        self.assertEqual(self.run_check(ONEPASS_SPARKLE_PUBLIC_KEY="", PLATFORM_NAME="iphoneos").returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
