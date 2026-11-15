#!/usr/bin/env python3
"""Tests of scripts/site_pack.py.

Run: python3 -I scripts/test_site_pack.py   (the signing test needs OpenSSL 3 or later on PATH,
or OPENSSL=/path/to/openssl). The fixtures in core/onepass-core/tests/fixtures/site-pack are
shared with the Rust core, which validates the same recipes.
"""

import base64
import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import appcast  # noqa: E402
import site_pack  # noqa: E402

FIXTURES = ROOT / "core" / "onepass-core" / "tests" / "fixtures" / "site-pack"

# RFC 8032, section 7.1, TEST 1.
RFC_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC_PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")


def has_openssl():
    try:
        appcast.openssl()
        return True
    except appcast.AppcastError:
        return False


def write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


class Recipes(unittest.TestCase):
    def check(self, folder):
        files = sorted((FIXTURES / "recipes" / folder).glob("*.json"))
        self.assertGreater(len(files), 3)
        for f in files:
            r = json.loads(f.read_text(encoding="utf-8"))
            yield f.stem, site_pack.validate_recipe(r["kind"], r["steps"], r["domains"])

    def test_every_valid_fixture_passes(self):
        for name, problems in self.check("valid"):
            self.assertEqual(problems, [], name)

    def test_every_invalid_fixture_fails(self):
        for name, problems in self.check("invalid"):
            self.assertNotEqual(problems, [], name)

    def test_invalid_reasons_name_the_rule(self):
        reasons = {n: " ".join(p) for n, p in self.check("invalid")}
        self.assertIn("not https", reasons["goto-http"])
        self.assertIn("not on the site's domains", reasons["goto-lookalike"])
        self.assertIn("destructive", reasons["click-delete-fr"])
        self.assertIn("final verify", reasons["click-verify-final"])
        self.assertIn("must end with expect_qr", reasons["totp-ends-without-expect-qr"])

    def test_subdomain_and_additional_domain_goto(self):
        step = lambda u: [{"do": "goto", "url": u}, {"do": "expect_qr"}]
        v = site_pack.validate_recipe
        self.assertEqual(v("setup_totp", step("https://a.b.example.com/x"), ["example.com"]), [])
        self.assertEqual(v("setup_totp", step("https://example.org/x"), ["example.com", "example.org"]), [])
        self.assertNotEqual(v("setup_totp", step("https://notexample.com/x"), ["example.com"]), [])
        self.assertNotEqual(v("setup_totp", step("https://user@example.com/x"), ["example.com"]), [])
        self.assertNotEqual(v("setup_totp", step("https://example.com:8443/x"), ["example.com"]), [])

    def test_destructive_words_are_whole_words(self):
        v = site_pack.validate_recipe
        def run(name):
            return v("setup_totp", [{"do": "click", "role": "button", "name": [name]}, {"do": "expect_qr"}], [])
        self.assertNotEqual(run("Remove device"), [])
        self.assertNotEqual(run("  DISABLE  "), [])
        self.assertNotEqual(run("Désactiver la double"), [])
        self.assertNotEqual(run("Activer"), [])
        self.assertEqual(run("Payments settings"), [])
        self.assertEqual(run("Activer la double"), [])

    def test_passkey_recipe_rules(self):
        v = site_pack.validate_recipe
        self.assertEqual(v("setup_passkey", [{"do": "expect_passkey_prompt"}], []), [])
        self.assertNotEqual(v("setup_passkey", [{"do": "expect_qr"}], []), [])
        self.assertNotEqual(v("other", [], []), [])
        self.assertNotEqual(v("setup_totp", "nope", []), [])


class Build(unittest.TestCase):
    def tmp(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        return d

    def upstream(self, root, twofa=(), passkeys=()):
        for domain, rec in twofa:
            write(root / "twofa" / "entries" / domain[0] / f"{domain}.json", {domain: dict(rec, domain=domain)})
        for domain, rec in passkeys:
            write(root / "passkeys" / "entries" / domain[0] / f"{domain}.json", {domain: rec})
        (root / "twofa").mkdir(exist_ok=True)
        (root / "passkeys").mkdir(exist_ok=True)

    def build(self, root, setup=None):
        return site_pack.build_pack(root / "twofa", root / "passkeys", setup or root / "setup", 7)

    def test_build_matches_expected(self):
        pack, report = site_pack.build_pack(FIXTURES / "upstream" / "twofa", FIXTURES / "upstream" / "passkeys",
                                            FIXTURES / "setup", 2026112001)
        expected = json.loads((FIXTURES / "expected-pack.json").read_text(encoding="utf-8"))
        self.assertEqual(pack, expected)
        self.assertEqual(report["refused"], [])
        self.assertEqual(report["sites"], 4)

    def test_pack_bytes_are_compact_and_sorted(self):
        pack, _ = site_pack.build_pack(FIXTURES / "upstream" / "twofa", FIXTURES / "upstream" / "passkeys",
                                       FIXTURES / "setup", 1)
        data = site_pack.pack_bytes(pack)
        self.assertNotIn(b": ", data)
        self.assertTrue(data.startswith(b'{"format":1,"sites":{"amazon.com"'))

    def test_unverified_setup_is_left_out_and_reported(self):
        root = self.tmp()
        self.upstream(root, twofa=[("example.com", {"tfa": ["totp"]})])
        write(root / "setup" / "example.com.json", {
            "domain": "example.com", "setup_totp": {"url": "https://example.com/security", "steps": []}})
        pack, report = self.build(root)
        self.assertNotIn("setup_totp", pack["sites"]["example.com"])
        self.assertEqual(report["refused"], [{"domain": "example.com", "block": "setup_totp", "reason": "unverified"}])

    def test_invalid_recipe_fails_the_build(self):
        root = self.tmp()
        self.upstream(root, twofa=[("example.com", {"tfa": ["totp"]})])
        write(root / "setup" / "example.com.json", {
            "domain": "example.com", "setup_totp": {
                "url": "https://example.com/security", "verified": {"date": "2026-11-20", "browser": "safari"},
                "steps": [{"do": "click", "role": "button", "name": ["Delete account"]}, {"do": "expect_qr"}]}})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = site_pack.main(["build", "--twofa", str(root / "twofa"), "--passkeys", str(root / "passkeys"),
                                   "--setup", str(root / "setup"), "--sources", str(root / "s.json"),
                                   "--version", "1", "--out", str(root / "out")])
        self.assertEqual(code, 1)  # no sources file yet
        write(root / "s.json", {})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = site_pack.main(["build", "--twofa", str(root / "twofa"), "--passkeys", str(root / "passkeys"),
                                   "--setup", str(root / "setup"), "--sources", str(root / "s.json"),
                                   "--version", "1", "--out", str(root / "out")])
        self.assertEqual(code, 1)
        self.assertIn("example.com.json", err.getvalue())
        self.assertIn("destructive word 'delete'", err.getvalue())
        self.assertFalse((root / "out" / "onepass-sites-1.json").exists())

    def test_map_file_name_must_match_domain(self):
        root = self.tmp()
        self.upstream(root)
        write(root / "setup" / "other.com.json", {"domain": "example.com"})
        with self.assertRaises(site_pack.SitePackError):
            self.build(root)

    def test_own_domain_beats_additional_domain(self):
        root = self.tmp()
        self.upstream(root, twofa=[("a.com", {"tfa": ["totp"], "additional-domains": ["b.com", "a-cdn.com"]}),
                                   ("b.com", {"tfa": ["sms"]})])
        pack, report = self.build(root)
        self.assertEqual(pack["sites"]["a.com"]["additional_domains"], ["a-cdn.com"])
        self.assertEqual(pack["sites"]["b.com"]["additional_domains"], [])
        self.assertEqual(report["dropped_additional_domains"], [{"domain": "a.com", "additional": "b.com"}])

    def test_shared_additional_domain_goes_to_first_sorted_site(self):
        root = self.tmp()
        self.upstream(root, twofa=[("zeta.com", {"tfa": ["totp"], "additional-domains": ["shared.net"]}),
                                   ("alpha.com", {"tfa": ["totp"], "additional-domains": ["shared.net"]})])
        pack, _ = self.build(root)
        self.assertEqual(pack["sites"]["alpha.com"]["additional_domains"], ["shared.net"])
        self.assertEqual(pack["sites"]["zeta.com"]["additional_domains"], [])

    def test_http_or_long_help_link_dropped(self):
        root = self.tmp()
        long_link = "https://example.com/" + "a" * 2100
        self.upstream(root,
                      twofa=[("a.com", {"tfa": ["totp"], "documentation": "http://a.com/help"}),
                             ("b.com", {"tfa": ["totp"], "documentation": long_link}),
                             ("c.com", {"tfa": ["totp"], "documentation": "http://c.com/help"})],
                      passkeys=[("c.com", {"documentation": "https://c.com/passkeys"})])
        pack, _ = self.build(root)
        self.assertNotIn("help", pack["sites"]["a.com"])
        self.assertNotIn("help", pack["sites"]["b.com"])
        self.assertEqual(pack["sites"]["c.com"]["help"], "https://c.com/passkeys")

    def test_passkey_mode(self):
        root = self.tmp()
        self.upstream(root, passkeys=[("a.com", {"passwordless": "allowed", "mfa": "allowed"}),
                                      ("b.com", {"mfa": "allowed"}),
                                      ("c.com", {"passwordless": "incomplete"})])
        pack, _ = self.build(root)
        self.assertEqual(pack["sites"]["a.com"]["passkey"], "signin")
        self.assertEqual(pack["sites"]["b.com"]["passkey"], "mfa")
        self.assertNotIn("passkey", pack["sites"]["c.com"])


@unittest.skipUnless(has_openssl(), "needs OpenSSL 3 (set OPENSSL=...)")
class Signing(unittest.TestCase):
    def test_sign_then_verify(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        pack = site_pack.pack_bytes({"format": 1, "version": 9, "sites": {"a.com": {"additional_domains": []}}})
        (tmp / "onepass-sites-9.json").write_bytes(pack)
        manifest = tmp / "site-pack-manifest.json"
        manifest.write_text(json.dumps({"format": 1, "version": 9, "sites": 1, "pack": {
            "file": "onepass-sites-9.json", "size": len(pack), "sha256": hashlib.sha256(pack).hexdigest()}}))
        os.environ["SITE_PACK_ED_PRIVATE_KEY"] = base64.b64encode(RFC_SEED).decode()
        self.addCleanup(os.environ.pop, "SITE_PACK_ED_PRIVATE_KEY", None)
        self.assertEqual(site_pack.main(["sign", "--manifest", str(manifest)]), 0)
        public = base64.b64encode(RFC_PUBLIC).decode()
        self.assertEqual(site_pack.verify_files(manifest, tmp / "onepass-sites-9.json", public)["version"], 9)
        # a tampered pack
        (tmp / "onepass-sites-9.json").write_bytes(pack + b" ")
        with self.assertRaises(site_pack.SitePackError):
            site_pack.verify_files(manifest, tmp / "onepass-sites-9.json", public)
        (tmp / "onepass-sites-9.json").write_bytes(pack)
        # a changed size, then a changed version (the signature no longer matches)
        original = manifest.read_text()
        manifest.write_text(original.replace(f'"size": {len(pack)}', f'"size": {len(pack) + 1}'))
        with self.assertRaises(site_pack.SitePackError):
            site_pack.verify_files(manifest, tmp / "onepass-sites-9.json", public)
        manifest.write_text(original.replace('"version": 9', '"version": 10'))
        with self.assertRaises(site_pack.SitePackError):
            site_pack.verify_files(manifest, tmp / "onepass-sites-9.json", public)

    def test_public_key_command(self):
        os.environ["SITE_PACK_ED_PRIVATE_KEY"] = base64.b64encode(RFC_SEED).decode()
        self.addCleanup(os.environ.pop, "SITE_PACK_ED_PRIVATE_KEY", None)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(site_pack.main(["public-key"]), 0)
        self.assertEqual(out.getvalue().strip(), base64.b64encode(RFC_PUBLIC).decode())


if __name__ == "__main__":
    unittest.main()
