#!/usr/bin/env python3
"""Signed Sparkle appcast of a notarized OnePass Mac release.

    appcast.py build --version V --archive ZIP --download-url URL --release-url URL --out FILE
        Checks the app inside ZIP (it must trust the key that signs, carry the
        release's version numbers and the strict update settings), signs ZIP,
        writes a one-item appcast, signs the feed (Sparkle's signed feed block),
        then verifies both signatures again.
    appcast.py verify --appcast FILE --archive ZIP [--public-key B64]
        Verifies the feed and archive signatures (default key: the app's own).
    appcast.py public-key
        Prints the public key (SUPublicEDKey) of the private key in use.

The private key is the 32-byte Ed25519 seed that Sparkle's generate_keys keeps,
base64 encoded. It is read from SPARKLE_ED_PRIVATE_KEY or, when that is unset,
from the login keychain (item "https://sparkle-project.org", account
"ed25519", where generate_keys puts it). It is never generated here and never
written anywhere but a 0600 file in a 0700 temporary folder, removed at once.

Ed25519 goes through the OpenSSL command line (3.0 or later; LibreSSL cannot
sign Ed25519): OPENSSL=/path/to/openssl, else the first usable one found.
Standard library only. Docs: docs/security/release-pipeline.md.
"""

import argparse
import base64
import binascii
import email.utils
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

SPARKLE_NS = "http://www.andymatuschak.org/xml-namespaces/sparkle"
SIGNING_PREFIX = b"<!-- sparkle-signatures:\n"
KEYCHAIN_SERVICE = "https://sparkle-project.org"
KEYCHAIN_ACCOUNT = "ed25519"
# DER prefixes of an Ed25519 PKCS#8 private key (RFC 8410) and of its
# SubjectPublicKeyInfo; the raw 32 bytes follow.
PRIVATE_DER_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
PUBLIC_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$")


class AppcastError(Exception):
    pass


# --- OpenSSL ---------------------------------------------------------------

def is_usable_openssl_version(text):
    m = re.match(r"^OpenSSL (\d+)\.", text.strip())
    return bool(m) and int(m.group(1)) >= 3


_OPENSSL = None


def openssl():
    global _OPENSSL
    if _OPENSSL:
        return _OPENSSL
    candidates = [os.environ.get("OPENSSL"), "/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", shutil.which("openssl")]
    for candidate in candidates:
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            out = subprocess.run([candidate, "version"], capture_output=True, text=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            continue
        if is_usable_openssl_version(out):
            _OPENSSL = candidate
            return candidate
    raise AppcastError("no OpenSSL 3 or later found (LibreSSL cannot sign Ed25519): set OPENSSL=/path/to/openssl")


def _run_openssl(args, **kwargs):
    return subprocess.run([openssl(), *args], capture_output=True, **kwargs)


class _PrivateDir:
    """A 0700 temporary folder, removed with everything in it."""

    def __enter__(self):
        self.path = Path(tempfile.mkdtemp(prefix="onepass-appcast-"))
        os.chmod(self.path, 0o700)
        return self.path

    def __exit__(self, *exc):
        shutil.rmtree(self.path, ignore_errors=True)


def _write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


# --- Ed25519 ---------------------------------------------------------------

def load_seed(text):
    try:
        seed = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise AppcastError("the private key is not base64") from None
    if len(seed) != 32:
        raise AppcastError(
            f"the private key decodes to {len(seed)} bytes, expected the 32-byte Ed25519 seed "
            "that Sparkle's generate_keys stores (the legacy 96-byte format is not supported)")
    return seed


def public_key(seed):
    with _PrivateDir() as d:
        key = d / "key.der"
        _write_private(key, PRIVATE_DER_PREFIX + seed)
        result = _run_openssl(["pkey", "-inform", "DER", "-in", str(key), "-pubout", "-outform", "DER"])
    if result.returncode != 0 or not result.stdout.startswith(PUBLIC_DER_PREFIX) or len(result.stdout) != 44:
        raise AppcastError("openssl could not derive the public key")
    return result.stdout[len(PUBLIC_DER_PREFIX):]


def sign(seed, data):
    with _PrivateDir() as d:
        key = d / "key.der"
        _write_private(key, PRIVATE_DER_PREFIX + seed)
        message = d / "message"
        message.write_bytes(data)
        result = _run_openssl(["pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", str(key), "-in", str(message)])
    if result.returncode != 0 or len(result.stdout) != 64:
        raise AppcastError("openssl could not sign: " + result.stderr.decode(errors="replace").strip())
    return result.stdout


def verify(public, data, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    with _PrivateDir() as d:
        pub = d / "pub.der"
        pub.write_bytes(PUBLIC_DER_PREFIX + public)
        message = d / "message"
        message.write_bytes(data)
        sig = d / "sig"
        sig.write_bytes(signature)
        result = _run_openssl(["pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", str(pub),
                               "-in", str(message), "-sigfile", str(sig)])
    return result.returncode == 0


def seed_from_environment():
    value = os.environ.get("SPARKLE_ED_PRIVATE_KEY")
    if value:
        return load_seed(value)
    if sys.platform != "darwin":
        raise AppcastError("SPARKLE_ED_PRIVATE_KEY is not set")
    result = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise AppcastError("SPARKLE_ED_PRIVATE_KEY is not set and the keychain has no Sparkle key "
                           f"({KEYCHAIN_SERVICE}, account {KEYCHAIN_ACCOUNT}): see docs/security/release-pipeline.md")
    return load_seed(result.stdout)


# --- The app inside the archive -------------------------------------------

def read_app_info(archive):
    with zipfile.ZipFile(archive) as z:
        names = [n for n in z.namelist() if re.fullmatch(r"[^/]+\.app/Contents/Info\.plist", n)]
        if len(names) != 1:
            raise AppcastError(f"{archive} must hold exactly one app at its top level (found {len(names)})")
        return plistlib.loads(z.read(names[0]))


def numeric_core(version):
    if not VERSION_RE.match(version):
        raise AppcastError(f"not a release version: {version}")
    return version.split("-", 1)[0]


def check_app(info, version, public):
    core = numeric_core(version)
    if info.get("SUPublicEDKey", "") != base64.b64encode(public).decode():
        raise AppcastError("the app's SUPublicEDKey is not the public key of the signing key: "
                           "the app would refuse this update (check SPARKLE_ED_PUBLIC_KEY)")
    if info.get("CFBundleShortVersionString") != core:
        raise AppcastError(f"CFBundleShortVersionString is {info.get('CFBundleShortVersionString')!r}, expected {core!r}")
    if info.get("CFBundleVersion") != core:
        raise AppcastError(f"CFBundleVersion is {info.get('CFBundleVersion')!r}, expected {core!r}")
    if not str(info.get("SUFeedURL", "")).startswith("https://"):
        raise AppcastError("SUFeedURL must be an https URL")
    if info.get("SURequireSignedFeed") is not True:
        raise AppcastError("SURequireSignedFeed must be true")
    if info.get("SUVerifyUpdateBeforeExtraction") is not True:
        raise AppcastError("SUVerifyUpdateBeforeExtraction must be true")
    if info.get("SUEnableSystemProfiling") not in (None, False):
        raise AppcastError("SUEnableSystemProfiling must be false")


# --- The feed -------------------------------------------------------------

def feed_xml(*, info, version, download_url, release_url, length, signature, source_date_epoch):
    short = info["CFBundleShortVersionString"]
    pub_date = email.utils.formatdate(source_date_epoch, usegmt=True)
    minimum = info.get("LSMinimumSystemVersion", "26.0")
    description = f"OnePass {short} is available. Release notes: {release_url}"
    return f"""<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="{SPARKLE_NS}">
  <channel>
    <title>OnePass</title>
    <link>{escape(release_url.rsplit('/tag/', 1)[0])}</link>
    <description>Updates of the OnePass Mac app</description>
    <language>en</language>
    <item>
      <title>{escape('OnePass ' + short)}</title>
      <link>{escape(release_url)}</link>
      <sparkle:version>{escape(info['CFBundleVersion'])}</sparkle:version>
      <sparkle:shortVersionString>{escape(short)}</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>{escape(minimum)}</sparkle:minimumSystemVersion>
      <sparkle:hardwareRequirements>arm64</sparkle:hardwareRequirements>
      <pubDate>{pub_date}</pubDate>
      <description sparkle:format="plain-text">{escape(description)}</description>
      <enclosure url={quoteattr(download_url)} length="{length}" type="application/octet-stream" sparkle:edSignature="{signature}"/>
    </item>
  </channel>
</rss>
""".encode()


def signing_block(seed, content):
    signature = base64.b64encode(sign(seed, content)).decode()
    return f"<!-- sparkle-signatures:\nedSignature: {signature}\nlength: {len(content)}\n-->\n".encode()


def build_appcast(*, seed, version, archive, download_url, release_url, source_date_epoch):
    for url in (download_url, release_url):
        if not url.startswith("https://"):
            raise AppcastError(f"not an https URL: {url}")
    public = public_key(seed)
    info = read_app_info(archive)
    check_app(info, version, public)
    data = Path(archive).read_bytes()
    signature = base64.b64encode(sign(seed, data)).decode()
    content = feed_xml(info=info, version=version, download_url=download_url, release_url=release_url,
                       length=len(data), signature=signature, source_date_epoch=source_date_epoch)
    feed = content + signing_block(seed, content)
    _verify_bytes(feed, data, public)
    return feed


def _verify_bytes(feed, archive_data, public):
    start = feed.rfind(SIGNING_PREFIX)
    if start < 0:
        raise AppcastError("the feed carries no signing block")
    end = feed.find(b"-->", start + len(SIGNING_PREFIX))
    if end < 0:
        raise AppcastError("the feed's signing block is not closed")
    content = feed[:start]
    fields = {}
    for line in feed[start + len(SIGNING_PREFIX):end].decode().splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    try:
        feed_signature = base64.b64decode(fields.get("edSignature", ""), validate=True)
    except (binascii.Error, ValueError):
        raise AppcastError("the feed signature is not base64") from None
    if fields.get("length") != str(len(content)) or not verify(public, content, feed_signature):
        raise AppcastError("the feed signature does not verify")
    match = re.search(rb'sparkle:edSignature="([^"]+)"', content)
    length = re.search(rb'<enclosure [^>]*length="(\d+)"', content)
    if not match or not length:
        raise AppcastError("the feed names no signed enclosure")
    if int(length.group(1)) != len(archive_data):
        raise AppcastError("the archive length does not match the feed")
    if not verify(public, archive_data, base64.b64decode(match.group(1))):
        raise AppcastError("the archive signature does not verify")


def verify_appcast(feed_path, archive, public=None):
    if public is None:
        public = base64.b64decode(read_app_info(archive).get("SUPublicEDKey", ""))
    _verify_bytes(Path(feed_path).read_bytes(), Path(archive).read_bytes(), public)


# --- Command line ----------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--version", required=True)
    b.add_argument("--archive", required=True)
    b.add_argument("--download-url", required=True)
    b.add_argument("--release-url", required=True)
    b.add_argument("--out", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--appcast", required=True)
    v.add_argument("--archive", required=True)
    v.add_argument("--public-key")
    sub.add_parser("public-key")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or os.path.getmtime(args.archive))
            feed = build_appcast(seed=seed_from_environment(), version=args.version, archive=args.archive,
                                 download_url=args.download_url, release_url=args.release_url,
                                 source_date_epoch=epoch)
            Path(args.out).write_bytes(feed)
            print(f"{args.out}: signed appcast for {args.version}, archive and feed signatures verified")
        elif args.command == "verify":
            public = base64.b64decode(args.public_key, validate=True) if args.public_key else None
            verify_appcast(args.appcast, args.archive, public)
            print("feed and archive signatures verified")
        else:
            print(base64.b64encode(public_key(seed_from_environment())).decode())
    except AppcastError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
