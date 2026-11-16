#!/usr/bin/env python3
"""OnePass site pack: which sites offer 2FA and passkeys, and where their settings pages are.

    site_pack.py build --twofa DIR --passkeys DIR --setup DIR --sources FILE --version N --out DIR
        Reads the 2FA Directory checkout and the 2factorauth/passkeys checkout (untrusted data,
        nothing in them runs) and the hand-checked setup maps in --setup (data/site-setup), and
        writes DIR/onepass-sites-<N>.json (the pack), DIR/site-pack-manifest.json (version, size
        and SHA-256 of the pack, the upstream commits) and DIR/report.json.
        --sources is a JSON object {"twofa": {"commit": ...}, "passkeys": {...}}.
        A recipe that breaks a rule fails the build. A setup block without `verified` is left
        out of the pack and listed in the report.
    site_pack.py sign --manifest FILE
        Writes FILE.sig: the Ed25519 signature (base64) of the manifest's exact bytes, then a
        newline, with the key in SITE_PACK_ED_PRIVATE_KEY (a 32-byte seed, base64).
    site_pack.py verify --manifest FILE --pack FILE --public-key B64
        Checks the signature, the pack's size and hash, its version, and every recipe.
    site_pack.py public-key
        Prints the public key of SITE_PACK_ED_PRIVATE_KEY.

Pack format 1: compact JSON, sorted keys, at most 16 MiB and 100,000 sites. See
data/site-setup/README.md for the recipe rules.
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import appcast  # noqa: E402
from icon_pack import normalized_domain  # noqa: E402

FORMAT = 1
MAX_PACK_BYTES = 16 * 1024 * 1024
MAX_SITES = 100_000
MAX_URL_BYTES = 2048
MAX_STEPS = 12
MAX_TIMEOUT_S = 60
BROWSERS = ("chromium", "firefox", "safari")
KINDS = ("setup_totp", "setup_passkey")
ROLES = ("button", "link", "radio", "checkbox", "tab", "menuitem", "option")
STEP_KEYS = {
    "goto": {"url"},
    "click": {"role", "name", "css"},
    "wait_for": {"role", "name", "css"},
    "reauth": set(),
    "expect_qr": set(),
    "expect_passkey_prompt": set(),
    "done": set(),
}
DESTRUCTIVE_WORDS = (
    "delete", "disable", "remove", "pay", "supprimer", "désactiver", "retirer", "payer",
    "eliminar", "desactivar", "quitar", "pagar", "elimina", "disattiva", "rimuovi", "paga")
FINAL_NAMES = (
    "verify", "activate", "confirm", "submit", "vérifier", "activer", "confirmer", "valider",
    "verificar", "activar", "confirmar", "verifica", "attiva", "conferma")
_DESTRUCTIVE = [re.compile(r"(?<!\w)" + re.escape(w) + r"(?!\w)") for w in DESTRUCTIVE_WORDS]
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


class SitePackError(Exception):
    pass


def _url_problem(url, domains):
    """None when `url` is https on one of `domains` (or a subdomain), else the reason.

    Mirrors url_allowed in core/onepass-core/src/site_pack/recipe.rs byte for byte."""
    if not isinstance(url, str) or not url:
        return "url is not a non-empty string"
    if len(url.encode("utf-8")) > MAX_URL_BYTES:
        return "url is longer than 2048 bytes"
    if not all(0x21 <= b <= 0x7E for b in url.encode("utf-8")):
        return "url has a byte outside printable ASCII"
    scheme, sep, rest = url.partition("://")
    if not sep or scheme.lower() != "https":
        return "url is not https"
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if "@" in authority or ":" in authority:
        return "url carries credentials or a port"
    host = authority.lower().rstrip(".")
    if any(c in authority for c in "\\[]%") or not host or not any(
            host == d.lower() or host.endswith("." + d.lower()) for d in domains):
        return f"url host {host or '(none)'} is not on the site's domains"
    return None


def _name_problem(names):
    if not isinstance(names, list) or not names:
        return "name is not a non-empty list"
    for n in names:
        if not isinstance(n, str) or not 1 <= len(n.strip()) <= 80 or len(n) > 80:
            return "a name is not a string of 1 to 80 characters"
    return None


def _click_name_problem(names):
    for n in names:
        folded = n.strip().casefold()
        for word, pattern in zip(DESTRUCTIVE_WORDS, _DESTRUCTIVE):
            if pattern.search(folded):
                return f"click name {n!r} contains the destructive word {word!r}"
        if folded in FINAL_NAMES:
            return f"click name {n!r} is a final verify or activate click"
    return None


def validate_recipe(kind, steps, domains):
    """Reasons a recipe is refused; an empty list means it is valid."""
    if kind not in KINDS:
        return [f"unknown kind {kind!r}"]
    if not isinstance(steps, list):
        return ["steps is not a list"]
    problems = []
    if len(steps) > MAX_STEPS:
        problems.append(f"{len(steps)} steps, at most {MAX_STEPS}")
    for i, step in enumerate(steps):
        where = f"step {i + 1}"
        if not isinstance(step, dict):
            problems.append(f"{where}: not an object")
            continue
        do = step.get("do")
        if do not in STEP_KEYS:
            problems.append(f"{where}: unknown do {do!r}")
            continue
        extra = set(step) - STEP_KEYS[do] - {"do", "timeout_s"}
        if extra:
            problems.append(f"{where}: unknown key {sorted(extra)[0]!r} for {do}")
        if "timeout_s" in step:
            t = step["timeout_s"]
            if isinstance(t, bool) or not isinstance(t, int) or not 1 <= t <= MAX_TIMEOUT_S:
                problems.append(f"{where}: timeout_s is not an integer from 1 to {MAX_TIMEOUT_S}")
        if do == "goto":
            reason = _url_problem(step.get("url"), domains)
            if reason:
                problems.append(f"{where}: {reason}")
        elif do in ("click", "wait_for"):
            if step.get("role") not in ROLES:
                problems.append(f"{where}: role is not one of {', '.join(ROLES)}")
            reason = _name_problem(step.get("name"))
            if reason:
                problems.append(f"{where}: {reason}")
            elif do == "click":
                reason = _click_name_problem(step["name"])
                if reason:
                    problems.append(f"{where}: {reason}")
            if "css" in step and (not isinstance(step["css"], str) or len(step["css"]) > 200):
                problems.append(f"{where}: css is not a string of at most 200 characters")
    dos = [s.get("do") for s in steps if isinstance(s, dict)]
    own, other = (("expect_qr", "expect_passkey_prompt") if kind == "setup_totp"
                  else ("expect_passkey_prompt", "expect_qr"))
    if other in dos:
        problems.append(f"a {kind} recipe must not contain {other}")
    if steps and dos[-1:] != [own]:
        problems.append(f"a {kind} recipe must end with {own}")
    return problems


# --- reading the inputs -------------------------------------------------------

def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SitePackError(f"{path}: {error}") from None


def _upstream_entries(root):
    """{domain: record} from an upstream `entries/<c>/<domain>.json` tree."""
    found = {}
    for path in sorted((Path(root) / "entries").glob("*/*.json")):
        data = _read_json(path)
        if not isinstance(data, dict) or not data:
            continue
        record = data[sorted(data)[0]]
        if not isinstance(record, dict):
            continue
        domain = normalized_domain(record.get("domain") or path.stem)
        if domain:
            found.setdefault(domain, record)
    return found


def _https_link(value):
    if isinstance(value, str) and value.startswith("https://") and len(value.encode("utf-8")) <= MAX_URL_BYTES:
        return value
    return None


def _domain_list(value):
    out = set()
    for item in value if isinstance(value, list) else []:
        d = normalized_domain(item) if isinstance(item, str) else None
        if d:
            out.add(d)
    return out


def _setup_maps(root):
    maps = {}
    if not root or not Path(root).is_dir():
        return maps
    for path in sorted(Path(root).glob("*.json")):
        data = _read_json(path)
        if not isinstance(data, dict):
            raise SitePackError(f"{path.name}: not an object")
        domain = normalized_domain(data.get("domain"))
        if domain is None or path.name != f"{domain}.json" or data.get("domain") != domain:
            raise SitePackError(f"{path.name}: the file name must be <domain>.json and match its domain")
        extra = set(data) - {"domain", "additional_domains", "setup_totp", "setup_passkey"}
        if extra:
            raise SitePackError(f"{path.name}: unknown key {sorted(extra)[0]!r}")
        maps[domain] = (path.name, data)
    return maps


def _verified_problem(verified):
    if not isinstance(verified, dict) or set(verified) != {"date", "browser"}:
        return "verified is not {date, browser}"
    if not isinstance(verified["date"], str) or not _DATE.fullmatch(verified["date"]):
        return "verified.date is not YYYY-MM-DD"
    try:
        datetime.date.fromisoformat(verified["date"])
    except ValueError:
        return "verified.date is not a real date"
    if verified["browser"] not in BROWSERS:
        return f"verified.browser is not one of {', '.join(BROWSERS)}"
    return None


# --- the pack -------------------------------------------------------------------

def build_pack(twofa_root, passkeys_root, setup_root, version):
    """(pack, report): the pack as a dict, the report of what was refused or dropped."""
    twofa = _upstream_entries(twofa_root)
    passkeys = _upstream_entries(passkeys_root)
    maps = _setup_maps(setup_root)
    domains = sorted(set(twofa) | set(passkeys) | set(maps))
    if len(domains) > MAX_SITES:
        raise SitePackError(f"{len(domains)} sites, at most {MAX_SITES}")
    own = set(domains)

    # Additional domains: an own site's domain is never another site's; a domain several sites
    # claim goes to the first of them in sorted order.
    claims = {}
    for d in domains:
        extra = _domain_list((twofa.get(d) or {}).get("additional-domains"))
        extra |= _domain_list((passkeys.get(d) or {}).get("additional-domains"))
        if d in maps:
            extra |= _domain_list(maps[d][1].get("additional_domains"))
        for a in extra - own:
            claims.setdefault(a, d)
    additional = {d: [] for d in domains}
    dropped_additional = []
    for d in domains:
        wanted = set()
        wanted |= _domain_list((twofa.get(d) or {}).get("additional-domains"))
        wanted |= _domain_list((passkeys.get(d) or {}).get("additional-domains"))
        if d in maps:
            wanted |= _domain_list(maps[d][1].get("additional_domains"))
        for a in sorted(wanted):
            if a == d:
                continue
            if a in own or claims.get(a) != d:
                dropped_additional.append({"domain": d, "additional": a})
            else:
                additional[d].append(a)

    sites = {}
    refused = []
    for d in domains:
        t, p = twofa.get(d) or {}, passkeys.get(d) or {}
        site = {}
        modes = sorted(x for x in (t.get("tfa") or []) if isinstance(x, str))
        if modes:
            site["twofa"] = modes
        if p.get("passwordless") == "allowed":
            site["passkey"] = "signin"
        elif p.get("mfa") == "allowed":
            site["passkey"] = "mfa"
        help_link = _https_link(t.get("documentation")) or _https_link(p.get("documentation"))
        if help_link:
            site["help"] = help_link
        site["additional_domains"] = additional[d]
        if d in maps:
            name, data = maps[d]
            for kind in KINDS:
                block = data.get(kind)
                if block is None:
                    continue
                if not isinstance(block, dict) or set(block) - {"url", "verified", "steps"}:
                    raise SitePackError(f"{name}: {kind} is not {{url, verified, steps}}")
                if "verified" not in block:
                    refused.append({"domain": d, "block": kind, "reason": "unverified"})
                    continue
                reason = _verified_problem(block["verified"])
                if reason:
                    raise SitePackError(f"{name}: {kind}: {reason}")
                steps = block.get("steps", [])
                allowed = [d] + additional[d]
                problems = validate_recipe(kind, steps, allowed)
                reason = _url_problem(block.get("url"), allowed)
                if reason:
                    problems.append(f"url: {reason}")
                if problems:
                    raise SitePackError(f"{name}: {kind}: " + "; ".join(problems))
                site[kind] = {"url": block["url"], "verified": block["verified"], "steps": steps}
        sites[d] = site
    pack = {"format": FORMAT, "version": version, "sites": sites}
    report = {
        "sites": len(sites),
        "twofa": sum(1 for s in sites.values() if "twofa" in s),
        "passkey": sum(1 for s in sites.values() if "passkey" in s),
        "setup_totp": sum(1 for s in sites.values() if "setup_totp" in s),
        "setup_passkey": sum(1 for s in sites.values() if "setup_passkey" in s),
        "refused": refused,
        "dropped_additional_domains": dropped_additional,
    }
    return pack, report


def pack_bytes(pack):
    data = json.dumps(pack, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_PACK_BYTES:
        raise SitePackError(f"the pack is {len(data)} bytes, at most {MAX_PACK_BYTES}")
    return data


def check_pack(data):
    """Parse pack bytes and re-check every recipe; returns the pack."""
    if len(data) > MAX_PACK_BYTES:
        raise SitePackError("the pack is too large")
    try:
        pack = json.loads(data)
    except ValueError:
        raise SitePackError("the pack is not JSON") from None
    if not isinstance(pack, dict) or pack.get("format") != FORMAT or not isinstance(pack.get("sites"), dict):
        raise SitePackError("the pack is not format 1")
    if len(pack["sites"]) > MAX_SITES:
        raise SitePackError("the pack has too many sites")
    for domain, site in pack["sites"].items():
        for kind in KINDS:
            block = site.get(kind)
            if block is None:
                continue
            if _verified_problem(block.get("verified")):
                raise SitePackError(f"{domain}: {kind} is not verified")
            allowed = [domain] + list(site.get("additional_domains", []))
            problems = validate_recipe(kind, block.get("steps"), allowed)
            reason = _url_problem(block.get("url"), allowed)
            if reason:
                problems.append(f"url: {reason}")
            if problems:
                raise SitePackError(f"{domain}: {kind}: " + "; ".join(problems))
    return pack


def build(args):
    sources = _read_json(args.sources)
    pack, report = build_pack(Path(args.twofa), Path(args.passkeys), Path(args.setup), args.version)
    data = pack_bytes(pack)
    check_pack(data)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    name = f"onepass-sites-{args.version}.json"
    (out / name).write_bytes(data)
    manifest = {
        "format": FORMAT,
        "version": args.version,
        "created": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
        "pack": {"file": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()},
        "sites": len(pack["sites"]),
        "sources": sources,
    }
    (out / "site-pack-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (out / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(f"{len(pack['sites'])} sites, {len(data)} bytes -> {out / name}")
    return 0


def seed_from_environment():
    value = os.environ.get("SITE_PACK_ED_PRIVATE_KEY")
    if not value:
        raise SitePackError("SITE_PACK_ED_PRIVATE_KEY is not set")
    try:
        return appcast.load_seed(value)
    except appcast.AppcastError as error:
        raise SitePackError(str(error)) from None


def verify_files(manifest_path, pack_path, public_b64):
    manifest_bytes = Path(manifest_path).read_bytes()
    signature = base64.b64decode(Path(str(manifest_path) + ".sig").read_text().strip(), validate=True)
    public = base64.b64decode(public_b64, validate=True)
    if not appcast.verify(public, manifest_bytes, signature):
        raise SitePackError("the manifest signature does not verify")
    manifest = json.loads(manifest_bytes)
    data = Path(pack_path).read_bytes()
    if len(data) != manifest["pack"]["size"] or hashlib.sha256(data).hexdigest() != manifest["pack"]["sha256"]:
        raise SitePackError("the pack does not match the manifest")
    pack = check_pack(data)
    if pack.get("version") != manifest["version"]:
        raise SitePackError("the pack's version is not the manifest's")
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--twofa", required=True)
    b.add_argument("--passkeys", required=True)
    b.add_argument("--setup", required=True)
    b.add_argument("--sources", required=True)
    b.add_argument("--version", required=True, type=int)
    b.add_argument("--out", required=True)
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
            return build(args)
        if args.command == "sign":
            signature = appcast.sign(seed_from_environment(), Path(args.manifest).read_bytes())
            Path(args.manifest + ".sig").write_text(base64.b64encode(signature).decode() + "\n")
            return 0
        if args.command == "verify":
            manifest = verify_files(args.manifest, args.pack, args.public_key)
            print(f"ok: version {manifest['version']}, {manifest['sites']} sites")
            return 0
        if args.command == "public-key":
            print(base64.b64encode(appcast.public_key(seed_from_environment())).decode())
            return 0
    except (SitePackError, appcast.AppcastError, OSError, ValueError, KeyError) as error:
        print(f"site_pack: {error}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
