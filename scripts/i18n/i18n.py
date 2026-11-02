#!/usr/bin/env python3
"""OnePass localization tool: check, stats, export, import, sync, rekey.

Run from anywhere with `python3 -I scripts/i18n/i18n.py <command>`. Standard library only.

  check            fail on a missing language, a placeholder mismatch, an incomplete plural,
                   a term/common entry that drifts from the glossary, an em dash, a banned call
  stats            per catalog: entries, semantic vs legacy keys, coverage per language
  export LANG      write a work file of every entry missing LANG (French, English, comment)
  import FILE      merge a translated work file back into the catalogs
  sync             copy glossary values into every term.* / common.* entry
  rekey CATALOG    replace legacy French-text keys of one Apple catalog with semantic keys,
                   in the catalog and in the target's Swift string literals

See docs/i18n.md.
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
EM_DASH = "\u2014"
SEMANTIC = re.compile(r"^[a-z][A-Za-z0-9]*\.\S")

# printf-style specifiers as Xcode writes them, plus `%#@name@` plural substitutions.
SPEC = re.compile(
    r"%%|%#@([A-Za-z0-9_]+)@|%(?:(\d+)\$)?[-+ #0']*\d*(?:\.\d+)?(?:hh|h|ll|l|q|z|t|j|L)?([@dDiuUxXoOfFeEgGaAcCsSp])"
)
APP_INTENT = re.compile(r"\$\{([A-Za-z0-9_]+)\}")
NAMED = re.compile(r"\{([A-Za-z][A-Za-z0-9_]*)\}")
CHROME_NAMED = re.compile(r"\$([A-Za-z0-9_]+)\$|\$(\d)")
CLASS = {**{c: "int" for c in "dDiuUxXoOcC"}, **{c: "float" for c in "fFeEgGaA"}, "@": "obj", "s": "cstr", "S": "cstr", "p": "ptr"}


def load_config() -> dict:
    with open(os.path.join(ROOT, "scripts", "i18n", "config.json"), encoding="utf-8") as f:
        return json.load(f)


def rel(path: str) -> str:
    return os.path.relpath(path, ROOT)


def _sorted(obj):
    if isinstance(obj, dict):
        return {k: _sorted(obj[k]) for k in sorted(obj)}
    if isinstance(obj, list):
        return [_sorted(v) for v in obj]
    return obj


def dump_xcstrings(obj: dict) -> str:
    """Xcode's layout: 2-space indent, ' : ' separators, sorted keys, no final newline.

    The order of `strings` is kept as found (agents append entries by hand; re-sorting would
    rewrite the whole file and collide with every other branch); new keys are inserted in
    code-point order by `insert_sorted`."""
    out = _sorted({k: v for k, v in obj.items() if k != "strings"})
    out["strings"] = {k: _sorted(v) for k, v in obj.get("strings", {}).items()}
    out = {k: out[k] for k in sorted(out)}
    return json.dumps(out, ensure_ascii=False, indent=2, separators=(",", " : "))


def insert_sorted(strings: dict, key: str, entry: dict) -> dict:
    """A copy of `strings` with `key` placed before the first larger key, order otherwise kept."""
    out = {}
    placed = False
    for k, v in strings.items():
        if not placed and k > key:
            out[key] = entry
            placed = True
        out[k] = v
    if not placed:
        out[key] = entry
    return out


def read_text(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_xcstrings(path: str, obj: dict) -> None:
    newline = False
    if os.path.exists(path):
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            if f.tell():
                f.seek(-1, os.SEEK_END)
                newline = f.read(1) == b"\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(dump_xcstrings(obj) + ("\n" if newline else ""))


def write_flat_json(path: str, obj: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")


# --- placeholders -------------------------------------------------------------------------------

def printf_signature(text: str) -> collections.Counter:
    sig: collections.Counter = collections.Counter()
    seq = 0
    for m in SPEC.finditer(text):
        whole, subst, pos, conv = m.group(0), m.group(1), m.group(2), m.group(3)
        if whole == "%%":
            continue
        if subst:
            sig[("subst", subst)] += 1
            continue
        if pos:
            idx = int(pos)
        else:
            seq += 1
            idx = seq
        sig[(idx, CLASS.get(conv, conv))] += 1
    for m in APP_INTENT.finditer(text):
        sig[("intent", m.group(1))] += 1
    return sig


def named_signature(text: str) -> set:
    return set(NAMED.findall(text))


def chrome_signature(text: str) -> set:
    return {a or b for a, b in CHROME_NAMED.findall(text)}


def same_args(ref: collections.Counter, got: collections.Counter) -> bool:
    """Equal sets of (argument, class); a language may repeat an argument."""
    return set(ref) == set(got)


# --- String Catalogs ----------------------------------------------------------------------------

def apple_catalogs(cfg: dict) -> list[str]:
    paths = glob.glob(os.path.join(ROOT, cfg["apple"]["catalogs"]), recursive=True)
    out = []
    for p in sorted(paths):
        r = "/" + rel(p)
        if any(x in r for x in cfg["apple"]["exclude"]):
            continue
        out.append(p)
    return out


def leaves(loc: dict, path: tuple = ()):  # yields (path, stringUnit)
    if "stringUnit" in loc:
        yield path, loc["stringUnit"]
    if "stringSet" in loc:  # App Shortcuts phrases: one leaf per phrase
        for i, v in enumerate(loc["stringSet"].get("values", [])):
            yield path + ("set", str(i)), {"state": loc["stringSet"].get("state", "translated"), "value": v}
    for kind, cases in loc.get("variations", {}).items():
        for case, sub in cases.items():
            yield from leaves(sub, path + (kind, case))
    for name, sub in loc.get("substitutions", {}).items():
        yield from leaves(sub, path + ("subst", name))


def translatable(key: str, entry: dict) -> bool:
    return key != "" and entry.get("shouldTranslate", True) is not False and entry.get("extractionState") != "stale"


def source_loc(key: str, entry: dict, source: str) -> dict | None:
    loc = entry.get("localizations", {}).get(source)
    if loc:
        return loc
    if SEMANTIC.match(key):
        return None
    return {"stringUnit": {"state": "translated", "value": key}}


def plural_cases(loc: dict) -> dict | None:
    return loc.get("variations", {}).get("plural")


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, where: str, msg: str) -> None:
        self.errors.append(f"{where}: {msg}")

    def warn(self, where: str, msg: str) -> None:
        self.warnings.append(f"{where}: {msg}")


def check_entry(where: str, key: str, entry: dict, langs: list[str], source: str, glossary: dict, rep: Report) -> None:
    src = source_loc(key, entry, source)
    if src is None:
        rep.error(where, f"semantic key without a '{source}' value")
        return
    src_leaves = dict(leaves(src))
    src_plural = plural_cases(src)
    ref_text = None
    if src_plural:
        other = src_plural.get("other", {}).get("stringUnit", {})
        ref_text = other.get("value", "")
    elif () in src_leaves:
        ref_text = src_leaves[()].get("value", "")
    for lang in langs:
        loc = src if lang == source else entry.get("localizations", {}).get(lang)
        if not loc:
            rep.error(where, f"missing '{lang}'")
            continue
        lv = list(leaves(loc))
        if not lv:
            rep.error(where, f"'{lang}' has no value")
            continue
        for path, unit in lv:
            value = unit.get("value")
            state = unit.get("state", "translated")
            if value is None or (value == "" and (ref_text or "") != ""):
                rep.error(where, f"'{lang}' {'/'.join(path) or 'value'} is empty")
                continue
            if state == "new" and lang != source:  # Xcode leaves the source language 'new'; that is harmless
                rep.error(where, f"'{lang}' {'/'.join(path) or 'value'} is still 'new'")
            elif state == "needs_review":
                rep.warn(where, f"'{lang}' needs review")
            if EM_DASH in value:
                rep.error(where, f"'{lang}' contains an em dash")
        plural = plural_cases(loc)
        if src_plural and lang != source and plural is None:
            # A plain value is allowed when the source is plural only for one-form languages.
            rep.error(where, f"'{lang}' needs plural variations like '{source}'")
        if plural is not None:
            for need in ("one", "other"):
                if need not in plural:
                    rep.error(where, f"'{lang}' plural lacks '{need}'")
        if ref_text is None:
            continue
        ref = printf_signature(ref_text)
        if plural is not None:
            for case, sub in plural.items():
                v = sub.get("stringUnit", {}).get("value", "")
                got = printf_signature(v)
                if case == "other":
                    if not same_args(ref, got):
                        rep.error(where, f"'{lang}' plural other placeholders {sorted(got)} != {sorted(ref)}")
                elif not set(got) <= set(ref):
                    rep.error(where, f"'{lang}' plural {case} has placeholders not in the source")
        else:
            for path, unit in lv:
                got = printf_signature(unit.get("value", ""))
                if path and path[0] == "device":
                    if not set(got) <= set(ref):
                        rep.error(where, f"'{lang}' {'/'.join(path)} placeholders differ")
                elif not same_args(ref, got):
                    rep.error(where, f"'{lang}' placeholders {sorted(got)} != {sorted(ref)}")
    if key.startswith(("term.", "common.")):
        g = glossary.get(key)
        if g is None:
            rep.error(where, "term/common key not in the glossary")
        else:
            for lang in langs:
                loc = entry.get("localizations", {}).get(lang, {})
                val = loc.get("stringUnit", {}).get("value")
                if val is not None and val != g[lang]:
                    rep.error(where, f"'{lang}' '{val}' differs from the glossary '{g[lang]}' (run `i18n.py sync`)")


def term_warnings(where: str, values: dict, glossary: dict, rep: Report) -> None:
    en = values.get("en", "").lower()
    if not en:
        return
    for key, g in glossary.items():
        forms = g.get("forms")
        if not forms:
            continue
        if not any(re.search(r"\b" + re.escape(f) + r"\b", en) for f in forms["en"]):
            continue
        for lang, fs in forms.items():
            if lang == "en" or lang not in values:
                continue
            v = values[lang].lower()
            if not any(f in v for f in fs):
                rep.warn(where, f"'{lang}' does not use the glossary term {key} ({' / '.join(fs)})")


def flat_values(key: str, entry: dict, source: str) -> dict:
    out = {}
    for lang, loc in entry.get("localizations", {}).items():
        lv = list(leaves(loc))
        if lv:
            out[lang] = " ".join(u.get("value", "") for _, u in lv)
    if source not in out and not SEMANTIC.match(key):
        out[source] = key
    return out


def check_apple(cfg: dict, glossary: dict, rep: Report, terms: bool) -> None:
    langs, source = cfg["languages"], cfg["source"]
    for path in apple_catalogs(cfg):
        cat = read_json(path)
        if cat.get("sourceLanguage") != source:
            rep.error(rel(path), f"sourceLanguage is {cat.get('sourceLanguage')}, expected {source}")
        for key, entry in cat.get("strings", {}).items():
            if not translatable(key, entry):
                continue
            where = f"{rel(path)} [{key}]"
            check_entry(where, key, entry, langs, source, glossary, rep)
            if terms:
                term_warnings(where, flat_values(key, entry, source), glossary, rep)


# --- browser extension --------------------------------------------------------------------------

def ext_catalog_path(cfg: dict, lang: str) -> str:
    return os.path.join(ROOT, cfg["extension"]["catalogs"], f"{lang}.json")


def ext_text(value) -> str:
    if isinstance(value, dict):
        return value.get("other", "")
    return value


def check_extension(cfg: dict, glossary: dict, rep: Report, terms: bool) -> None:
    langs, source = cfg["languages"], cfg["source"]
    base = os.path.join(ROOT, cfg["extension"]["catalogs"])
    if os.path.isdir(base):
        cats = {}
        for lang in langs:
            p = ext_catalog_path(cfg, lang)
            if not os.path.exists(p):
                rep.error(rel(p), "missing catalog")
                continue
            cats[lang] = read_json(p)
        ref = cats.get(source, {})
        for lang, cat in cats.items():
            where = rel(ext_catalog_path(cfg, lang))
            for k in sorted(set(ref) - set(cat)):
                rep.error(where, f"missing key {k}")
            for k in sorted(set(cat) - set(ref)):
                rep.error(where, f"key {k} is not in {source}.json")
            for k, v in cat.items():
                if k not in ref:
                    continue
                r = ref[k]
                if isinstance(r, dict) != isinstance(v, dict):
                    rep.error(where, f"{k}: plural shape differs from {source}")
                    continue
                if isinstance(v, dict):
                    for need in ("one", "other"):
                        if need not in v:
                            rep.error(where, f"{k}: plural lacks '{need}'")
                    texts = list(v.values())
                    if named_signature(v.get("other", "")) != named_signature(r.get("other", "")):
                        rep.error(where, f"{k}: placeholders differ from {source}")
                else:
                    texts = [v]
                    if named_signature(v) != named_signature(r):
                        rep.error(where, f"{k}: placeholders {sorted(named_signature(v))} != {sorted(named_signature(r))}")
                for t in texts:
                    if not t:
                        rep.error(where, f"{k}: empty")
                    if EM_DASH in t:
                        rep.error(where, f"{k}: em dash")
                if k.startswith(("term.", "common.")):
                    g = glossary.get(k)
                    if g is None:
                        rep.error(where, f"{k}: term/common key not in the glossary")
                    elif v != g[lang]:
                        rep.error(where, f"{k}: differs from the glossary (run `i18n.py sync`)")
            if terms:
                for k in ref:
                    term_warnings(f"extension [{k}]", {l: ext_text(c.get(k, "")) for l, c in cats.items()}, glossary, rep)
    manifest = os.path.join(ROOT, cfg["extension"]["manifest"])
    if os.path.isdir(manifest):
        msgs = {}
        for lang in langs:
            p = os.path.join(manifest, lang, "messages.json")
            if not os.path.exists(p):
                rep.error(rel(p), "missing manifest messages")
                continue
            msgs[lang] = read_json(p)
        ref = msgs.get(source, {})
        for lang, m in msgs.items():
            where = rel(os.path.join(manifest, lang, "messages.json"))
            if set(m) != set(ref):
                rep.error(where, f"keys differ from {source}: {sorted(set(m) ^ set(ref))}")
            for k, v in m.items():
                text = v.get("message", "")
                if not text:
                    rep.error(where, f"{k}: empty")
                if EM_DASH in text:
                    rep.error(where, f"{k}: em dash")
                if k in ref and chrome_signature(text) != chrome_signature(ref[k].get("message", "")):
                    rep.error(where, f"{k}: placeholders differ from {source}")
    code = os.path.join(ROOT, cfg["extension"]["code"])
    banned = cfg["extension"].get("banned_calls", [])
    for p in sorted(glob.glob(os.path.join(code, "**", "*.ts"), recursive=True)):
        if p.endswith(os.path.join("shared", "i18n.ts")):
            continue
        with open(p, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                for b in banned:
                    if re.search(r"(?<![A-Za-z0-9_.])" + re.escape(b), line):
                        rep.error(f"{rel(p)}:{n}", f"`{b}` is gone: add a key to l10n/*.json and call t()")


def load_glossary(cfg: dict) -> dict:
    return read_json(os.path.join(ROOT, cfg["glossary"]))["entries"]


def check_glossary(cfg: dict, glossary: dict, rep: Report) -> None:
    for k, g in glossary.items():
        if not k.startswith(("term.", "common.")):
            rep.error("glossary", f"{k}: keys start with term. or common.")
        for lang in cfg["languages"]:
            if not g.get(lang):
                rep.error("glossary", f"{k}: missing '{lang}'")
            elif EM_DASH in g[lang]:
                rep.error("glossary", f"{k}: em dash")


def cmd_check(args) -> int:
    cfg = load_config()
    glossary = load_glossary(cfg)
    rep = Report()
    check_glossary(cfg, glossary, rep)
    check_apple(cfg, glossary, rep, args.terms)
    check_extension(cfg, glossary, rep, args.terms)
    for w in rep.warnings if args.verbose or args.terms else []:
        print("warning:", w)
    for e in rep.errors:
        print("error:", e)
    print(f"i18n check: {len(rep.errors)} error(s), {len(rep.warnings)} warning(s)")
    return 1 if rep.errors else 0


# --- stats --------------------------------------------------------------------------------------

def cmd_stats(args) -> int:
    cfg = load_config()
    langs, source = cfg["languages"], cfg["source"]
    for path in apple_catalogs(cfg):
        cat = read_json(path)["strings"]
        live = {k: v for k, v in cat.items() if translatable(k, v)}
        sem = sum(1 for k in live if SEMANTIC.match(k))
        cover = {l: sum(1 for k, v in live.items() if (l == source and not SEMANTIC.match(k)) or v.get("localizations", {}).get(l)) for l in langs}
        print(f"{rel(path)}: {len(live)} entries, {sem} semantic, {len(live) - sem} legacy, " + ", ".join(f"{l} {c}" for l, c in cover.items()))
    base = os.path.join(ROOT, cfg["extension"]["catalogs"])
    if os.path.isdir(base):
        for lang in langs:
            p = ext_catalog_path(cfg, lang)
            if os.path.exists(p):
                print(f"{rel(p)}: {len(read_json(p))} keys")
    return 0


# --- export / import ----------------------------------------------------------------------------

def cmd_export(args) -> int:
    cfg = load_config()
    lang, source = args.lang, cfg["source"]
    work = []
    for path in apple_catalogs(cfg):
        if rel(path) in cfg["apple"].get("generated", {}):
            continue
        cat = read_json(path)
        for key, entry in cat["strings"].items():
            if not translatable(key, entry):
                continue
            locs = entry.get("localizations", {})
            if lang in locs and not args.all:
                continue
            src = source_loc(key, entry, source) or {}
            item = {"catalog": rel(path), "key": key}
            if entry.get("comment"):
                item["comment"] = entry["comment"]
            for l, loc in ((source, src), ("en", locs.get("en", {}))):
                pl = plural_cases(loc)
                item[l] = {c: s["stringUnit"]["value"] for c, s in pl.items()} if pl else loc.get("stringUnit", {}).get("value", "")
            pl = plural_cases(src) or plural_cases(locs.get("en", {}))
            item[lang] = {"one": "", "other": ""} if pl else ""
            work.append(item)
    base = os.path.join(ROOT, cfg["extension"]["catalogs"])
    if os.path.isdir(base):
        ref = read_json(ext_catalog_path(cfg, source))
        en = read_json(ext_catalog_path(cfg, "en")) if os.path.exists(ext_catalog_path(cfg, "en")) else {}
        p = ext_catalog_path(cfg, lang)
        have = read_json(p) if os.path.exists(p) else {}
        for k, v in ref.items():
            if k in have and not args.all:
                continue
            work.append({"catalog": rel(p), "key": k, source: v, "en": en.get(k, ""), lang: {"one": "", "other": ""} if isinstance(v, dict) else ""})
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(work, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(f"{len(work)} entries to translate into '{lang}' written to {args.out}")
    return 0


def put_apple(entry: dict, lang: str, value) -> None:
    locs = entry.setdefault("localizations", {})
    if isinstance(value, dict):
        locs[lang] = {"variations": {"plural": {c: {"stringUnit": {"state": "translated", "value": v}} for c, v in value.items()}}}
    else:
        locs[lang] = {"stringUnit": {"state": "translated", "value": value}}


def cmd_import(args) -> int:
    cfg = load_config()
    with open(args.file, encoding="utf-8") as f:
        work = json.load(f)
    by_cat: dict[str, list] = collections.defaultdict(list)
    for item in work:
        by_cat[item["catalog"]].append(item)
    langs = [l for l in cfg["languages"]] + ([args.lang] if args.lang else [])
    changed = 0
    for catalog, items in by_cat.items():
        path = os.path.join(ROOT, catalog)
        if catalog.endswith(".xcstrings"):
            cat = read_json(path)
            for item in items:
                entry = cat["strings"].get(item["key"])
                if entry is None:
                    print(f"skip {catalog} [{item['key']}]: key is gone")
                    continue
                for lang in set(langs):
                    if lang in item and lang not in ("catalog", "key") and item[lang] not in ("", None, {}):
                        if lang == cfg["source"] and not SEMANTIC.match(item["key"]) and not isinstance(item[lang], dict):
                            continue
                        if lang == "en" and not args.overwrite_en:
                            continue
                        put_apple(entry, lang, item[lang])
                        changed += 1
            write_xcstrings(path, cat)
        else:
            lang = os.path.splitext(os.path.basename(path))[0]
            cat = read_json(path) if os.path.exists(path) else {}
            for item in items:
                v = item.get(lang)
                if v not in ("", None, {}):
                    cat[item["key"]] = v
                    changed += 1
            ref = read_json(ext_catalog_path(cfg, cfg["source"]))
            write_flat_json(path, {k: cat[k] for k in ref if k in cat} | {k: v for k, v in cat.items() if k not in ref})
    print(f"{changed} value(s) imported")
    return 0


# --- glossary sync ------------------------------------------------------------------------------

def cmd_sync(args) -> int:
    cfg = load_config()
    glossary = load_glossary(cfg)
    n = 0
    for path in apple_catalogs(cfg):
        cat = read_json(path)
        dirty = False
        for key, entry in cat["strings"].items():
            g = glossary.get(key)
            if g is None:
                continue
            for lang in cfg["languages"]:
                cur = entry.get("localizations", {}).get(lang, {}).get("stringUnit", {}).get("value")
                if cur != g[lang]:
                    put_apple(entry, lang, g[lang])
                    dirty = True
                    n += 1
            entry["extractionState"] = "manual"
            if g.get("note") and not entry.get("comment"):
                entry["comment"] = g["note"]
                dirty = True
        if dirty:
            write_xcstrings(path, cat)
    base = os.path.join(ROOT, cfg["extension"]["catalogs"])
    if os.path.isdir(base):
        for lang in cfg["languages"]:
            p = ext_catalog_path(cfg, lang)
            if not os.path.exists(p):
                continue
            cat = read_json(p)
            dirty = False
            for key in list(cat):
                g = glossary.get(key)
                if g and cat[key] != g[lang]:
                    cat[key] = g[lang]
                    dirty = True
                    n += 1
            if dirty:
                write_flat_json(p, cat)
    print(f"{n} value(s) synced from the glossary")
    return 0


# --- rekey --------------------------------------------------------------------------------------

STOP = {"a", "an", "the", "your", "you", "this", "that", "its", "is", "are", "be"}


def slug(english: str, words: int = 4) -> str:
    text = re.sub(SPEC, " ", english)
    text = re.sub(r"[’'`]", "", text)
    toks = [t for t in re.split(r"[^A-Za-z0-9]+", text) if t]
    keep = [t for t in toks if t.lower() not in STOP] or toks
    keep = keep[:words] or ["text"]
    out = keep[0].lower() + "".join(t[:1].upper() + t[1:].lower() for t in keep[1:])
    if out[0].isdigit():
        out = "n" + out
    return out


def swift_literal_body(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")


INTERP = r"\\\((?:[^()\"]|\((?:[^()]|\([^()]*\))*\)|\"[^\"]*\")*\)"


def literal_regex(key: str) -> re.Pattern | None:
    """Regex for a Swift literal whose localization key is `key` (one interpolation per specifier)."""
    parts = []
    last = 0
    for m in SPEC.finditer(key):
        if m.group(0) == "%%" or m.group(1) or m.group(2):
            return None
        parts.append(re.escape(swift_literal_body(key[last:m.start()])))
        parts.append("(" + INTERP + ")")
        last = m.end()
    parts.append(re.escape(swift_literal_body(key[last:])))
    return re.compile(r'(?<![\\"#])"' + "".join(parts) + r'"(?!")')


def key_specs(key: str) -> list[str]:
    return [m.group(0) for m in SPEC.finditer(key) if m.group(0) != "%%"]


def swift_files(dirs: list[str]) -> list[str]:
    out = []
    for d in dirs:
        out += glob.glob(os.path.join(ROOT, d, "**", "*.swift"), recursive=True)
    return sorted(p for p in out if "/.build/" not in p and "/Tests/" not in p)


def area_of(path: str, dirs: list[str]) -> str:
    r = rel(path)
    for d in dirs:
        if r.startswith(d + "/"):
            r = r[len(d) + 1:]
    parts = [p for p in r.split("/") if p not in ("Sources", "VaultKit", "DesignKit", "Support", "Resources")]
    name = parts[0] if len(parts) > 1 else os.path.splitext(parts[0])[0]
    name = re.sub(r"[^A-Za-z0-9]", "", name)
    return name[:1].lower() + name[1:]


def cmd_rekey(args) -> int:
    cfg = load_config()
    source = cfg["source"]
    glossary = load_glossary(cfg)
    catalog = os.path.join(ROOT, args.catalog)
    dirs = cfg["apple"]["sources"].get(rel(catalog))
    if not dirs:
        print(f"no source directories for {rel(catalog)} in config.json")
        return 2
    cat = read_json(catalog)
    files = {p: read_text(p) for p in swift_files(dirs)}
    if args.only:
        only = set(args.only)
    else:
        only = None
    used = set(cat["strings"])
    by_value = {(g["fr"], g["en"]): k for k, g in glossary.items()}
    plan = []
    skipped = collections.Counter()
    for key, entry in sorted(cat["strings"].items()):
        if not translatable(key, entry) or SEMANTIC.match(key):
            continue
        rx = literal_regex(key)
        if rx is None:
            skipped["positional or %%"] += 1
            continue
        hits = [(p, m) for p, text in files.items() for m in rx.finditer(text)]
        if only is not None and not any(area_of(p, dirs) in only for p, _ in hits):
            continue
        if not hits:
            skipped["no literal in source"] += 1
            continue
        en_loc = entry.get("localizations", {}).get("en", {})
        en = en_loc.get("stringUnit", {}).get("value") or (plural_cases(en_loc) or {}).get("other", {}).get("stringUnit", {}).get("value") or key
        fr_loc = entry.get("localizations", {}).get(source)
        specs = key_specs(key)
        g = by_value.get((key, en)) if not specs and not fr_loc else None
        if g:
            base = g
        else:
            areas = {area_of(p, dirs) for p, _ in hits}
            area = areas.pop() if len(areas) == 1 else "common"
            base = f"{area}.{slug(en)}"
        new = base if not specs else base + " " + " ".join(specs)
        n = 2
        while new in used and not (g and new == g):
            stem = f"{base}{n}"
            new = stem if not specs else stem + " " + " ".join(specs)
            n += 1
        if g and g in cat["strings"] and g != key:
            new = g  # merge into the existing glossary entry
        used.add(new)
        plan.append((key, new, hits))
    if args.dry_run:
        for old, new, hits in plan:
            print(f"{new!r:60} <- {old!r} ({len(hits)} literal(s))")
        print(f"{len(plan)} key(s) to rename; skipped: {dict(skipped)}")
        return 0
    edits: dict[str, list] = collections.defaultdict(list)
    for old, new, hits in plan:
        entry = cat["strings"].pop(old)
        if new in cat["strings"]:
            pass  # a glossary entry already there: the old one folds into it
        else:
            locs = entry.setdefault("localizations", {})
            if source not in locs:
                locs[source] = {"stringUnit": {"state": "translated", "value": old}}
            entry["extractionState"] = "manual"
            g = glossary.get(new)
            if g:
                for lang in cfg["languages"]:
                    put_apple(entry, lang, g[lang])
            cat["strings"] = insert_sorted(cat["strings"], new, entry)
        sem = new.split(" ")[0]
        for p, m in hits:
            interps = [m.group(i) for i in range(1, (m.lastindex or 0) + 1)]
            lit = '"' + sem + ("" if not interps else " " + " ".join(interps)) + '"'
            edits[p].append((m.start(), m.end(), lit))
    for p, es in edits.items():
        text = files[p]
        for start, end, lit in sorted(set(es), reverse=True):
            text = text[:start] + lit + text[end:]
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
    write_xcstrings(catalog, cat)
    print(f"{len(plan)} key(s) renamed in {len(edits)} file(s); skipped: {dict(skipped)}")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--terms", action="store_true", help="also warn on glossary terms missing from translations")
    c.add_argument("-v", "--verbose", action="store_true")
    c.set_defaults(func=cmd_check)
    s = sub.add_parser("stats")
    s.set_defaults(func=cmd_stats)
    e = sub.add_parser("export")
    e.add_argument("lang")
    e.add_argument("--out", default="i18n-work.json")
    e.add_argument("--all", action="store_true", help="also entries that already have the language")
    e.set_defaults(func=cmd_export)
    i = sub.add_parser("import")
    i.add_argument("file")
    i.add_argument("--lang", help="a language not yet in config.json")
    i.add_argument("--overwrite-en", action="store_true")
    i.set_defaults(func=cmd_import)
    y = sub.add_parser("sync")
    y.set_defaults(func=cmd_sync)
    r = sub.add_parser("rekey")
    r.add_argument("catalog")
    r.add_argument("--only", nargs="*", help="areas (first directory under the target) to migrate")
    r.add_argument("--dry-run", action="store_true")
    r.set_defaults(func=cmd_rekey)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
