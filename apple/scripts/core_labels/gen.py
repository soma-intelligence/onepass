"""Write VaultKit's CoreLabels.xcstrings from the Rust templates and menus.

usage: python3 -I apple/scripts/core_labels/gen.py core apple/VaultKit/Sources/VaultKit/Resources/CoreLabels.xcstrings
Rerun after any change to templates.rs or menus.rs; a new label fails until en_core.py, es_core.py
and it_core.py have it. Adding a language: copy en_core.py to <lang>_core.py, translate, add it to LANGS."""
import json, os, sys, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse import parse
import importlib
from en_core import OVERRIDE, LABEL, MENU, TYPE

# Languages besides French (the stored text) and English, each from <lang>_core.py.
LANGS = {code: importlib.import_module(f"{code}_core") for code in ("es", "it")}

core, out = sys.argv[1], sys.argv[2]
templates, options = parse(core)
strings = {}

def dump(obj):
    """Xcode layout: 2-space indent, ' : ' separators, sorted keys, empty dicts as {\\n\\n}."""
    text = json.dumps(obj, ensure_ascii=False, indent=2, separators=(",", " : "), sort_keys=True)
    return text


def put(key, fr, en, comment, others):
    values = {"fr": fr, "en": en, **others}
    assert all("\u2014" not in v for v in values.values())
    strings[key] = {"comment": comment, "extractionState": "manual", "localizations": {
        lang: {"stringUnit": {"state": "translated", "value": v}} for lang, v in values.items()}}

def english(fr, fid):
    return OVERRIDE.get((fr, fid)) or LABEL[fr]

def label(fr, fid=None):
    return {code: m.OVERRIDE.get((fr, fid)) or m.LABEL[fr] for code, m in LANGS.items()}

def menu(o):
    return {code: m.MENU[o] for code, m in LANGS.items()}

def type_name(t):
    return {code: m.TYPE[t] for code, m in LANGS.items()}

seen = {}
for t, v in templates.items():
    for sid, fr in v["sections"]:
        put(f"section.{t}.{sid}", fr, english(fr, sid), f"Section of the {t} template (core id {sid}).", label(fr, sid))
    for fid, fr in v["fields"]:
        en = english(fr, fid)
        prev = seen.setdefault((fid, fr), en)
        assert prev == en, (fid, fr, prev, en)
        put(f"field.{t}.{fid}", fr, en, f"Field of the {t} template (core id {fid}).", label(fr, fid))
put("section.custom", "Champs perso", "Custom fields", "Section of the fields the user adds (ItemDraft.customSectionLabel).",
    {"es": "Campos personalizados", "it": "Campi personalizzati"})
put("section.imported", "Importé", LABEL["Importé"], "Section the importer adds for fields it could not map.", label("Importé"))
missing = [o for o in options if o not in MENU and not re.search(r"[a-zà-ÿ]{3}", o)]
for o in options:
    if o in MENU:
        put(f"menu.{o}", o, MENU[o], "Option of a menu field (stored value stays French).", menu(o))
for t, (fr, en) in TYPE.items():
    put(f"type.{t}", fr, en, "Singular name of an item type.", type_name(t))
unknown = [o for o in options if o not in MENU]
print("menu options kept as stored:", unknown, file=sys.stderr)
cat = {"sourceLanguage": "fr", "strings": strings, "version": "1.0"}
with open(out, "w") as f:
    f.write(dump(cat))
print(f"{out}: {len(strings)} keys", file=sys.stderr)
