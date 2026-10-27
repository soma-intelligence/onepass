"""Write VaultKit's CoreLabels.xcstrings from the Rust templates and menus.

usage: python3 -I apple/scripts/core_labels/gen.py core apple/VaultKit/Sources/VaultKit/Resources/CoreLabels.xcstrings
Rerun after any change to templates.rs or menus.rs; a new label fails until en_core.py has its English."""
import json, os, sys, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse import parse
from en_core import OVERRIDE, LABEL, MENU, TYPE

core, out = sys.argv[1], sys.argv[2]
templates, options = parse(core)
strings = {}

def dump(obj):
    """Xcode layout: 2-space indent, ' : ' separators, sorted keys, empty dicts as {\\n\\n}."""
    text = json.dumps(obj, ensure_ascii=False, indent=2, separators=(",", " : "), sort_keys=True)
    return text


def put(key, fr, en, comment):
    assert "\u2014" not in en and "\u2014" not in fr
    strings[key] = {"comment": comment, "extractionState": "manual", "localizations": {
        "en": {"stringUnit": {"state": "translated", "value": en}},
        "fr": {"stringUnit": {"state": "translated", "value": fr}}}}

def english(fr, fid):
    return OVERRIDE.get((fr, fid)) or LABEL[fr]

seen = {}
for t, v in templates.items():
    for sid, fr in v["sections"]:
        put(f"section.{t}.{sid}", fr, english(fr, sid), f"Section of the {t} template (core id {sid}).")
    for fid, fr in v["fields"]:
        en = english(fr, fid)
        prev = seen.setdefault((fid, fr), en)
        assert prev == en, (fid, fr, prev, en)
        put(f"field.{t}.{fid}", fr, en, f"Field of the {t} template (core id {fid}).")
put("section.custom", "Champs perso", "Custom fields", "Section of the fields the user adds (ItemDraft.customSectionLabel).")
put("section.imported", "Importé", LABEL["Importé"], "Section the importer adds for fields it could not map.")
missing = [o for o in options if o not in MENU and not re.search(r"[a-zà-ÿ]{3}", o)]
for o in options:
    if o in MENU:
        put(f"menu.{o}", o, MENU[o], "Option of a menu field (stored value stays French).")
for t, (fr, en) in TYPE.items():
    put(f"type.{t}", fr, en, "Singular name of an item type.")
unknown = [o for o in options if o not in MENU]
print("menu options kept as stored:", unknown, file=sys.stderr)
cat = {"sourceLanguage": "fr", "strings": strings, "version": "1.0"}
with open(out, "w") as f:
    f.write(dump(cat))
print(f"{out}: {len(strings)} keys", file=sys.stderr)
