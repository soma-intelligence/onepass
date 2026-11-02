"""Tests of scripts/i18n/i18n.py on toy catalogs. Run: python3 -I scripts/i18n/test_i18n.py"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import i18n  # noqa: E402

LANGS = ["fr", "en", "es", "it"]


def unit(v):
    return {"stringUnit": {"state": "translated", "value": v}}


def plural(one, other):
    return {"variations": {"plural": {"one": unit(one), "other": unit(other)}}}


class Toy(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = self.dir.name
        os.makedirs(os.path.join(self.root, "scripts", "i18n"))
        os.makedirs(os.path.join(self.root, "apple", "App"))
        os.makedirs(os.path.join(self.root, "extension", "src", "shared", "l10n"))
        os.makedirs(os.path.join(self.root, "extension", "src", "ui"))
        cfg = {
            "source": "fr",
            "languages": LANGS,
            "apple": {"catalogs": "apple/**/*.xcstrings", "exclude": [], "generated": {},
                      "sources": {"apple/App/Localizable.xcstrings": ["apple/App"]}},
            "extension": {"catalogs": "extension/src/shared/l10n", "manifest": "extension/src/_locales",
                          "code": "extension/src", "banned_calls": ["tr("]},
            "glossary": "scripts/i18n/glossary.json",
        }
        self.write("scripts/i18n/config.json", cfg)
        self.write("scripts/i18n/glossary.json", {"entries": {
            "common.cancel": {"fr": "Annuler", "en": "Cancel", "es": "Cancelar", "it": "Annulla"},
            "term.vault": {"fr": "Coffre", "en": "Vault", "es": "Bóveda", "it": "Cassaforte",
                           "forms": {"fr": ["coffre"], "en": ["vault"], "es": ["bóveda"], "it": ["cassaforte"]}},
        }})
        for lang in LANGS:
            self.write(f"extension/src/shared/l10n/{lang}.json", {"menu.fill": "x"})
        self.old_root = i18n.ROOT
        i18n.ROOT = self.root

    def tearDown(self):
        i18n.ROOT = self.old_root
        self.dir.cleanup()

    def write(self, rel, obj):
        with open(os.path.join(self.root, rel), "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False)

    def load(self, path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def catalog(self, strings):
        self.write("apple/App/Localizable.xcstrings", {"sourceLanguage": "fr", "strings": strings, "version": "1.0"})

    def run_cmd(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = i18n.main(list(argv))
        return code, out.getvalue()

    def full(self, fr, en, es, it):
        return {"extractionState": "manual", "localizations": {"fr": unit(fr), "en": unit(en), "es": unit(es), "it": unit(it)}}

    def test_complete_catalog_passes(self):
        self.catalog({"items.addTo %@": self.full("Ajouter à %@", "Add to %@", "Añadir a %@", "Aggiungi a %@")})
        code, out = self.run_cmd("check")
        self.assertEqual(code, 0, out)

    def test_missing_language_fails(self):
        e = self.full("A", "B", "C", "D")
        del e["localizations"]["it"]
        self.catalog({"x.y": e})
        code, out = self.run_cmd("check")
        self.assertEqual(code, 1)
        self.assertIn("missing 'it'", out)

    def test_legacy_key_is_its_own_french(self):
        self.catalog({"Annuler la demande": {"localizations": {"en": unit("Cancel"), "es": unit("Cancelar"), "it": unit("Annulla")}}})
        self.assertEqual(self.run_cmd("check")[0], 0)

    def test_placeholder_mismatch_fails(self):
        self.catalog({"x.y %@ %lld": self.full("%@ et %lld", "%@ and %lld", "%@ y %@", "%2$lld e %1$@")})
        code, out = self.run_cmd("check")
        self.assertEqual(code, 1)
        self.assertIn("'es' placeholders", out)
        self.assertNotIn("'it' placeholders", out)

    def test_plural_needs_one_and_other(self):
        e = {"localizations": {"fr": plural("%lld élément", "%lld éléments"), "en": plural("%lld item", "%lld items"),
                               "es": {"variations": {"plural": {"other": unit("%lld elementos")}}},
                               "it": plural("Un elemento", "%lld elementi")}}
        self.catalog({"x.count %lld": e})
        code, out = self.run_cmd("check")
        self.assertIn("'es' plural lacks 'one'", out)
        self.assertNotIn("'it' plural", out)

    def test_glossary_drift_fails_and_sync_fixes(self):
        self.catalog({"common.cancel": self.full("Annuler", "Cancel", "Anular", "Annulla")})
        code, out = self.run_cmd("check")
        self.assertIn("differs from the glossary", out)
        self.run_cmd("sync")
        self.assertEqual(self.run_cmd("check")[0], 0)

    def test_em_dash_fails(self):
        self.catalog({"x.y": self.full("A — B", "A", "A", "A")})
        self.assertIn("em dash", self.run_cmd("check")[1])

    def test_extension_missing_key_and_tr_call(self):
        self.write("extension/src/shared/l10n/es.json", {})
        with open(os.path.join(self.root, "extension/src/ui/menu.ts"), "w") as f:
            f.write('const a = tr("Oui", "Yes");\nconst b = new Transcript(x);\n')
        code, out = self.run_cmd("check")
        self.assertIn("missing key menu.fill", out)
        self.assertIn("menu.ts:1", out)
        self.assertNotIn("menu.ts:2", out)

    def test_extension_named_placeholders(self):
        self.write("extension/src/shared/l10n/fr.json", {"menu.fill": "Pour {site}"})
        self.write("extension/src/shared/l10n/en.json", {"menu.fill": "For {site}"})
        self.write("extension/src/shared/l10n/es.json", {"menu.fill": "Para {sitio}"})
        self.write("extension/src/shared/l10n/it.json", {"menu.fill": "Per {site}"})
        out = self.run_cmd("check")[1]
        self.assertIn("es.json: menu.fill: placeholders", out)
        self.assertNotIn("it.json", out)

    def test_term_warning(self):
        self.catalog({"x.y": self.full("Ton coffre", "Your vault", "Tu caja", "La tua cassaforte")})
        out = self.run_cmd("check", "--terms")[1]
        self.assertIn("'es' does not use the glossary term term.vault", out)
        self.assertNotIn("'it' does not use", out)

    def test_export_then_import_round_trip(self):
        e = {"localizations": {"en": unit("Lock")}}
        self.catalog({"Verrouiller": e})
        work = os.path.join(self.root, "w.json")
        self.run_cmd("export", "es", "--out", work)
        items = self.load(work)
        self.assertEqual(items[0]["fr"], "Verrouiller")
        self.assertEqual(items[0]["en"], "Lock")
        items[0]["es"] = "Bloquear"
        self.write("w.json", items)
        self.run_cmd("import", work)
        cat = self.load(os.path.join(self.root, "apple/App/Localizable.xcstrings"))
        self.assertEqual(cat["strings"]["Verrouiller"]["localizations"]["es"]["stringUnit"]["value"], "Bloquear")

    def test_rekey_renames_entry_and_literals(self):
        self.catalog({
            "Ajouter à %@": {"localizations": {"en": unit("Add to %@"), "es": unit("Añadir a %@"), "it": unit("Aggiungi a %@")}},
            "Annuler": {"localizations": {"en": unit("Cancel"), "es": unit("Cancelar"), "it": unit("Annulla")}},
        })
        os.makedirs(os.path.join(self.root, "apple/App/Items"))
        src = os.path.join(self.root, "apple/App/Items/AddView.swift")
        with open(src, "w") as f:
            f.write('Text("Ajouter à \\(vault.name(for: "x"))")\nButton("Annuler") {}\nlet raw = "Annuler la suite"\n')
        code, out = self.run_cmd("rekey", "apple/App/Localizable.xcstrings")
        self.assertEqual(code, 0, out)
        with open(src) as f:
            text = f.read()
        self.assertIn('Text("items.addTo \\(vault.name(for: "x"))")', text)
        self.assertIn('Button("common.cancel")', text)
        self.assertIn('"Annuler la suite"', text)
        cat = self.load(os.path.join(self.root, "apple/App/Localizable.xcstrings"))["strings"]
        self.assertEqual(cat["items.addTo %@"]["localizations"]["fr"]["stringUnit"]["value"], "Ajouter à %@")
        self.assertEqual(cat["items.addTo %@"]["localizations"]["it"]["stringUnit"]["value"], "Aggiungi a %@")
        self.assertIn("common.cancel", cat)
        self.assertEqual(self.run_cmd("check")[0], 0)

    def test_dump_keeps_entry_order(self):
        obj = {"sourceLanguage": "fr", "strings": {"b": {}, "a": {}}, "version": "1.0"}
        text = i18n.dump_xcstrings(obj)
        self.assertLess(text.index('"b"'), text.index('"a"'))
        self.assertEqual(list(i18n.insert_sorted({"a": 1, "c": 3}, "b", 2)), ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main()
