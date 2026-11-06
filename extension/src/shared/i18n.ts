// UI language: French (the source, informal "tu"), Spanish (tú), Italian (tu) or English, from
// the browser's UI language; English for any other language. French when there is no extension
// runtime (unit tests). Strings live in ./l10n/<lang>.json under semantic keys; product terms and
// shared actions (term.*, common.*) are copied from scripts/i18n/glossary.json. Rules:
// docs/i18n.md (no sentence built from fragments, plurals through tn()).
import { ext } from "./browser";
import fr from "./l10n/fr.json" with { type: "json" };
import en from "./l10n/en.json" with { type: "json" };
import es from "./l10n/es.json" with { type: "json" };
import it from "./l10n/it.json" with { type: "json" };

export type Lang = "fr" | "en" | "es" | "it";
export const LANGS: readonly Lang[] = ["fr", "en", "es", "it"];

/** Every key of the French catalog; a language file that lacks one does not compile. */
export type Key = keyof typeof fr;
type Plural = { readonly one: string; readonly other: string } & Partial<Record<Intl.LDMLPluralRule, string>>;
type Value = string | Plural;
export type Args = Readonly<Record<string, string | number>>;

const catalogs: Record<Lang, Record<Key, Value>> = { fr, en, es, it };

function detect(): Lang {
  try {
    const ui = ext?.i18n?.getUILanguage?.();
    if (typeof ui !== "string" || ui === "") return "fr";
    const l = ui.toLowerCase();
    for (const c of ["fr", "es", "it"] as const) if (l.startsWith(c)) return c;
    return "en";
  } catch {
    return "fr";
  }
}

let current: Lang = detect();

export function lang(): Lang {
  return current;
}

/** Tests and the visual harness only. */
export function setLang(l: Lang): void {
  current = l;
}

function fill(text: string, args?: Args): string {
  if (!args) return text;
  return text.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g, (whole, name: string) => {
    const v = args[name];
    return v === undefined ? whole : String(v);
  });
}

/** The text of `key` in the current language, with `{name}` arguments filled in. */
export function t(key: Key, args?: Args): string {
  const v = catalogs[current][key] ?? catalogs.en[key];
  return fill(typeof v === "string" ? v : v.other, args);
}

/** A plural entry: the form for `count` by the language's plural rules; `{count}` is filled too. */
export function tn(key: Key, count: number, args?: Args): string {
  const v = catalogs[current][key] ?? catalogs.en[key];
  if (typeof v === "string") return fill(v, { count, ...args });
  const form = new Intl.PluralRules(current).select(count);
  return fill(v[form] ?? v.other, { count, ...args });
}

/**
 * @deprecated Use t() with a key in ./l10n/*.json (docs/i18n.md). Kept so a branch written
 * before the key catalogs still compiles; `scripts/i18n/i18n.py check` refuses every call.
 */
export function tr(fr: string, en: string): string {
  return current === "fr" ? fr : en;
}
