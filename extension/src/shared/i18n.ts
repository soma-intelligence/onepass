// UI language: French (informal "tu") or English, from the browser's UI
// language. French when the browser says French or when there is no
// extension runtime (unit tests), English otherwise. Strings live next to
// their use as `tr(fr, en)` pairs: the French text stays the reference.
import { ext } from "./browser";

export type Lang = "fr" | "en";

function detect(): Lang {
  try {
    const ui = ext?.i18n?.getUILanguage?.();
    if (typeof ui !== "string" || ui === "") return "fr";
    return ui.toLowerCase().startsWith("fr") ? "fr" : "en";
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

export function tr(fr: string, en: string): string {
  return current === "fr" ? fr : en;
}
