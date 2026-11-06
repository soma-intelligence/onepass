// Picks the option of a country or region list that means the vault's value
// (spec 2026-10-31, section 3). Each option gets a score; the best wins, and
// best options with different values are a tie: nothing is picked.
import { resolveCountry, resolveCountryValue } from "./countries";
import { demonymCountry } from "./demonyms";
import { fold } from "./fold";
import { regionFromPostal } from "./postal";
import { parentRegion, resolveRegion } from "./regions";

export interface OptionLike {
  value: string;
  text: string;
}

/** Index of the single best option (score > 0), -1 on none or a tie. */
function best(opts: readonly OptionLike[], score: (o: OptionLike) => number): number {
  let top = 0;
  let at = -1;
  let tie = false;
  opts.forEach((o, i) => {
    const s = score(o);
    if (s <= 0) return;
    if (s > top) {
      top = s;
      at = i;
      tie = false;
    } else if (s === top && fold(o.value) !== fold(opts[at]!.value)) {
      tie = true;
    }
  });
  return tie ? -1 : at;
}

const same = (a: string, b: string) => a.trim().toLowerCase() === b.trim().toLowerCase();
/** A placeholder ("--", "Choose") has no value. */
const placeholder = (o: OptionLike) => o.value.trim() === "";

/** Index of the option of a country list meaning `want`, or -1. */
export function pickCountry(opts: readonly OptionLike[], want: string, langs: readonly string[]): number {
  if (want.trim() === "") return -1;
  const cc = resolveCountry(want, langs);
  const folded = fold(want);
  return best(opts, (o) => {
    if (same(o.value, want) || same(o.text, want)) return 3;
    if (placeholder(o)) return 0;
    if (cc !== null) {
      const c = resolveCountry(o.text, langs) ?? resolveCountryValue(o.value, langs);
      return c === cc ? 2 : 0;
    }
    return folded !== "" && fold(o.text) === folded ? 1 : 0;
  });
}

/**
 * Index of the option of a nationality list meaning `want` (an alpha-2 code, a country name or a
 * demonym), or -1 (spec section 8): the option's own text or value first, then its country by
 * name or code, then by demonym in any of the seven languages; a tie picks nothing.
 */
export function pickNationality(opts: readonly OptionLike[], want: string, langs: readonly string[]): number {
  if (want.trim() === "") return -1;
  const cc = resolveCountry(want, langs) ?? demonymCountry(want);
  return best(opts, (o) => {
    if (same(o.value, want) || same(o.text, want)) return 3;
    if (placeholder(o) || cc === null) return 0;
    const c = resolveCountry(o.text, langs) ?? demonymCountry(o.text) ?? resolveCountryValue(o.value, langs) ?? demonymCountry(o.value);
    return c === cc ? 2 : 0;
  });
}

/**
 * The region codes an item means: its region resolved within `country`, or,
 * without a region, the one its postal code gives (country needed).
 */
export function regionWanted(region: string, country: string | null, postal: string | null): string[] {
  if (region.trim() !== "") return resolveRegion(region, country);
  if (country === null || postal === null || postal.trim() === "") return [];
  const r = regionFromPostal(country, postal);
  return r ? [r] : [];
}

/**
 * The region the postal code gives, when it agrees with the item's region
 * (the same, or a department of it), or when the region named nothing.
 */
export function postalFallback(region: string, country: string | null, postal: string | null): string | null {
  if (country === null || postal === null || postal.trim() === "") return null;
  const r = regionFromPostal(country, postal);
  if (!r) return null;
  const wanted = resolveRegion(region, country);
  if (wanted.length === 0 || wanted.includes(r)) return r;
  const parent = parentRegion(r);
  return parent !== null && wanted.includes(parent) ? r : null;
}

/** The single region code an option names (its text first, then its value), or null. */
function optionRegion(o: OptionLike, country: string | null): string | null {
  for (const s of [o.text, o.value]) {
    const codes = resolveRegion(s, country);
    if (codes.length === 1) return codes[0]!;
    if (codes.length > 1) return null;
  }
  return null;
}

/**
 * Index of the option of a region list meaning one of `wanted` (codes from
 * `regionWanted`), or -1. `raw` is the item's own text, tried first as is.
 * A department also matches its region (lower score), never the reverse.
 */
export function pickRegion(opts: readonly OptionLike[], wanted: readonly string[], country: string | null, raw = ""): number {
  const want = new Set(wanted);
  const parents = new Set(wanted.map(parentRegion).filter((p): p is string => p !== null));
  if (want.size === 0 && raw.trim() === "") return -1;
  return best(opts, (o) => {
    if (raw.trim() !== "" && (same(o.value, raw) || same(o.text, raw))) return 3;
    if (placeholder(o)) return 0;
    const code = optionRegion(o, country);
    if (code === null) return 0;
    if (want.has(code)) return 2;
    return parents.has(code) ? 1 : 0;
  });
}
