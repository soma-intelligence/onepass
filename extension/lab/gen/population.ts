// Simulated user population of the autofill lab: seeded profiles that differ
// in vault size, duplicates, several accounts per site, language and country
// formats, and what the user does after the extension fills. The first
// profile is always the lab's historical single user (its world and vault are
// unchanged); the others come from a separate Rng stream, one fork per
// profile, so asking for more profiles never perturbs the earlier ones.
// Everything is synthetic: filler items live on reserved .test hosts.
import type { Address } from "./data.ts";
import { addressFor, card, COUNTRY_CODES, fillerWords, formatCardNumber, password, person, phoneFor } from "./data.ts";
import type { FixtureFile, Lang, Site } from "./model.ts";
import { Rng } from "./rng.ts";

export type Behaviour = "complete" | "partial" | "corrects_field" | "abandons_step";

export interface Profile {
  id: string;
  /**
   * Items in the profile's vault, 0 to 500. 0 is an empty vault (the extension has nothing to offer).
   * Otherwise a floor: the vault always holds the world's own items (the scenarios need them) and
   * synthetic filler items bring it up to this size.
   */
  vaultSize: number;
  /** Site logins repeated exactly (an import that doubled some entries). */
  duplicates: number;
  /** A second account (other username and password) for every password site. */
  multiAccount: boolean;
  lang: Lang;
  /** ISO country of the profile's identity items (address, phone and postal code formats). */
  country: string;
  browser: "chromium";
  behaviour: Behaviour;
}

export const DEFAULT_PROFILE_ID = "p0";
/** The historical single user: the world's own vault, no filler, no duplicate, complete behaviour. */
export const DEFAULT_PROFILE: Profile = {
  id: DEFAULT_PROFILE_ID, vaultSize: 1, duplicates: 0, multiAccount: false, lang: "en", country: "US", browser: "chromium", behaviour: "complete",
};

/** Profile id of a scenario or result (absent: the default profile). */
export function profileOf(x: { profile?: string }): string {
  return x.profile ?? DEFAULT_PROFILE_ID;
}

const COUNTRY_WEIGHTS: [string, number][] = [["US", 25], ["FR", 20], ["DE", 15], ["ES", 12], ["GB", 13], ["JP", 15]];
const COUNTRY_LANG: Record<string, Lang> = { US: "en", GB: "en", FR: "fr", DE: "de", ES: "es", JP: "ja" };
const BEHAVIOURS: [Behaviour, number][] = [["complete", 55], ["partial", 15], ["corrects_field", 15], ["abandons_step", 15]];

function drawVaultSize(r: Rng): number {
  switch (r.weighted<"empty" | "world" | "small" | "mid" | "large">([["empty", 8], ["world", 24], ["small", 22], ["mid", 22], ["large", 24]])) {
    case "empty": return 0;
    case "world": return 1;
    case "small": return r.int(20, 60);
    case "mid": return r.int(100, 200);
    case "large": return r.int(300, 500);
  }
}

/** `n` profiles of `seed`: the default one, then n - 1 drawn ones. */
export function drawProfiles(seed: string, n: number): Profile[] {
  const root = new Rng(`${seed}/population`);
  const out: Profile[] = [DEFAULT_PROFILE];
  for (let k = 1; k < n; k++) {
    const r = root.fork(`profile:${k}`);
    const country = r.weighted(COUNTRY_WEIGHTS);
    out.push({
      id: `p${k}`,
      vaultSize: drawVaultSize(r),
      duplicates: r.chance(0.35) ? r.int(1, 8) : 0,
      multiAccount: r.chance(0.4),
      lang: COUNTRY_LANG[country] ?? "en",
      country,
      browser: "chromium",
      behaviour: r.weighted(BEHAVIOURS),
    });
  }
  return out.slice(0, n);
}

interface Item { type: string; title: string; vault?: string; urls?: { url: string; rule: string }[]; fields: Record<string, unknown>; totp_uri?: string }
const VAULT = "Lab";
const cap = (w: string) => w.charAt(0).toUpperCase() + w.slice(1);
const addressFields = (a: Address) => ({ line1: a.line1, line2: a.line2, city: a.city, postal_code: a.postalCode, region: a.region, country: a.country });

/**
 * The vault of `profile` for a world: `base` is the world's own fixture (what
 * the default profile gets, untouched). Others get identity items rewritten in
 * their country's formats, a second account per password site, exact
 * duplicates, and synthetic filler up to `vaultSize`; vaultSize 0 is empty.
 */
export function fixtureFor(profile: Profile, sites: Site[], base: FixtureFile): FixtureFile {
  if (profile.id === DEFAULT_PROFILE_ID) return base;
  if (profile.vaultSize === 0) return { ...base, items: [] };
  const items = (base.items as Item[]).map((i) => ({ ...i }));
  for (const s of sites) {
    if (!s.identityTitle) continue;
    const at = items.findIndex((i) => i.type === "identity" && i.title === s.identityTitle);
    if (at < 0) continue;
    const r = new Rng(`${s.seed}/profile:${profile.id}`);
    items[at] = { ...items[at]!, fields: { ...items[at]!.fields, mobile_phone: phoneFor(r, profile.country), address: addressFields(addressFor(r, profile.country)) } };
  }
  const logins = sites
    .filter((s) => s.account && s.account.password !== "")
    .flatMap((s) => items.filter((i) => i.type === "login" && i.urls?.[0]?.url === `https://${s.host}` && i.fields.password !== undefined)
      .map((i) => ({ site: s, item: i })));
  if (profile.multiAccount) {
    for (const { site, item } of logins) {
      const r = new Rng(`${site.seed}/profile:${profile.id}/second`);
      const who = person(r, site.lang);
      const username = String(item.fields.username).includes("@") ? who.email : `${who.given}.${who.family}`.toLowerCase();
      items.push({ type: "login", title: `${item.title} (2)`, vault: VAULT, urls: item.urls!, fields: { username, password: password(r) } });
    }
  }
  for (const { item } of logins.slice(0, profile.duplicates)) items.push(structuredClone(item));
  const seedKey = sites[0]?.seed ?? "empty-world";
  const rf = new Rng(`${seedKey}/profile:${profile.id}/filler`);
  for (let i = items.length, n = 0; i < profile.vaultSize; i++, n++) items.push(filler(rf.fork(`item:${n}`), n, profile));
  return { ...base, items };
}

/** One synthetic filler item (tenth card, ninth identity, the rest logins) on a host of its own under a reserved .test name. */
function filler(r: Rng, n: number, profile: Profile): Item {
  const [a, b] = fillerWords(r);
  const title = `${cap(a)} ${cap(b)} archive ${n + 1}`;
  const who = person(r);
  if (n % 10 === 7) {
    const c = card(r);
    return {
      type: "credit_card", title: `Carte ${title}`, vault: VAULT,
      fields: { cardholder: `${who.given} ${who.family}`, number: formatCardNumber(c.number), expiry: `${String(c.expMonth).padStart(2, "0")}/${c.expYear}`, cvv: c.cvc },
    };
  }
  if (n % 10 === 9) {
    return {
      type: "identity", title: `${who.given} ${who.family} (${title})`, vault: VAULT,
      fields: {
        first_name: who.given, last_name: who.family, email: who.email, mobile_phone: phoneFor(r, profile.country), birth_date: who.birthDate,
        company: who.company, address: addressFields(addressFor(r, profile.country)),
      },
    };
  }
  return {
    type: "login", title, vault: VAULT, urls: [{ url: `https://${a}-${b}-${n + 1}-archive.test`, rule: "domain" }],
    fields: { username: who.email, password: password(r) },
  };
}

/** Host of a filler item from its title ("Carte Amber Falcon archive 5" gives "amber-falcon-5-archive.test"); undefined for any other title. */
export function archiveHostOf(title: string): string | undefined {
  const m = /^(?:Carte )?([A-Z][a-z]+) ([A-Z][a-z]+) archive (\d+)$/.exec(title);
  return m ? `${m[1]!.toLowerCase()}-${m[2]!.toLowerCase()}-${m[3]}-archive.test` : undefined;
}
