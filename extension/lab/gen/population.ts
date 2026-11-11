// Simulated user population of the autofill lab: seeded profiles that differ
// in vault size, duplicates, several accounts per site, language and country
// formats, and what the user does after the extension fills. The first
// profile is always the lab's historical single user (its world and vault are
// unchanged); the others come from a separate Rng stream, one fork per
// profile, so asking for more profiles never perturbs the earlier ones.
// Everything is synthetic: filler items live on reserved .test hosts.
// Account profiles (p1 to p3) are fixed, not drawn: the historical vault
// plus a second login on every plain password site, to measure several
// accounts on one site with and without site memory. Each states its
// expected outcome (ACCOUNT_OUTCOME); they never mix with drawn profiles.
import type { Address } from "./data.ts";
import { addressFor, card, COUNTRY_CODES, fillerWords, formatCardNumber, password, person, phoneFor } from "./data.ts";
import type { FixtureFile, FlowId, Lang, Site } from "./model.ts";
import { Rng } from "./rng.ts";

export type Behaviour = "complete" | "partial" | "corrects_field" | "abandons_step";
/**
 * Several logins of one site in the vault (account profiles): two accounts and no site memory, two accounts
 * of which the second was used last on this site, or one exact-host item next to a domain-wide one.
 */
export type AccountSetup = "two" | "two_last_used" | "exact_and_domain";

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
  /** Account profiles only: the logins every plain password site has in this vault. */
  accounts?: AccountSetup;
}

export const DEFAULT_PROFILE_ID = "p0";
/** The historical single user: the world's own vault, no filler, no duplicate, complete behaviour. */
export const DEFAULT_PROFILE: Profile = {
  id: DEFAULT_PROFILE_ID, vaultSize: 1, duplicates: 0, multiAccount: false, lang: "en", country: "US", browser: "chromium", behaviour: "complete",
};

/** The account profiles, by id: the historical vault plus a second login per plain password site. */
export const ACCOUNT_PROFILES: readonly Profile[] = [
  { ...DEFAULT_PROFILE, id: "p1", accounts: "two" },
  { ...DEFAULT_PROFILE, id: "p2", accounts: "two_last_used" },
  { ...DEFAULT_PROFILE, id: "p3", accounts: "exact_and_domain" },
];

/** What each account profile expects of one gesture, stated in its scenarios and in the report. */
export const ACCOUNT_OUTCOME: Record<AccountSetup, string> = {
  two: "two accounts, no site memory: OnePass cannot know which one, so it asks; the user picks hers and is signed in with two gestures. Signing in without asking is a guess.",
  two_last_used: "two accounts, the second used last on this site: one gesture signs in with that account, no question asked.",
  exact_and_domain: "one exact-host item and one domain-wide item, no site memory: the exact-host item is the closer match; one gesture signs in with it, no question asked.",
};

/** Flows the account profiles are played on: a plain password sign-in (no code, no passkey, no provider). */
export const ACCOUNT_FLOWS: ReadonlySet<FlowId> = new Set<FlowId>(["login_single", "login_username_first", "login_email_then_password"]);

/**
 * URL the second login of an account profile is saved under: the site's own, except the domain-wide item of
 * exact_and_domain, saved for another host of the same registrable domain. On the very same host both items
 * would be exact-host matches, and the bridge rightly finds no sole one.
 */
export const secondUrl = (setup: AccountSetup, host: string): string => (setup === "exact_and_domain" ? `https://www.${host}` : `https://${host}`);

/** Title of the second login an account profile adds to a site. */
export const secondTitle = (setup: AccountSetup, title: string): string => (setup === "exact_and_domain" ? `${title} (domaine)` : `${title} (2)`);

/** The profiles of a comma list of ids ("p0,p2"), in id order; throws on an unknown or repeated id. */
export function accountProfiles(ids: readonly string[]): Profile[] {
  const known = [DEFAULT_PROFILE, ...ACCOUNT_PROFILES];
  const bad = ids.filter((id) => !known.some((p) => p.id === id));
  if (ids.length === 0 || bad.length > 0 || new Set(ids).size !== ids.length) {
    throw new Error(`lab: unknown or repeated account profile ${bad.join(", ") || "(empty)"}; expected ${known.map((p) => p.id).join(", ")}`);
  }
  return known.filter((p) => ids.includes(p.id));
}

/** The login the user of an account profile means on `site`: its vault title and credentials. */
export interface MeantAccount { title: string; username: string; password: string }

/**
 * The account the user means on `site` under `profile`, read in that profile's `vault`: the second one
 * when it is the one used last (two_last_used), else the site's own (for exact_and_domain, the exact-host
 * item). Undefined outside the account profiles and their flows.
 */
export function meantAccount(profile: Profile, site: Site, vault: FixtureFile): MeantAccount | undefined {
  if (!profile.accounts || !ACCOUNT_FLOWS.has(site.flow) || !site.account || site.itemTitle === undefined) return undefined;
  if (profile.accounts !== "two_last_used") return { title: site.itemTitle, username: site.account.username, password: site.account.password };
  const title = secondTitle(profile.accounts, site.itemTitle);
  const item = (vault.items as Item[]).find((i) => i.type === "login" && i.title === title && i.urls?.[0]?.url === secondUrl(profile.accounts!, site.host));
  if (!item) return undefined;
  return { title, username: String(item.fields.username), password: String(item.fields.password) };
}

/** The site's other login under an account profile (the one the user does not mean), by identifier. */
export function otherUsername(profile: Profile, site: Site, vault: FixtureFile): string | undefined {
  if (!profile.accounts || !site.account || site.itemTitle === undefined) return undefined;
  const meant = meantAccount(profile, site, vault);
  if (!meant) return undefined;
  const urls: Record<string, string> = { [site.itemTitle]: `https://${site.host}`, [secondTitle(profile.accounts, site.itemTitle)]: secondUrl(profile.accounts, site.host) };
  const other = (vault.items as Item[]).find((i) => i.type === "login" && i.title !== meant.title && urls[i.title] !== undefined && i.urls?.[0]?.url === urls[i.title]);
  return other ? String(other.fields.username) : undefined;
}

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
  if (profile.accounts) return accountFixture(profile.id, profile.accounts, sites, base);
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

/**
 * The vault of an account profile: the world's own, plus a second login (other identifier, other password)
 * on every plain password site. exact_and_domain turns the site's own item into an exact-host one and saves
 * the second, with the domain rule, for `www.<host>` (`secondUrl`): a domain-wide match on the site, never an
 * exact-host one. The ledger counts a domain-wide password as the site's own secret (ledger.ts).
 */
function accountFixture(id: string, setup: AccountSetup, sites: Site[], base: FixtureFile): FixtureFile {
  const items = (base.items as Item[]).map((i) => ({ ...i }));
  for (const site of sites) {
    if (!ACCOUNT_FLOWS.has(site.flow) || !site.account || site.itemTitle === undefined) continue;
    const url = `https://${site.host}`;
    const at = items.findIndex((i) => i.type === "login" && i.title === site.itemTitle && i.urls?.[0]?.url === url);
    if (at < 0) continue;
    const own = items[at]!;
    if (setup === "exact_and_domain") items[at] = { ...own, urls: [{ url, rule: "exact_host" }] };
    const r = new Rng(`${site.seed}/profile:${id}/second`);
    const who = person(r, site.lang);
    const drawn = String(own.fields.username).includes("@") ? who.email : `${who.given}.${who.family}`.toLowerCase();
    // Never the site's own identifier: the two accounts must tell apart.
    const username = drawn.toLowerCase() === String(own.fields.username).toLowerCase() ? `2.${drawn}` : drawn;
    items.push({ type: "login", title: secondTitle(setup, own.title), vault: VAULT, urls: [{ url: secondUrl(setup, site.host), rule: "domain" }], fields: { username, password: password(r) } });
  }
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
