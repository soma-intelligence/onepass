// Seeded world generator of the autofill lab: expands a seed into fictional
// .test sites (flow, traits, fields, and since version 2 multi-step forms,
// layouts and simulated frameworks drawn from the corpus), mock identity provider accounts, the
// vault fixture loaded by the real native host, and the scenarios with their
// expected outcome. Each site draws from its own forked Rng so adding a trait
// to one site does not shift the others.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Patterns } from "../corpus/types.ts";
import { expectationFor } from "./capabilities.ts";
import { countryCases } from "./cases.ts";
import { buildForms, FORMS_FLOWS, isFormsFlow, type CoreLabeler } from "./forms-flows.ts";
import { address, brandOf, card, formatCardNumber, hostName, lookalikeHost, passkey, passkeyPkcs8, password, person, totpSecret, userHandle } from "./data.ts";
import { GENERATOR_VERSION, START_STATES } from "./model.ts";
import { LAYOUTS } from "./layouts.ts";
import { drawPolicy, POLICY_RATE } from "./policy.ts";
import { ACCOUNT_FLOWS, ACCOUNT_OUTCOME, accountProfiles, DEFAULT_PROFILE_ID, drawProfiles, fixtureFor, meantAccount, type Profile } from "./population.ts";
import type {
  Account, DriverGroup, DriverId, FieldSpec, FixtureFile, FlowId, FrameworkId, GhostVariant, HoneypotStyle, IdpAccount, LabRole, Lang, LayoutId, LoginStyle, LookalikeKind, ProviderId, Role, SaveVariant, Scenario, Site, StartState, TraitId, World,
} from "./model.ts";
import { Rng } from "./rng.ts";
import { pickSteps } from "./steps.ts";

/** Reads the committed distilled corpus next to this module (works under vitest and plain node). */
export function loadPatterns(): Patterns {
  const here = dirname(fileURLToPath(import.meta.url));
  return JSON.parse(readFileSync(join(here, "..", "corpus", "patterns.json"), "utf8")) as Patterns;
}

/** The flows of the first sites, one each, in order (the four forms flows since version 4). */
export const FLOWS: FlowId[] = ["login_single", "login_username_first", "login_email_then_password", "login_totp", "login_passkey",
  "sso", "signup", "checkout_card", "address", "identity", "multi_step", ...FORMS_FLOWS];
// After the first sites: login 45 % (split over the five login flows), sso 15 %, the rest 10 % each,
// multi_step 10 more (relative weights: the shares above shrink by a tenth). Since version 4 a site's own
// "forms-flow" stream replaces this draw by one of the forms flows with probability FORMS_FLOW_RATE.
export const FLOW_WEIGHTS: [FlowId, number][] = [["login_single", 9], ["login_username_first", 9], ["login_email_then_password", 9],
  ["login_totp", 9], ["login_passkey", 9], ["sso", 15], ["signup", 10], ["checkout_card", 10], ["address", 10], ["identity", 10],
  ["multi_step", 10]];
export const FORMS_FLOW_RATE = 0.25;
const PASSWORD_LOGIN: FlowId[] = ["login_single", "login_username_first", "login_email_then_password", "login_totp"];
const ONE_CLICK: FlowId[] = [...PASSWORD_LOGIN, "login_passkey", "sso"];

const TRAITS: TraitId[] = ["iframe_same_origin", "iframe_cross_site", "shadow_open", "shadow_closed", "spa_rerender",
  "delayed_fields", "no_autocomplete", "obfuscated_names", "split_otp", "honeypot", "decoy_form", "lookalike", "mixed_language"];
/** Baseline trait weights (percent): distill.ts nudges them with the corpus into patterns.json `traits`. */
export const TRAIT_WEIGHTS: Record<TraitId, number> = {
  iframe_same_origin: 6, iframe_cross_site: 6, shadow_open: 4, shadow_closed: 3, spa_rerender: 6, delayed_fields: 8,
  no_autocomplete: 8, obfuscated_names: 8, split_otp: 0, honeypot: 8, decoy_form: 6, lookalike: 8, mixed_language: 6,
};
const TRAIT_COUNT: [number, number][] = [[0, 30], [1, 35], [2, 25], [3, 10]];
const HONEYPOT_STYLES: HoneypotStyle[] = ["display_none", "offscreen", "opacity", "one_pixel", "aria_hidden"];
const LOOKALIKE_KINDS: LookalikeKind[] = ["suffix", "typo", "hyphen", "idn"];
// "stacked" is the version 1 look; the other layouts share the rest.
const LAYOUT_WEIGHTS: [LayoutId, number][] = LAYOUTS.map((l) => [l, l === "stacked" ? 40 : 10]);
const FRAMEWORKS: FrameworkId[] = ["static", "react", "vue", "angular"];

const PROVIDERS: ProviderId[] = ["google", "apple", "microsoft"];
const PROVIDER_NAME: Record<ProviderId, string> = { google: "Google", apple: "Apple", microsoft: "Microsoft" };
const PROVIDER_HOST: Record<ProviderId, string> = {
  google: "accounts.google.com", apple: "appleid.apple.com", microsoft: "login.microsoftonline.com",
};
const SSO_LABEL: Record<string, (p: string) => string> = {
  en: (p) => `Continue with ${p}`, fr: (p) => `Continuer avec ${p}`, de: (p) => `Weiter mit ${p}`, es: (p) => `Continuar con ${p}`,
  it: (p) => `Continua con ${p}`, pt: (p) => `Continuar com ${p}`, nl: (p) => `Doorgaan met ${p}`,
};
/** The languages sharing the 0.2 left by French and English (spec 4.2, plan Task 8), in equal parts. */
export const OTHER_LANGS: readonly Lang[] = ["de", "es", "it", "pt", "nl"];

const AUTOCOMPLETE: Record<Role, string> = {
  username: "username", email: "email", password: "current-password", new_password: "new-password", otp: "one-time-code",
  cc_name: "cc-name", cc_number: "cc-number", cc_exp: "cc-exp", cc_exp_month: "cc-exp-month", cc_exp_year: "cc-exp-year",
  cc_csc: "cc-csc", given_name: "given-name", family_name: "family-name", tel: "tel", birth_date: "bday",
  organization: "organization", address_line1: "address-line1", address_line2: "address-line2", postal_code: "postal-code",
  city: "address-level2", country: "country",
};
const INPUT_TYPE: Partial<Record<Role, string>> = {
  email: "email", password: "password", new_password: "password", tel: "tel", birth_date: "date",
  cc_exp_month: "select", cc_exp_year: "select",
};
const SAFE_TOKEN = /^[a-z][a-z0-9_-]{1,30}$/i;
const VAULT = "Lab";
const MAX_LABEL = 40;

/**
 * `profiles`: simulated users (default 1: the historical single user, no profile keys in the world).
 * `accounts`: account profile ids ("p0" to "p3", population.ts) played instead; never with `profiles` above 1.
 */
export interface GenerateOptions { sites: number; patterns: Patterns; profiles?: number; accounts?: readonly string[] }

export function generate(seed: string, opts: GenerateOptions): World {
  const root = new Rng(seed);
  const { patterns } = opts;
  const langs = selectableLangs();
  const used = new Set<string>();
  const brands = new Set<string>();
  // Full names of the passport and license holders: unique, so a document matches one identity only.
  const holders = new Set<string>();
  const idp = makeIdp(root.fork("idp"));
  const sites: Site[] = [];
  const items: unknown[] = [];
  for (const p of PROVIDERS) {
    for (const a of idp[p]) {
      items.push(login(a.itemTitle, `https://${PROVIDER_HOST[p]}`, "exact_host", { username: a.email, password: a.password }));
    }
  }
  for (let i = 0; i < opts.sites; i++) {
    const r = root.fork(`site:${i}`);
    const host = hostName(r.fork("host"), used);
    let brand = brandOf(host);
    if (brands.has(brand)) brand = `${brand} ${i}`;
    brands.add(brand);
    const built = buildSite(r, { index: i, seed: `${seed}/site:${i}`, host, brand }, patterns, langs, used, idp, holders);
    sites.push(built.site);
    items.push(...built.items);
  }
  const base: Scenario[] = [];
  for (const s of sites) {
    const drivers: DriverId[] = [ONE_CLICK.includes(s.flow) ? "one_click" : "menu_fill"];
    if (s.lookalike) drivers.push("lookalike");
    // The control needs the passkey step on the site's own host: a cross-site
    // password widget leads to none (its frame host cannot ask for the site's key).
    const crossSiteWidget = !s.passkeyOnly && s.traits.includes("iframe_cross_site");
    if (s.flow === "login_passkey" && !crossSiteWidget) drivers.push("passkey_control");
    for (const driver of drivers) base.push({ id: `${s.index}:${driver}`, site: s.index, driver, ...expectationFor(s, driver) });
  }
  const nProfiles = opts.profiles ?? 1;
  if (!Number.isInteger(nProfiles) || nProfiles < 1) throw new Error(`generate: profiles must be a positive integer (${opts.profiles})`);
  const byAccount = opts.accounts !== undefined && opts.accounts.length > 0 ? accountProfiles(opts.accounts) : undefined;
  if (byAccount && nProfiles > 1) throw new Error("generate: account profiles and drawn profiles do not mix (same ids)");
  const profiles = byAccount ?? (nProfiles > 1 ? drawProfiles(seed, nProfiles) : undefined);
  const scenarios = profiles ? profiles.flatMap((p) => (p.accounts ? [] : scenariosOf(p, sites, base))) : base;
  const fixture: FixtureFile = {
    _comment: `Fictional data generated by the OnePass autofill lab (seed ${seed}, generator v${GENERATOR_VERSION}). No real account, card or person.`,
    account: "lab@onepass.test",
    vaults: [{ name: VAULT, color: "#5856D6" }],
    items,
  };
  // The country and region fixture cases: the same in every world, outside the seeded draw.
  const cases = countryCases();
  items.push(...cases.items);
  const hosts = new Set<string>(PROVIDERS.map((p) => PROVIDER_HOST[p]));
  for (const s of sites) for (const h of [s.host, s.lookalike?.host, s.frameHost]) if (h) hosts.add(h);
  for (const h of cases.hosts) hosts.add(h);
  // Account profiles: one sign-in scenario per plain password site, once the vault is whole.
  for (const p of profiles ?? []) if (p.accounts) scenarios.push(...accountScenarios(p, sites, fixture, "one_click"));
  return {
    version: GENERATOR_VERSION, seed, sites, scenarios, idp, fixture, hosts: [...hosts].sort(), cases: cases.cases,
    ...(profiles ? { profiles } : {}),
  };
}

/**
 * The default scenarios as one profile plays them: tagged with the profile (ids of the default profile stay "<site>:<driver>"),
 * expectations of an empty vault, and the profile's behaviour on menu_fill
 * (abandons_step only where a form has steps to abandon).
 */
function scenariosOf(p: Profile, sites: Site[], base: Scenario[]): Scenario[] {
  return base.map((s) => {
    const site = sites[s.site]!;
    const out: Scenario = { ...s, id: p.id === DEFAULT_PROFILE_ID ? s.id : `${p.id}:${s.id}`, profile: p.id, ...expectationFor(site, s.driver, p) };
    if (s.driver === "menu_fill" && p.behaviour !== "complete" && (p.behaviour !== "abandons_step" || site.flow === "multi_step")) {
      out.behaviour = p.behaviour;
    }
    return out;
  });
}

/**
 * The scenarios of an account profile for `driver`: every plain password site, with the account the user
 * means (title and identifier, never a password) and the outcome the profile states.
 */
function accountScenarios(p: Profile, sites: Site[], base: FixtureFile, driver: DriverId): Scenario[] {
  if (!p.accounts) return [];
  const vault = fixtureFor(p, sites, base);
  const out: Scenario[] = [];
  for (const s of sites) {
    if (!ACCOUNT_FLOWS.has(s.flow)) continue;
    const meant = meantAccount(p, s, vault);
    if (!meant) continue;
    out.push({
      id: `${p.id}:${s.index}:${driver}`, site: s.index, driver, profile: p.id, ...expectationFor(s, driver, p),
      account: {
        title: meant.title, username: meant.username, outcome: ACCOUNT_OUTCOME[p.accounts],
        ...(p.accounts === "two_last_used" ? { lastUsed: true } : {}),
      },
    });
  }
  return out;
}

export const DRIVER_GROUPS: readonly DriverGroup[] = ["current", "smart_fill", "save_ghost"];

/** The driver set a scenario belongs to: smart_fill alone, ghost and save_typed together, every other driver is "current". */
export const groupOf = (d: DriverId): DriverGroup => (d === "smart_fill" ? "smart_fill" : d === "ghost" || d === "save_typed" ? "save_ghost" : "current");

export const SAVE_VARIANTS: readonly SaveVariant[] = ["new_auto", "second_account", "update_card", "no_username", "spa_stays", "failed_login", "private_window"];
export const GHOST_VARIANTS: readonly GhostVariant[] = ["accept_tab", "accept_click", "ignore_typing", "menu_arrow", "fallback_narrow", "fallback_transform"];
/** Sites each variant is played on (spread over the eligible sites, stable for a seed). */
const SAVE_GHOST_PER_VARIANT = 2;
const SAVE_FLOWS = new Set<FlowId>(["login_single", "login_username_first", "login_email_then_password"]);

/**
 * The save and ghost scenarios (spec 7.2): every save variant on plain password login sites (the typed sign-in
 * the save follows), every ghost variant on signup sites (where a new password is asked). Not part of the
 * historical world: added by withDrivers for the "save_ghost" set, so a seed's base digest never moves. All
 * expect "pass": the menu fallbacks count as a pass when the menu opened (oracle.ts).
 */
export function saveGhostScenarios(sites: readonly Site[], perVariant: number = SAVE_GHOST_PER_VARIANT): Scenario[] {
  const plain = (s: Site): boolean => !s.traits.some((t) => t === "iframe_cross_site" || t === "iframe_same_origin" || t === "shadow_closed");
  const saveSites = sites.filter((s) => SAVE_FLOWS.has(s.flow) && s.account !== undefined && plain(s));
  const ghostSites = sites.filter((s) => s.flow === "signup" && plain(s));
  const pick = (pool: readonly Site[], k: number, prefer?: (s: Site) => boolean): Site[] => {
    if (pool.length === 0) return [];
    const ordered = prefer ? [...pool.filter(prefer), ...pool.filter((s) => !prefer(s))] : pool;
    const out = new Set<Site>();
    for (let j = 0; j < perVariant && out.size < ordered.length; j++) {
      let i = (prefer && j === 0 ? 0 : k * perVariant + j) % ordered.length;
      while (out.has(ordered[i]!)) i = (i + 1) % ordered.length;
      out.add(ordered[i]!);
    }
    return [...out];
  };
  const out: Scenario[] = [];
  SAVE_VARIANTS.forEach((v, k) => {
    const prefer = v === "spa_stays" ? (s: Site) => s.traits.includes("spa_rerender") : undefined;
    for (const s of pick(saveSites, k, prefer)) out.push({ id: `save:${v}:${s.index}`, site: s.index, driver: "save_typed", variant: v, expect: "pass" });
  });
  GHOST_VARIANTS.forEach((v, k) => {
    for (const s of pick(ghostSites, k)) out.push({ id: `ghost:${v}:${s.index}`, site: s.index, driver: "ghost", variant: v, expect: "pass" });
  });
  return out;
}

/**
 * The world with the scenarios of `groups` only: "current" keeps the
 * generated ones, "smart_fill" adds one smart_fill scenario per site (same
 * capability table). Sites, fixture and hosts are untouched, so one seed
 * gives the same world to every driver set.
 */
export function withDrivers(world: World, groups: readonly DriverGroup[]): World {
  const scenarios: Scenario[] = groups.includes("current") ? [...world.scenarios] : [];
  if (groups.includes("smart_fill")) {
    // The default profile plays every site (as before); an account profile its plain password sites.
    if (!world.profiles || world.profiles.some((p) => p.id === DEFAULT_PROFILE_ID)) {
      for (const s of world.sites) {
        scenarios.push({ id: `${s.index}:smart_fill`, site: s.index, driver: "smart_fill", ...expectationFor(s, "smart_fill") });
      }
    }
    for (const p of world.profiles ?? []) scenarios.push(...accountScenarios(p, world.sites, world.fixture, "smart_fill"));
  }
  if (groups.includes("save_ghost")) scenarios.push(...saveGhostScenarios(world.sites));
  return { ...world, scenarios };
}

/** How smart_fill is started: the field's icon (toolbar Fill on a page without one), or the fill-smart command. */
export type SmartTrigger = "icon" | "shortcut";
export const SMART_TRIGGERS: readonly SmartTrigger[] = ["icon", "shortcut"];

/** Drivers whose scenarios have a gesture that can meet a locked vault or a stopped host. */
const STARTABLE = new Set<DriverId>(["one_click", "menu_fill", "smart_fill", "ghost", "save_typed"]);

/**
 * The world with its scenarios played from each of `starts` and, for smart_fill, started by each of
 * `triggers`. The defaults (unlocked_warm, icon) change nothing. A shortcut variant is "<id>/shortcut";
 * a start state other than unlocked_warm is "<id>@<start>" and only for the scenarios with a goal
 * (a locked vault or a stopped host fills nothing: "nofill" would pass for the wrong reason).
 */
export function withStarts(world: World, starts: readonly StartState[] = ["unlocked_warm"], triggers: readonly SmartTrigger[] = ["icon"]): World {
  const scenarios: Scenario[] = [];
  for (const s of world.scenarios) {
    const byTrigger: Scenario[] = s.driver !== "smart_fill" ? [s] : [
      ...(triggers.includes("icon") ? [s] : []),
      ...(triggers.includes("shortcut") ? [{ ...s, id: `${s.id}/shortcut`, shortcut: true }] : []),
    ];
    for (const t of byTrigger) {
      for (const start of START_STATES) {
        if (!starts.includes(start)) continue;
        if (start === "unlocked_warm") scenarios.push(t);
        else if (STARTABLE.has(t.driver) && t.expect !== "nofill") scenarios.push({ ...t, id: `${t.id}@${start}`, start });
      }
    }
  }
  return { ...world, scenarios };
}

/** Parses a comma list against `known` ("locked,cold"), keeping the order of `known`. */
function parseList<T extends string>(raw: string, known: readonly T[], what: string): T[] {
  const asked = raw.split(",").map((x) => x.trim()).filter((x) => x !== "");
  const bad = asked.filter((x) => !(known as readonly string[]).includes(x));
  if (asked.length === 0 || bad.length > 0) throw new Error(`lab: unknown ${what} ${bad.join(", ") || "(empty)"}; expected ${known.join(", ")}`);
  return known.filter((k) => asked.includes(k));
}

export const parseStarts = (raw: string): StartState[] => parseList(raw, START_STATES, "start state");
export const parseTriggers = (raw: string): SmartTrigger[] => parseList(raw, SMART_TRIGGERS, "trigger");

/** Parses a comma list of driver sets ("current,smart_fill"). */
export function parseDriverGroups(raw: string): DriverGroup[] {
  const groups = raw.split(",").map((x) => x.trim()).filter((x) => x !== "");
  const bad = groups.filter((g) => !(DRIVER_GROUPS as readonly string[]).includes(g));
  if (groups.length === 0 || bad.length > 0) throw new Error(`lab: unknown driver set ${bad.join(", ") || "(empty)"}; expected ${DRIVER_GROUPS.join(", ")}`);
  return DRIVER_GROUPS.filter((g) => groups.includes(g));
}

/**
 * Site languages (spec 4.2, fr and en in the majority): fr 0.4, en 0.4, and
 * 0.2 shared in equal parts by de, es, it, pt and nl, the languages the
 * extension's lexicon and the baseline lexicon (seed-lexicon.json) cover.
 * Since generator version 3; before, the 0.2 followed the corpus languages
 * (zh, ru, pl... without labels of their own, so English labels).
 */
function selectableLangs(): [Lang, number][] {
  return [["fr", 0.4], ["en", 0.4], ...OTHER_LANGS.map((l) => [l, 0.2 / OTHER_LANGS.length] as [Lang, number])];
}

function makeIdp(rng: Rng): Record<ProviderId, IdpAccount[]> {
  const emails = new Set<string>();
  const titles = new Set<string>();
  const out = {} as Record<ProviderId, IdpAccount[]>;
  for (const p of PROVIDERS) {
    const r = rng.fork(p);
    const n = r.int(2, 3);
    out[p] = [];
    for (let k = 0; k < n; k++) {
      const who = person(r);
      let email = who.email;
      if (emails.has(email)) email = email.replace("@", `.${p}${k}@`);
      emails.add(email);
      let itemTitle = `${PROVIDER_NAME[p]} ${who.given} ${who.family}`;
      if (titles.has(itemTitle)) itemTitle = `${itemTitle} ${k + 1}`;
      titles.add(itemTitle);
      out[p].push({ email, password: password(r), name: `${who.given} ${who.family}`, itemTitle });
    }
  }
  return out;
}

function login(title: string, url: string, rule: string, fields: Record<string, string>, extra: Record<string, unknown> = {}): unknown {
  return { type: "login", title, vault: VAULT, urls: [{ url, rule }], fields, ...extra };
}

function rolesFor(flow: FlowId, style: LoginStyle | undefined, passkeyOnly: boolean, splitExp: boolean, steps: Role[][]): Role[] {
  const pw = (s: LoginStyle | undefined): Role[] => [s === "email_then_password" ? "email" : "username", "password"];
  switch (flow) {
    case "login_single": return pw("single");
    case "login_username_first": return pw("username_first");
    case "login_email_then_password": return pw("email_then_password");
    case "login_totp": return [...pw(style), "otp"];
    case "login_passkey": return passkeyOnly ? [] : pw(style);
    case "sso": return [];
    case "signup": return ["email", "new_password", "new_password"];
    case "checkout_card": return ["cc_name", "cc_number", ...(splitExp ? ["cc_exp_month", "cc_exp_year"] as Role[] : ["cc_exp"] as Role[]), "cc_csc"];
    case "address": return ["given_name", "family_name", "address_line1", "address_line2", "postal_code", "city", "country"];
    case "identity": return ["given_name", "family_name", "email", "tel", "birth_date", "organization"];
    case "multi_step": return steps.flat();
    case "travel_booking": case "company_b2b": case "car_rental": case "admin_identity":
      throw new Error(`generate: ${flow} is drawn from generator version 4`);
  }
}

function traitAllowed(t: TraitId, flow: FlowId, roles: LabRole[], langCount: number): boolean {
  switch (t) {
    case "split_otp": return false; // drawn in the site shape (login_totp), never from the pool
    case "lookalike": case "decoy_form": return PASSWORD_LOGIN.includes(flow);
    case "mixed_language": return langCount > 1;
    // Multi-step pages are served on the site's own host only (no frame route for the later steps).
    case "iframe_same_origin": case "iframe_cross_site": return flow !== "multi_step" && roles.length > 0;
    // Every other trait alters form fields: none on sso or passkey-only sites.
    default: return roles.length > 0;
  }
}

const isStructural = (t: TraitId) => t.startsWith("iframe_") || t.startsWith("shadow_");

/** Weight of a trait: the corpus-nudged one of patterns.json (version 2), else the baseline. */
function traitWeight(patterns: Patterns, t: TraitId): number {
  if (t === "split_otp") return 0; // drawn in the site shape (login_totp), never from the pool
  const w = patterns.traits?.[t];
  return w !== undefined ? w * 100 : TRAIT_WEIGHTS[t];
}

function pickTraits(r: Rng, patterns: Patterns, flow: FlowId, roles: LabRole[], langCount: number, splitOtp: boolean): TraitId[] {
  const chosen = new Set<TraitId>(splitOtp ? ["split_otp"] : []);
  const count = Math.min(r.weighted(TRAIT_COUNT), 3 - chosen.size);
  for (let k = 0; k < count; k++) {
    const hasStructural = [...chosen].some(isStructural);
    const pool = TRAITS.filter((t) => !chosen.has(t) && traitAllowed(t, flow, roles, langCount) && !(hasStructural && isStructural(t)));
    if (pool.length === 0) break;
    chosen.add(r.weighted(pool.map((t) => [t, traitWeight(patterns, t)] as const)));
  }
  return TRAITS.filter((t) => chosen.has(t));
}

function randomToken(r: Rng): string {
  const abc = "abcdefghijklmnopqrstuvwxyz";
  return r.pick([...abc]) + Array.from({ length: 7 }, () => r.pick([...`${abc}0123456789`])).join("");
}

function unique(base: string, taken: Set<string>): string {
  let name = base;
  for (let k = 2; taken.has(name); k++) name = `${base}_${k}`;
  taken.add(name);
  return name;
}

function labelsFor(patterns: Patterns, role: Role, lang: Lang): string[] {
  const labels = patterns.roles[role]?.labels ?? {};
  const own = labels[lang] ?? [];
  const xs = own.length > 0 ? own : labels.en ?? [];
  // Some corpus labels swallowed a <select>'s option list: prefer the short ones.
  const short = xs.filter((l) => l.length <= MAX_LABEL);
  return short.length > 0 ? short : xs;
}

function buttonLabel(r: Rng, patterns: Patterns, kind: keyof Patterns["buttons"], lang: Lang, fallback: string): string {
  const byLang = patterns.buttons[kind] ?? {};
  const xs = byLang[lang]?.length ? byLang[lang]! : byLang.en ?? [];
  return xs.length > 0 ? r.pick(xs) : fallback;
}

function buildFields(r: Rng, roles: Role[], patterns: Patterns, labelLang: Lang, traits: TraitId[]): FieldSpec[] {
  const obfuscated = traits.includes("obfuscated_names");
  const noAuto = traits.includes("no_autocomplete");
  const names = new Set<string>();
  const ids = new Set<string>();
  return roles.map((role) => {
    const spec = patterns.roles[role];
    const labels = labelsFor(patterns, role, labelLang);
    const label = labels.length > 0 ? r.pick(labels) : role;
    const tokens = (spec?.tokens ?? []).filter((t) => SAFE_TOKEN.test(t));
    const name = unique(obfuscated ? randomToken(r) : r.pick(tokens.length > 0 ? tokens : [role]), names);
    const id = unique(obfuscated ? randomToken(r) : name, ids);
    const field: FieldSpec = { role, name, id, label, type: INPUT_TYPE[role] ?? "text" };
    if (!noAuto && r.chance(spec?.autocompleteRate ?? 0.5)) field.autocomplete = AUTOCOMPLETE[role];
    return field;
  });
}

/** Framework weights of the corpus ("static" when the corpus has none of the simulated ones). */
function frameworkWeights(patterns: Patterns): [FrameworkId, number][] {
  const known = (patterns.frameworks ?? []).filter(([f, w]) => FRAMEWORKS.includes(f as FrameworkId) && w > 0) as [FrameworkId, number][];
  return known.length > 0 ? known : [["static", 1]];
}

interface SiteBase { index: number; seed: string; host: string; brand: string }

/** The flow of site `index` drawn from its Rng `r`: the forced first ones, else the forms stream, else the version 3 draw. */
export function flowOf(r: Rng, index: number): FlowId {
  if (index < FLOWS.length) return FLOWS[index]!;
  const rf = r.fork("forms-flow");
  return rf.chance(FORMS_FLOW_RATE) ? rf.pick(FORMS_FLOWS) : r.fork("flow").weighted(FLOW_WEIGHTS);
}

/** Labels, names and autocomplete rates of the corpus for a version 3 role in `labelLang`. */
function coreLabeler(patterns: Patterns, labelLang: Lang): CoreLabeler {
  return (r, role) => {
    const labels = labelsFor(patterns, role, labelLang);
    const tokens = (patterns.roles[role]?.tokens ?? []).filter((t) => SAFE_TOKEN.test(t));
    return {
      label: labels.length > 0 ? r.pick(labels) : role, token: r.pick(tokens.length > 0 ? tokens : [role]),
      autocompleteRate: patterns.roles[role]?.autocompleteRate ?? 0.5,
    };
  };
}

function buildSite(r: Rng, base: SiteBase, patterns: Patterns, langs: [Lang, number][], used: Set<string>,
  idp: Record<ProviderId, IdpAccount[]>, holders: Set<string>): { site: Site; items: unknown[] } {
  const flow = flowOf(r, base.index);
  const formsFlow = isFormsFlow(flow);
  const lang = r.fork("lang").weighted(langs);
  const rs = r.fork("shape");
  const loginStyle: LoginStyle | undefined = flow === "login_totp" || flow === "login_passkey"
    ? rs.pick<LoginStyle>(["single", "username_first", "email_then_password"]) : undefined;
  const passkeyOnly = flow === "login_passkey" ? rs.chance(0.5) : false;
  const splitExp = flow === "checkout_card" && rs.chance(0.4);
  const splitOtp = flow === "login_totp" && rs.chance(0.35);
  // Half the sso sites also show an identifier + password form next to the provider button (own fork: nothing shifts).
  const ssoForm = flow === "sso" && r.fork("sso-form").chance(0.5);
  const stepRoles = flow === "multi_step" ? pickSteps(r.fork("steps"), patterns, lang) : [];
  const coreRoles = formsFlow ? [] : ssoForm ? rolesFor("login_single", undefined, false, false, []) : rolesFor(flow, loginStyle, passkeyOnly, splitExp, stepRoles);
  // Field traits stay off sso sites, form or not: the provider button is what they test. A forms page always has fields.
  const traits = pickTraits(r.fork("traits"), patterns, flow, flow === "sso" ? [] : formsFlow ? ["given_name"] : coreRoles, langs.length, splitOtp);
  const labelLang = traits.includes("mixed_language")
    ? r.fork("label-lang").weighted(langs.filter(([l]) => l !== lang)) : lang;
  const formsBuild = formsFlow
    ? buildForms(r, flow, { host: base.host, brand: base.brand, lang, labelLang, traits }, coreLabeler(patterns, labelLang), holders)
    : undefined;
  const fields = formsBuild?.fields ?? buildFields(r.fork("fields"), coreRoles, patterns, labelLang, traits);
  const roles: LabRole[] = fields.map((f) => f.role);

  const rb = r.fork("buttons");
  const site: Site = { ...base, lang, labelLang, flow, traits, fields, buttons: { submit: "" } };
  if (flow === "multi_step") {
    let k = 0;
    site.steps = stepRoles.map((step) => fields.slice(k, (k += step.length)));
  }
  site.layout = r.fork("layout").weighted(LAYOUT_WEIGHTS);
  site.framework = r.fork("framework").weighted(frameworkWeights(patterns));
  if (loginStyle) site.loginStyle = loginStyle;
  const nextStep = flow === "login_username_first" || flow === "login_email_then_password" || flow === "multi_step"
    || (loginStyle !== undefined && loginStyle !== "single" && !passkeyOnly);
  switch (flow) {
    case "signup": site.buttons.submit = buttonLabel(rb, patterns, "signup", labelLang, "Sign up"); break;
    case "checkout_card": site.buttons.submit = buttonLabel(rb, patterns, "pay", labelLang, "Pay"); break;
    case "address": case "identity": case "travel_booking": case "company_b2b": case "car_rental": case "admin_identity":
      site.buttons.submit = buttonLabel(rb, patterns, "save", labelLang, "Save");
      break;
    default:
      site.buttons.submit = buttonLabel(rb, patterns, "signin", labelLang, "Sign in");
      if (nextStep) site.buttons.next = buttonLabel(rb, patterns, "next", labelLang, "Next");
      if (flow === "login_passkey") site.buttons.passkey = buttonLabel(rb, patterns, "passkey", labelLang, "Sign in with a passkey");
  }

  const ra = r.fork("account");
  const who = person(ra, lang);
  const url = `https://${base.host}`;
  let item: unknown;
  if (formsBuild) {
    site.identityTitle = formsBuild.identityTitle;
    site.forms = formsBuild.forms;
  } else if (PASSWORD_LOGIN.includes(flow) || flow === "login_passkey" || flow === "multi_step") {
    const usesEmail = roles.includes("email");
    const account: Account = { username: usesEmail ? who.email : who.email.split("@")[0]!, password: password(ra) };
    const extra: Record<string, unknown> = {};
    if (flow === "login_totp" || roles.includes("otp")) {
      account.totpSecret = totpSecret(ra);
      const enc = encodeURIComponent;
      extra.totp_uri = `otpauth://totp/${enc(base.brand)}:${enc(account.username)}?secret=${account.totpSecret}&issuer=${enc(base.brand)}`;
    }
    if (flow === "login_passkey") {
      account.passkey = passkey(ra);
      site.passkeyOnly = passkeyOnly;
    }
    if (account.passkey) {
      // The site's passkey in the vault, as the native host fixture reads it (fixture.rs PasskeyDef).
      extra.passkeys = [{
        rp_id: base.host, user_name: account.username, user_handle: userHandle(base.host, account.username),
        credential_id: account.passkey.credentialId, private_key: passkeyPkcs8(account.passkey).toString("base64url"),
      }];
    }
    site.account = account;
    site.itemTitle = base.brand;
    item = login(base.brand, url, "domain", { username: account.username, password: account.password }, extra);
  } else if (flow === "sso") {
    const provider = ra.weighted(PROVIDERS.map((p) => [p, Math.max(patterns.structure?.sso?.[p] ?? 0, 0.1)] as const));
    const acct = ra.pick(idp[provider]);
    site.sso = { provider, email: acct.email };
    site.buttons.sso = (SSO_LABEL[labelLang] ?? SSO_LABEL.en!)(PROVIDER_NAME[provider]);
    site.itemTitle = `${base.brand} via ${PROVIDER_NAME[provider]}`;
    item = login(base.brand, url, "domain", { username: acct.email }, { login_methods: [{ provider, account_title: acct.itemTitle }] });
  } else if (flow === "signup") {
    site.account = { username: who.email, password: "" };
    // Own streams: drawing a policy shifts nothing else of the site.
    const rp = r.fork("policy");
    if (rp.chance(POLICY_RATE)) site.passwordPolicy = drawPolicy(rp.fork("draw"), lang);
  } else if (flow === "checkout_card") {
    const c = card(ra);
    site.cardTitle = `Carte ${base.brand}`;
    item = {
      type: "credit_card", title: site.cardTitle, vault: VAULT,
      fields: {
        cardholder: `${who.given} ${who.family}`, number: formatCardNumber(c.number),
        expiry: `${String(c.expMonth).padStart(2, "0")}/${c.expYear}`, cvv: c.cvc,
      },
    };
  } else {
    const a = address(ra, lang);
    site.identityTitle = `${who.given} ${who.family} (${base.brand})`;
    item = {
      type: "identity", title: site.identityTitle, vault: VAULT,
      fields: {
        first_name: who.given, last_name: who.family, email: who.email, mobile_phone: who.phone, birth_date: who.birthDate,
        company: who.company,
        address: { line1: a.line1, line2: a.line2, city: a.city, postal_code: a.postalCode, region: a.region, country: a.country },
      },
    };
  }

  const rx = r.fork("extras");
  if (traits.includes("split_otp")) site.totpCells = true;
  if (traits.includes("delayed_fields")) site.delayMs = rx.int(500, 6000);
  if (traits.includes("honeypot")) {
    const bait = roles.filter((x) => x === "email" || x === "password" || x === "username");
    // Forms flows: half the honeypots imitate the document number (spec 11.1).
    const document = roles.find((x) => x === "passport_number" || x === "license_number");
    const role = formsFlow && document && rx.chance(0.5) ? document : rx.pick(bait.length > 0 ? bait : roles);
    const taken = new Set(fields.map((f) => f.name));
    const tokens = (patterns.roles[role as Role]?.tokens ?? []).filter((t) => SAFE_TOKEN.test(t));
    const name = unique(traits.includes("obfuscated_names") ? randomToken(rx) : rx.pick(tokens.length > 0 ? tokens : [role]), taken);
    site.honeypot = { role, name, style: rx.pick(HONEYPOT_STYLES) };
  }
  if (traits.includes("iframe_cross_site")) site.frameHost = hostName(r.fork("frame"), used);
  if (traits.includes("lookalike")) {
    const rl = r.fork("lookalike");
    for (const kind of rl.shuffle(LOOKALIKE_KINDS)) {
      const h = lookalikeHost(rl, base.host, kind);
      if (h === null || used.has(h)) continue;
      used.add(h);
      site.lookalike = { host: h, kind };
      break;
    }
    if (!site.lookalike) throw new Error(`generate: no free lookalike host for ${base.host}`);
  }
  return { site, items: formsBuild ? formsBuild.items : item !== undefined ? [item] : [] };
}
