// Seeded world generator of the autofill lab: expands a seed into fictional
// .test sites (flow, traits, fields), mock identity provider accounts, the
// vault fixture loaded by the real native host, and the scenarios with their
// expected outcome. Each site draws from its own forked Rng so adding a trait
// to one site does not shift the others.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Patterns } from "../corpus/types.ts";
import { expectationFor } from "./capabilities.ts";
import { address, brandOf, card, formatCardNumber, hostName, lookalikeHost, passkey, password, person, totpSecret } from "./data.ts";
import { GENERATOR_VERSION } from "./model.ts";
import type {
  Account, DriverId, FieldSpec, FixtureFile, FlowId, HoneypotStyle, IdpAccount, Lang, LoginStyle, LookalikeKind,
  ProviderId, Role, Scenario, Site, TraitId, World,
} from "./model.ts";
import { Rng } from "./rng.ts";

/** Reads the committed distilled corpus next to this module (works under vitest and plain node). */
export function loadPatterns(): Patterns {
  const here = dirname(fileURLToPath(import.meta.url));
  return JSON.parse(readFileSync(join(here, "..", "corpus", "patterns.json"), "utf8")) as Patterns;
}

const FLOWS: FlowId[] = ["login_single", "login_username_first", "login_email_then_password", "login_totp", "login_passkey",
  "sso", "signup", "checkout_card", "address", "identity"];
// After the first ten sites: login 45 % (split over the five login flows), sso 15 %, the rest 10 % each.
const FLOW_WEIGHTS: [FlowId, number][] = [["login_single", 9], ["login_username_first", 9], ["login_email_then_password", 9],
  ["login_totp", 9], ["login_passkey", 9], ["sso", 15], ["signup", 10], ["checkout_card", 10], ["address", 10], ["identity", 10]];
const PASSWORD_LOGIN: FlowId[] = ["login_single", "login_username_first", "login_email_then_password", "login_totp"];
const ONE_CLICK: FlowId[] = [...PASSWORD_LOGIN, "login_passkey", "sso"];

const TRAITS: TraitId[] = ["iframe_same_origin", "iframe_cross_site", "shadow_open", "shadow_closed", "spa_rerender",
  "delayed_fields", "no_autocomplete", "obfuscated_names", "split_otp", "honeypot", "decoy_form", "lookalike", "mixed_language"];
const TRAIT_WEIGHTS: Record<TraitId, number> = {
  iframe_same_origin: 6, iframe_cross_site: 6, shadow_open: 4, shadow_closed: 3, spa_rerender: 6, delayed_fields: 8,
  no_autocomplete: 8, obfuscated_names: 8, split_otp: 0, honeypot: 8, decoy_form: 6, lookalike: 8, mixed_language: 6,
};
const TRAIT_COUNT: [number, number][] = [[0, 30], [1, 35], [2, 25], [3, 10]];
const HONEYPOT_STYLES: HoneypotStyle[] = ["display_none", "offscreen", "opacity", "one_pixel", "aria_hidden"];
const LOOKALIKE_KINDS: LookalikeKind[] = ["suffix", "typo", "hyphen", "idn"];

const PROVIDERS: ProviderId[] = ["google", "apple", "microsoft"];
const PROVIDER_NAME: Record<ProviderId, string> = { google: "Google", apple: "Apple", microsoft: "Microsoft" };
const PROVIDER_HOST: Record<ProviderId, string> = {
  google: "accounts.google.com", apple: "appleid.apple.com", microsoft: "login.microsoftonline.com",
};
const SSO_LABEL: Record<string, (p: string) => string> = {
  en: (p) => `Continue with ${p}`, fr: (p) => `Continuer avec ${p}`, de: (p) => `Weiter mit ${p}`, es: (p) => `Continuar con ${p}`,
};

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

export interface GenerateOptions { sites: number; patterns: Patterns }

export function generate(seed: string, opts: GenerateOptions): World {
  const root = new Rng(seed);
  const { patterns } = opts;
  const langs = selectableLangs(patterns);
  const used = new Set<string>();
  const brands = new Set<string>();
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
    const built = buildSite(r, { index: i, seed: `${seed}/site:${i}`, host, brand }, patterns, langs, used, idp);
    sites.push(built.site);
    if (built.item) items.push(built.item);
  }
  const scenarios: Scenario[] = [];
  for (const s of sites) {
    const drivers: DriverId[] = [ONE_CLICK.includes(s.flow) ? "one_click" : "menu_fill"];
    if (s.lookalike) drivers.push("lookalike");
    // The control needs the passkey step on the site's own host: a cross-site
    // password widget leads to none (its frame host cannot ask for the site's key).
    const crossSiteWidget = !s.passkeyOnly && s.traits.includes("iframe_cross_site");
    if (s.flow === "login_passkey" && !crossSiteWidget) drivers.push("passkey_control");
    for (const driver of drivers) scenarios.push({ id: `${s.index}:${driver}`, site: s.index, driver, ...expectationFor(s, driver) });
  }
  const fixture: FixtureFile = {
    _comment: `Fictional data generated by the OnePass autofill lab (seed ${seed}, generator v${GENERATOR_VERSION}). No real account, card or person.`,
    account: "lab@onepass.test",
    vaults: [{ name: VAULT, color: "#5856D6" }],
    items,
  };
  const hosts = new Set<string>(PROVIDERS.map((p) => PROVIDER_HOST[p]));
  for (const s of sites) for (const h of [s.host, s.lookalike?.host, s.frameHost]) if (h) hosts.add(h);
  return { version: GENERATOR_VERSION, seed, sites, scenarios, idp, fixture, hosts: [...hosts].sort() };
}

/**
 * Site languages (spec 4.2, fr and en in the majority): fr 0.4, en 0.4, and
 * 0.2 shared by the other corpus languages in proportion to their corpus
 * weight ("und" is never a site language).
 */
function selectableLangs(patterns: Patterns): [Lang, number][] {
  const others = patterns.langs.filter(([l, w]) => l !== "und" && l !== "en" && l !== "fr" && w > 0);
  const total = others.reduce((s, [, w]) => s + w, 0);
  if (total === 0) return [["fr", 0.5], ["en", 0.5]];
  return [["fr", 0.4], ["en", 0.4], ...others.map(([l, w]) => [l, (0.2 * w) / total] as [Lang, number])];
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

function rolesFor(flow: FlowId, style: LoginStyle | undefined, passkeyOnly: boolean, splitExp: boolean): Role[] {
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
  }
}

function traitAllowed(t: TraitId, flow: FlowId, roles: Role[], langCount: number): boolean {
  switch (t) {
    case "split_otp": return false; // drawn in the site shape (login_totp), never from the pool
    case "lookalike": case "decoy_form": return PASSWORD_LOGIN.includes(flow);
    case "mixed_language": return langCount > 1;
    // Every other trait alters form fields: none on sso or passkey-only sites.
    default: return roles.length > 0;
  }
}

const isStructural = (t: TraitId) => t.startsWith("iframe_") || t.startsWith("shadow_");

function pickTraits(r: Rng, flow: FlowId, roles: Role[], langCount: number, splitOtp: boolean): TraitId[] {
  const chosen = new Set<TraitId>(splitOtp ? ["split_otp"] : []);
  const count = Math.min(r.weighted(TRAIT_COUNT), 3 - chosen.size);
  for (let k = 0; k < count; k++) {
    const hasStructural = [...chosen].some(isStructural);
    const pool = TRAITS.filter((t) => !chosen.has(t) && traitAllowed(t, flow, roles, langCount) && !(hasStructural && isStructural(t)));
    if (pool.length === 0) break;
    chosen.add(r.weighted(pool.map((t) => [t, TRAIT_WEIGHTS[t]] as const)));
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

interface SiteBase { index: number; seed: string; host: string; brand: string }

function buildSite(r: Rng, base: SiteBase, patterns: Patterns, langs: [Lang, number][], used: Set<string>,
  idp: Record<ProviderId, IdpAccount[]>): { site: Site; item?: unknown } {
  const flow = base.index < FLOWS.length ? FLOWS[base.index]! : r.fork("flow").weighted(FLOW_WEIGHTS);
  const lang = r.fork("lang").weighted(langs);
  const rs = r.fork("shape");
  const loginStyle: LoginStyle | undefined = flow === "login_totp" || flow === "login_passkey"
    ? rs.pick<LoginStyle>(["single", "username_first", "email_then_password"]) : undefined;
  const passkeyOnly = flow === "login_passkey" ? rs.chance(0.5) : false;
  const splitExp = flow === "checkout_card" && rs.chance(0.4);
  const splitOtp = flow === "login_totp" && rs.chance(0.35);
  // Half the sso sites also show an identifier + password form next to the provider button (own fork: nothing shifts).
  const ssoForm = flow === "sso" && r.fork("sso-form").chance(0.5);
  const roles = ssoForm ? rolesFor("login_single", undefined, false, false) : rolesFor(flow, loginStyle, passkeyOnly, splitExp);
  // Field traits stay off sso sites, form or not: the provider button is what they test.
  const traits = pickTraits(r.fork("traits"), flow, flow === "sso" ? [] : roles, langs.length, splitOtp);
  const labelLang = traits.includes("mixed_language")
    ? r.fork("label-lang").weighted(langs.filter(([l]) => l !== lang)) : lang;
  const fields = buildFields(r.fork("fields"), roles, patterns, labelLang, traits);

  const rb = r.fork("buttons");
  const site: Site = { ...base, lang, labelLang, flow, traits, fields, buttons: { submit: "" } };
  if (loginStyle) site.loginStyle = loginStyle;
  const nextStep = flow === "login_username_first" || flow === "login_email_then_password"
    || (loginStyle !== undefined && loginStyle !== "single" && !passkeyOnly);
  switch (flow) {
    case "signup": site.buttons.submit = buttonLabel(rb, patterns, "signup", labelLang, "Sign up"); break;
    case "checkout_card": site.buttons.submit = buttonLabel(rb, patterns, "pay", labelLang, "Pay"); break;
    case "address": case "identity": site.buttons.submit = buttonLabel(rb, patterns, "save", labelLang, "Save"); break;
    default:
      site.buttons.submit = buttonLabel(rb, patterns, "signin", labelLang, "Sign in");
      if (nextStep) site.buttons.next = buttonLabel(rb, patterns, "next", labelLang, "Next");
      if (flow === "login_passkey") site.buttons.passkey = buttonLabel(rb, patterns, "passkey", labelLang, "Sign in with a passkey");
  }

  const ra = r.fork("account");
  const who = person(ra, lang);
  const url = `https://${base.host}`;
  let item: unknown;
  if (PASSWORD_LOGIN.includes(flow) || flow === "login_passkey") {
    const usesEmail = roles.includes("email");
    const account: Account = { username: usesEmail ? who.email : who.email.split("@")[0]!, password: password(ra) };
    const extra: Record<string, unknown> = {};
    if (flow === "login_totp") {
      account.totpSecret = totpSecret(ra);
      const enc = encodeURIComponent;
      extra.totp_uri = `otpauth://totp/${enc(base.brand)}:${enc(account.username)}?secret=${account.totpSecret}&issuer=${enc(base.brand)}`;
    }
    if (flow === "login_passkey") {
      account.passkey = passkey(ra);
      site.passkeyOnly = passkeyOnly;
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
    const role = rx.pick(bait.length > 0 ? bait : roles);
    const taken = new Set(fields.map((f) => f.name));
    const tokens = (patterns.roles[role]?.tokens ?? []).filter((t) => SAFE_TOKEN.test(t));
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
  return { site, item };
}
