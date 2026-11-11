// Mock relying party of the autofill lab (spec 5.1): serves a generated site's
// pages and checks what they post. Password login (one page, username first,
// email then password), TOTP (RFC 6238, SHA-1, 30 s, 6 digits, one period of
// tolerance), WebAuthn passkey assertions, signup, and the card / address /
// identity forms compared field by field with the fictional values of the
// vault fixture. Signup takes only a generated-looking password. Trap fields
// refuse the post. Events name fields, never values.
//
// Submit events: `form` is the site's flow for the main form (entry or same
// page in a frame), else the step ("password", "otp", "passkey", "decoy",
// "oauth", "step" for the later pages of a multi_step site); `fields` lists
// the fields found wrong. A multi_step site checks each page's fields
// (identifier, password, TOTP code) and serves the next page only to the
// session that passed the previous one.
import { randomBytes } from "node:crypto";
import { totp } from "../../e2e/server.ts";
import { isFormsFlow } from "../gen/forms-flows.ts";
import { CIVILITY_OF, CIVILITY_OPTIONS, DEMONYMS, FORMS_LANGS, SEX_OPTIONS } from "../gen/forms-lexicon.ts";
import type { Civility, SexCode } from "../gen/forms-lexicon.ts";
import type { FieldSpec, LabRole, Site, World } from "../gen/model.ts";
import { policyViolation } from "../gen/policy.ts";
import { PAGE_PATH, renderSitePage, stepPath } from "../gen/render.ts";
import type { PageContext, PageId } from "../gen/render.ts";
import type { Exchange, LabState } from "./server.ts";
import { verifyAssertion } from "./webauthn.ts";

const PERIOD_MS = 30_000;

/** RFC 6238 check at `now` (ms), accepting the previous and the next period. Spaces in the code are ignored. */
export function totpOk(secret: string, code: string, now: number): boolean {
  const c = code.replace(/\s/g, "");
  if (!/^\d{6}$/.test(c)) return false;
  return [-PERIOD_MS, 0, PERIOD_MS].some((d) => totp(secret, now + d) === c);
}

/**
 * A password as a generator makes it: 12 characters or more, at least three character classes.
 * Under a site policy, the length floor drops to the policy's maximum when that is below 12, and a
 * `noSpecial` policy counts three classes (lower, upper, digit) since a special one is forbidden.
 */
export function looksGenerated(pw: string, policy?: Site["passwordPolicy"]): boolean {
  const res = [/[a-z]/, /[A-Z]/, /\d/];
  if (!policy?.noSpecial) res.push(/[^A-Za-z\d]/);
  const classes = res.filter((re) => re.test(pw)).length;
  return [...pw].length >= Math.min(12, policy?.max ?? 12) && classes >= 3;
}

// ---- expected values of the card / address / identity forms ----

interface CardFields { cardholder: string; number: string; expiry: string; cvv: string }
interface IdentityFields {
  first_name: string; last_name: string; email: string; mobile_phone: string; birth_date: string; company: string;
  honorific?: string; middle_name?: string; birth_name?: string; sex?: string; birth_place?: string; nationality?: string;
  work_phone?: string; job_title?: string; department?: string; website?: string;
  address: { line1: string; line2: string; city: string; postal_code: string; region: string; country: string };
}
interface Item { type: string; title: string; fields: unknown }

/** The fixture value each role of the site's form should receive (card expiry as "MM/YYYY"). */
export function expectedValues(world: World, site: Site): Partial<Record<LabRole, string>> {
  const items = world.fixture.items as Item[];
  if (site.cardTitle) {
    const c = items.find((i) => i.type === "credit_card" && i.title === site.cardTitle)?.fields as CardFields | undefined;
    if (!c) return {};
    return {
      cc_name: c.cardholder, cc_number: c.number, cc_exp: c.expiry, cc_exp_month: c.expiry.slice(0, 2),
      cc_exp_year: c.expiry.slice(3), cc_csc: c.cvv,
    };
  }
  if (site.identityTitle) {
    const p = items.find((i) => i.type === "identity" && i.title === site.identityTitle)?.fields as IdentityFields | undefined;
    if (!p) return {};
    const core: Partial<Record<LabRole, string>> = {
      given_name: p.first_name, family_name: p.last_name, email: p.email, tel: p.mobile_phone, birth_date: p.birth_date,
      organization: p.company, address_line1: p.address.line1, address_line2: p.address.line2,
      postal_code: p.address.postal_code, city: p.address.city, country: p.address.country,
    };
    return isFormsFlow(site.flow) ? { ...core, ...formsValues(items, site, p) } : core;
  }
  return {};
}

const fieldsOf = (items: Item[], type: string, title: string | undefined) =>
  (title === undefined ? undefined : items.find((i) => i.type === type && i.title === title)?.fields) as Record<string, string> | undefined;

/**
 * The values of the forms flows (spec 11.2): person roles from the identity, company ids from the
 * site (the vault holds them only once the generator puts them there), documents from their item.
 * On a travel site the passport's names win over the identity's. A role the vault cannot answer
 * (birth country, a loyalty program the vault lacks) expects an empty field. Dates stay ISO here:
 * `matches` compares them in the format the field renders.
 */
function formsValues(items: Item[], site: Site, p: IdentityFields): Partial<Record<LabRole, string>> {
  const out: Partial<Record<LabRole, string>> = {
    honorific: p.honorific ?? "", additional_name: p.middle_name ?? "", birth_name: p.birth_name ?? "", sex: p.sex ?? "",
    birth_place: p.birth_place ?? "", birth_country: "", nationality: p.nationality ?? "",
    bday_day: p.birth_date, bday_month: p.birth_date, bday_year: p.birth_date,
    job_title: p.job_title ?? "", department: p.department ?? "", website: p.website ?? "", tel_work: p.work_phone ?? "",
    vat_number: site.forms?.vatNumber ?? "", company_id: site.forms?.companyId ?? "",
    loyalty_number: fieldsOf(items, "reward_program", site.forms?.loyaltyTitle)?.member_number ?? "",
  };
  const pp = fieldsOf(items, "passport", site.forms?.passportTitle);
  if (pp) {
    Object.assign(out, {
      given_name: pp.first_names, family_name: pp.last_name, passport_number: pp.number, passport_issuing_country: pp.issuing_country,
      passport_issue_date: pp.issued_on, passport_expiry: pp.expiry,
    });
  }
  const dl = fieldsOf(items, "driver_license", site.forms?.licenseTitle);
  if (dl) {
    Object.assign(out, {
      license_number: dl.number, license_issuing_country: dl.country, license_issue_date: dl.issued_on, license_expiry: dl.expiry,
    });
  }
  return out;
}

const text = (s: string) => s.trim().replace(/\s+/g, " ").toLowerCase();
const phone = (s: string) => s.trim().replace(/(?!^\+)[^\d]/g, "");

/** "MM/YY", "MM/YYYY", "MM / YY", "MM-YY" as [month, four-digit year]. */
function expiry(s: string): [number, number] | undefined {
  const m = /^(\d{1,2})\s*[/-]\s*(\d{2}|\d{4})$/.exec(s.trim());
  return m ? [Number(m[1]), year(m[2]!)] : undefined;
}
const year = (s: string) => (s.length === 2 ? 2000 + Number(s) : Number(s));

function countryMatches(posted: string, code: string, lang: string, demonyms = false): boolean {
  if (text(posted) === text(code)) return true;
  if (code.length !== 2) return false;
  const up = code.toUpperCase() as keyof (typeof DEMONYMS)["fr"];
  if (demonyms && FORMS_LANGS.some((l) => (DEMONYMS[l][up] ?? []).some((d) => text(d) === text(posted)))) return true;
  for (const l of new Set(["en", "fr", lang, ...(demonyms ? FORMS_LANGS : [])])) {
    try {
      const name = new Intl.DisplayNames([l], { type: "region" }).of(code.toUpperCase());
      if (name && text(name) === text(posted)) return true;
    } catch {
      // unknown language tag: skip
    }
  }
  return false;
}

const DATE_ROLES = new Set<LabRole>(["bday_day", "bday_month", "bday_year", "passport_issue_date", "passport_expiry", "license_issue_date", "license_expiry"]);
const COUNTRY_ROLES = new Set<LabRole>(["nationality", "passport_issuing_country", "license_issuing_country", "birth_country"]);
const ID_ROLES = new Set<LabRole>(["vat_number", "company_id", "passport_number", "license_number", "loyalty_number"]);
const ident = (s: string) => s.replace(/[\s.\-]/g, "").toUpperCase();

/** The label of the option a posted list or radio value names (the value itself when the field has no options). */
function shown(posted: string, field?: FieldSpec): string {
  const c = field?.render?.choice;
  if (!c || c.kind === "text") return posted;
  return c.options.find((o) => o.value === posted)?.label ?? posted;
}

const CIVILITY_BY_LABEL = new Map<string, Civility>(FORMS_LANGS.flatMap((l) => CIVILITY_OPTIONS[l].map(([label, c]) => [text(label), c] as const)));
const SEX_BY_LABEL = new Map<string, SexCode>([
  ...FORMS_LANGS.flatMap((l) => SEX_OPTIONS[l].map(([label, c]) => [text(label), c] as const)),
  ["féminin", "f"], ["masculin", "m"], ["autre", "x"],
]);
const civility = (s: string) => CIVILITY_OF[s.trim()] ?? CIVILITY_BY_LABEL.get(text(s));

/** A date posted in the field's rendered format only: ISO for a date input, the site's pattern for text, a number for a part. */
function dateMatches(role: LabRole, posted: string, want: string, field?: FieldSpec): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(want)) return posted.trim() === "" && want === "";
  const [y, m, d] = [want.slice(0, 4), want.slice(5, 7), want.slice(8, 10)];
  const r = field?.render?.date;
  const part = r?.kind === "part" ? r.part : role === "bday_day" ? "day" : role === "bday_month" ? "month" : role === "bday_year" ? "year" : undefined;
  const v = posted.trim();
  if (part === "year") return v === y;
  if (part) return /^\d{1,2}$/.test(v) && Number(v) === Number(part === "day" ? d : m);
  if (r?.kind === "text") return v === r.format.replace("YYYY", y).replace("MM", m).replace("DD", d);
  return v === want;
}

/**
 * Whether a posted value is the fixture value `want` of `role` (formats as the site accepts them).
 * `field`, when given, says how the field renders: dates then match in that format only, list and
 * radio values through their option's label.
 */
export function matches(role: LabRole, posted: string, want: string, lang: string, field?: FieldSpec): boolean {
  if (DATE_ROLES.has(role) || (role === "birth_date" && field?.render?.date)) return dateMatches(role, posted, want, field);
  if (COUNTRY_ROLES.has(role)) return want === "" ? posted.trim() === "" : countryMatches(shown(posted, field), want, lang, true);
  if (ID_ROLES.has(role)) return ident(posted) === ident(want);
  if (role === "honorific") {
    if (want === "") return posted.trim() === "";
    const c = civility(shown(posted, field));
    return c !== undefined && c === civility(want);
  }
  if (role === "sex") {
    if (want === "") return posted.trim() === "";
    const c = SEX_BY_LABEL.get(text(shown(posted, field)));
    return c !== undefined && c === SEX_BY_LABEL.get(text(want));
  }
  if (role === "tel_work") return phone(posted) === phone(want);
  switch (role) {
    case "cc_number": return posted.replace(/\D/g, "") === want.replace(/\D/g, "");
    case "cc_exp": {
      const a = expiry(posted), b = expiry(want);
      return a !== undefined && b !== undefined && a[0] === b[0] && a[1] === b[1];
    }
    case "cc_exp_month": return /^\d{1,2}$/.test(posted.trim()) && Number(posted) === Number(want);
    case "cc_exp_year": return /^(\d{2}|\d{4})$/.test(posted.trim()) && year(posted.trim()) === Number(want);
    case "cc_csc": return posted.trim() === want;
    case "tel": return phone(posted) === phone(want);
    case "country": return countryMatches(posted, want, lang);
    default: return text(posted) === text(want);
  }
}

/** Names of the site's form fields whose posted value differs from the fixture (a missing field counts as empty). */
export function wrongFields(world: World, site: Site, body: Record<string, string>): string[] {
  const want = expectedValues(world, site);
  const ok = (f: FieldSpec): boolean => {
    const posted = body[f.name] ?? "";
    // Passengers 2 and later are other people: the user types them, the check wants them non empty.
    if ((f.person ?? 0) > 0) return posted.trim() !== "";
    // A shipping block hidden behind "same as billing" posts nothing.
    if (f.block === "shipping" && site.forms?.shippingSame) return posted.trim() === "";
    return matches(f.role, posted, want[f.role] ?? "", site.lang, f);
  };
  return site.fields.filter((f) => !ok(f)).map((f) => f.name);
}

// ---- pages ----

const PASSWORD_LOGIN = new Set<Site["flow"]>(["login_single", "login_username_first", "login_email_then_password", "login_totp", "login_passkey"]);
const FORM_FLOWS = new Set<Site["flow"]>(["checkout_card", "address", "identity", "travel_booking", "company_b2b", "car_rental", "admin_identity"]);
const MSG = {
  credentials: "Identifiant ou mot de passe incorrect",
  code: "Code incorrect",
  refused: "Envoi refusé",
  fields: "Informations incorrectes",
  saved: "Enregistré",
  signup: "Inscription impossible",
  session: "Session expirée, recommencez",
};

const styleOf = (site: Site) => site.flow === "login_username_first" ? "username_first"
  : site.flow === "login_email_then_password" ? "email_then_password" : site.loginStyle ?? "single";
const nameOf = (site: Site, ...roles: LabRole[]) => site.fields.find((f) => roles.includes(f.role))?.name;
const same = (a: string, b: string) => a.trim().toLowerCase() === b.trim().toLowerCase();

/** The account a login site checks against: the one the user means (account profiles), the one created by signup, else the generated one. */
function accountOf(site: Site, st: LabState) {
  return st.meant.get(site.host) ?? st.created.get(site.host) ?? site.account;
}

/**
 * Serves `site` on `x.host`. `mode` "frame" is the site's auth widget on its
 * cross-site frame host (spec iframe_cross_site): only the frame and the steps
 * it leads to, whose relative actions resolve against that host.
 */
export function handleSite(site: Site, x: Exchange, st: LabState, mode: "site" | "frame"): void {
  const note = (e: { form: string; ok: boolean; fields: string[]; reason?: string }) =>
    st.ledger.note({ at: Date.now(), host: x.host, kind: "submit", ...e });
  const page = (id: PageId, ctx: PageContext = {}) => x.html(renderSitePage(site, id, ctx, { labelMarks: st.labelMarks }));
  const challenge = () => {
    const c = randomBytes(32).toString("base64url");
    x.session().challenge = c;
    return c;
  };
  const signIn = (user: string, via?: NonNullable<Site["sso"]>["provider"]) => {
    const s = x.session();
    s.user = user;
    delete s.pending;
    st.ledger.note({ at: Date.now(), host: x.host, kind: "signin", user, ...(via ? { via } : {}) });
    x.redirect(PAGE_PATH.home);
  };
  const framed = site.traits.includes("iframe_same_origin") || site.traits.includes("iframe_cross_site");
  const frameOnly = new Set<string>([PAGE_PATH.frame, PAGE_PATH.password, PAGE_PATH.otp, PAGE_PATH.home, "/logout"]);
  if (mode === "frame" && !frameOnly.has(x.path)) return x.notFound();

  const stepAt = site.steps ? stepIndex(x.path) : undefined;
  if (!x.post) {
    if (stepAt !== undefined && stepAt > 0) return stepAt < site.steps!.length ? page("step", { step: stepAt }) : x.notFound();
    switch (x.path) {
      case PAGE_PATH.entry: {
        const passkeyEntry = site.flow === "login_passkey" && site.passkeyOnly;
        return page("entry", passkeyEntry ? { challenge: challenge() } : {});
      }
      case PAGE_PATH.password: return page("password");
      case PAGE_PATH.otp: return page("otp");
      case PAGE_PATH.passkey:
        return site.account?.passkey ? page("passkey", { challenge: challenge() }) : x.notFound();
      case PAGE_PATH.home: {
        const user = x.peek()?.user;
        return page("home", { status: user ? `Connecté : ${user}` : "Non connecté" });
      }
      case PAGE_PATH.frame: return framed ? page("frame") : x.notFound();
      case "/logout": {
        const s = x.peek();
        if (s) delete s.user;
        return x.redirect(mode === "frame" ? PAGE_PATH.frame : PAGE_PATH.entry);
      }
      case "/oauth/callback": return oauthCallback(x, st, signIn, page);
      default: return x.notFound();
    }
  }

  // ---- POST ----
  const formPage: PageId = x.path === PAGE_PATH.frame ? "frame" : x.path === PAGE_PATH.password ? "password"
    : x.path === PAGE_PATH.otp ? "otp" : "entry";
  if (x.path === PAGE_PATH.passkey) return passkeyPost(site, x, st);
  if (x.path === PAGE_PATH.decoy) {
    note({ form: "decoy", ok: false, fields: Object.keys(x.body).filter((k) => x.body[k]), reason: "decoy" });
    return page("entry", { error: MSG.refused });
  }
  if (site.flow === "multi_step" && stepAt !== undefined) return multiStepPost(site, x, st, stepAt, page, signIn);
  const known = [PAGE_PATH.entry, PAGE_PATH.frame, PAGE_PATH.password, PAGE_PATH.otp] as string[];
  if (!known.includes(x.path) || (x.path === PAGE_PATH.frame && !framed)) return x.notFound();
  const mainForm = formPage === "entry" || formPage === "frame";
  const formName = mainForm ? site.flow : formPage;
  const hp = site.honeypot;
  if (hp && (x.body[hp.name] ?? "").trim() !== "") {
    note({ form: formName, ok: false, fields: [hp.name], reason: "honeypot" });
    return page(formPage, { error: MSG.refused });
  }

  if (FORM_FLOWS.has(site.flow) && mainForm) {
    const wrong = wrongFields(st.world, site, x.body);
    note({ form: formName, ok: wrong.length === 0, fields: wrong, ...(wrong.length ? { reason: "wrong_fields" } : {}) });
    return page(formPage, wrong.length ? { error: MSG.fields } : { status: MSG.saved });
  }

  if (site.flow === "signup" && mainForm) {
    const email = nameOf(site, "email");
    const [p1, p2] = site.fields.filter((f) => f.role === "new_password").map((f) => f.name);
    const user = (x.body[email ?? ""] ?? "").trim();
    const pw = x.body[p1 ?? ""] ?? "";
    const wrong: string[] = [];
    if (!user && email) wrong.push(email);
    if (!pw && p1) wrong.push(p1);
    if (pw !== (x.body[p2 ?? ""] ?? "") && p2) wrong.push(p2);
    const exists = st.created.has(site.host);
    if (wrong.length > 0 || exists) {
      note({ form: formName, ok: false, fields: wrong, reason: exists ? "exists" : "wrong_fields" });
      return page(formPage, { error: MSG.signup });
    }
    // The generator's password, not any matching pair: a typed or empty-ish one does not count.
    if (!looksGenerated(pw, site.passwordPolicy)) {
      note({ form: formName, ok: false, fields: p1 ? [p1] : [], reason: "weak_password" });
      return page(formPage, { error: MSG.signup });
    }
    // The site's own rules, after the generated-looking check.
    if (site.passwordPolicy && policyViolation(pw, site.passwordPolicy) !== undefined) {
      note({ form: formName, ok: false, fields: p1 ? [p1] : [], reason: "policy" });
      return page(formPage, { error: MSG.signup });
    }
    st.created.set(site.host, { username: user, password: pw });
    st.ledger.addSecret(pw, "password", site.host);
    note({ form: formName, ok: true, fields: [] });
    return signIn(user);
  }

  // An sso site's password form: there is no password account, every post is an unknown user.
  if (site.flow === "sso" && mainForm && site.fields.length > 0) {
    const idName = nameOf(site, "username", "email") ?? "";
    note({ form: formName, ok: false, fields: [idName], reason: "unknown_user" });
    return page(formPage, { error: MSG.credentials });
  }

  const account = accountOf(site, st);
  if (!PASSWORD_LOGIN.has(site.flow) || !account || (site.flow === "login_passkey" && site.passkeyOnly)) {
    return x.notFound();
  }
  const idName = nameOf(site, "username", "email") ?? "";
  const pwName = nameOf(site, "password") ?? "";
  const afterPassword = () => {
    // Password then passkey (login_passkey without passkeyOnly): the assertion is the second step.
    if (site.flow === "login_passkey" && account.passkey) {
      x.session().pending = account.username;
      return x.redirect(PAGE_PATH.passkey);
    }
    if (account.totpSecret) {
      x.session().pending = account.username;
      return x.redirect(PAGE_PATH.otp);
    }
    return signIn(account.username);
  };

  if (mainForm) {
    const idOk = same(x.body[idName] ?? "", account.username);
    if (styleOf(site) === "username_first") {
      note({ form: formName, ok: idOk, fields: idOk ? [] : [idName], ...(idOk ? {} : { reason: "unknown_user" }) });
      if (!idOk) return page(formPage, { error: MSG.credentials });
      x.session().pending = account.username;
      return x.redirect(PAGE_PATH.password);
    }
    const pwOk = (x.body[pwName] ?? "") === account.password;
    const wrong = [...(idOk ? [] : [idName]), ...(pwOk ? [] : [pwName])];
    note({ form: formName, ok: wrong.length === 0, fields: wrong, ...(wrong.length ? { reason: idOk ? "wrong_password" : "unknown_user" } : {}) });
    if (wrong.length) return page(formPage, { error: MSG.credentials });
    return afterPassword();
  }

  const pending = x.peek()?.pending;
  if (pending !== account.username) {
    note({ form: formName, ok: false, fields: [], reason: "no_pending" });
    return page(formPage, { error: MSG.session });
  }
  if (formPage === "password") {
    const pwOk = (x.body[pwName] ?? "") === account.password;
    note({ form: formName, ok: pwOk, fields: pwOk ? [] : [pwName], ...(pwOk ? {} : { reason: "wrong_password" }) });
    if (!pwOk) return page("password", { error: MSG.credentials });
    return afterPassword();
  }
  const otpName = nameOf(site, "otp") ?? "";
  const otpOk = account.totpSecret !== undefined && totpOk(account.totpSecret, x.body[otpName] ?? "", Date.now());
  note({ form: formName, ok: otpOk, fields: otpOk ? [] : [otpName], ...(otpOk ? {} : { reason: "wrong_code" }) });
  if (!otpOk) return page("otp", { error: MSG.code });
  return signIn(account.username);
}

/** Step of a multi_step path: 0 for "/", k for "/step/<k>", undefined otherwise. */
function stepIndex(path: string): number | undefined {
  if (path === PAGE_PATH.entry) return 0;
  const m = /^\/step\/(\d{1,3})$/.exec(path);
  return m ? Number(m[1]) : undefined;
}

function multiStepPost(site: Site, x: Exchange, st: LabState, k: number, page: (id: PageId, ctx?: PageContext) => void,
  signIn: (user: string) => void): void {
  const steps = site.steps!;
  const account = accountOf(site, st);
  if (k >= steps.length || !account) return x.notFound();
  const pageId: PageId = k === 0 ? "entry" : "step";
  const formName = k === 0 ? site.flow : "step";
  const note = (e: { ok: boolean; fields: string[]; reason?: string }) =>
    st.ledger.note({ at: Date.now(), host: x.host, kind: "submit", form: formName, ...e });
  const hp = site.honeypot;
  if (hp && steps[k]!.some((f) => f.role === hp.role) && (x.body[hp.name] ?? "").trim() !== "") {
    note({ ok: false, fields: [hp.name], reason: "honeypot" });
    return page(pageId, { step: k, error: MSG.refused });
  }
  const s = x.session();
  if (k > 0 && (s.pending !== account.username || s.step !== k)) {
    note({ ok: false, fields: [], reason: "no_pending" });
    return page(pageId, { step: k, error: MSG.session });
  }
  let reason: string | undefined;
  const wrong: string[] = [];
  for (const f of steps[k]!) {
    const v = x.body[f.name] ?? "";
    const ok = f.role === "password" ? v === account.password
      : f.role === "otp" ? account.totpSecret !== undefined && totpOk(account.totpSecret, v, Date.now())
        : same(v, account.username);
    if (ok) continue;
    wrong.push(f.name);
    reason ??= f.role === "password" ? "wrong_password" : f.role === "otp" ? "wrong_code" : "unknown_user";
  }
  note({ ok: wrong.length === 0, fields: wrong, ...(reason ? { reason } : {}) });
  if (wrong.length > 0) return page(pageId, { step: k, error: reason === "wrong_code" ? MSG.code : MSG.credentials });
  if (k === steps.length - 1) {
    delete s.step;
    return signIn(account.username);
  }
  s.pending = account.username;
  s.step = k + 1;
  return x.redirect(stepPath(k + 1));
}

function passkeyPost(site: Site, x: Exchange, st: LabState): void {
  const key = site.account?.passkey;
  const s = x.session();
  const expected = s.challenge ?? "";
  delete s.challenge; // one attempt per challenge
  const fail = (reason: string) => {
    st.ledger.note({ at: Date.now(), host: x.host, kind: "submit", form: "passkey", ok: false, fields: [], reason });
    x.json(403, { ok: false, reason });
  };
  if (!key || !site.account) return fail("no_passkey");
  // After a password step, only the session that passed it may finish with the passkey.
  if (!site.passkeyOnly && s.pending !== site.account.username) return fail("no_pending");
  const { credentialId = "", clientDataJSON = "", authenticatorData = "", signature = "" } = x.body;
  if (credentialId !== key.credentialId) return fail("unknown_credential");
  const r = verifyAssertion({ credentialId, clientDataJSON, authenticatorData, signature }, {
    challenge: expected, origin: `https://${site.host}`, rpId: site.host, publicKey: { x: key.x, y: key.y },
    prevCounter: st.counters.get(site.host) ?? 0,
  });
  if (!r.ok) return fail(r.reason);
  st.counters.set(site.host, r.counter);
  st.ledger.note({ at: Date.now(), host: x.host, kind: "submit", form: "passkey", ok: true, fields: [] });
  s.user = site.account.username;
  delete s.pending;
  st.ledger.note({ at: Date.now(), host: x.host, kind: "signin", user: site.account.username });
  // 200, not a redirect: the page script then goes to /home itself.
  x.json(200, { ok: true });
}

function oauthCallback(x: Exchange, st: LabState,
  signIn: (user: string, via?: NonNullable<Site["sso"]>["provider"]) => void, page: (id: PageId, ctx?: PageContext) => void): void {
  const code = x.query.get("code") ?? "";
  const grant = st.codes.get(code);
  if (!grant || grant.host !== x.host) {
    st.ledger.note({ at: Date.now(), host: x.host, kind: "submit", form: "oauth", ok: false, fields: [], reason: "bad_code" });
    return page("home", { error: "Code de connexion invalide" });
  }
  st.codes.delete(code);
  signIn(grant.email, grant.provider);
}
