// The single fill path (spec 8.4): verify the target frame, ask the host
// (which redoes the origin match), verify again, then hand the values to the
// content script of that exact frame. Values are not kept anywhere.
import type { Ctx, FillField, LoginFill } from "../bridge/client";
import type { BgToCs, Extra, FieldRole, FillHints, FormInfo, ProviderId, UsernameCheckReply } from "../shared/messages";
import type { BgExt } from "./ext";
import type { Frames } from "./frames";
import { BgError, type Session } from "./session";

export interface FillTarget {
  tabId: number;
  frameId: number;
  /** Origin bound when the gesture started (from `sender`). */
  origin: string;
  documentId?: string;
  formRef: string;
  /** A child frame must have exactly the top frame's origin (the chain, spec C1). */
  sameOriginAsTop?: boolean;
  /**
   * Roles of the target form's owner fields (passengers 2 and later left out), from the page's
   * analysis: an identity fill without a plan asks the documents and loyalty of these roles only.
   */
  formRoles?: readonly FieldRole[];
}

/** The roles of `form` that are the owner's (person 0): what a fill may write there. */
export function ownerRoles(form: FormInfo): FieldRole[] {
  return [...new Set(form.fields.filter((f) => (f.person ?? 0) === 0).map((f) => f.role))];
}

/** The documents and loyalty a form with `roles` asks of `fill_identity` (spec 10.2). */
export function extrasFor(roles: readonly FieldRole[]): Extra[] {
  const out: Extra[] = [];
  if (roles.some((r) => r.startsWith("passport_"))) out.push("passport");
  if (roles.some((r) => r.startsWith("license_"))) out.push("driver_license");
  if (roles.includes("loyalty_number")) out.push("loyalty");
  return out;
}

export type FillValues = Partial<Record<FieldRole, string>>;

function put(values: FillValues, role: FieldRole, v: string | undefined): void {
  if (typeof v === "string" && v !== "") values[role] = v;
}

/**
 * Only the values of `roles` (a planned group's roles: the fields the plan
 * fills, never one the user typed in). Every value when `roles` is absent.
 */
function only(values: FillValues, roles: readonly FieldRole[] | undefined): FillValues {
  if (roles === undefined) return values;
  const out: FillValues = {};
  for (const r of roles) if (Object.hasOwn(values, r)) out[r] = values[r];
  return out;
}

function loginValues(r: LoginFill): FillValues {
  const values: FillValues = {};
  put(values, "username", r.username);
  put(values, "email", r.username);
  put(values, "current_password", r.password);
  put(values, "otp", r.totp);
  return values;
}

/**
 * The hints a fill may carry (`FillHints`), for the roles it writes: the sex for a civility, a sex or
 * a nationality, a civility from the sex only when the civility is asked, the work phone with the
 * phone. Undefined when none is left.
 */
function hintsFor(h: FillHints, roles: readonly FieldRole[] | undefined): FillHints | undefined {
  const asks = (r: FieldRole) => roles === undefined || roles.includes(r);
  const out: FillHints = {};
  if (h.sex !== undefined && (asks("honorific_prefix") || asks("sex") || asks("nationality"))) out.sex = h.sex;
  if (h.civility_from_sex && out.sex !== undefined && asks("honorific_prefix")) out.civility_from_sex = true;
  if (h.work_tel !== undefined && asks("tel")) out.work_tel = h.work_tel;
  return Object.keys(out).length > 0 ? out : undefined;
}

/** Most candidates a sign-up username is tested with in the page. */
const MAX_USERNAME_TRIES = 8;

/** "Élodie Dupont-Moreau" -> "elodiedupontmoreau": ASCII letters and digits only. */
export function handleWord(v: string | undefined): string {
  return (v ?? "")
    .normalize("NFD")
    .replace(/\p{M}/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

/** Four random digits (1000 to 9999). */
function randomDigits(): string {
  const a = new Uint32Array(1);
  globalThis.crypto.getRandomValues(a);
  return String(1000 + ((a[0] ?? 0) % 9000));
}

/**
 * Handles for a sign-up username, best first: from the identity's names (else the e-mail's local
 * part, else "user"), plain, then with random digits; each cut to `max` characters.
 */
export function handleCandidates(given: string | undefined, family: string | undefined, email: string | undefined, max?: number, digits = randomDigits()): string[] {
  const g = handleWord(given);
  const f = handleWord(family);
  const local = handleWord(email?.split("@")[0]);
  const base = g !== "" ? g : local !== "" ? local : "user";
  const words = g !== "" && f !== "" ? [`${g}.${f}`, `${g}${f}`, `${g}_${f}`] : [base];
  const out: string[] = [];
  const cut = (head: string, tail = ""): string => {
    if (max === undefined || max <= 0 || head.length + tail.length <= max) return head + tail;
    return head.slice(0, Math.max(1, max - tail.length)) + tail;
  };
  for (const w of words) out.push(cut(w));
  out.push(cut(g !== "" && f !== "" ? `${g}${f}` : base, digits), cut(base, digits), cut(`${base}_`, digits));
  return [...new Set(out)].filter((x) => x !== "" && (max === undefined || max <= 0 || x.length <= max));
}

export class Filler {
  /** Told each login, card or identity item this filler wrote into a page (the save flow stays quiet on cards and identities, knows the login a change-password form is about). */
  onFilled: ((tabId: number, origin: string, kind: "login" | "card" | "identity", itemId: string) => void) | null = null;

  constructor(
    private readonly tabs: Pick<BgExt["tabs"], "sendMessage">,
    private readonly frames: Pick<Frames, "checkFillTarget">,
    private readonly session: Pick<Session, "request">,
  ) {}

  /** `candidate` against the target form's username field; null when the page did not answer. */
  private async usernameCheck(t: FillTarget, candidate: string): Promise<UsernameCheckReply | null> {
    const msg: BgToCs = { type: "username_check", origin: t.origin, formRef: t.formRef, candidate };
    const opts = t.documentId !== undefined ? { documentId: t.documentId } : { frameId: t.frameId };
    try {
      const r = (await this.tabs.sendMessage(t.tabId, msg, opts)) as UsernameCheckReply | undefined;
      if (!r || r.ok !== true || typeof r.matches !== "boolean") return null;
      return r;
    } catch {
      return null;
    }
  }

  /**
   * The identifier for a sign-up's username field (MS-06): the e-mail when the form has no
   * e-mail field of its own and the username field takes it; else a handle from the identity
   * (names, then random digits) that the field's own pattern and length accept. Undefined when
   * none fits (the field is left to the user).
   */
  private async signupUsername(t: FillTarget, r: { given_name?: string; family_name?: string; email?: string }, separateEmail: boolean): Promise<string | undefined> {
    let max: number | undefined;
    if (!separateEmail && r.email) {
      const fit = await this.usernameCheck(t, r.email);
      if (fit === null || fit.matches) return r.email;
      max = fit.max_length;
    }
    let tries = 0;
    for (const c of handleCandidates(r.given_name, r.family_name, r.email, max)) {
      if (tries++ >= MAX_USERNAME_TRIES) break;
      const fit = await this.usernameCheck(t, c);
      if (fit === null || fit.matches) return c;
      if (max === undefined && fit.max_length !== undefined && c.length > fit.max_length) {
        // Too long for the field: the rest, cut to its length.
        max = fit.max_length;
        for (const short of handleCandidates(r.given_name, r.family_name, r.email, max)) {
          if (tries++ >= MAX_USERNAME_TRIES) break;
          const f2 = await this.usernameCheck(t, short);
          if (f2 === null || f2.matches) return short;
        }
        return undefined;
      }
    }
    return undefined;
  }

  private async verify(t: FillTarget): Promise<void> {
    const c = await this.frames.checkFillTarget(t.tabId, t.frameId, t.origin, t.documentId, t.sameOriginAsTop ? "same_origin" : "same_site");
    if (!c.ok) throw new BgError(c.code);
  }

  /** Sends the values; resolves with how many roles had one (0: nothing sent). */
  private async deliver(t: FillTarget, all: FillValues, roles?: readonly FieldRole[], hints: FillHints = {}): Promise<number> {
    const values = only(all, roles);
    const h = hintsFor(hints, roles);
    const written = Object.keys(values).length;
    // No value at all (a planned group whose roles got none, a step the item has nothing for): nothing to write.
    if (written === 0) return 0;
    // The host may have taken seconds (Touch ID): the page could have moved.
    await this.verify(t);
    const msg: BgToCs = { type: "fill", origin: t.origin, formRef: t.formRef, values };
    if (h) msg.hints = h;
    // documentId pins the exact document; frameId alone where unsupported.
    const opts = t.documentId !== undefined ? { documentId: t.documentId } : { frameId: t.frameId };
    await this.tabs.sendMessage(t.tabId, msg, opts);
    return written;
  }

  /**
   * `roles`: a planned group's roles, the only ones written (likewise below).
   * Each fill resolves with the roles it sent a value for.
   */
  async fillLogin(t: FillTarget, itemId: string, fields: FillField[], ctx: Ctx = "menu", roles?: readonly FieldRole[]): Promise<number> {
    await this.verify(t);
    const r = await this.session.request({ op: "fill_login", ctx, item_id: itemId, origin: t.origin, fields });
    const written = await this.deliver(t, loginValues(r), roles);
    // The login a change-password form in this tab is about (save-flow `savePendingUpdate`).
    if (written > 0) this.onFilled?.(t.tabId, t.origin, "login", itemId);
    return written;
  }

  /**
   * The provider account's own credentials, on an official host of that
   * provider (the host checks `provider_origin` and the account), during a
   * sign-in chain to `siteOrigin`.
   */
  async fillProvider(
    t: FillTarget,
    accountItemId: string,
    provider: ProviderId,
    siteOrigin: string,
    fields: FillField[],
  ): Promise<void> {
    await this.verify(t);
    const r = await this.session.request({
      op: "fill_provider",
      ctx: "chain",
      account_item_id: accountItemId,
      provider,
      provider_origin: t.origin,
      site_origin: siteOrigin,
      fields,
    });
    await this.deliver(t, loginValues(r));
  }

  async fillCard(t: FillTarget, itemId: string, ctx: Ctx = "menu", roles?: readonly FieldRole[]): Promise<number> {
    await this.verify(t);
    const r = await this.session.request({ op: "fill_card", ctx, item_id: itemId, origin: t.origin });
    const values: FillValues = {};
    put(values, "cc_name", r.cardholder);
    put(values, "cc_number", r.number);
    put(values, "cc_exp_month", r.exp_month);
    put(values, "cc_exp_year", r.exp_year);
    if (r.exp_month !== "" && r.exp_year !== "") put(values, "cc_exp", `${r.exp_month}/${r.exp_year.slice(-2)}`);
    put(values, "cc_csc", r.cvv);
    const written = await this.deliver(t, values, roles);
    if (written > 0) this.onFilled?.(t.tabId, t.origin, "card", itemId);
    return written;
  }

  /**
   * With `roles`, the identity's e-mail alone can go into a signup or checkout group, also as its `username`.
   * `onIdentifier`: told the e-mail once it was sent to an `email` or `username` field of `roles`
   * (the pending signup Login's username); not kept here.
   */
  async fillIdentity(
    t: FillTarget,
    itemId: string,
    ctx: Ctx = "menu",
    roles?: readonly FieldRole[],
    onIdentifier?: (email: string) => void,
  ): Promise<number> {
    await this.verify(t);
    // Documents and loyalty only for the roles the form has (a plan's group, else the analysis).
    const extras = extrasFor(roles ?? t.formRoles ?? []);
    const r = await this.session.request({ op: "fill_identity", ctx, item_id: itemId, origin: t.origin, ...(extras.length > 0 ? { extras } : {}) });
    const values: FillValues = {};
    const p = r.passport;
    // The ticket's name is the passport's (spec section 4), when the form asks the passport.
    const given = p?.first_names || r.given_name;
    const family = p?.last_name || r.family_name;
    put(values, "given_name", given);
    put(values, "family_name", family);
    put(values, "full_name", [given, family].filter((x) => x).join(" "));
    put(values, "email", r.email);
    // A signup's identifier field (`username` role), only when a plan put it in the identity
    // group: the e-mail if the field takes it and the form has no e-mail field of its own, else
    // a handle the field accepts (MS-06).
    if (roles?.includes("username")) put(values, "username", await this.signupUsername(t, r, roles.includes("email")));
    put(values, "tel", r.tel);
    put(values, "organization", r.organization);
    put(values, "bday", r.birthday || p?.birth_date);
    // Person and company values written as they are (forms coverage, ruling R39); civility, sex
    // and nationality are chosen in the page by their tables (spec sections 7 and 8).
    put(values, "additional_name", r.middle_name);
    put(values, "birth_name", r.birth_name);
    put(values, "birth_place", r.birth_place || p?.birth_place);
    put(values, "job_title", r.job_title);
    put(values, "department", r.department);
    put(values, "website", r.website);
    put(values, "vat_number", r.vat_number);
    put(values, "company_id", r.company_registration);
    const sex = r.sex || p?.sex;
    put(values, "honorific_prefix", r.honorific);
    put(values, "sex", sex);
    put(values, "nationality", r.nationality || p?.nationality);
    // The associated documents and the site's loyalty (bridge, rulings R2 and R11); birth country never.
    if (p) {
      put(values, "passport_number", p.number);
      put(values, "passport_issuing_country", p.issuing_country);
      put(values, "passport_issue_date", p.issued_on);
      put(values, "passport_expiry", p.expiry);
    }
    const dl = r.driver_license;
    if (dl) {
      put(values, "license_number", dl.number);
      put(values, "license_issuing_country", dl.country);
      put(values, "license_issue_date", dl.issued_on);
      put(values, "license_expiry", dl.expiry);
    }
    put(values, "loyalty_number", r.loyalty?.number);
    const hints: FillHints = {};
    if (sex) hints.sex = sex;
    if (sex && !r.honorific) hints.civility_from_sex = true;
    if (r.work_tel) hints.work_tel = r.work_tel;
    const a = r.address;
    if (a) {
      put(values, "address_line1", a.line1);
      put(values, "address_line2", a.line2);
      put(values, "city", a.city);
      put(values, "postal_code", a.postal_code);
      put(values, "region", a.region);
      put(values, "country", a.country);
    }
    const written = await this.deliver(t, values, roles, hints);
    if (written > 0) this.onFilled?.(t.tabId, t.origin, "identity", itemId);
    // The pending signup Login's identifier: the username the site gets, else the e-mail.
    const email = values.username ?? values.email;
    if (written > 0 && onIdentifier && email !== undefined && roles?.some((r) => r === "email" || r === "username")) onIdentifier(email);
    return written;
  }

  /** A freshly generated password into the new and confirm fields. */
  async fillGenerated(t: FillTarget, password: string, roles?: readonly FieldRole[]): Promise<number> {
    const values: FillValues = {};
    put(values, "new_password", password);
    put(values, "confirm_password", password);
    return this.deliver(t, values, roles);
  }

  /**
   * Submit `t.formRef` (a plan's `FillAndSubmit`), after the same frame check
   * as a fill. `planned`: the content script re-checks the button's class at
   * click time and refuses a re-rendered copy of the form.
   */
  async submit(t: FillTarget): Promise<void> {
    await this.verify(t);
    const msg: BgToCs = { type: "submit", origin: t.origin, ref: t.formRef, planned: true };
    const opts = t.documentId !== undefined ? { documentId: t.documentId } : { frameId: t.frameId };
    await this.tabs.sendMessage(t.tabId, msg, opts);
  }
}
