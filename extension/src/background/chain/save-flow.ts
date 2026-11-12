// When to propose saving a login (spec 8.5, 8.8): submitted credentials are
// kept in memory (never in a storage area) for at most 2 minutes, with the
// origin given by `sender`. The prompt waits for a sign that the sign-in
// worked, never a mere delay: the next page of the submitting frame (a new
// document, or the same one for a single-page app) shows no credential form
// with a password field any more. A new document that shows one again is a
// failed sign-in (the site's form with its error): the submission is
// dropped. The same document must stay without it for SETTLE_MS (a page
// that hides its form behind a spinner, then shows it again with an error,
// is not a success). A new top document that never reports an analysis
// counts after NAV_SETTLE_MS. Then the host is asked `check_credentials`;
// `new` or `update` opens the save prompt (save.ts) in the top frame, unless
// the site is in the "Ne jamais proposer" list. A locked vault opens it too
// (`locked`): Save unlocks first.
//
// A submission without an identifier takes the one of the lone identifier
// step just sent in this tab on the same site (`submitted_identifier`, kept
// IDENTIFIER_TTL_MS in memory): identifier first, password on the next page.
// Without one it is not proposed (it would always look `new`), except when
// its password is one OnePass just generated and filled in this tab (spec
// 8.8): a signup or change-password form often has no identifier field.
//
// Pending save (spec 7): right after a generated password went into a signup
// form, `savePending` writes it to the vault as a Login tagged
// `onepass:pending` (and `onepass:weak-by-site` when the site imposed a weak
// one), so a lock or a closed tab loses nothing. A reset form does not: its
// password is only remembered, and the save prompt then updates the Login
// the user already has. Per tab, only the item id, site and username are
// kept here, in memory: never the password. A new generation on the same
// tab and site replaces the item's password (`update_password`, the old one
// goes to its history, the weak tag follows the new draw). The submission of
// that password confirms the item (`confirm_pending`); once the sign-up
// worked (same success rule as a sign-in), the card shows it as saved, with
// nothing to answer (a generated password is never saved out of sight). When this memory is gone (lock, service worker restart), the
// host still finds the item: `check_credentials` answers `pending` for it
// whatever the username, and the submission confirms it, or leaves it pending
// silently without a username; never a second save. The confirmation happens
// at the submission: a signup the server then refuses stays confirmed.
//
// Every time (founder, 2026-11-04): each sign-in with credentials OnePass
// does not hold gets the card, on any site, for any account: a site never
// seen, a second account on a known site (`new`), a known account with
// another password (`update`). "Pas maintenant" puts away that very card
// only (save.ts `recentlyDismissed`: the same site, identifier and password
// within a few minutes); "Ne jamais proposer pour <site>" silences the site.
//
// Cards and identities typed by hand (MS-04): a card, identity or address
// form sent by the user (`submitted_form`, same trusted-gesture rule as a
// sign-in) is followed the same way: once the page moved on without that
// form, `check_card` or `check_identity` decides; one OnePass already holds
// (filled from it, saved before) gets nothing. Its values live here at most
// SUBMIT_TTL_MS, like a password. A locked vault offers nothing for them (the
// check needs the vault). Cards and identities belong to no site, so a page
// could fill a form with values of its choosing and watch whether a card
// appears: the card stays quiet only for the very item OnePass filled in this
// tab and site moments ago (`noteFilled`); any other `same` still shows the
// card, whose Save then says it is already there. An identity OnePass filled
// in this tab and site keeps any later address of it quiet (the page often
// reformats a phone or a country: never a duplicate offered).
//
// Also here: the per item auto-submit preference of the chain (R-12), in
// `storage.local` key `autoSubmit:<itemId>`, true unless set to false.
import { parseOrigin, sameSite } from "../../shared/domain";
import type { IdentityValues } from "../../bridge/client";
import type { CsToBg, FormKind, PageAnalysis, SavedFormKind, SubmittedValues } from "../../shared/messages";
import type { StorageArea } from "../ext";
import type { CsContext } from "../frames";
import type { NeverSave } from "../never-save";
import {
  type CardDraft,
  PENDING_TAG,
  type SavePending,
  type SavePrompts,
  WEAK_BY_SITE_TAG,
  cardQuietKey,
  identityQuietKey,
  loginQuietKey,
  titleFromSite,
} from "../save";
import { HostCompat } from "../host-compat";
import { BgError, type Session } from "../session";

export const SUBMIT_TTL_MS = 2 * 60 * 1000;
/** The same document stays without its password form this long before it counts as signed in. */
export const SETTLE_MS = 1000;
/** A new top document without any analysis (no form, no content script) counts after this. */
export const NAV_SETTLE_MS = 2000;
/** The identifier of a lone identifier step feeds the next password step this long. */
export const IDENTIFIER_TTL_MS = 10 * 60 * 1000;

const CREDENTIAL_FORMS: ReadonlySet<FormKind> = new Set<FormKind>(["login", "signup", "change_password"]);

/** The page still asks for a password: a credential form with a password field. */
export function asksPassword(a: PageAnalysis): boolean {
  return a.forms.some((f) => CREDENTIAL_FORMS.has(f.kind) && f.fields.some((x) => x.role === "current_password" || x.role === "new_password"));
}
/** The page still shows a card form (its number field): the payment did not go through. */
export function asksCard(a: PageAnalysis): boolean {
  return a.forms.some((f) => f.kind === "card" && f.fields.some((x) => x.role === "cc_number"));
}

/** The page still shows an identity or address form. */
export function asksIdentity(a: PageAnalysis): boolean {
  return a.forms.some((f) => f.kind === "identity" || f.kind === "address");
}

/** "04/29", "4 / 2029", "0429": month and year of a single expiry field; "" when unreadable. */
export function splitExpiry(v: string): { month: string; year: string } {
  // Without a separator only MMYY or MMYYYY (a three digit "122" is ambiguous).
  const m = /^\s*(\d{1,2})\s*[/\-. ]\s*(\d{2}|\d{4})\s*$/.exec(v) ?? /^\s*(\d{2})(\d{2}|\d{4})\s*$/.exec(v);
  if (!m?.[1] || !m[2]) return { month: "", year: "" };
  return { month: m[1].padStart(2, "0"), year: m[2] };
}

/** The card of a sent card form: digits of the number, expiry from one or two fields. */
export function cardFromValues(v: SubmittedValues): CardDraft | null {
  const number = (v.cc_number ?? "").replace(/[\s-]/g, "");
  if (!/^\d{12,19}$/.test(number)) return null;
  let month = (v.cc_exp_month ?? "").trim();
  let year = (v.cc_exp_year ?? "").trim();
  if ((month === "" || year === "") && v.cc_exp !== undefined) ({ month, year } = splitExpiry(v.cc_exp));
  const thisYear = new Date().getFullYear();
  const fullYear = year.length === 2 ? 2000 + Number(year) : Number(year);
  // A plausible expiry only: month 1 to 12, year from last year to 25 years on (a security code
  // read as a year is dropped, never saved).
  if (!/^\d{1,2}$/.test(month) || Number(month) < 1 || Number(month) > 12 || !/^(\d{2}|\d{4})$/.test(year) || fullYear < thisYear - 1 || fullYear > thisYear + 25)
    month = year = "";
  return { cardholder: (v.cc_name ?? "").trim(), number, exp_month: month === "" ? "" : month.padStart(2, "0"), exp_year: year };
}

/** The identity of a sent identity or address form; null when nothing worth saving. */
export function identityFromValues(v: SubmittedValues): IdentityValues | null {
  const t = (x: string | undefined) => (x ?? "").trim();
  let given = t(v.given_name);
  let family = t(v.family_name);
  const full = t(v.full_name);
  if (given === "" && family === "" && full !== "") {
    const at = full.lastIndexOf(" ");
    given = at === -1 ? full : full.slice(0, at).trim();
    family = at === -1 ? "" : full.slice(at + 1).trim();
  }
  const out: IdentityValues = { given_name: given, family_name: family, email: t(v.email), tel: t(v.tel), organization: t(v.organization) };
  const address = {
    line1: t(v.address_line1),
    line2: t(v.address_line2),
    city: t(v.city),
    postal_code: t(v.postal_code),
    region: t(v.region),
    country: t(v.country),
  };
  if (Object.values(address).some((x) => x !== "")) out.address = address;
  // Only a postal address is worth a card: a street line with its postal code or city. A contact,
  // newsletter or store-finder form (name, e-mail, phone, a city alone) is not.
  if (address.line1 === "" || (address.postal_code === "" && address.city === "")) return null;
  return out;
}

/** A card or identity OnePass filled keeps its own submission quiet this long. */
export const FILLED_TTL_MS = 10 * 60 * 1000;

/** A generated password feeds the proposal of a submission this recent. */
export const GENERATED_TTL_MS = 10 * 60 * 1000;

const AUTO_SUBMIT_PREFIX = "autoSubmit:";

export async function autoSubmitFor(area: StorageArea, itemId: string): Promise<boolean> {
  const k = AUTO_SUBMIT_PREFIX + itemId;
  return (await area.get(k))[k] !== false;
}

export async function setAutoSubmit(area: StorageArea, itemId: string, on: boolean): Promise<void> {
  if (on) await area.remove(AUTO_SUBMIT_PREFIX + itemId);
  else await area.set({ [AUTO_SUBMIT_PREFIX + itemId]: false });
}

export interface Timers {
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(id: unknown): void;
}

const realTimers: Timers = {
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (id) => clearTimeout(id as ReturnType<typeof setTimeout>),
};

interface Pending {
  /** A sign-in (default), or a card or identity form sent by hand. */
  kind?: SavedFormKind;
  card?: CardDraft;
  identity?: IdentityValues;
  origin: string;
  username: string;
  password: string;
  at: number;
  /** The submitting frame, and its document where the browser reports it. */
  frameId: number;
  documentId?: string;
  /** The top frame committed a new document since the submission. */
  navigated: boolean;
  /** Timer of the success check (settle), or null. */
  check: unknown;
  /** Already saved and confirmed (a generated password): the card only shows it saved. */
  confirmed?: boolean;
  expire: unknown;
}

interface Identifier {
  site: string;
  username: string;
  at: number;
}

interface Generated {
  site: string;
  password: string;
  at: number;
}

/** A pending Login saved for a tab: no password. */
interface Saved {
  site: string;
  itemId: string;
  username: string;
}

/** What `noteFilled` records. */
export type FilledKind = "login" | "card" | "identity";

export interface PendingOptions {
  /** The identifier known at fill time; empty when none. */
  username?: string;
  /** The site's rules forced a weak password (report `weak_by_site`). */
  weak?: boolean;
}

export interface SaveFlowDeps {
  session: Pick<Session, "request">;
  /** `vaults` with its origin, whatever the app's age (shared by the worker). */
  host?: HostCompat;
  saves: Pick<SavePrompts, "open"> & Partial<Pick<SavePrompts, "recentlyDismissed">>;
  neverSave: Pick<NeverSave, "has">;
  /**
   * The top frame of a tab as the browser reports it now
   * (`webNavigation.getFrame`): its URL, and its document where supported.
   */
  topFrame: (tabId: number) => Promise<{ url: string; documentId?: string } | null>;
  /** A sign-in chain runs in this tab: its submissions are not proposed. */
  chainRunning?: (tabId: number) => Promise<boolean>;
  now?: () => number;
  timers?: Timers;
}

export class SaveFlow {
  private readonly pending = new Map<number, Pending>();
  private readonly generated = new Map<number, Generated>();
  private readonly saved = new Map<number, Saved>();
  private readonly identifiers = new Map<number, Identifier>();
  /** Login, card and identity items OnePass filled per tab, with their site and when. */
  private readonly filled = new Map<number, { site: string; kind: FilledKind; itemId: string; at: number }[]>();
  private readonly now: () => number;
  private readonly timers: Timers;
  private readonly host: HostCompat;

  constructor(private readonly deps: SaveFlowDeps) {
    this.host = deps.host ?? new HostCompat(deps.session);
    this.now = deps.now ?? Date.now;
    this.timers = deps.timers ?? realTimers;
  }

  /** A password OnePass generated and filled in `tabId` (menu or popup). */
  rememberGenerated(tabId: number, origin: string, password: string): void {
    const site = parseOrigin(origin)?.site;
    if (!site || password === "") return;
    const prev = this.generated.get(tabId);
    if (prev) prev.password = "";
    this.generated.set(tabId, { site, password, at: this.now() });
  }

  /**
   * Save `password`, just generated and filled in `tabId`, as a pending
   * Login of the site of `origin`; a pending item of this tab and site gets
   * the new password instead. True once the vault holds it. Never throws: a
   * locked vault or a refusal leaves the save prompt as the fallback.
   */
  async savePending(tabId: number, origin: string, password: string, opts: PendingOptions = {}): Promise<boolean> {
    const page = parseOrigin(origin);
    if (page?.https !== true || password === "") return false;
    const prev = this.saved.get(tabId);
    if (prev && prev.site === page.site) {
      try {
        await this.deps.session.request({
          op: "update_password",
          ctx: "save_prompt",
          item_id: prev.itemId,
          origin,
          password,
          weak_by_site: opts.weak === true,
        });
        return true;
      } catch (e) {
        // Gone, or no longer of this site: a new pending item. Any other
        // refusal (locked, rate limited...) keeps the item, no second one.
        if (!(e instanceof BgError) || (e.code !== "not_found" && e.code !== "origin_mismatch")) return false;
        if (this.saved.get(tabId) === prev) this.saved.delete(tabId);
      }
    }
    const username = opts.username?.trim() ?? "";
    try {
      // Listed for the page: the first is the default vault of the account it routes to.
      const { vaults } = await this.host.vaults(origin);
      const vault = vaults[0];
      if (!vault) return false;
      const saved = await this.deps.session.request({
        op: "save_login",
        ctx: "save_prompt",
        origin,
        title: titleFromSite(page.site),
        username,
        password,
        vault_id: vault.id,
        rule: "domain",
        tags: opts.weak === true ? [PENDING_TAG, WEAK_BY_SITE_TAG] : [PENDING_TAG],
      });
      this.saved.set(tabId, { site: page.site, itemId: saved.item_id, username });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Spec 5.2: `password`, just generated and filled in a change-password
   * form of `tabId`, goes at once to the login being changed
   * (`update_password`, the old password to its history): the site's only
   * login, or the one OnePass filled in this tab. Several logins and none
   * filled here: nothing written, the password stays remembered for the
   * submission (the card asks which one, Task 11). Never throws.
   */
  async savePendingUpdate(tabId: number, origin: string, password: string, opts: PendingOptions = {}): Promise<boolean> {
    const page = parseOrigin(origin);
    if (page?.https !== true || password === "") return false;
    try {
      const { items } = await this.deps.session.request({ op: "list_for_origin", ctx: "save_prompt", origin });
      const logins = items.filter((x) => x.kind === "login");
      const here = this.lastFilled(tabId, origin, "login");
      const itemId = here !== null && logins.some((x) => x.item_id === here) ? here : logins.length === 1 ? logins[0]?.item_id : undefined;
      if (itemId === undefined) return false;
      await this.deps.session.request({
        op: "update_password",
        ctx: "save_prompt",
        item_id: itemId,
        origin,
        password,
        weak_by_site: opts.weak === true,
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * The pending item of `tabId` for the site of `origin` was sent: drop its
   * tag, complete its username. False when there is none or the host
   * refused (the host's `pending` verdict then applies).
   */
  private async confirm(tabId: number, origin: string, username: string): Promise<boolean> {
    const s = this.saved.get(tabId);
    if (!s || s.site !== parseOrigin(origin)?.site) return false;
    try {
      await this.deps.session.request({
        op: "confirm_pending",
        ctx: "save_prompt",
        item_id: s.itemId,
        origin,
        username: username.trim() !== "" ? username : s.username,
      });
    } catch {
      return false;
    }
    if (this.saved.get(tabId) === s) this.saved.delete(tabId);
    return true;
  }

  /**
   * The vault locked: forget every generated password still waiting for a
   * submission. Pending items stay known (they hold no secret): once
   * unlocked, the host recognizes their password at the submission.
   */
  clearGenerated(): void {
    for (const g of this.generated.values()) g.password = "";
    this.generated.clear();
  }

  private takeGenerated(tabId: number, origin: string, password: string): boolean {
    const g = this.generated.get(tabId);
    if (!g) return false;
    const fresh = this.now() - g.at <= GENERATED_TTL_MS;
    const match = fresh && g.site === parseOrigin(origin)?.site && g.password === password;
    if (match || !fresh) {
      g.password = "";
      this.generated.delete(tabId);
    }
    return match;
  }

  /** A lone identifier step was sent: its identifier names the next password step of this site. */
  onIdentifier(m: Extract<CsToBg, { type: "submitted_identifier" }>, cs: CsContext): void {
    const page = parseOrigin(cs.origin);
    const username = m.username.trim();
    if (page?.https !== true || username === "") return;
    this.identifiers.set(cs.tabId, { site: page.site, username, at: this.now() });
  }

  /** The identifier of the last identifier step of this tab, if it was on the site of `origin` and recent. */
  private identifierFor(tabId: number, origin: string): string {
    const id = this.identifiers.get(tabId);
    if (!id) return "";
    if (this.now() - id.at > IDENTIFIER_TTL_MS) {
      this.identifiers.delete(tabId);
      return "";
    }
    return id.site === parseOrigin(origin)?.site ? id.username : "";
  }

  async onSubmitted(m: Extract<CsToBg, { type: "submitted_credentials" }>, cs: CsContext): Promise<void> {
    if (parseOrigin(cs.origin)?.https !== true) return;
    const username = m.username.trim() !== "" ? m.username : this.identifierFor(cs.tabId, cs.origin);
    const generated = this.takeGenerated(cs.tabId, cs.origin, m.password);
    // The password OnePass generated and already saved: confirmed, nothing to ask; the card
    // says it is saved once the sign-up worked.
    const confirmed = generated && (await this.confirm(cs.tabId, cs.origin, username));
    if (!confirmed) {
      if (username.trim() === "" && !generated) return;
      if (await this.deps.chainRunning?.(cs.tabId)) return;
    }
    this.drop(cs.tabId);
    const p: Pending = {
      origin: cs.origin,
      username,
      password: confirmed ? "" : m.password,
      at: this.now(),
      frameId: cs.frameId,
      navigated: false,
      check: null,
      expire: null,
    };
    if (confirmed) p.confirmed = true;
    if (cs.documentId !== undefined) p.documentId = cs.documentId;
    // Spec 8.5: kept at most 2 minutes.
    p.expire = this.timers.setTimeout(() => this.drop(cs.tabId), SUBMIT_TTL_MS);
    this.pending.set(cs.tabId, p);
  }

  /** OnePass filled the login, card or identity `itemId` in `tabId` (menu, popup, plan or chain). */
  noteFilled(tabId: number, origin: string, kind: FilledKind, itemId: string): void {
    const site = parseOrigin(origin)?.site;
    if (!site) return;
    const now = this.now();
    const list = (this.filled.get(tabId) ?? []).filter((f) => now - f.at <= FILLED_TTL_MS && !(f.kind === kind && f.itemId === itemId));
    list.push({ site, kind, itemId, at: now });
    this.filled.set(tabId, list.slice(-8));
  }

  private filledHere(tabId: number, origin: string, kind: FilledKind, itemId?: string): boolean {
    const site = parseOrigin(origin)?.site;
    const now = this.now();
    return (this.filled.get(tabId) ?? []).some((f) => f.site === site && f.kind === kind && now - f.at <= FILLED_TTL_MS && (itemId === undefined || f.itemId === itemId));
  }

  /** The last item of `kind` OnePass filled in `tabId` on the site of `origin`, if still recent. */
  private lastFilled(tabId: number, origin: string, kind: FilledKind): string | null {
    const site = parseOrigin(origin)?.site;
    const now = this.now();
    const hit = (this.filled.get(tabId) ?? []).filter((f) => f.site === site && f.kind === kind && now - f.at <= FILLED_TTL_MS).at(-1);
    return hit?.itemId ?? null;
  }

  /** A card, identity or address form was sent by hand in `cs`: followed like a sign-in. */
  onForm(m: Extract<CsToBg, { type: "submitted_form" }>, cs: CsContext): void {
    if (parseOrigin(cs.origin)?.https !== true) return;
    const card = m.kind === "card" ? cardFromValues(m.values) : null;
    const identity = m.kind === "identity" ? identityFromValues(m.values) : null;
    if (!card && !identity) return;
    // A sign-in waiting for its success check keeps its place: it is the one asked first.
    if (this.pending.get(cs.tabId)?.kind === undefined && this.pending.has(cs.tabId)) return;
    this.drop(cs.tabId);
    const p: Pending = { kind: m.kind, origin: cs.origin, username: "", password: "", at: this.now(), frameId: cs.frameId, navigated: false, check: null, expire: null };
    if (card) p.card = card;
    if (identity) p.identity = identity;
    if (cs.documentId !== undefined) p.documentId = cs.documentId;
    p.expire = this.timers.setTimeout(() => this.drop(cs.tabId), SUBMIT_TTL_MS);
    this.pending.set(cs.tabId, p);
  }

  /**
   * The top frame of `tabId` committed a new document (at `url`): wait for
   * its analysis. Another site: the tab's pending item and identifier are
   * no longer followed.
   */
  onNavigation(tabId: number, url?: string): void {
    const site = url !== undefined ? parseOrigin(url)?.site : undefined;
    const s = this.saved.get(tabId);
    if (s && url !== undefined && site !== s.site) this.saved.delete(tabId);
    const id = this.identifiers.get(tabId);
    if (id && url !== undefined && site !== id.site) this.identifiers.delete(tabId);
    const p = this.pending.get(tabId);
    if (!p) return;
    p.navigated = true;
    this.timers.clearTimeout(p.check);
    p.check = null;
  }

  /**
   * A page analysis of `cs`: the sign of success (or failure) the pending
   * submission of its tab waits for. Only the submitting frame, or the top
   * frame once it navigated, counts.
   */
  onAnalysis(a: PageAnalysis, cs: CsContext): void {
    const p = this.pending.get(cs.tabId);
    if (!p) return;
    // A new document of the submitting frame (the browser says so), or the top frame after a commit.
    const newDoc =
      (cs.frameId === p.frameId && cs.documentId !== undefined && p.documentId !== undefined && cs.documentId !== p.documentId) ||
      (p.navigated && cs.frameId === 0 && !(cs.documentId !== undefined && cs.documentId === p.documentId));
    if (cs.frameId !== p.frameId && !newDoc) return;
    this.timers.clearTimeout(p.check);
    p.check = null;
    const asks = p.kind === "card" ? asksCard(a) : p.kind === "identity" ? asksIdentity(a) : asksPassword(a);
    if (asks) {
      // The site asks again on a new page: the sign-in failed. Same page: still waiting.
      if (newDoc) this.drop(cs.tabId);
      return;
    }
    if (newDoc) {
      void this.check(cs.tabId);
      return;
    }
    p.check = this.timers.setTimeout(() => void this.check(cs.tabId), SETTLE_MS);
  }

  /** The new top document finished loading: counts after NAV_SETTLE_MS unless an analysis decides first. */
  onReady(tabId: number): void {
    const p = this.pending.get(tabId);
    if (!p?.navigated || p.check !== null) return;
    p.check = this.timers.setTimeout(() => void this.check(tabId), NAV_SETTLE_MS);
  }

  onTabRemoved(tabId: number): void {
    this.drop(tabId);
    this.generated.delete(tabId);
    this.saved.delete(tabId);
    this.identifiers.delete(tabId);
    this.filled.delete(tabId);
  }

  private drop(tabId: number): void {
    const p = this.pending.get(tabId);
    if (!p) return;
    this.timers.clearTimeout(p.check);
    this.timers.clearTimeout(p.expire);
    p.password = "";
    if (p.card) p.card.number = "";
    delete p.card;
    delete p.identity;
    this.pending.delete(tabId);
  }

  /** Ask the host, then prompt. One check per submission. */
  async check(tabId: number): Promise<void> {
    const p = this.pending.get(tabId);
    if (!p) return;
    const { origin, username, password, at, confirmed, kind, card, identity } = p;
    // Copied before the drop (which blanks the held number).
    const cardCopy = card ? { ...card } : undefined;
    this.drop(tabId);
    if (this.now() - at > SUBMIT_TTL_MS) return;
    const site = parseOrigin(origin)?.site;
    if (!site || (await this.deps.neverSave.has(site))) return;
    if (confirmed) {
      await this.showSaved(tabId, origin, username);
      return;
    }
    if (kind !== undefined) {
      await this.checkForm(tabId, origin, cardCopy, identity);
      return;
    }
    // "Pas maintenant" on this very credential moments ago: not asked again.
    if (await this.quiet(origin, loginQuietKey(username, password))) return;
    // The prompt goes to the top frame: it must show this site (checked
    // again below, after the host answered).
    if (!(await this.verifiedTop(tabId, origin))) return;
    let r: { status: "new" | "same" | "update" | "pending"; item_id?: string; title?: string };
    let locked = false;
    try {
      r = await this.deps.session.request({ op: "check_credentials", ctx: "save_prompt", origin, username, password });
    } catch (e) {
      // Locked in the app: the card still shows, Save unlocks and checks again.
      if (!(e instanceof BgError) || e.code !== "locked") return;
      r = { status: "new" };
      locked = true;
    }
    if (r.status === "same") return;
    // A pending item of this site holds this password (memory of it lost
    // here): confirmed with the submitted username, never a second save.
    // Without a username it stays pending, silently.
    if (r.status === "pending") {
      if (r.item_id === undefined || username.trim() === "") return;
      const itemId = r.item_id;
      try {
        await this.deps.session.request({ op: "confirm_pending", ctx: "save_prompt", item_id: itemId, origin, username });
      } catch {
        return;
      }
      if (this.saved.get(tabId)?.itemId === itemId) this.saved.delete(tabId);
      await this.showSaved(tabId, origin, username);
      return;
    }
    // The top frame may have moved during the host request (or before the
    // submission was even registered): read it again and pin the prompt to
    // that very document, of this site.
    const top = await this.verifiedTop(tabId, origin);
    if (!top) return;
    const pending: SavePending = { tabId, origin, kind: "login", status: r.status, username, password, topOrigin: top.origin };
    if (top.documentId !== undefined) pending.documentId = top.documentId;
    if (r.status === "update" && r.item_id !== undefined) pending.update = { itemId: r.item_id, title: r.title ?? "" };
    if (locked) pending.locked = true;
    try {
      await this.deps.saves.open(pending);
    } catch {
      // Content script gone (tab closed, navigated again): nothing to show.
    }
  }

  private async quiet(origin: string, key: string): Promise<boolean> {
    return (await this.deps.saves.recentlyDismissed?.(origin, key).catch(() => false)) === true;
  }

  /** A card or identity sent by hand: offered unless OnePass holds it or it was just put away. */
  private async checkForm(tabId: number, origin: string, card: CardDraft | undefined, identity: IdentityValues | undefined): Promise<void> {
    const key = card ? cardQuietKey(card.number, card.exp_month, card.exp_year) : identity ? identityQuietKey(identity) : null;
    if (key === null || (await this.quiet(origin, key))) return;
    // An identity OnePass filled here: what was sent is that identity, maybe reformatted by the page.
    if (identity && this.filledHere(tabId, origin, "identity")) return;
    if (!(await this.verifiedTop(tabId, origin))) return;
    let r: { status: "new" | "same" | "update"; item_id?: string; title?: string };
    try {
      r = card
        ? await this.deps.session.request({ op: "check_card", ctx: "save_prompt", origin, number: card.number, exp_month: card.exp_month, exp_year: card.exp_year })
        : await this.deps.session.request({ op: "check_identity", ctx: "save_prompt", origin, ...(identity as IdentityValues) });
    } catch {
      // Locked, refused, an older host without these checks: nothing offered.
      return;
    }
    // The very card OnePass filled here: nothing to ask. Any other card or identity it holds: the
    // card shows anyway (no oracle for the page), its Save says it is already there.
    if (r.status === "same" && card && r.item_id !== undefined && this.filledHere(tabId, origin, "card", r.item_id)) return;
    const top = await this.verifiedTop(tabId, origin);
    if (!top) return;
    const pending: SavePending = {
      tabId,
      origin,
      kind: card ? "card" : "identity",
      status: r.status === "update" && r.item_id !== undefined ? "update" : "new",
      username: "",
      password: "",
      topOrigin: top.origin,
    };
    if (r.status === "same") pending.known = true;
    if (card) pending.card = { ...card };
    if (identity) pending.identity = identity;
    if (pending.status === "update" && r.item_id !== undefined) pending.update = { itemId: r.item_id, title: r.title ?? "" };
    if (top.documentId !== undefined) pending.documentId = top.documentId;
    try {
      await this.deps.saves.open(pending);
    } catch {
      // Content script gone: nothing to show.
    }
  }

  /** The card, as done: a generated password OnePass saved, confirmed by this sign-up. */
  private async showSaved(tabId: number, origin: string, username: string): Promise<void> {
    const top = await this.verifiedTop(tabId, origin);
    if (!top) return;
    const pending: SavePending = { tabId, origin, kind: "login", status: "new", username, password: "", view: "saved", topOrigin: top.origin };
    if (top.documentId !== undefined) pending.documentId = top.documentId;
    try {
      await this.deps.saves.open(pending);
    } catch {
      // Content script gone: nothing to show, the login is saved anyway.
    }
  }

  /**
   * The current top document of `tabId` if it is HTTPS and of the same
   * registrable domain as `origin`: its origin and, where the browser
   * reports it, its documentId (the prompt is delivered to exactly it).
   */
  private async verifiedTop(tabId: number, origin: string): Promise<{ origin: string; documentId?: string } | null> {
    let f: { url: string; documentId?: string } | null;
    try {
      f = await this.deps.topFrame(tabId);
    } catch {
      return null;
    }
    const top = f ? parseOrigin(f.url) : null;
    if (!f || !top?.https || !sameSite(f.url, origin)) return null;
    return f.documentId !== undefined ? { origin: top.origin, documentId: f.documentId } : { origin: top.origin };
  }

  /** Menu "Enregistrer un nouveau login": the edit view, site prefilled, nothing typed. */
  async openNewLogin(tabId: number, origin: string, documentId?: string): Promise<void> {
    const pending: SavePending = { tabId, origin, kind: "login", status: "new", username: "", password: "", view: "edit" };
    if (documentId !== undefined) pending.documentId = documentId;
    await this.deps.saves.open(pending);
  }

  /** For tests: submissions currently held. */
  get size(): number {
    return this.pending.size;
  }
}
