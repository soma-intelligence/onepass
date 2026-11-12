// "Connexion en un clic" overlay (spec 8.6): `overlay.html#<token>` in the
// top frame of a tab. The token binds the tab, top frame and origin; the
// overlay gets the sign-in choices for that origin and starts or stops the
// chain. It renders whatever state the chain driver reports.
//
// A locked vault (or an app that is not running) does not cost a second
// click: the click on the card, or the chain a click started, asks the app to
// unlock, the token keeps what was asked (`pending`: ids and a time, no
// secret), and the card's polls start or continue the sign-in the moment the
// vault opens. One attempt, inside the shared deadline, in the document the
// token is bound to.
//
// The same wait serves a sign-in asked outside the card (`signIn`: a menu
// row whose chain start found the vault locked) and a page as a whole
// (`pending.kind` "page"): a generic card, shown on a sign-in page reached
// with the vault locked, whose click unlocks; and a gesture without a field
// (the command, the toolbar's Fill) that had no menu to wait in. After the
// unlock the page's own plan runs there, once (`resumePage`). A generic
// card never holds or shows anything of the vault.
import type { Summary } from "../bridge/client";
import type { BgToCs, FrameKind, ProviderId } from "../shared/messages";
import { parseOrigin } from "../shared/domain";
import { PROVIDERS } from "../shared/providers";
import type { OverlayAccount, OverlayInit, SignInChoice } from "../shared/ui";
import { UNLOCK_WAIT_MS } from "../shared/unlock";
import { signInChoices } from "./chain/choices";
import type { ChainDriver, StartOptions } from "./chain/types";
import type { BgExt, StorageArea } from "./ext";
import type { CsContext, Frames, UiContext } from "./frames";
import { BgError, type Session, toBgError } from "./session";
import { type BoundRecord, FrameTokens, isBoundRecord } from "./tokens";

export const OVERLAY_TTL_MS = 30 * 60 * 1000;
/** While a card waits for an unlock, the app is asked for its state at most this often. */
export const UNLOCK_CHECK_MS = 1000;

/** What asking the app to unlock led to (app.ts `askAppUnlock`). */
export type UnlockAsked = "unlocked" | "asked" | "launching" | "failed";
/** What a waiting card is waiting for: the unlock in the app, or the app itself (launching). */
export type OverlayWaiting = "locked" | "host_missing";

/**
 * What the app was asked to unlock for, kept on the token: a sign-in to start (`start`, the
 * click on the card) or the chain of this tab to continue (`chain`, locked mid-way; its state
 * stays with the driver). Ids and a time, never a secret.
 */
export interface OverlayPending {
  /** `page`: no item named; the page's own plan runs after the unlock (`OverlayDeps.resumePage`). */
  kind: "start" | "chain" | "page";
  itemId?: string;
  provider?: ProviderId;
  accountId?: string;
  /** `start`: the user picked the item's row in the menu (`StartOptions.picked`). */
  picked?: "menu";
  at: number;
  /** The app got the unlock request (false: still launching, asked once it answers). */
  sent: boolean;
}

export interface OverlayOffer {
  password: boolean;
  providers: ProviderId[];
}

export interface OverlayRecord extends BoundRecord {
  /** Sign-in choices shown by `overlay_init`; a start must be one of them. */
  offered?: Record<string, OverlayOffer>;
  /** Provider accounts shown per provider; a picked account must be one of them. */
  accounts?: Record<string, string[]>;
  /** An unlock asked for this card: what resumes once the vault opens, once. */
  pending?: OverlayPending;
  /** Opened on a locked vault, with nothing of it: no account until the vault answers. */
  generic?: boolean;
}

function parsePending(raw: unknown): OverlayPending | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  if ((r.kind !== "start" && r.kind !== "chain" && r.kind !== "page") || typeof r.sent !== "boolean") return null;
  if (typeof r.at !== "number" || !Number.isSafeInteger(r.at) || r.at < 0) return null;
  const p: OverlayPending = { kind: r.kind, at: r.at, sent: r.sent };
  if (r.kind !== "start") return p;
  if (typeof r.itemId !== "string") return null;
  p.itemId = r.itemId;
  if (r.provider !== undefined) {
    const known = PROVIDERS.find((x) => x.id === r.provider);
    if (!known) return null;
    p.provider = known.id;
  }
  if (r.accountId !== undefined) {
    if (typeof r.accountId !== "string" || p.provider === undefined) return null;
    p.accountId = r.accountId;
  }
  if (r.picked !== undefined) {
    if (r.picked !== "menu") return null;
    p.picked = "menu";
  }
  return p;
}

function parseOverlay(raw: unknown): OverlayRecord | null {
  if (!isBoundRecord(raw)) return null;
  const r = raw as unknown as Record<string, unknown>;
  const rec: OverlayRecord = {
    tabId: raw.tabId,
    frameId: raw.frameId,
    origin: raw.origin,
    createdAt: raw.createdAt,
  };
  if (raw.documentId !== undefined) rec.documentId = raw.documentId;
  const offered = r.offered;
  if (typeof offered === "object" && offered !== null) {
    rec.offered = {};
    for (const [id, o] of Object.entries(offered as Record<string, unknown>)) {
      const x = o as Partial<OverlayOffer> | null;
      if (!x || typeof x.password !== "boolean" || !Array.isArray(x.providers)) return null;
      rec.offered[id] = { password: x.password, providers: x.providers.filter((p) => typeof p === "string") };
    }
  }
  const accounts = r.accounts;
  if (typeof accounts === "object" && accounts !== null) {
    rec.accounts = {};
    for (const [p, ids] of Object.entries(accounts as Record<string, unknown>)) {
      if (!Array.isArray(ids)) return null;
      rec.accounts[p] = ids.filter((x): x is string => typeof x === "string");
    }
  }
  if (r.pending !== undefined) {
    // A malformed request is dropped, the card stays.
    const pending = parsePending(r.pending);
    if (pending) rec.pending = pending;
  }
  if (r.generic === true) rec.generic = true;
  return rec;
}

export function providerName(id: ProviderId): string {
  return PROVIDERS.find((p) => p.id === id)?.name ?? id;
}

/**
 * Every way to sign in with these items: password logins, then provider
 * methods with the account each would use (`choices`, from the host) and
 * the other accounts of that provider for the inline picker.
 */
export function overlayAccounts(items: Summary[], choices: readonly SignInChoice[] = []): OverlayAccount[] {
  const out: OverlayAccount[] = [];
  for (const it of items) {
    if (it.kind !== "login") continue;
    const base: Pick<OverlayAccount, "itemId" | "title" | "iconLetter" | "iconColor" | "vault" | "account" | "associated"> = {
      itemId: it.item_id, title: it.title, iconLetter: it.icon_letter, iconColor: it.icon_color, vault: { id: it.vault_id, name: it.vault_name },
    };
    if (typeof it.account === "string" && it.account !== "") base.account = it.account;
    if (it.associated === true) base.associated = true;
    if (it.has_password) out.push({ ...base, subtitle: it.subtitle, ...(it.has_totp ? { totp: true } : {}) });
    for (const m of it.methods) {
      const c = choices.find((x) => x.itemId === it.item_id && x.provider === m.provider);
      const def = c?.accounts.find((a) => a.itemId === c.accountId);
      const email = def?.email ?? m.account_email;
      const a: OverlayAccount = { ...base, subtitle: email, provider: m.provider, email };
      if (c?.accountId !== undefined) a.accountId = c.accountId;
      if (c && c.accounts.length > 0) a.accounts = c.accounts;
      out.push(a);
    }
  }
  return out;
}

/** Sends `remove_frame` to the exact frame a token was bound to. */
export async function removeFrame(
  tabs: Pick<BgExt["tabs"], "sendMessage">,
  rec: Pick<BoundRecord, "tabId" | "frameId" | "documentId">,
  kind: FrameKind,
): Promise<void> {
  const msg: BgToCs = { type: "remove_frame", kind };
  const opts = rec.documentId !== undefined ? { documentId: rec.documentId } : { frameId: rec.frameId };
  try {
    await tabs.sendMessage(rec.tabId, msg, opts);
  } catch {
    // Tab or document gone: nothing left to remove.
  }
}

/** Sends `resize_frame` to the exact frame a token was bound to. */
export async function resizeFrame(
  tabs: Pick<BgExt["tabs"], "sendMessage">,
  rec: Pick<BoundRecord, "tabId" | "frameId" | "documentId">,
  kind: FrameKind,
  height: number,
  width?: number,
): Promise<void> {
  const msg: BgToCs = { type: "resize_frame", kind, height, ...(width !== undefined ? { width } : {}) };
  const opts = rec.documentId !== undefined ? { documentId: rec.documentId } : { frameId: rec.frameId };
  try {
    await tabs.sendMessage(rec.tabId, msg, opts);
  } catch {
    // Document gone: nothing to size.
  }
}

export interface OverlayDeps {
  ext: Pick<BgExt, "tabs" | "runtime">;
  area: StorageArea;
  /** `storage.local`: the provider account last picked per site (choices.ts). */
  local?: StorageArea;
  session: Pick<Session, "request">;
  chain: ChainDriver;
  /** The top frame as the browser reports it now: a resume checks the card's document again. */
  frames?: Pick<Frames, "details">;
  /**
   * A trusted click on the card found the vault locked or the app missing: unlock it (Face ID
   * right there on iOS, the click being the one attempt; elsewhere the app comes forward,
   * launched if needed, and is asked). Absent: no resume, the card says to unlock and retry.
   */
  askUnlock?: (tabId: number) => Promise<UnlockAsked>;
  /**
   * The chain a click started found the vault locked mid-way: the same, without any prompt
   * of the worker's own on iOS ("failed" there).
   */
  askUnlockChain?: (tabId: number) => Promise<UnlockAsked>;
  /** The bridge `unlock` for a gesture in `tabId` (it names the tab's top origin); true while locked. */
  unlockOp?: (tabId: number) => Promise<boolean>;
  /** Continues the chain of `tabId` stopped `locked` from the step it could not run (driver.ts); false when refused. */
  resumeChain?: (tabId: number) => Promise<boolean>;
  /**
   * The unlock a card asked for its page as a whole ended (`pending.kind` "page"): the page's own
   * plan runs in the card's tab, as the gesture that asked would have (the chain, a fill, or the
   * menu). The caller has checked the top frame still holds the card's document.
   */
  resumePage?: (rec: Pick<OverlayRecord, "tabId" | "origin" | "documentId">) => Promise<void>;
  /**
   * The login the page's plan would sign in with in this top document (planner.ts `signIn`), if
   * it chooses one: the card's first account. Absent or null: the order of the list.
   */
  primary?: (tabId: number, origin: string, documentId: string | undefined) => Promise<string | null>;
  now?: () => number;
}

export class Overlays {
  readonly tokens: FrameTokens<OverlayRecord>;
  private readonly now: () => number;
  /** Tokens whose resume is being decided: one attempt, whatever the polls do. */
  private readonly resuming = new Set<string>();
  /** Per waiting token: the last look at the app, and what it showed. */
  private readonly checked = new Map<string, { at: number; waiting: OverlayWaiting }>();

  constructor(private readonly deps: OverlayDeps) {
    this.now = deps.now ?? Date.now;
    this.tokens = new FrameTokens<OverlayRecord>({
      prefix: "overlay:",
      ttlMs: OVERLAY_TTL_MS,
      area: deps.area,
      parse: parseOverlay,
      ...(deps.now ? { now: deps.now } : {}),
    });
  }

  /**
   * Shows the overlay in the top frame `cs`: under the field `anchorRef` of
   * that document when given (the progress of a chain started from the
   * menu shows where the user clicked), else at the top right.
   */
  async open(cs: CsContext, anchorRef?: string, generic = false, pending?: OverlayPending): Promise<string> {
    if (cs.frameId !== 0) throw new BgError("invalid");
    const rec: Omit<OverlayRecord, "createdAt"> = { tabId: cs.tabId, frameId: 0, origin: cs.origin };
    if (cs.documentId !== undefined) rec.documentId = cs.documentId;
    if (generic) rec.generic = true;
    if (pending) rec.pending = pending;
    const token = await this.tokens.register(rec);
    const msg: BgToCs = { type: "show_frame", kind: "overlay", url: `${this.deps.ext.runtime.getURL("overlay.html")}#${token}` };
    if (anchorRef !== undefined) msg.ref = anchorRef;
    const opts = cs.documentId !== undefined ? { documentId: cs.documentId } : { frameId: 0 };
    try {
      await this.deps.ext.tabs.sendMessage(cs.tabId, msg, opts);
    } catch (e) {
      // Not shown: no live token may claim the tab has its overlay.
      await this.tokens.drop(token);
      throw e;
    }
    return token;
  }

  private async record(token: string, ui: UiContext): Promise<OverlayRecord> {
    const rec = await this.tokens.resolve(token, ui);
    if (!rec) throw new BgError("invalid");
    return rec;
  }

  /** The sign-ins the overlay shows in tab `tabId` at `origin`, and whether the page is provider-only. */
  private async accountsFor(tabId: number, origin: string, documentId: string | undefined): Promise<{ accounts: OverlayAccount[]; only: boolean }> {
    const { items } = await this.deps.session.request({ op: "list_for_origin", ctx: "overlay", origin });
    const choices = this.deps.local ? await signInChoices(this.deps.session, this.deps.local, "overlay", origin, items) : [];
    // A provider-only page (spec E1): only the sign-ins through the providers it shows.
    const only = await this.deps.chain.providerOnly?.(tabId, documentId);
    // A login offered through an associated domain is the user's to pick, in the menu or the
    // popup: the bridge serves it to such a pick only, never to the card's button (`ctx` overlay,
    // chain). Not offered here until that pick made it this site's own.
    const all = overlayAccounts(items.filter((x) => x.associated !== true), choices);
    return { accounts: only ? all.filter((x) => x.provider !== undefined && only.includes(x.provider)) : all, only: !!only };
  }

  /** `accounts` with the password login of `itemId` first (the page's plan would sign in with it); the rest in order. */
  private async primaryFirst(rec: OverlayRecord, accounts: OverlayAccount[]): Promise<OverlayAccount[]> {
    if (accounts.length < 2 || !this.deps.primary) return accounts;
    let first: string | null = null;
    try {
      first = await this.deps.primary(rec.tabId, rec.origin, rec.documentId);
    } catch {
      // No plan: the list as it is.
    }
    const at = first === null ? -1 : accounts.findIndex((a) => a.itemId === first && a.provider === undefined);
    return at <= 0 ? accounts : [accounts[at] as OverlayAccount, ...accounts.slice(0, at), ...accounts.slice(at + 1)];
  }

  /**
   * Smart fill where the plan signs nobody in (a provider-only page, or a sign-in form the vault
   * has no password login for): the one sign-in the overlay would offer in top document `cs`,
   * when it goes through a provider whose button the page shows. That chain starts (the click on
   * the button, the account chooser, the provider's own credentials on its exact hosts). False
   * when the page offers no such way, or several ways to choose from (the menu then).
   */
  async providerSignIn(cs: CsContext): Promise<boolean> {
    if (cs.frameId !== 0) return false;
    // Nothing is asked of the vault for a page that shows no provider button.
    const buttons = (await this.deps.chain.providerOnly?.(cs.tabId, cs.documentId)) ?? (await this.deps.chain.providersShown?.(cs.tabId, cs.documentId)) ?? [];
    if (buttons.length === 0) return false;
    const { accounts, only } = await this.accountsFor(cs.tabId, cs.origin, cs.documentId);
    // Beside a sign-in form, every way counts: its password logins, and the providers it shows.
    const shown = only ? null : new Set(buttons);
    // A login reached through an associated domain is never started without the user picking it.
    const ways = (shown === null ? accounts : accounts.filter((x) => x.provider === undefined || shown.has(x.provider))).filter((x) => x.associated !== true);
    const a = ways[0];
    if (ways.length !== 1 || a?.provider === undefined) return false;
    await this.deps.chain.start(cs.tabId, a.itemId, a.provider, a.accountId !== undefined ? { accountId: a.accountId } : {});
    return true;
  }

  async init(token: string, ui: UiContext): Promise<OverlayInit & { waiting?: OverlayWaiting }> {
    const rec = await this.record(token, ui);
    let accounts: OverlayAccount[] = [];
    let generic = false;
    try {
      ({ accounts } = await this.accountsFor(rec.tabId, rec.origin, rec.documentId));
      accounts = await this.primaryFirst(rec, accounts);
      // The vault answers: a card like any other from now on.
      delete rec.generic;
    } catch (e) {
      // A card shown to wait for an unlock (its chain stopped locked on this page), or a generic
      // card on a locked vault: no list yet.
      const code = toBgError(e).code;
      if ((!rec.pending && !rec.generic) || (code !== "locked" && code !== "host_missing")) throw e;
      generic = rec.generic === true && !rec.pending;
    }
    const offered: Record<string, OverlayOffer> = {};
    const shown: Record<string, string[]> = {};
    for (const a of accounts) {
      const o = (offered[a.itemId] ??= { password: false, providers: [] });
      if (a.provider) {
        o.providers.push(a.provider);
        const ids = (shown[a.provider] ??= []);
        for (const x of a.accounts ?? []) if (!ids.includes(x.itemId)) ids.push(x.itemId);
      } else o.password = true;
    }
    rec.offered = offered;
    rec.accounts = shown;
    await this.tokens.update(token, rec);
    let chain = await this.deps.chain.state(rec.tabId, true, rec.documentId);
    if (!rec.pending) return generic ? { origin: rec.origin, accounts, chain, generic: true } : { origin: rec.origin, accounts, chain };
    const waiting = await this.resume(token, rec);
    if (waiting) return { origin: rec.origin, accounts, chain, waiting };
    chain = await this.deps.chain.state(rec.tabId, true, rec.documentId);
    return { origin: rec.origin, accounts, chain };
  }

  async state(token: string, ui: UiContext) {
    const rec = await this.record(token, ui);
    let chain = await this.deps.chain.state(rec.tabId, false, rec.documentId);
    // Read after the chain's queued work: a chain that just stopped `locked` left its request by now.
    if (!rec.pending) return { chain };
    const waiting = await this.resume(token, rec);
    if (waiting) return { chain, waiting };
    chain = await this.deps.chain.state(rec.tabId, false, rec.documentId);
    return { chain };
  }

  async start(token: string, ui: UiContext, itemId: string, provider?: ProviderId, accountId?: string): Promise<object> {
    const rec = await this.record(token, ui);
    const o = rec.offered && Object.hasOwn(rec.offered, itemId) ? rec.offered[itemId] : undefined;
    const ok = o !== undefined && (provider === undefined ? o.password && accountId === undefined : o.providers.includes(provider));
    if (!ok) throw new BgError("invalid");
    if (provider !== undefined && accountId !== undefined) {
      const shown = rec.accounts && Object.hasOwn(rec.accounts, provider) ? rec.accounts[provider] : undefined;
      if (!shown?.includes(accountId)) throw new BgError("invalid");
    }
    await this.setPending(token, rec, undefined);
    const pending = await this.startOrAsk(rec.tabId, itemId, provider, accountId !== undefined ? { accountId } : {});
    if (!pending) return {};
    await this.setPending(token, rec, pending);
    return { waiting: pending.sent ? "locked" : "host_missing" };
  }

  /**
   * Starts the chain; a locked vault or a missing app is asked to unlock at once (the caller's
   * click is the gesture). Null: started. Else what to keep until the vault opens (`pending`).
   * Throws when it cannot start and nothing will wait: the app could not be opened, or any other
   * refusal.
   */
  private async startOrAsk(tabId: number, itemId: string, provider: ProviderId | undefined, opts: StartOptions): Promise<OverlayPending | null> {
    const run = () => this.deps.chain.start(tabId, itemId, provider, opts);
    try {
      await run();
      return null;
    } catch (e) {
      const code = toBgError(e).code;
      if ((code !== "locked" && code !== "host_missing") || !this.deps.askUnlock) throw e;
      // The click is the gesture: the unlock is asked now, and the sign-in starts by itself after it.
      const at = this.now();
      const asked = await this.deps.askUnlock(tabId).catch((): UnlockAsked => "failed");
      if (asked === "unlocked") {
        await run();
        return null;
      }
      // Not opened: said so, another click tries again.
      if (asked === "failed") throw e;
      const pending: OverlayPending = { kind: "start", itemId, at, sent: asked === "asked" };
      if (provider !== undefined) pending.provider = provider;
      if (provider !== undefined && opts.accountId !== undefined) pending.accountId = opts.accountId;
      if (opts.picked !== undefined) pending.picked = opts.picked;
      return pending;
    }
  }

  /** A fresh card in top frame `cs` that waits for `pending` (any card already there gives way). */
  private async waitingCard(cs: CsContext, pending: OverlayPending, anchorRef?: string): Promise<void> {
    const live = await this.tokens.forTab(cs.tabId);
    if (live) {
      this.checked.delete(live.token);
      await this.tokens.drop(live.token);
      await removeFrame(this.deps.ext.tabs, live.rec, "overlay");
    }
    await this.open(cs, anchorRef, true, pending);
  }

  /**
   * A sign-in asked outside the card, by a trusted click on a row of the menu in top document
   * `cs`: started now; or, the vault locked or the app missing, the app is asked at once and a
   * card of the page waits (under `opts.anchorRef` when given) to start it after the unlock. No
   * second click. Throws as `ChainDriver.start` does when nothing can wait.
   */
  async signIn(cs: CsContext, itemId: string, provider: ProviderId | undefined, opts: StartOptions): Promise<void> {
    const pending = await this.startOrAsk(cs.tabId, itemId, provider, opts);
    if (pending) await this.waitingCard(cs, pending, opts.anchorRef);
  }

  /**
   * A gesture without a field (the command, the toolbar's Fill) found the vault locked or the app
   * missing, and the app was asked at `at`: a card of top document `cs` waits, and the page's own
   * plan runs after the unlock (`resumePage`), once.
   */
  async pageWait(cs: CsContext, at: number, sent: boolean): Promise<void> {
    if (!this.deps.resumePage) return;
    await this.waitingCard(cs, { kind: "page", at, sent });
  }

  /**
   * The click on a generic card: the app is asked to unlock (Face ID right there on iOS). Open
   * at once: the page's plan runs. Else the card waits and runs it after the unlock, once.
   */
  async unlock(token: string, ui: UiContext): Promise<object> {
    const rec = await this.record(token, ui);
    if (!rec.generic || !this.deps.askUnlock || !this.deps.resumePage) throw new BgError("invalid");
    const at = this.now();
    const asked = await this.deps.askUnlock(rec.tabId).catch((): UnlockAsked => "failed");
    if (asked === "failed") throw new BgError("locked");
    if (asked === "unlocked") {
      await this.setPending(token, rec, undefined);
      if (await this.stillBound(rec)) await this.deps.resumePage(rec);
      return {};
    }
    await this.setPending(token, rec, { kind: "page", at, sent: asked === "asked" });
    return { waiting: asked === "asked" ? "locked" : "host_missing" };
  }

  /**
   * The chain of `tabId` stopped `locked` mid-way (driver.ts): the app is asked to unlock and the
   * card of the tab waits, to continue the chain once (`resumeChain`). False when nothing waits:
   * no card in the tab, or the app could not be asked.
   */
  async awaitUnlock(tabId: number): Promise<boolean> {
    const live = await this.tokens.forTab(tabId);
    if (!live || !this.deps.askUnlockChain || !this.deps.resumeChain) return false;
    // Kept before the app is asked: a poll of the card meanwhile already finds it.
    const pending: OverlayPending = { kind: "chain", at: this.now(), sent: false };
    await this.setPending(live.token, live.rec, pending);
    const asked = await this.deps.askUnlockChain(tabId).catch((): UnlockAsked => "failed");
    if (live.rec.pending !== pending) return false;
    if (asked === "failed") {
      await this.setPending(live.token, live.rec, undefined);
      return false;
    }
    pending.sent = asked !== "launching";
    await this.tokens.update(live.token, live.rec);
    return true;
  }

  private async setPending(token: string, rec: OverlayRecord, pending: OverlayPending | undefined): Promise<void> {
    this.checked.delete(token);
    if (pending === undefined) {
      if (rec.pending === undefined) return;
      delete rec.pending;
    } else rec.pending = pending;
    await this.tokens.update(token, rec);
  }

  /**
   * One look at the unlock a card waits for. Still locked, or the app still starting: what it
   * waits for. Open: the request is spent first, then the sign-in starts (or the chain goes on)
   * if the top frame still holds the card's https document; one attempt. Null: nothing waits
   * any more (resumed, refused, or past the deadline).
   */
  private async resume(token: string, rec: OverlayRecord): Promise<OverlayWaiting | null> {
    const p = rec.pending;
    if (!p) return null;
    const t = this.now();
    if (t < p.at || t - p.at > UNLOCK_WAIT_MS) {
      await this.setPending(token, rec, undefined);
      return null;
    }
    const last = this.checked.get(token);
    if (this.resuming.has(token)) return last?.waiting ?? "locked";
    if (last && t >= last.at && t - last.at < UNLOCK_CHECK_MS) return last.waiting;
    this.resuming.add(token);
    try {
      const wait = (waiting: OverlayWaiting): OverlayWaiting => {
        this.checked.set(token, { at: t, waiting });
        return waiting;
      };
      let locked: boolean;
      try {
        if (p.sent) locked = (await this.deps.session.request({ op: "status" })).locked;
        else {
          // The app launched for this card answers now: its `unlock` goes, once, open already or
          // not (the Mac app's cue to give the front back to the browser).
          locked = this.deps.unlockOp ? await this.deps.unlockOp(rec.tabId) : (await this.deps.session.request({ op: "unlock" })).locked;
          p.sent = true;
          await this.tokens.update(token, rec);
        }
      } catch (e) {
        const code = toBgError(e).code;
        if (code === "locked") return wait("locked");
        if (code === "host_missing" || code === "timeout") return wait("host_missing");
        await this.setPending(token, rec, undefined);
        return null;
      }
      if (locked) return wait("locked");
      if (rec.pending !== p) return null;
      await this.setPending(token, rec, undefined);
      if (!(await this.stillBound(rec))) return null;
      try {
        if (p.kind === "chain") await this.deps.resumeChain?.(rec.tabId);
        else if (p.kind === "page") await this.deps.resumePage?.(rec);
        else if (p.itemId !== undefined) {
          const opts: StartOptions = p.accountId !== undefined ? { accountId: p.accountId } : {};
          if (p.picked !== undefined) opts.picked = p.picked;
          await this.deps.chain.start(rec.tabId, p.itemId, p.provider, opts);
        }
      } catch {
        // Not started: the card shows its offer (or the chain's stop) again.
      }
      return null;
    } finally {
      this.resuming.delete(token);
    }
  }

  /** The top frame still holds the https document the card was opened in. */
  private async stillBound(rec: OverlayRecord): Promise<boolean> {
    const f = await this.deps.frames?.details(rec.tabId, 0);
    const o = f ? parseOrigin(f.url) : null;
    if (!f || !o?.page || o.origin !== rec.origin) return false;
    return rec.documentId === undefined || f.documentId === undefined || f.documentId === rec.documentId;
  }

  /** The overlay page's content height: its frame is sized to it. */
  async resize(token: string, ui: UiContext, height: number): Promise<object> {
    const rec = await this.record(token, ui);
    await resizeFrame(this.deps.ext.tabs, rec, "overlay", height);
    return {};
  }

  /**
   * One surface (the inline menu, a save prompt) takes the place of the
   * overlay: an offer or an ended chain goes away, and is not offered again
   * in that document. A running chain keeps its progress (true).
   */
  async yieldTo(tabId: number): Promise<boolean> {
    const live = await this.tokens.forTab(tabId);
    if (!live) return false;
    if ((await this.deps.chain.state(tabId))?.status === "running") return true;
    await this.tokens.drop(live.token);
    await removeFrame(this.deps.ext.tabs, live.rec, "overlay");
    await this.deps.chain.closed?.(tabId, live.rec.origin, live.rec.documentId);
    return false;
  }

  async stop(token: string, ui: UiContext): Promise<object> {
    const rec = await this.record(token, ui);
    // "Annuler" while the card waits for an unlock: nothing resumes.
    await this.setPending(token, rec, undefined);
    await this.deps.chain.stop(rec.tabId);
    return {};
  }

  async close(token: string, ui: UiContext): Promise<object> {
    const rec = await this.record(token, ui);
    this.checked.delete(token);
    await this.tokens.drop(token);
    await removeFrame(this.deps.ext.tabs, rec, "overlay");
    await this.deps.chain.closed?.(rec.tabId, rec.origin, rec.documentId);
    return {};
  }
}
