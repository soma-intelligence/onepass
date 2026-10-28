// "Connexion en un clic" overlay (spec 8.6): `overlay.html#<token>` in the
// top frame of a tab. The token binds the tab, top frame and origin; the
// overlay gets the sign-in choices for that origin and starts or stops the
// chain. It renders whatever state the chain driver reports.
import type { Summary } from "../bridge/client";
import type { BgToCs, FrameKind, ProviderId } from "../shared/messages";
import { PROVIDERS } from "../shared/providers";
import type { OverlayAccount, OverlayInit, SignInChoice } from "../shared/ui";
import { signInChoices } from "./chain/choices";
import type { ChainDriver } from "./chain/types";
import type { BgExt, StorageArea } from "./ext";
import type { CsContext, UiContext } from "./frames";
import { BgError, type Session } from "./session";
import { type BoundRecord, FrameTokens, isBoundRecord } from "./tokens";

export const OVERLAY_TTL_MS = 30 * 60 * 1000;

export interface OverlayOffer {
  password: boolean;
  providers: ProviderId[];
}

export interface OverlayRecord extends BoundRecord {
  /** Sign-in choices shown by `overlay_init`; a start must be one of them. */
  offered?: Record<string, OverlayOffer>;
  /** Provider accounts shown per provider; a picked account must be one of them. */
  accounts?: Record<string, string[]>;
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
    const base = { itemId: it.item_id, title: it.title, iconLetter: it.icon_letter, iconColor: it.icon_color };
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
): Promise<void> {
  const msg: BgToCs = { type: "resize_frame", kind, height };
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
  now?: () => number;
}

export class Overlays {
  readonly tokens: FrameTokens<OverlayRecord>;

  constructor(private readonly deps: OverlayDeps) {
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
  async open(cs: CsContext, anchorRef?: string): Promise<string> {
    if (cs.frameId !== 0) throw new BgError("invalid");
    const rec: Omit<OverlayRecord, "createdAt"> = { tabId: cs.tabId, frameId: 0, origin: cs.origin };
    if (cs.documentId !== undefined) rec.documentId = cs.documentId;
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

  async init(token: string, ui: UiContext): Promise<OverlayInit> {
    const rec = await this.record(token, ui);
    const { items } = await this.deps.session.request({ op: "list_for_origin", ctx: "overlay", origin: rec.origin });
    const choices = this.deps.local ? await signInChoices(this.deps.session, this.deps.local, "overlay", rec.origin, items) : [];
    const accounts = overlayAccounts(items, choices);
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
    return { origin: rec.origin, accounts, chain: await this.deps.chain.state(rec.tabId, true) };
  }

  async state(token: string, ui: UiContext) {
    const rec = await this.record(token, ui);
    return { chain: await this.deps.chain.state(rec.tabId) };
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
    await this.deps.chain.start(rec.tabId, itemId, provider, accountId !== undefined ? { accountId } : {});
    return {};
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
    await this.deps.chain.stop(rec.tabId);
    return {};
  }

  async close(token: string, ui: UiContext): Promise<object> {
    const rec = await this.record(token, ui);
    await this.tokens.drop(token);
    await removeFrame(this.deps.ext.tabs, rec, "overlay");
    await this.deps.chain.closed?.(rec.tabId, rec.origin, rec.documentId);
    return {};
  }
}
