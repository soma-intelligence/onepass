// Passkeys (spec 3.2): `navigator.credentials.get/create` of a page, relayed
// by the content scripts (content/passkey-shim.ts in the MAIN world, then
// content/passkey.ts), answered with the native bridge's `passkey_list`,
// `passkey_get` and `passkey_create`.
//
// Rules:
// - the origin is the frame's as the browser reports it in `sender`, never a
//   value of the page; the page's `rpId` is only a request, checked by the host;
// - the top frame, or a frame whose every ancestor has exactly its origin; any
//   other frame, http, no matching passkey: the browser's own API (`fallback`);
// - a passkey is used without a window only while a chain "Connexion en un clic"
//   the user started runs in this tab for the item holding it (its click is the
//   consent), in the top frame at exactly the origin of the chain's current
//   step, for an rpId that is its host or a parent, once per chain; otherwise
//   the choice window `passkey.html#<token>` opens, bound to the requesting tab,
//   frame and document, and nothing is signed before a trusted click there (the
//   page's click guard). A creation always asks;
// - the window opens only on a page call made under a user activation (read by
//   the isolated relay), in the active tab, at most PASSKEY_WINDOWS_PER_MIN per
//   tab, never within PASSKEY_COOLDOWN_MS of a refusal for the same tab, site
//   and kind of call (get or create);
//   the host's list is asked at most PASSKEY_PROBES_PER_MIN per tab. Past any of
//   these, the browser's API (a page cannot pop windows or probe the vault);
// - one window per document: a second request while one is open is refused;
// - the page (MAIN world) only ever gets the final assertion or registration.
import type { RequestFor } from "../bridge/client";
import { parseOrigin } from "../shared/domain";
import {
  type PasskeyAccount,
  type PasskeyCreateRequest,
  type PasskeyErrorName,
  type PasskeyGetRequest,
  type PasskeyInit,
  type PasskeyRequest,
  type PasskeyResult,
  isB64url,
  parsePasskeyRequest,
  PASSKEY_MAX_CREDENTIAL_ID,
} from "../shared/messages";
import { newToken } from "../shared/tokens";
import type { ChainDriver } from "./chain/types";
import type { BgExt, Event, MessageListener } from "./ext";
import { type CsContext, type Frames, type UiContext, contentSender, extensionSender } from "./frames";
import { BgError, type Session, toBgError } from "./session";

/** COSE ES256: the only algorithm the host signs with. */
export const ES256 = -7;
/** A request waits at most this long for the user; the page's `timeout` may shorten it, not below the floor. */
export const PASSKEY_MAX_WAIT_MS = 5 * 60 * 1000;
export const PASSKEY_MIN_WAIT_MS = 30 * 1000;
/** Size of the choice window. */
export const PASSKEY_WINDOW = { width: 380, height: 460 } as const;
export const PASSKEY_PAGE = "passkey.html";
/** After a cancel (or a closed window), the browser's API for that tab, site and kind of call this long. */
export const PASSKEY_COOLDOWN_MS = 10 * 1000;
/** Per tab and minute: choice windows opened, host lists asked. */
export const PASSKEY_WINDOWS_PER_MIN = 3;
export const PASSKEY_PROBES_PER_MIN = 6;
const MINUTE = 60 * 1000;

const TOKEN_RE = /^[A-Za-z0-9_-]{22}$/;
const REQ_ID_RE = /^[A-Za-z0-9_-]{1,32}$/;
const MAX_ITEM_ID = 128;

/** The slice of `windows` the choice window needs (absent: the browser's API is used). */
export interface PasskeyWindows {
  create(o: {
    url: string;
    type: "popup";
    width: number;
    height: number;
    focused: boolean;
  }): Promise<{ id?: number; tabs?: { id?: number }[] } | undefined>;
  remove(windowId: number): Promise<void>;
  /** "Autre appareil": the requesting tab's window comes back to the front first. */
  update?(windowId: number, o: { focused: boolean }): Promise<unknown>;
  onRemoved: Event<(windowId: number) => void>;
}

export interface PasskeyDeps {
  session: Pick<Session, "request">;
  frames: Pick<Frames, "ancestorsOfOrigin" | "checkFillTarget" | "frameOrigin">;
  chain: Pick<ChainDriver, "state">;
  windows?: PasskeyWindows;
  runtime: Pick<BgExt["runtime"], "getURL">;
  /** The requesting tab must be the active one of its window. */
  tabs: { get(tabId: number): Promise<{ active?: boolean; windowId?: number } | undefined> };
  now?: () => number;
  timers?: { setTimeout(fn: () => void, ms: number): unknown; clearTimeout(id: unknown): void };
}

interface Ctx {
  cs: CsContext;
  topOrigin: string;
  rpId: string;
}

interface Pending extends Ctx {
  token: string;
  key: string;
  doc: string;
  req: PasskeyRequest;
  /** get: the passkeys the window may offer; create: the site's passkeys (exclude check). */
  offered: PasskeyAccount[];
  /** create: the vaults `passkey_init` offered. */
  vaults?: { id: string; name: string }[];
  windowId?: number;
  uiTabId?: number;
  opened: Promise<void>;
  timer: unknown;
  busy: boolean;
  resolve: (r: PasskeyResult) => void;
}

/** A request between its arrival and its window: an abort or a navigation lands here (no window then). */
interface Early {
  tabId: number;
  frameId: number;
  aborted: boolean;
  /** The requesting document went away (a navigation of its frame or of the top frame). */
  gone: boolean;
}

const FALLBACK: PasskeyResult = { kind: "fallback" };
const fail = (name: PasskeyErrorName): PasskeyResult => ({ kind: "error", name });

function hostOf(origin: string): string {
  try {
    return new URL(origin).hostname;
  } catch {
    return "";
  }
}

export class Passkeys {
  private readonly byToken = new Map<string, Pending>();
  private readonly byKey = new Map<string, Pending>();
  private readonly byDoc = new Map<string, Pending>();
  private readonly early = new Map<string, Early>();
  /** `tabId:site:kind` -> end of the cooldown. */
  private readonly cooldown = new Map<string, number>();
  /** Per tab: times of the windows opened, of the lists asked (last minute). */
  private readonly opened = new Map<number, number[]>();
  private readonly probes = new Map<number, number[]>();
  /** Chains (`tabId:itemId:startedAt`) that already signed once without a window. */
  private readonly chainSigned = new Set<string>();
  private readonly timers: NonNullable<PasskeyDeps["timers"]>;
  private readonly now: () => number;

  constructor(private readonly deps: PasskeyDeps) {
    this.now = deps.now ?? (() => Date.now());
    this.timers = deps.timers ?? {
      setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
      clearTimeout: (id) => globalThis.clearTimeout(id as ReturnType<typeof setTimeout>),
    };
  }

  install(ext: { webNavigation: Pick<BgExt["webNavigation"], "onCommitted">; tabs: Pick<BgExt["tabs"], "onRemoved"> }): void {
    ext.webNavigation.onCommitted.addListener((d) => {
      for (const e of this.early.values()) {
        if (e.tabId === d.tabId && (d.frameId === 0 || d.frameId === e.frameId)) e.gone = true;
      }
      for (const p of [...this.byToken.values()]) {
        if (p.cs.tabId === d.tabId && (d.frameId === 0 || d.frameId === p.cs.frameId)) this.finish(p, fail("NotAllowedError"));
      }
    });
    ext.tabs.onRemoved.addListener((tabId) => {
      for (const p of [...this.byToken.values()]) if (p.cs.tabId === tabId) this.finish(p, fail("NotAllowedError"));
      this.opened.delete(tabId);
      this.probes.delete(tabId);
      this.forgetChains(tabId);
      for (const k of [...this.cooldown.keys()]) if (k.startsWith(`${tabId}:`)) this.cooldown.delete(k);
    });
    this.deps.windows?.onRemoved.addListener((windowId) => {
      for (const p of [...this.byToken.values()]) {
        if (p.windowId === windowId) {
          this.coolDown(p);
          this.finish(p, fail("NotAllowedError"), false);
        }
      }
    });
  }

  /** Times of `map[tabId]` within the last minute (pruned). */
  private recent(map: Map<number, number[]>, tabId: number): number[] {
    const since = this.now() - MINUTE;
    const list = (map.get(tabId) ?? []).filter((t) => t > since);
    map.set(tabId, list);
    return list;
  }

  private cooldownKey(cs: CsContext, kind: PasskeyRequest["kind"]): string {
    return `${cs.tabId}:${parseOrigin(cs.origin)?.site ?? cs.origin}:${kind}`;
  }

  private coolDown(p: Pending): void {
    this.cooldown.set(this.cooldownKey(p.cs, p.req.kind), this.now() + PASSKEY_COOLDOWN_MS);
  }

  /** May a choice window open for this request (before any list is asked)? */
  private async mayOpen(cs: CsContext, kind: PasskeyRequest["kind"], activated: boolean): Promise<boolean> {
    if (!activated || !this.deps.windows) return false;
    const until = this.cooldown.get(this.cooldownKey(cs, kind));
    if (until !== undefined && this.now() < until) return false;
    if (this.recent(this.opened, cs.tabId).length >= PASSKEY_WINDOWS_PER_MIN) return false;
    const tab = await Promise.resolve()
      .then(() => this.deps.tabs.get(cs.tabId))
      .catch(() => undefined);
    return tab?.active === true;
  }

  /**
   * The running chain of this tab, when it may sign without a window here:
   * the top frame, at exactly the origin of the chain's current step on its
   * site (for a provider chain, once back on it), an rpId that is that
   * origin's host or one of its parents, and no silent assertion yet in this
   * chain. Anything else: the window.
   */
  private async silentChain(c: Ctx): Promise<{ itemId: string; key: string } | null> {
    const { cs, rpId } = c;
    let chain;
    try {
      chain = await this.deps.chain.state(cs.tabId);
    } catch {
      // Unreadable: no silent assertion, and what this tab's chains signed is kept.
      return null;
    }
    if (chain?.status !== "running") {
      this.forgetChains(cs.tabId);
      return null;
    }
    if (chain.startedAt === undefined) return null;
    const key = `${cs.tabId}:${chain.itemId}:${chain.startedAt}`;
    if (cs.frameId !== 0 || this.chainSigned.has(key)) return null;
    if (chain.origin === undefined || chain.origin !== cs.origin) return null;
    const host = hostOf(cs.origin);
    if (host === "" || !(rpId === host || host.endsWith(`.${rpId}`))) return null;
    if (chain.provider !== undefined && !(chain.phase === "back" || chain.phase === "signin" || chain.phase === "code")) return null;
    return { itemId: chain.itemId, key };
  }

  /** No chain runs in this tab any more: what its chains signed is forgotten. */
  private forgetChains(tabId: number): void {
    for (const k of [...this.chainSigned]) if (k.startsWith(`${tabId}:`)) this.chainSigned.delete(k);
  }

  /**
   * A page asked for a passkey; resolves when it has its answer. `activated`:
   * the page's call came with a transient user activation (the relay read it).
   */
  async request(cs: CsContext, reqId: string, req: PasskeyRequest, activated: boolean): Promise<PasskeyResult> {
    const key = `${cs.tabId}:${cs.frameId}:${reqId}`;
    if (this.early.has(key) || this.byKey.has(key)) return fail("NotAllowedError");
    const e: Early = { tabId: cs.tabId, frameId: cs.frameId, aborted: false, gone: false };
    this.early.set(key, e);
    try {
      return await this.route(cs, reqId, req, activated, e);
    } finally {
      if (this.early.get(key) === e) this.early.delete(key);
    }
  }

  private async route(cs: CsContext, reqId: string, req: PasskeyRequest, activated: boolean, e: Early): Promise<PasskeyResult> {
    const origin = parseOrigin(cs.origin);
    if (!origin?.https) return FALLBACK;
    if (cs.frameId !== 0 && !(await this.deps.frames.ancestorsOfOrigin(cs.tabId, cs.frameId, origin.origin))) return FALLBACK;
    // The top frame's origin as the browser reports it (the host refuses `top_origin` != `origin`).
    const topOrigin = cs.frameId === 0 ? origin.origin : await this.deps.frames.frameOrigin(cs.tabId, 0);
    if (topOrigin === null) return FALLBACK;
    const rpId = req.rpId ?? hostOf(origin.origin);
    if (rpId === "") return FALLBACK;
    const c: Ctx = { cs: { ...cs, origin: origin.origin }, topOrigin, rpId };
    // A creation never goes through a chain; a get may, else it needs the window.
    const chain = req.kind === "get" ? await this.silentChain(c) : null;
    const canOpen = await this.mayOpen(c.cs, req.kind, activated);
    if (!chain && !canOpen) return FALLBACK;
    const probes = this.recent(this.probes, cs.tabId);
    if (probes.length >= PASSKEY_PROBES_PER_MIN) return FALLBACK;
    probes.push(this.now());
    let listed: PasskeyAccount[];
    try {
      const r = await this.deps.session.request({ op: "passkey_list", ctx: "passkey", origin: origin.origin, rp_id: rpId });
      listed = r.passkeys.map((p) => ({
        itemId: p.item_id,
        credentialId: p.credential_id,
        title: p.title,
        userName: p.user_name,
        vaultName: p.vault_name,
      }));
    } catch {
      // Locked, unpaired, an rpId the host refuses: the browser decides.
      return FALLBACK;
    }
    // The page aborted, or its document went away, while the host listed: no window.
    if (e.aborted) return fail("AbortError");
    if (e.gone) return fail("NotAllowedError");
    if (req.kind === "get") return this.get(c, reqId, req, listed, chain, canOpen);
    return this.create(c, reqId, req, listed, canOpen);
  }

  private async get(
    c: Ctx,
    reqId: string,
    req: PasskeyGetRequest,
    listed: PasskeyAccount[],
    chain: { itemId: string; key: string } | null,
    canOpen: boolean,
  ): Promise<PasskeyResult> {
    const offered = req.allow.length === 0 ? listed : listed.filter((p) => req.allow.includes(p.credentialId));
    if (offered.length === 0) return FALLBACK;
    // Spec 3.2: the click that started this tab's chain for this very item is the consent.
    // Checked again here, with no wait before it is noted: two requests listed side by side sign once.
    const own = chain && !this.chainSigned.has(chain.key) ? offered.find((p) => p.itemId === chain.itemId) : undefined;
    if (chain && own) {
      this.chainSigned.add(chain.key);
      try {
        return await this.assert(c, req, own, "chain");
      } catch {
        return fail("NotAllowedError");
      }
    }
    if (!canOpen) return FALLBACK;
    return this.open(c, reqId, req, offered);
  }

  private async create(c: Ctx, reqId: string, req: PasskeyCreateRequest, listed: PasskeyAccount[], canOpen: boolean): Promise<PasskeyResult> {
    if (!req.algs.includes(ES256) || !canOpen) return FALLBACK;
    return this.open(c, reqId, req, listed);
  }

  private async assert(c: Ctx, req: PasskeyGetRequest, p: PasskeyAccount, ctx: "passkey" | "chain"): Promise<PasskeyResult> {
    const body = {
      op: "passkey_get",
      ctx,
      origin: c.cs.origin,
      top_origin: c.topOrigin,
      rp_id: c.rpId,
      item_id: p.itemId,
      credential_id: p.credentialId,
      challenge: req.challenge,
    };
    const a = await this.deps.session.request(body as RequestFor<"passkey_get">);
    return {
      kind: "assertion",
      credentialId: a.credential_id,
      clientDataJSON: a.client_data_json,
      authenticatorData: a.authenticator_data,
      signature: a.signature,
      userHandle: a.user_handle,
    };
  }

  private open(c: Ctx, reqId: string, req: PasskeyRequest, offered: PasskeyAccount[]): Promise<PasskeyResult> {
    const windows = this.deps.windows;
    if (!windows) return Promise.resolve(FALLBACK);
    const doc = `${c.cs.tabId}:${c.cs.frameId}:${c.cs.documentId ?? ""}`;
    if (this.byDoc.has(doc)) return Promise.resolve(fail("NotAllowedError"));
    const key = `${c.cs.tabId}:${c.cs.frameId}:${reqId}`;
    return new Promise<PasskeyResult>((resolve) => {
      const token = newToken();
      const wait = Math.min(PASSKEY_MAX_WAIT_MS, Math.max(PASSKEY_MIN_WAIT_MS, req.timeout ?? PASSKEY_MAX_WAIT_MS));
      const p: Pending = { ...c, token, key, doc, req, offered, opened: Promise.resolve(), timer: undefined, busy: false, resolve };
      p.timer = this.timers.setTimeout(() => this.finish(p, fail("NotAllowedError")), wait);
      this.byToken.set(token, p);
      this.byKey.set(key, p);
      this.early.delete(key);
      this.recent(this.opened, c.cs.tabId).push(this.now());
      this.byDoc.set(doc, p);
      p.opened = windows
        .create({ url: `${this.deps.runtime.getURL(PASSKEY_PAGE)}#${token}`, type: "popup", ...PASSKEY_WINDOW, focused: true })
        .then((w) => {
          if (typeof w?.id === "number") p.windowId = w.id;
          const tab = w?.tabs?.[0]?.id;
          if (typeof tab === "number") p.uiTabId = tab;
          // Finished while the window opened: close it now.
          if (this.byToken.get(token) !== p && p.windowId !== undefined) void windows.remove(p.windowId).catch(() => undefined);
        })
        .catch(() => this.finish(p, FALLBACK));
    });
  }

  private finish(p: Pending, r: PasskeyResult, closeWindow = true): void {
    if (this.byToken.get(p.token) !== p) return;
    this.byToken.delete(p.token);
    this.byKey.delete(p.key);
    this.byDoc.delete(p.doc);
    this.timers.clearTimeout(p.timer);
    p.offered = [];
    if (closeWindow && p.windowId !== undefined) void this.deps.windows?.remove(p.windowId).catch(() => undefined);
    p.resolve(r);
  }

  /** The page's AbortSignal fired. */
  async abort(cs: CsContext, reqId: string): Promise<object> {
    const key = `${cs.tabId}:${cs.frameId}:${reqId}`;
    const e = this.early.get(key);
    if (e) e.aborted = true;
    const p = this.byKey.get(key);
    if (p) this.finish(p, fail("AbortError"));
    return {};
  }

  /** The pending request of `token`, if `ui` is its own window. */
  private async pending(token: string, ui: UiContext): Promise<Pending> {
    const p = TOKEN_RE.test(token) ? this.byToken.get(token) : undefined;
    if (!p || ui.page !== PASSKEY_PAGE) throw new BgError("invalid");
    await p.opened;
    if (ui.tabId === undefined || ui.tabId !== p.uiTabId || this.byToken.get(token) !== p) throw new BgError("invalid");
    return p;
  }

  async init(token: string, ui: UiContext): Promise<PasskeyInit> {
    const p = await this.pending(token, ui);
    const out: PasskeyInit = { kind: p.req.kind, origin: p.cs.origin, rpId: p.rpId, accounts: [] };
    if (p.req.kind === "get") {
      out.accounts = p.offered.map((a) => ({ ...a }));
    } else {
      out.userName = p.req.userName;
      try {
        const r = await this.deps.session.request({ op: "vaults" });
        p.vaults = r.vaults.map((v) => ({ id: v.id, name: v.name }));
      } catch {
        p.vaults = [];
      }
      out.vaults = p.vaults.map((v) => ({ ...v }));
    }
    return out;
  }

  /** Re-reads the requesting frame: still the same document and origin, still allowed. */
  private async stillThere(p: Pending): Promise<boolean> {
    const check = await this.deps.frames.checkFillTarget(p.cs.tabId, p.cs.frameId, p.cs.origin, p.cs.documentId, "same_origin");
    return check.ok;
  }

  private async exclusive(p: Pending, fn: () => Promise<void>): Promise<object> {
    if (p.busy) throw new BgError("invalid");
    p.busy = true;
    try {
      if (!(await this.stillThere(p))) {
        this.finish(p, fail("NotAllowedError"));
        return {};
      }
      await fn();
      return {};
    } finally {
      p.busy = false;
    }
  }

  async pick(token: string, ui: UiContext, itemId: string, credentialId: string): Promise<object> {
    const p = await this.pending(token, ui);
    const req = p.req;
    if (req.kind !== "get") throw new BgError("invalid");
    const chosen = p.offered.find((a) => a.itemId === itemId && a.credentialId === credentialId);
    if (!chosen) throw new BgError("invalid");
    return this.exclusive(p, async () => {
      // A refusal (reprompt, rate limit, locked) stays in the window: the user sees it.
      this.finish(p, await this.assert(p, req, chosen, "passkey"));
    });
  }

  async save(token: string, ui: UiContext, vaultId?: string): Promise<object> {
    const p = await this.pending(token, ui);
    const req = p.req;
    if (req.kind !== "create") throw new BgError("invalid");
    if (vaultId !== undefined && !p.vaults?.some((v) => v.id === vaultId)) throw new BgError("invalid");
    return this.exclusive(p, async () => {
      // WebAuthn: an excluded credential answers InvalidStateError, after the user's consent.
      if (req.exclude.some((id) => p.offered.some((a) => a.credentialId === id))) {
        this.finish(p, fail("InvalidStateError"));
        return;
      }
      const body: Record<string, unknown> = {
        op: "passkey_create",
        ctx: "passkey",
        origin: p.cs.origin,
        top_origin: p.topOrigin,
        rp_id: p.rpId,
        user_name: req.userName,
        user_handle: req.userId,
        challenge: req.challenge,
        exclude: [...req.exclude],
      };
      if (vaultId !== undefined) body.vault_id = vaultId;
      let r;
      try {
        r = await this.deps.session.request(body as unknown as RequestFor<"passkey_create">);
      } catch (e) {
        // The host's `excluded` (a credential outside the listed logins, archived or hidden).
        if (toBgError(e).code === "excluded") {
          this.finish(p, fail("InvalidStateError"));
          return;
        }
        throw toBgError(e);
      }
      this.finish(p, {
        kind: "registration",
        credentialId: r.credential_id,
        clientDataJSON: r.client_data_json,
        attestationObject: r.attestation_object,
        authenticatorData: r.authenticator_data,
        publicKey: r.public_key,
        publicKeyAlgorithm: r.public_key_algorithm,
      });
    });
  }

  /**
   * "Autre appareil": the requesting tab's window is focused again, then the
   * page's call goes to the browser, whose own dialog then shows over that
   * tab rather than behind the closing window.
   */
  async other(token: string, ui: UiContext): Promise<object> {
    const p = await this.pending(token, ui);
    await this.refocus(p.cs.tabId);
    this.finish(p, FALLBACK);
    return {};
  }

  private async refocus(tabId: number): Promise<void> {
    const update = this.deps.windows?.update;
    if (!update) return;
    try {
      const tab = await this.deps.tabs.get(tabId);
      if (typeof tab?.windowId === "number") await update.call(this.deps.windows, tab.windowId, { focused: true });
    } catch {
      // The tab or its window is gone: the browser's API all the same.
    }
  }

  async cancel(token: string, ui: UiContext): Promise<object> {
    const p = await this.pending(token, ui);
    this.coolDown(p);
    this.finish(p, fail("NotAllowedError"));
    return {};
  }
}

// ---- router ----

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const tokenOf = (o: Obj): string | null => (typeof o.token === "string" && TOKEN_RE.test(o.token) ? o.token : null);
const itemIdOf = (v: unknown): string | null => (typeof v === "string" && v.length >= 1 && v.length <= MAX_ITEM_ID ? v : null);

type Reply = { ok: unknown } | { err: string };

function run(p: Promise<unknown>, sendResponse: (r: Reply) => void): true {
  p.then(
    (ok) => sendResponse({ ok: ok ?? null }),
    (e) => sendResponse({ err: toBgError(e).code }),
  );
  return true;
}

/**
 * The passkey messages of the worker, a `runtime.onMessage` listener beside
 * the main router: `passkey_*` from passkey.html only, `passkey_request` and
 * `passkey_abort` from content scripts (origin from `sender`). Everything
 * else: no reply, the main router handles it.
 */
export function createPasskeyRouter(runtime: Pick<BgExt["runtime"], "id" | "getURL">, passkeys: Passkeys): MessageListener {
  return (message, sender, sendResponse) => {
    if (!isObj(message) || typeof message.type !== "string" || !message.type.startsWith("passkey_")) return undefined;
    const m = message;
    const ui = extensionSender(runtime, sender);
    if (ui) {
      if (ui.page !== PASSKEY_PAGE) return undefined;
      const token = tokenOf(m);
      if (!token) return undefined;
      switch (m.type) {
        case "passkey_init":
          return run(passkeys.init(token, ui), sendResponse);
        case "passkey_pick": {
          const itemId = itemIdOf(m.itemId);
          if (!itemId || !isB64url(m.credentialId, PASSKEY_MAX_CREDENTIAL_ID)) return undefined;
          return run(passkeys.pick(token, ui, itemId, m.credentialId), sendResponse);
        }
        case "passkey_save": {
          let vaultId: string | undefined;
          if (m.vaultId !== undefined) {
            const v = itemIdOf(m.vaultId);
            if (!v) return undefined;
            vaultId = v;
          }
          return run(passkeys.save(token, ui, vaultId), sendResponse);
        }
        case "passkey_other":
          return run(passkeys.other(token, ui), sendResponse);
        case "passkey_cancel":
          return run(passkeys.cancel(token, ui), sendResponse);
        default:
          return undefined;
      }
    }
    if (sender.id !== runtime.id) return undefined;
    if (typeof m.reqId !== "string" || !REQ_ID_RE.test(m.reqId)) return undefined;
    const reqId = m.reqId;
    if (m.type === "passkey_request") {
      // Passkeys trust only the origin the browser stamps on the sender, never
      // one derived from `sender.url` (absent on Firefox, "null" when opaque):
      // without it, the browser's own API.
      const so = (sender as { origin?: unknown }).origin;
      if (typeof so !== "string" || so === "null") {
        sendResponse({ ok: FALLBACK });
        return undefined;
      }
    }
    const cs = contentSender(runtime, sender);
    if (!cs) return undefined;
    if (m.type === "passkey_request") {
      // Rebuilt from checked fields only: an `origin` of the page never gets through.
      const req = parsePasskeyRequest(m.request);
      if (!req) return undefined;
      return run(passkeys.request(cs, reqId, req, m.activated === true), sendResponse);
    }
    if (m.type === "passkey_abort") return run(passkeys.abort(cs, reqId), sendResponse);
    return undefined;
  };
}
