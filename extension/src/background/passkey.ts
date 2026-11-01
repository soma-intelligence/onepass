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
//   consent); otherwise the choice window `passkey.html#<token>` opens, bound to
//   the requesting tab, frame and document, and nothing is signed before a
//   trusted click there (the page's click guard). A creation always asks;
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
  onRemoved: Event<(windowId: number) => void>;
}

export interface PasskeyDeps {
  session: Pick<Session, "request">;
  frames: Pick<Frames, "ancestorsOfOrigin" | "checkFillTarget" | "frameOrigin">;
  chain: Pick<ChainDriver, "state">;
  windows?: PasskeyWindows;
  runtime: Pick<BgExt["runtime"], "getURL">;
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
  private readonly timers: NonNullable<PasskeyDeps["timers"]>;

  constructor(private readonly deps: PasskeyDeps) {
    this.timers = deps.timers ?? {
      setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
      clearTimeout: (id) => globalThis.clearTimeout(id as ReturnType<typeof setTimeout>),
    };
  }

  install(ext: { webNavigation: Pick<BgExt["webNavigation"], "onCommitted">; tabs: Pick<BgExt["tabs"], "onRemoved"> }): void {
    ext.webNavigation.onCommitted.addListener((d) => {
      for (const p of [...this.byToken.values()]) {
        if (p.cs.tabId === d.tabId && (d.frameId === 0 || d.frameId === p.cs.frameId)) this.finish(p, fail("NotAllowedError"));
      }
    });
    ext.tabs.onRemoved.addListener((tabId) => {
      for (const p of [...this.byToken.values()]) if (p.cs.tabId === tabId) this.finish(p, fail("NotAllowedError"));
    });
    this.deps.windows?.onRemoved.addListener((windowId) => {
      for (const p of [...this.byToken.values()]) if (p.windowId === windowId) this.finish(p, fail("NotAllowedError"), false);
    });
  }

  /** A page asked for a passkey; resolves when it has its answer. */
  async request(cs: CsContext, reqId: string, req: PasskeyRequest): Promise<PasskeyResult> {
    const origin = parseOrigin(cs.origin);
    if (!origin?.https) return FALLBACK;
    if (cs.frameId !== 0 && !(await this.deps.frames.ancestorsOfOrigin(cs.tabId, cs.frameId, origin.origin))) return FALLBACK;
    // The top frame's origin as the browser reports it (the host refuses `top_origin` != `origin`).
    const topOrigin = cs.frameId === 0 ? origin.origin : await this.deps.frames.frameOrigin(cs.tabId, 0);
    if (topOrigin === null) return FALLBACK;
    const rpId = req.rpId ?? hostOf(origin.origin);
    if (rpId === "") return FALLBACK;
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
    const c: Ctx = { cs: { ...cs, origin: origin.origin }, topOrigin, rpId };
    if (req.kind === "get") return this.get(c, reqId, req, listed);
    return this.create(c, reqId, req, listed);
  }

  private async get(c: Ctx, reqId: string, req: PasskeyGetRequest, listed: PasskeyAccount[]): Promise<PasskeyResult> {
    const offered = req.allow.length === 0 ? listed : listed.filter((p) => req.allow.includes(p.credentialId));
    if (offered.length === 0) return FALLBACK;
    // Spec 3.2: the click that started this tab's chain for this very item is the consent.
    const chain = await this.deps.chain.state(c.cs.tabId).catch(() => null);
    if (chain?.status === "running") {
      const own = offered.find((p) => p.itemId === chain.itemId);
      if (own) {
        try {
          return await this.assert(c, req, own, "chain");
        } catch {
          return fail("NotAllowedError");
        }
      }
    }
    return this.open(c, reqId, req, offered);
  }

  private async create(c: Ctx, reqId: string, req: PasskeyCreateRequest, listed: PasskeyAccount[]): Promise<PasskeyResult> {
    if (!req.algs.includes(ES256)) return FALLBACK;
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
    const p = this.byKey.get(`${cs.tabId}:${cs.frameId}:${reqId}`);
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

  async other(token: string, ui: UiContext): Promise<object> {
    this.finish(await this.pending(token, ui), FALLBACK);
    return {};
  }

  async cancel(token: string, ui: UiContext): Promise<object> {
    this.finish(await this.pending(token, ui), fail("NotAllowedError"));
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
    const cs = contentSender(runtime, sender);
    if (!cs) return undefined;
    if (typeof m.reqId !== "string" || !REQ_ID_RE.test(m.reqId)) return undefined;
    const reqId = m.reqId;
    if (m.type === "passkey_request") {
      // Rebuilt from checked fields only: an `origin` of the page never gets through.
      const req = parsePasskeyRequest(m.request);
      if (!req) return undefined;
      return run(passkeys.request(cs, reqId, req), sendResponse);
    }
    if (m.type === "passkey_abort") return run(passkeys.abort(cs, reqId), sendResponse);
    return undefined;
  };
}
