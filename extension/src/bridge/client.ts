// Bridge client: pairing, session opening and application requests over a
// message transport (`chrome.runtime.connectNative` port in the extension,
// stdio of the native host in tests).
//
// Handshake frames are queued and consumed in order; once the session is
// open, `msg` frames are opened strictly in arrival order and replies are
// matched to requests by `id`. Ids start at 1 per client and are never
// reused, even after a timeout. Any protocol failure (bad frame, bad MAC,
// replayed or skipped counter, host error frame, transport closed) fails
// every pending request and closes the transport.
import type {
  ClientInfoRequest,
  Extra,
  IdentityFill,
  NoteAutofillRequest,
  NoteFillRequest,
  NoteFillResponse,
  PlanFillRequest,
  PlanFillResponse,
  ProviderId,
  WirePasswordContext,
} from "../shared/messages";
import { BridgeError, utf8, wipe } from "./bytes";
import type { Channel } from "./channel";
import { ExtPairing, PAIRING_TIMEOUT_MS, type PairingOptions, type PairingRecord } from "./pairing";
import { extHello } from "./session";
import { type Envelope, type EnvelopeType, type MsgEnvelope, expectType, parseEnvelope } from "./wire";

/** A message port: chrome native messaging, or a test double. */
export interface Transport {
  send(env: Envelope): void;
  /** Each received message, a parsed JSON value. */
  onMessage(cb: (msg: unknown) => void): void;
  onClose(cb: (reason?: Error) => void): void;
  close(): void;
}

// ---- Application requests (mirror of onepass_bridge::api) ----

/** `passkey`: the passkey choice window. */
/** `auto`: pair only if the app vouches for this browser (spec 2026-11-02-browser-auto-pairing). */
export interface PairOptions {
  auto?: boolean;
}

/**
 * `agent`: a fill an MCP agent asked for and the holder approved in the app
 * (spec 2026-11-07-agent-browser-fill 5); `plan_fill`, `fill_login` and
 * `fill_card` only, each with `agent_request`.
 */
export type Ctx = "popup" | "menu" | "overlay" | "save_prompt" | "chain" | "passkey" | "agent";
export type FillField = "username" | "password" | "totp";
export type MatchRule = "domain" | "exact_host" | "exact_url" | "never";

export interface Summary {
  item_id: string;
  vault_id: string;
  vault_name: string;
  title: string;
  subtitle: string;
  kind: "login" | "card" | "identity";
  icon_letter: string;
  icon_color: string;
  has_password: boolean;
  has_totp: boolean;
  methods: { provider: ProviderId; account_email: string }[];
  match: "exact_host" | "domain" | null;
  /** The match is an associated site (Apple's shared-credentials list), sent as `domain` in `match`; left out otherwise. */
  associated?: true;
  /** Label of the item's account, sent only when items of several accounts answer. */
  account?: string;
}

/** `smart` profile: Strong (default), Readable (words) or Custom (`length` and `symbols`). */
export type RecipeProfile = "strong" | "readable" | "custom";

/**
 * Generator recipe (`deny_unknown_fields` on the host: nothing else).
 * `profile`, `context` and `narrow` apply to `smart`; `length` is 8..=64
 * and, for `smart`, only read with the custom profile.
 */
export interface Recipe {
  kind: "random" | "memorable" | "pin" | "smart";
  length?: number;
  symbols?: boolean;
  profile?: RecipeProfile;
  context?: WirePasswordContext;
  /** Retry step after a `pattern` miss: 1 without symbols, 2 lowercase and digits. */
  narrow?: 0 | 1 | 2;
}

/** Where a constraint came from (onepass_core::site_password::Source). */
export type ReportSource = "password_rules" | "attributes" | "quirks" | "hints";

/** What `smart` generated, without any character of the password. */
export interface GenerationReport {
  length: number;
  lower: boolean;
  upper: boolean;
  digit: boolean;
  special: boolean;
  sources: ReportSource[];
  dropped: ReportSource[];
  fallback: boolean;
  readable_fell_back: boolean;
  weak_by_site: boolean;
  entropy_bits: number;
}

export interface LoginFill {
  username?: string;
  password?: string;
  totp?: string;
}

export interface Address {
  line1: string;
  line2: string;
  city: string;
  postal_code: string;
  region: string;
  country: string;
}

/** What `check_identity` and `save_identity` take: values typed in a form, "" when absent. */
export interface IdentityValues {
  given_name: string;
  family_name: string;
  email: string;
  tel: string;
  organization: string;
  address?: Address;
}

/** A passkey as `passkey_list` gives it: no key, no user handle. `credential_id` is base64url. */
export interface PasskeySummary {
  item_id: string;
  vault_id: string;
  vault_name: string;
  title: string;
  user_name: string;
  credential_id: string;
}

/** `passkey_get` reply: every value unpadded base64url; `client_data_json` built by the host from `origin`. */
export interface PasskeyAssertion {
  credential_id: string;
  client_data_json: string;
  authenticator_data: string;
  signature: string;
  user_handle: string;
}

/**
 * `passkey_create` reply: values unpadded base64url but `item_id` and `public_key_algorithm`
 * (always -7, ES256); `public_key` is the DER SubjectPublicKeyInfo.
 */
export interface PasskeyRegistration {
  item_id: string;
  credential_id: string;
  client_data_json: string;
  attestation_object: string;
  authenticator_data: string;
  public_key: string;
  public_key_algorithm: number;
}

/** `plan_fill` for an agent job: needs a live ticket of `agent_request`, which it does not spend. */
export interface AgentPlanFillRequest {
  ctx: "agent";
  agent_request: number;
  origin: string;
  context: PlanFillRequest["context"];
}

/** Error codes of an agent job, as the host reads them (`onepass_bridge::api::agent_error`). */
export type AgentErrorCode = "tab_mismatch" | "origin_mismatch" | "cross_site_frame" | "no_fields" | "timeout" | "denied";

/** A job of the agent session (`AgentJobWire`). */
export type AgentJob =
  | { job: "probe"; request_id: number; url: string }
  | { job: "fill"; request_id: number; item_id: string; kind: "login" | "card"; submit: boolean; document_id: string };

/** The active tab a probe found. */
export interface AgentProbe {
  tab_title: string;
  origin: string;
  document_id: string;
}

/** What a fill wrote: field names, never values. */
export interface AgentFilled {
  filled: string[];
  submitted: boolean;
}

/** A job result on the wire: `{"ok": {...}}` or `{"err": "<code>"}`. */
export type AgentResult<T> = { ok: T } | { err: AgentErrorCode };

interface Ops {
  status: { req: object; res: { locked: boolean; account: string; vaults: number } };
  /**
   * `origin`: the top-frame origin of the tab whose trusted gesture asks (https, or http on a
   * loopback host), for the app to show on its unlock. Absent when no page is concerned.
   */
  unlock: { req: { origin?: string }; res: { locked: boolean } };
  /** `account`: the OnePass account of the vault, when the host names one (several accounts). */
  /**
   * `origin`: the page a new item is for. The vaults of the account that page routes to come
   * first (the first is the default of a save there); a `save_*` with `vault_id: ""` goes to it.
   */
  vaults: { req: { origin?: string }; res: { vaults: { id: string; name: string; color: string | null; account?: string; shared?: boolean }[] } };
  list_for_origin: { req: { ctx: Ctx; origin: string }; res: { items: Summary[] } };
  search: { req: { ctx: Ctx; query: string }; res: { items: Summary[] } };
  list_fillable: { req: { ctx: Ctx; origin: string; kind: "card" | "identity" }; res: { items: Summary[] } };
  /** `agent_request`: with ctx `agent` only, the approved agent request whose ticket this fill spends. */
  fill_login: {
    req: { ctx: Ctx; agent_request?: number; item_id: string; origin: string; fields: FillField[] };
    res: LoginFill;
  };
  fill_card: {
    req: { ctx: Ctx; agent_request?: number; item_id: string; origin: string };
    /** `exp_month` "04", `exp_year` "2029": zero-padded strings, empty when unknown. */
    res: { cardholder: string; number: string; exp_month: string; exp_year: string; cvv?: string };
  };
  /** `extras`: only the documents and loyalty the form has roles for (left out when empty). */
  fill_identity: {
    req: { ctx: Ctx; item_id: string; origin: string; extras?: Extra[] };
    res: IdentityFill;
  };
  totp: { req: { ctx: Ctx; item_id: string; origin?: string }; res: { code: string; remaining: number } };
  reveal: { req: { ctx: Ctx; item_id: string; field: string }; res: { value: string } };
  check_credentials: {
    req: { ctx: Ctx; origin: string; username: string; password: string };
    /** `pending`: a pending Login of the site holds this password, whatever its username. */
    res: { status: "new" | "same" | "update" | "pending"; item_id?: string; title?: string };
  };
  save_login: {
    req: {
      ctx: Ctx;
      origin: string;
      title: string;
      username: string;
      password: string;
      vault_id: string;
      rule: MatchRule;
      tags: string[];
    };
    res: { item_id: string };
  };
  /**
   * A card typed by hand in a checkout (`save_prompt` only): `same` when a card with this number
   * is there (expiry equal or unknown), `update` when only its expiry differs.
   */
  check_card: {
    req: { ctx: Ctx; origin: string; number: string; exp_month: string; exp_year: string };
    res: { status: "new" | "same" | "update"; item_id?: string; title?: string };
  };
  /** A new card, or with `item_id` the expiry of that card (same number). Never a security code. */
  save_card: {
    req: {
      ctx: Ctx;
      origin: string;
      vault_id: string;
      title: string;
      cardholder: string;
      number: string;
      exp_month: string;
      exp_year: string;
      item_id?: string;
    };
    res: { item_id: string };
  };
  /** An identity or address typed by hand: `same` when one item already holds every value. */
  check_identity: {
    req: { ctx: Ctx; origin: string } & IdentityValues;
    res: { status: "new" | "same"; item_id?: string; title?: string };
  };
  save_identity: {
    req: { ctx: Ctx; origin: string; vault_id: string; title: string } & IdentityValues;
    res: { item_id: string };
  };
  update_password: {
    /**
     * `weak_by_site`: a regenerated pending Login's weak tag is set (true) or cleared (false).
     * `pending`: a change-password form's generated password (spec 5.2): the Login gets
     * `onepass:pending` in the same write, its form's submission confirms it (`confirm_pending`).
     */
    req: { ctx: Ctx; item_id: string; origin: string; password: string; weak_by_site?: boolean; pending?: boolean };
    res: Record<string, never>;
  };
  /**
   * A pending Login (tag `onepass:pending`) whose form was sent: the tag drops, a non-blank
   * `username` replaces the stored one. Same origin check as `update_password`; `invalid` for an
   * item without the tag, or one left without a username.
   */
  confirm_pending: {
    req: { ctx: Ctx; item_id: string; origin: string; username: string };
    res: Record<string, never>;
  };
  /**
   * Delete for good a Login the bridge saved itself through `save_login` in the last 60 s, for
   * the same registrable domain and not edited since (the save toast's Undo). `not_found` for
   * anything else.
   */
  undo_save: {
    req: { ctx: "save_prompt"; item_id: string; origin: string };
    res: Record<string, never>;
  };
  /**
   * Delete for good the pending Login `item_id`: a generated password the save card moved into the
   * login the user picked (spec 5.2). Only one this bridge session wrote through `save_login` as
   * pending, same registrable domain, still tagged `onepass:pending` and not edited since (but by
   * the session's own `update_password`). `not_found` for anything else.
   */
  discard_pending: {
    req: { ctx: "save_prompt"; item_id: string; origin: string };
    res: Record<string, never>;
  };
  /**
   * The save toast's Edit: a Login the bridge saved itself through `save_login` in the last 600 s,
   * same registrable domain, not edited since, gets `title` (blank: the site) and `username`
   * (blank: kept) in place; another `vault_id` moves it (saved there first, the old item deleted
   * after). `item_id`: the login as it is now (a new id after a move). `not_found` for anything else.
   */
  amend_save: {
    req: { ctx: "save_prompt"; item_id: string; origin: string; title: string; username: string; vault_id: string };
    res: { item_id: string };
  };
  generate: {
    req: {
      ctx: Ctx;
      recipe: Recipe;
      /** Page origin, for the site's known rules (`smart` only). */
      origin?: string;
    };
    res: { password: string; entropy_bits: number; report?: GenerationReport };
  };
  provider_accounts: {
    req: { ctx: Ctx; provider: ProviderId; origin: string };
    res: { accounts: Summary[]; linked_item_id?: string };
  };
  fill_provider: {
    req: {
      ctx: Ctx;
      account_item_id: string;
      provider: ProviderId;
      provider_origin: string;
      site_origin: string;
      fields: FillField[];
    };
    res: LoginFill;
  };
  link_provider: {
    req: { ctx: Ctx; site_origin: string; provider: ProviderId; account_item_id: string };
    res: { item_id: string };
  };
  /** The bridge session's username salt: 32 bytes as lower-case hex, the same until the session ends. */
  fill_salt: { req: { ctx: Ctx }; res: { salt: string } };
  /** A plan of item ids, roles and refs for a page context; never a value. */
  plan_fill: { req: PlanFillRequest | AgentPlanFillRequest; res: PlanFillResponse };
  /** What was filled where, for the site memory. */
  note_fill: { req: NoteFillRequest; res: NoteFillResponse };
  /** Forget a site in every item's memory (popup only); `site` is a host or an https origin, reduced by the host. */
  forget_site: { req: { ctx: Ctx; site: string }; res: { items: number } };
  /** This session's browser and opaque profile id, for the app's on-device autofill history. */
  client_info: { req: ClientInfoRequest; res: Record<string, never> };
  /** One autofill history event (a list shown, a pick, a dismissal, a fill); item ids only, never a value. */
  note_autofill: { req: NoteAutofillRequest; res: Record<string, never> };
  /**
   * Passkeys of `rp_id` for the browser's `origin` (ctx `passkey` or `chain`). The host checks
   * `rp_id` against `origin` (host or registrable parent, never a public suffix).
   */
  passkey_list: { req: { ctx: Ctx; origin: string; rp_id: string }; res: { passkeys: PasskeySummary[] } };
  /**
   * An assertion (ctx `passkey` or `chain`); `credential_id` and `challenge` base64url.
   * `top_origin`: the browser's origin of the tab's top frame; `not_allowed` unless it equals
   * `origin` (same-origin frames only). The authenticator data never claims UV.
   */
  passkey_get: {
    req: {
      ctx: Ctx;
      origin: string;
      top_origin: string;
      rp_id: string;
      item_id: string;
      credential_id: string;
      challenge: string;
    };
    res: PasskeyAssertion;
  };
  /**
   * A new passkey (ctx `passkey` only); `user_handle`, `challenge` and `exclude` ids base64url.
   * Error `excluded` when a stored credential is in `exclude`. `vault_id`: vault of a new Login
   * (first vault when left out).
   */
  /** Long poll of the agent session: the next agent job, `null` after the host's wait (25 s). */
  agent_wait: { req: object; res: { job: AgentJob | null } };
  /** The answer to a probe job. */
  agent_probe_result: { req: { request_id: number; result: AgentResult<AgentProbe> }; res: Record<string, never> };
  /** The answer to a fill job: field names, never values. */
  agent_fill_result: { req: { request_id: number; result: AgentResult<AgentFilled> }; res: Record<string, never> };
  passkey_create: {
    req: {
      ctx: Ctx;
      origin: string;
      /** As for `passkey_get`. */
      top_origin: string;
      rp_id: string;
      /** No control, format or bidi control character. */
      user_name: string;
      user_handle: string;
      challenge: string;
      exclude: string[];
      vault_id?: string;
    };
    res: PasskeyRegistration;
  };
}

export type Op = keyof Ops;
/** A request without its `id`, which the client assigns. */
export type RequestFor<O extends Op> = { op: O } & Ops[O]["req"];
export type ResponseFor<O extends Op> = Ops[O]["res"];

/** Error reply of the host: `{"id", "err": {"code", "msg"}}` (spec 10 codes). */
export class BridgeAppError extends Error {
  readonly code: string;
  readonly detail: string;

  constructor(code: string, detail: string) {
    super(`${code}: ${detail}`);
    this.name = "BridgeAppError";
    this.code = code;
    this.detail = detail;
  }
}

export interface ClientOptions {
  /** Request deadline, 30 s by default. */
  requestTimeoutMs?: number;
  /** Deadline of each automatic handshake step, 30 s by default. */
  stepTimeoutMs?: number;
  /** Clock of the pairing deadline. */
  now?: () => number;
}

interface Pending {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface Waiter {
  resolve: (e: Envelope) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

/** Swallow a rejection that is also observed elsewhere. */
function quiet(p: Promise<unknown>): void {
  p.catch(() => undefined);
}

export class BridgeClient {
  private readonly requestTimeoutMs: number;
  private readonly stepTimeoutMs: number;
  private readonly pairingOpts: PairingOptions;
  private readonly inbox: Envelope[] = [];
  private waiter: Waiter | undefined;
  private channel: Channel | undefined;
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();
  private sendChain: Promise<void> = Promise.resolve();
  private recvChain: Promise<void> = Promise.resolve();
  private failure: Error | undefined;
  private handshaking = false;
  private readonly failListeners = new Set<(e: Error) => void>();

  constructor(
    private readonly transport: Transport,
    opts: ClientOptions = {},
  ) {
    this.requestTimeoutMs = opts.requestTimeoutMs ?? 30_000;
    this.stepTimeoutMs = opts.stepTimeoutMs ?? 30_000;
    this.pairingOpts = opts.now ? { now: opts.now } : {};
    transport.onMessage((m) => this.onFrame(m));
    transport.onClose((reason) =>
      this.fail(new BridgeError("transport", reason?.message ?? "transport closed")),
    );
  }

  /** True once a session is open and nothing failed. */
  get isOpen(): boolean {
    return !this.failure && !!this.channel && !this.channel.closed;
  }

  /** Close the session and the transport; pending requests fail. */
  close(): void {
    this.fail(new BridgeError("closed"));
  }

  // ---- inbound ----

  private onFrame(raw: unknown): void {
    if (this.failure) return;
    let env: Envelope;
    try {
      env = parseEnvelope(raw);
    } catch (e) {
      this.fail(e instanceof BridgeError ? e : new BridgeError("bad_frame"));
      return;
    }
    if (env.t === "error") {
      this.fail(new BridgeError("host", env.code, env.code));
      return;
    }
    if (this.channel) {
      if (env.t !== "msg") {
        this.fail(new BridgeError("bad_frame", `unexpected ${env.t}`));
        return;
      }
      const msg = env;
      this.recvChain = this.recvChain.then(() => this.onMsg(msg));
      return;
    }
    if (this.waiter) {
      const w = this.waiter;
      this.waiter = undefined;
      clearTimeout(w.timer);
      w.resolve(env);
    } else {
      this.inbox.push(env);
    }
  }

  private async onMsg(msg: MsgEnvelope): Promise<void> {
    const channel = this.channel;
    if (this.failure || !channel) return;
    let reply: unknown;
    let plain: Uint8Array | undefined;
    try {
      plain = await channel.open(msg);
      const text = new TextDecoder("utf-8", { fatal: true }).decode(plain);
      reply = JSON.parse(text);
    } catch (e) {
      this.fail(e instanceof BridgeError ? e : new BridgeError("bad_frame", "reply"));
      return;
    } finally {
      wipe(plain);
    }
    this.dispatch(reply);
  }

  private dispatch(reply: unknown): void {
    if (typeof reply !== "object" || reply === null) {
      this.fail(new BridgeError("bad_frame", "reply"));
      return;
    }
    const r = reply as Record<string, unknown>;
    const err = r.err as { code?: unknown; msg?: unknown } | undefined;
    const hasErr = typeof err === "object" && err !== null && typeof err.code === "string";
    const hasOk = typeof r.ok === "object" && r.ok !== null;
    if (hasErr === hasOk) {
      this.fail(new BridgeError("bad_frame", "reply"));
      return;
    }
    let id: number | undefined;
    if (r.id === null && hasErr) {
      // The host could not read the request id; it answers in order, so
      // this is the oldest request still waiting.
      id = this.pending.keys().next().value;
      if (id === undefined) return;
    } else if (typeof r.id === "number" && Number.isSafeInteger(r.id) && r.id > 0) {
      id = r.id;
    } else {
      this.fail(new BridgeError("bad_frame", "reply id"));
      return;
    }
    const p = this.pending.get(id);
    if (!p) {
      // A late reply to a timed out request is dropped; an id never issued
      // is a protocol violation.
      if (id >= this.nextId) this.fail(new BridgeError("bad_frame", "reply id"));
      return;
    }
    this.pending.delete(id);
    clearTimeout(p.timer);
    if (hasErr && err) {
      p.reject(new BridgeAppError(err.code as string, typeof err.msg === "string" ? err.msg : ""));
    } else {
      p.resolve(r.ok);
    }
  }

  /** The next handshake envelope of type `t`, within `timeoutMs`. */
  private next<T extends EnvelopeType>(t: T, timeoutMs: number): Promise<Extract<Envelope, { t: T }>> {
    return this.nextOf([t], timeoutMs);
  }

  /** The next handshake envelope, of one of `types`, within `timeoutMs`. */
  private nextOf<T extends EnvelopeType>(types: readonly T[], timeoutMs: number): Promise<Extract<Envelope, { t: T }>> {
    const t = types.join(" or ");
    if (this.failure) return Promise.reject(this.failure);
    const queued = this.inbox.shift();
    const got: Promise<Envelope> = queued
      ? Promise.resolve(queued)
      : new Promise<Envelope>((resolve, reject) => {
          // `fail` rejects this waiter.
          const timer = setTimeout(() => this.fail(new BridgeError("timeout", `waiting for ${t}`)), timeoutMs);
          this.waiter = { resolve, reject, timer };
        });
    return got.then((env) => {
      try {
        const want = types.find((x) => x === env.t) ?? (types[0] as T);
        return expectType(env, want);
      } catch (e) {
        this.fail(e as Error);
        throw e;
      }
    });
  }

  private send(env: Envelope): void {
    if (this.failure) throw this.failure;
    try {
      this.transport.send(env);
    } catch (e) {
      const err = new BridgeError("transport", e instanceof Error ? e.message : "send failed");
      this.fail(err);
      throw err;
    }
  }

  private fail(e: Error): void {
    if (this.failure) return;
    this.failure = e;
    for (const l of this.failListeners) l(e);
    this.failListeners.clear();
    this.channel?.close();
    if (this.waiter) {
      clearTimeout(this.waiter.timer);
      this.waiter.reject(e);
      this.waiter = undefined;
    }
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(e);
    }
    this.pending.clear();
    this.inbox.length = 0;
    try {
      this.transport.close();
    } catch {
      // Already closed.
    }
  }

  // ---- handshakes ----

  /**
   * Pair with the app (spec 6.4). `confirmCodes` shows the six digit code
   * and resolves with the user's answer ("Les codes sont identiques"); the
   * pairing completes only once the host MAC verified and the user agreed.
   * The same transport may then `open` a session with the record.
   */
  async pair(
    extName: string,
    browser: string,
    confirmCodes: (sas: string) => Promise<boolean>,
    opts: PairOptions = {},
  ): Promise<PairingRecord> {
    this.beginHandshake();
    let state: ExtPairing | undefined;
    let stored: PairingRecord | undefined;
    // The whole pairing, user step included, is bounded by 120 s (spec 6.4
    // item 7): past it the state is wiped and the transport closed.
    const deadline = setTimeout(
      () => this.fail(new BridgeError("expired", "pairing deadline")),
      PAIRING_TIMEOUT_MS,
    );
    const failed = this.untilFailure();
    try {
      const started = await Promise.race([
        ExtPairing.start(extName, browser, this.pairingOpts),
        failed.promise,
      ]);
      state = started.state;
      const st = state;
      this.send(opts.auto ? { ...started.hello, auto: true } : started.hello);
      const offer = await this.next("pair_offer", this.stepTimeoutMs);
      const { reveal, sas } = await st.onOffer(offer);
      this.send(reveal);
      if (opts.auto) {
        // No person on either side: the app vouched for this browser by its
        // code signature, or it refuses (an older app asking for the code
        // is refused here: the code flow starts only from the user's click).
        const autoVerified = (async () => {
          const step = await this.nextOf(["pair_auto", "pair_sas"], this.stepTimeoutMs);
          if (step.t !== "pair_auto") throw new BridgeError("refused", "the app asks for the code");
          const done = await this.next("pair_done", this.stepTimeoutMs);
          await st.onDone(done);
        })();
        quiet(autoVerified);
        await Promise.race([autoVerified, failed.promise]);
      } else {
        const hostVerified = (async () => {
          await this.next("pair_sas", this.stepTimeoutMs);
          // The host waits for its user before `pair_done`.
          const done = await this.next("pair_done", PAIRING_TIMEOUT_MS);
          await st.onDone(done);
        })();
        const userAgreed = Promise.resolve()
          .then(() => confirmCodes(sas))
          .then((ok) => {
            if (!ok) throw new BridgeError("refused", "codes rejected");
          });
        quiet(hostVerified);
        quiet(userAgreed);
        // A user step that never settles still ends at the deadline or when
        // the connection fails.
        await Promise.race([Promise.all([hostVerified, userAgreed]), failed.promise]);
      }
      const out = await Promise.race([st.confirm(), failed.promise]);
      stored = out.record;
      this.send(out.confirm);
      await this.next("pair_ok", this.stepTimeoutMs);
      stored = undefined;
      return out.record;
    } catch (e) {
      state?.abort();
      // The record was never handed out: its key goes with the failure.
      wipe(stored?.key);
      const err = e instanceof Error ? e : new BridgeError("bad_frame");
      this.fail(err);
      throw this.failure ?? err;
    } finally {
      clearTimeout(deadline);
      failed.dispose();
      this.handshaking = false;
    }
  }

  /** Open a session for a stored pairing (spec 6.5). */
  async open(record: PairingRecord): Promise<void> {
    this.beginHandshake();
    try {
      const { pending, hello } = extHello(record);
      try {
        this.send(hello);
        const welcome = await this.next("welcome", this.stepTimeoutMs);
        const { channel, finish } = await pending.onWelcome(welcome);
        this.send(finish);
        if (this.failure) {
          channel.close();
          throw this.failure;
        }
        this.channel = channel;
      } catch (e) {
        pending.abort();
        const err = e instanceof Error ? e : new BridgeError("bad_frame");
        this.fail(err);
        throw err;
      }
    } finally {
      this.handshaking = false;
    }
  }

  /**
   * One handshake at a time per client: a second concurrent `pair` or
   * `open` is refused with `busy` and leaves the first one untouched.
   */
  private beginHandshake(): void {
    if (this.failure) throw this.failure;
    if (this.handshaking) throw new BridgeError("busy", "handshake in progress");
    if (this.channel) throw new BridgeError("bad_frame", "session already open");
    this.handshaking = true;
  }

  /** A promise rejected by the next `fail`, and its disposer. */
  private untilFailure(): { promise: Promise<never>; dispose: () => void } {
    let listener: ((e: Error) => void) | undefined;
    const promise = new Promise<never>((_, reject) => {
      listener = reject;
    });
    quiet(promise);
    const l = listener as (e: Error) => void;
    this.failListeners.add(l);
    return { promise, dispose: () => this.failListeners.delete(l) };
  }

  // ---- requests ----

  /** Send one application request; resolves with the `ok` payload. */
  request<O extends Op>(req: RequestFor<O>): Promise<ResponseFor<O>> {
    if (this.failure) return Promise.reject(this.failure);
    const channel = this.channel;
    if (!channel) return Promise.reject(new BridgeError("closed", "no session"));
    const id = this.nextId++;
    const plain = utf8(JSON.stringify({ ...req, id }));
    const result = new Promise<ResponseFor<O>>((resolve, reject) => {
      const timer = setTimeout(() => {
        // The id stays burnt: a late reply is dropped.
        this.pending.delete(id);
        reject(new BridgeError("timeout", `request ${id}`));
      }, this.requestTimeoutMs);
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject, timer });
    });
    this.sendChain = this.sendChain.then(async () => {
      try {
        if (this.failure) return;
        this.send(await channel.seal(plain));
      } catch (e) {
        this.fail(e instanceof Error ? e : new BridgeError("crypto"));
      } finally {
        wipe(plain);
      }
    });
    return result;
  }
}
