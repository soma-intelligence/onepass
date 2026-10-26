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
import type { ProviderId } from "../shared/messages";
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

export type Ctx = "popup" | "menu" | "overlay" | "save_prompt" | "chain";
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

interface Ops {
  status: { req: object; res: { locked: boolean; account: string; vaults: number } };
  unlock: { req: object; res: { locked: boolean } };
  vaults: { req: object; res: { vaults: { id: string; name: string; color: string | null }[] } };
  list_for_origin: { req: { ctx: Ctx; origin: string }; res: { items: Summary[] } };
  search: { req: { ctx: Ctx; query: string }; res: { items: Summary[] } };
  list_fillable: { req: { ctx: Ctx; origin: string; kind: "card" | "identity" }; res: { items: Summary[] } };
  fill_login: {
    req: { ctx: Ctx; item_id: string; origin: string; fields: FillField[] };
    res: LoginFill;
  };
  fill_card: {
    req: { ctx: Ctx; item_id: string; origin: string };
    /** `exp_month` "04", `exp_year` "2029": zero-padded strings, empty when unknown. */
    res: { cardholder: string; number: string; exp_month: string; exp_year: string; cvv?: string };
  };
  fill_identity: {
    req: { ctx: Ctx; item_id: string; origin: string };
    res: {
      given_name?: string;
      family_name?: string;
      email?: string;
      tel?: string;
      organization?: string;
      birthday?: string;
      address?: Address;
    };
  };
  totp: { req: { ctx: Ctx; item_id: string; origin?: string }; res: { code: string; remaining: number } };
  reveal: { req: { ctx: Ctx; item_id: string; field: string }; res: { value: string } };
  check_credentials: {
    req: { ctx: Ctx; origin: string; username: string; password: string };
    res: { status: "new" | "same" | "update"; item_id?: string; title?: string };
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
  update_password: {
    req: { ctx: Ctx; item_id: string; origin: string; password: string };
    res: Record<string, never>;
  };
  generate: {
    req: {
      ctx: Ctx;
      recipe: { kind: "random" | "memorable" | "pin" | "smart"; length?: number; symbols?: boolean };
    };
    res: { password: string; entropy_bits: number };
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
        return expectType(env, t);
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
      this.send(started.hello);
      const offer = await this.next("pair_offer", this.stepTimeoutMs);
      const { reveal, sas } = await st.onOffer(offer);
      this.send(reveal);
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
