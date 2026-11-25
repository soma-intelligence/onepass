// One encrypted session with the native host, shared by every caller.
//
// `getClient` opens the session on demand with the stored pairing and
// reuses it while the port lives. Concurrent callers share one opening
// (BridgeClient refuses a second concurrent handshake with `busy`). A
// transport failure is retried after 1, 2 then 4 s; past that the host is
// reported missing, and for a short while the next openings try once. A
// missing host is launched only for the requests of a trusted user gesture
// (`withWake`). Errors leave this module as `BgError` with a stable code
// (spec 10, plus `unpaired`, `host_missing`, `timeout`): a raw host message
// is never surfaced.
import { BridgeError, wipe } from "../bridge/bytes";
import { BridgeAppError, type Op, type PairOptions, type RequestFor, type ResponseFor } from "../bridge/client";
import type { PairingRecord } from "../bridge/pairing";
import type { Store } from "./store";

/** The BridgeClient surface the background uses (a fake in tests). */
export interface BridgeLike {
  readonly isOpen: boolean;
  open(record: PairingRecord): Promise<void>;
  pair(
    extName: string,
    browser: string,
    confirmCodes: (sas: string) => Promise<boolean>,
    opts?: PairOptions,
  ): Promise<PairingRecord>;
  request<O extends Op>(req: RequestFor<O>): Promise<ResponseFor<O>>;
  close(): void;
}

/** Spec 10 application codes. */
export const APP_CODES = [
  "version",
  "unknown_pairing",
  "bad_mac",
  "bad_frame",
  "locked",
  "not_found",
  "origin_mismatch",
  "insecure_origin",
  "cross_site_frame",
  "not_allowed",
  "reprompt_required",
  "rate_limited",
  "invalid",
  "internal",
  /** passkey_create: a stored credential is in `exclude` (the page gets InvalidStateError). */
  "excluded",
] as const;

export type BgErrorCode =
  | Exclude<(typeof APP_CODES)[number], "unknown_pairing">
  | "unpaired"
  | "host_missing"
  | "timeout"
  | "refused"
  | "expired"
  /** No form of the needed kind in the active tab (popup fill). */
  | "no_form"
  /** The page's `pattern` refused every generated password (spec 6.3). */
  | "site_refused";

const APP_CODE_SET: ReadonlySet<string> = new Set(APP_CODES);

export class BgError extends Error {
  constructor(readonly code: BgErrorCode) {
    super(code);
    this.name = "BgError";
  }
}

function fromAppCode(code: string): BgError {
  if (code === "unknown_pairing") return new BgError("unpaired");
  if (APP_CODE_SET.has(code)) return new BgError(code as BgErrorCode);
  return new BgError("internal");
}

/** Normalize any failure to a stable code, dropping host-provided text. */
export function toBgError(e: unknown): BgError {
  if (e instanceof BgError) return e;
  if (e instanceof BridgeAppError) return fromAppCode(e.code);
  if (e instanceof BridgeError) {
    switch (e.code) {
      case "host":
        return fromAppCode(e.hostCode ?? "internal");
      case "transport":
      case "closed":
        return new BgError("host_missing");
      case "timeout":
        return new BgError("timeout");
      case "expired":
        return new BgError("expired");
      case "refused":
        return new BgError("refused");
      case "bad_mac":
      case "bad_frame":
      case "version":
        return new BgError(e.code);
      default:
        return new BgError("internal");
    }
  }
  return new BgError("internal");
}

/** Failures worth another connection attempt: the host is not (yet) there. */
function retryable(e: unknown): boolean {
  if (e instanceof BridgeError) return e.code === "transport" || e.code === "closed" || e.code === "timeout";
  // connectNative itself threw.
  return !(e instanceof BridgeAppError) && !(e instanceof BgError);
}

/**
 * Requests that read and change nothing: sent again once when the session died under them. Fills,
 * saves, unlocks and passkey ceremonies are never replayed (a gesture's ticket, a side effect).
 */
export const REPLAYABLE_OPS: ReadonlySet<string> = new Set([
  "status",
  "vaults",
  "list_for_origin",
  "search",
  "list_fillable",
  "provider_accounts",
  "plan_fill",
  "passkey_list",
  "check_credentials",
  "check_card",
  "check_identity",
  "client_info",
]);

export const RECONNECT_DELAYS_MS = [1000, 2000, 4000] as const;
/**
 * An opening no gesture waits on (a menu, a page load): nothing launched the app, so one short
 * retry, then `host_missing`. The menu says the app is missing within about a second, not seven.
 */
export const PASSIVE_DELAYS_MS = [1000] as const;
/**
 * After the host was found missing, an opening this soon after tries once: a page that waits for
 * the app asks every second, and a gesture is not held 7 s per request.
 */
export const MISSING_QUIET_MS = 15_000;

export interface SessionDeps {
  store: Pick<Store, "getPairing"> & Partial<Pick<Store, "clearPairing">>;
  /** A client on a fresh native port. */
  newClient: () => BridgeLike;
  sleep?: (ms: number) => Promise<void>;
  /**
   * Without a stored pairing, pair without a code if the app vouches for
   * this browser (it adopts its client on success). True when paired.
   */
  autoPair?: () => Promise<boolean>;
  now?: () => number;
}

/** An opening overtaken by `adopt` or `close`: its waiters ask again. */
const SUPERSEDED = Symbol("superseded");

interface Opening {
  promise: Promise<BridgeLike>;
  cancel: () => void;
}

function quiet(p: Promise<unknown>): void {
  p.catch(() => undefined);
}

export class Session {
  private client: BridgeLike | undefined;
  private opening: Opening | undefined;
  /** Bumped by `adopt` and `close`: an opening started before it is discarded. */
  private generation = 0;
  private readonly lockedListeners = new Set<() => void>();
  /** `fill_salt` of `client`'s session. */
  private salt: { client: BridgeLike; value: string } | undefined;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  /** When the host was last found missing (cleared by a connection). */
  private missingAt: number | undefined;
  /** Armed by `withWake` while the requests of a trusted gesture run. */
  private readonly wakers = new Set<{ wake: () => unknown }>();

  constructor(private readonly deps: SessionDeps) {
    this.sleep = deps.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.now = deps.now ?? Date.now;
  }

  /**
   * Runs `fn`, the requests of a trusted user gesture. If the host turns out missing meanwhile,
   * `wake` (launch the app) runs at the first failed attempt of the opening, once per opening.
   * Nothing else ever arms it: a page load, a poll or a timer never launches the app.
   */
  async withWake<T>(wake: () => unknown, fn: () => Promise<T>): Promise<T> {
    const armed = { wake };
    this.wakers.add(armed);
    try {
      return await fn();
    } finally {
      this.wakers.delete(armed);
    }
  }

  /** The open client, opening (or reopening) the session if needed. */
  async getClient(): Promise<BridgeLike> {
    // Each pass either returns, throws, or follows a generation change
    // (an adopted client, or a cleared pairing on the next pass).
    for (let pass = 0; pass < 8; pass++) {
      if (this.client?.isOpen) return this.client;
      this.opening ??= this.startOpening();
      try {
        return await this.opening.promise;
      } catch (e) {
        if (e !== SUPERSEDED) throw e;
      }
    }
    throw new BgError("internal");
  }

  /**
   * One application request; host and protocol errors become `BgError`. A read whose session died
   * under it (the app closed an idle session, the Mac slept, Safari restarted its relay) is sent
   * once more on a fresh session: the dead one only shows when a request uses it.
   */
  async request<O extends Op>(req: RequestFor<O>): Promise<ResponseFor<O>> {
    const client = await this.getClient();
    try {
      return await client.request(req);
    } catch (e) {
      if (REPLAYABLE_OPS.has(req.op) && this.diedUnder(client, e)) return this.requestOnce(req);
      throw this.mapped(e);
    }
  }

  private async requestOnce<O extends Op>(req: RequestFor<O>): Promise<ResponseFor<O>> {
    const client = await this.getClient();
    try {
      return await client.request(req);
    } catch (e) {
      throw this.mapped(e);
    }
  }

  private mapped(e: unknown): BgError {
    const err = toBgError(e);
    if (err.code === "locked") for (const l of this.lockedListeners) l();
    return err;
  }

  /** The transport of `client` failed under a request: it is dropped, the next opening is fresh. */
  private diedUnder(client: BridgeLike, e: unknown): boolean {
    if (!(e instanceof BridgeError) || (e.code !== "transport" && e.code !== "closed")) return false;
    if (client.isOpen) return false;
    if (this.client === client) {
      client.close();
      this.client = undefined;
      this.salt = undefined;
    }
    return true;
  }

  /**
   * The username salt of the bridge session (`fill_salt`). The host draws
   * it once per session, so it is kept with the client it came from and
   * fetched again from the next client after a reconnect.
   */
  async fillSalt(again = true): Promise<string> {
    const client = await this.getClient();
    if (this.salt?.client === client) return this.salt.value;
    let salt: string;
    try {
      ({ salt } = await client.request({ op: "fill_salt", ctx: "menu" }));
    } catch (e) {
      // A read like any other: once more on a fresh session when this one died under it.
      if (again && this.diedUnder(client, e)) return this.fillSalt(false);
      throw toBgError(e);
    }
    if (!/^[0-9a-f]{64}$/.test(salt)) throw new BgError("internal");
    this.salt = { client, value: salt };
    return salt;
  }

  /** Called whenever the host answers `locked` (e.g. to clear UI caches). */
  onLocked(cb: () => void): void {
    this.lockedListeners.add(cb);
  }

  /** Install a client opened elsewhere (the pairing port, reused). */
  adopt(client: BridgeLike): void {
    if (this.client && this.client !== client) this.client.close();
    this.client = client;
    this.supersede();
  }

  /** Drop the session; an opening in flight is discarded. */
  close(): void {
    this.client?.close();
    this.client = undefined;
    this.supersede();
  }

  private supersede(): void {
    this.generation++;
    this.salt = undefined;
    const o = this.opening;
    this.opening = undefined;
    o?.cancel();
  }

  private startOpening(): Opening {
    let cancel!: () => void;
    const cancelled = new Promise<never>((_, reject) => {
      cancel = () => reject(SUPERSEDED);
    });
    const connecting = this.connect(this.generation);
    quiet(connecting);
    quiet(cancelled);
    const entry: Opening = { promise: Promise.race([connecting, cancelled]), cancel };
    const clear = () => {
      if (this.opening === entry) this.opening = undefined;
    };
    entry.promise.then(clear, clear);
    return entry;
  }

  private async connect(generation: number): Promise<BridgeLike> {
    const record = await this.deps.store.getPairing();
    try {
      if (generation !== this.generation) throw SUPERSEDED;
      if (!record) {
        // A success adopts the pairing's client, which supersedes this opening.
        // A refusal leaves the manual pairing; a missing app is reported.
        if (this.deps.autoPair && (await this.deps.autoPair())) throw SUPERSEDED;
        throw new BgError("unpaired");
      }
      // Missing a moment ago: one try, no backoff.
      const t = this.now();
      const quick = this.missingAt !== undefined && t >= this.missingAt && t - this.missingAt <= MISSING_QUIET_MS;
      let woken = false;
      for (let attempt = 0; ; attempt++) {
        if (generation !== this.generation) throw SUPERSEDED;
        let client: BridgeLike | undefined;
        try {
          client = this.deps.newClient();
          await client.open(record);
        } catch (e) {
          client?.close();
          const err = toBgError(e);
          if (err.code === "unpaired" && this.deps.autoPair && this.deps.store.clearPairing) {
            // The app no longer knows this pairing (reinstalled, its data reset, or revoked):
            // the stale record goes, and the app is asked once to vouch for this browser again.
            // A revoked browser stays refused by the app (`not_allowed`).
            await this.deps.store.clearPairing();
            if (generation !== this.generation) throw SUPERSEDED;
            if (await this.deps.autoPair()) throw SUPERSEDED;
            throw err;
          }
          if (!retryable(e)) throw err;
          if (!woken) {
            // A gesture is waiting on this opening: the app is launched, the retries find it.
            for (const w of this.wakers) {
              woken = true;
              quiet(Promise.resolve().then(w.wake));
              break;
            }
          }
          // Woken: the app is launching, the retries wait for it. Else nothing will start it.
          const delays: readonly number[] = woken ? RECONNECT_DELAYS_MS : PASSIVE_DELAYS_MS;
          const delay = quick ? undefined : delays[attempt];
          if (delay === undefined) {
            this.missingAt = this.now();
            throw new BgError("host_missing");
          }
          await this.sleep(delay);
          continue;
        }
        if (generation !== this.generation) {
          // Overtaken while opening: this client is not the session.
          client.close();
          throw SUPERSEDED;
        }
        this.client?.close();
        this.client = client;
        this.missingAt = undefined;
        return client;
      }
    } finally {
      wipe(record?.key);
    }
  }
}
