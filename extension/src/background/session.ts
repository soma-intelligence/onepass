// One encrypted session with the native host, shared by every caller.
//
// `getClient` opens the session on demand with the stored pairing and
// reuses it while the port lives. Concurrent callers share one opening
// (BridgeClient refuses a second concurrent handshake with `busy`). A
// transport failure is retried after 1, 2 then 4 s; past that the host is
// reported missing. Errors leave this module as `BgError` with a stable code
// (spec 10, plus `unpaired`, `host_missing`, `timeout`): a raw host message
// is never surfaced.
import { BridgeError, wipe } from "../bridge/bytes";
import { BridgeAppError, type Op, type RequestFor, type ResponseFor } from "../bridge/client";
import type { PairingRecord } from "../bridge/pairing";
import type { Store } from "./store";

/** The BridgeClient surface the background uses (a fake in tests). */
export interface BridgeLike {
  readonly isOpen: boolean;
  open(record: PairingRecord): Promise<void>;
  pair(extName: string, browser: string, confirmCodes: (sas: string) => Promise<boolean>): Promise<PairingRecord>;
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
] as const;

export type BgErrorCode =
  | Exclude<(typeof APP_CODES)[number], "unknown_pairing">
  | "unpaired"
  | "host_missing"
  | "timeout"
  | "refused"
  | "expired"
  /** No form of the needed kind in the active tab (popup fill). */
  | "no_form";

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

export const RECONNECT_DELAYS_MS = [1000, 2000, 4000] as const;

export interface SessionDeps {
  store: Pick<Store, "getPairing">;
  /** A client on a fresh native port. */
  newClient: () => BridgeLike;
  sleep?: (ms: number) => Promise<void>;
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

  constructor(private readonly deps: SessionDeps) {
    this.sleep = deps.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
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

  /** One application request; host and protocol errors become `BgError`. */
  async request<O extends Op>(req: RequestFor<O>): Promise<ResponseFor<O>> {
    const client = await this.getClient();
    try {
      return await client.request(req);
    } catch (e) {
      const err = toBgError(e);
      if (err.code === "locked") for (const l of this.lockedListeners) l();
      throw err;
    }
  }

  /**
   * The username salt of the bridge session (`fill_salt`). The host draws
   * it once per session, so it is kept with the client it came from and
   * fetched again from the next client after a reconnect.
   */
  async fillSalt(): Promise<string> {
    const client = await this.getClient();
    if (this.salt?.client === client) return this.salt.value;
    let salt: string;
    try {
      ({ salt } = await client.request({ op: "fill_salt", ctx: "menu" }));
    } catch (e) {
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
      if (!record) throw new BgError("unpaired");
      for (let attempt = 0; ; attempt++) {
        if (generation !== this.generation) throw SUPERSEDED;
        let client: BridgeLike | undefined;
        try {
          client = this.deps.newClient();
          await client.open(record);
        } catch (e) {
          client?.close();
          if (!retryable(e)) throw toBgError(e);
          const delay = RECONNECT_DELAYS_MS[attempt];
          if (delay === undefined) throw new BgError("host_missing");
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
        return client;
      }
    } finally {
      wipe(record?.key);
    }
  }
}
