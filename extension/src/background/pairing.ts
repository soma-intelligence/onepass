// Pairing flow (spec 6.4): start shows the six digit code, confirm is the
// user's "Les codes sont identiques". `autoPair` pairs without a code when
// the app vouches for this browser by its code signature (spec
// 2026-11-02-browser-auto-pairing): no screen, no click. The record is
// stored in the extension origin's IndexedDB (see store.ts) and the pairing
// port is reused as the first session.
import { wipe } from "../bridge/bytes";
import type { PairingRecord } from "../bridge/pairing";
import { BgError, type BridgeLike, type Session, toBgError } from "./session";
import type { Store } from "./store";

export const EXT_NAME = "OnePass";

/** Browser family shown by the app next to the pairing. */
export function browserName(ua: string): string {
  if (/Firefox\//.test(ua)) return "Firefox";
  if (/Edg\//.test(ua)) return "Edge";
  if (/Chrome\//.test(ua)) return "Chrome";
  if (/Safari\//.test(ua)) return "Safari";
  return "Chromium";
}

export interface PairingDeps {
  store: Pick<Store, "setPairing" | "clearPairing">;
  session: Pick<Session, "adopt" | "close">;
  newClient: () => BridgeLike;
  browser?: string;
  now?: () => number;
}

/** After the app refused an automatic pairing, background attempts wait this long. */
export const AUTO_RETRY_MS = 5 * 60_000;

interface Pending {
  client: BridgeLike;
  done: Promise<PairingRecord>;
  decide: ((ok: boolean) => void) | undefined;
  /** The user said the codes match: the app's answer is awaited even if the popup closes. */
  confirmed: boolean;
}

function quiet(p: Promise<unknown>): void {
  p.catch(() => undefined);
}

/** The app answers a refused pairing with `not_allowed`: say it was refused. */
function pairingError(e: unknown): BgError {
  const err = toBgError(e);
  return err.code === "not_allowed" ? new BgError("refused") : err;
}

export class PairingFlow {
  private current: Pending | undefined;
  private auto: Promise<boolean> | undefined;
  private refusedAt: number | undefined;
  private paired = false;

  constructor(private readonly deps: PairingDeps) {}

  private now(): number {
    return (this.deps.now ?? Date.now)();
  }

  /**
   * Pair without a code if the app vouches for this browser. True once
   * paired (record stored, session adopted); false when the app refused
   * (unknown browser, revoked) or a code pairing is under way. Host
   * failures throw `BgError` (`host_missing`...). After a refusal, calls
   * without `force` return false for `AUTO_RETRY_MS`.
   */
  autoPair(force = false): Promise<boolean> {
    if (this.current) return Promise.resolve(false);
    if (!force && this.refusedAt !== undefined && this.now() - this.refusedAt < AUTO_RETRY_MS) {
      return Promise.resolve(false);
    }
    this.auto ??= this.runAuto().finally(() => (this.auto = undefined));
    return this.auto;
  }

  /** True once after an automatic pairing: the popup says "Connected". */
  takeJustPaired(): boolean {
    const p = this.paired;
    this.paired = false;
    return p;
  }

  private async runAuto(): Promise<boolean> {
    let client: BridgeLike;
    try {
      client = this.deps.newClient();
    } catch {
      throw new BgError("host_missing");
    }
    let record: PairingRecord;
    try {
      record = await client.pair(EXT_NAME, this.deps.browser ?? "Chromium", async () => false, { auto: true });
    } catch (e) {
      client.close();
      const err = toBgError(e);
      if (err.code === "not_allowed" || err.code === "refused") {
        this.refusedAt = this.now();
        return false;
      }
      throw err;
    }
    this.refusedAt = undefined;
    try {
      await this.deps.store.setPairing(record);
      try {
        await client.open(record);
        this.deps.session.adopt(client);
      } catch {
        client.close();
        this.deps.session.close();
      }
    } finally {
      wipe(record.key);
    }
    this.paired = true;
    return true;
  }

  /** Start a pairing; resolves with the code to compare. Cancels any previous one. */
  async startPairing(): Promise<{ sas: string }> {
    this.abort();
    let client: BridgeLike;
    try {
      client = this.deps.newClient();
    } catch {
      throw new BgError("host_missing");
    }
    let gotSas!: (s: string) => void;
    const sasP = new Promise<string>((r) => (gotSas = r));
    const cur: Pending = {
      client,
      done: Promise.resolve() as unknown as Promise<PairingRecord>,
      decide: undefined,
      confirmed: false,
    };
    cur.done = client.pair(EXT_NAME, this.deps.browser ?? "Chromium", (sas) => {
      gotSas(sas);
      return new Promise<boolean>((resolve) => {
        cur.decide = resolve;
      });
    });
    quiet(cur.done);
    this.current = cur;
    try {
      const sas = await Promise.race([
        sasP,
        cur.done.then(() => {
          throw new BgError("internal");
        }),
      ]);
      return { sas };
    } catch (e) {
      if (this.current === cur) this.current = undefined;
      client.close();
      throw pairingError(e);
    }
  }

  /** The user confirmed the codes match: finish, store, open the session. */
  async confirmPairing(): Promise<void> {
    const cur = this.current;
    // The flow ended (popup closed before the codes were confirmed, or a newer pairing).
    if (!cur?.decide) throw new BgError("expired");
    cur.confirmed = true;
    cur.decide(true);
    let record: PairingRecord;
    try {
      record = await cur.done;
    } catch (e) {
      cur.client.close();
      throw pairingError(e);
    } finally {
      if (this.current === cur) this.current = undefined;
    }
    try {
      await this.deps.store.setPairing(record);
      try {
        await cur.client.open(record);
        // Replaces any old session; callers waiting on an opening get this client.
        this.deps.session.adopt(cur.client);
      } catch {
        // Paired all the same; the next request opens a fresh session.
        cur.client.close();
        this.deps.session.close();
      }
    } finally {
      wipe(record.key);
    }
  }

  /**
   * The user cancelled, or the popup closed. Once the codes are confirmed the pairing waits for
   * the app: in Safari, switching to the app to approve closes the popup.
   */
  cancelPairing(): void {
    if (this.current?.confirmed) return;
    this.abort();
  }

  private abort(): void {
    const cur = this.current;
    if (!cur) return;
    this.current = undefined;
    cur.decide?.(false);
    cur.client.close();
  }

  /** Forget the pairing on this browser. */
  async forgetPairing(): Promise<void> {
    this.abort();
    // Cleared first: callers waiting on the session retry and find nothing.
    await this.deps.store.clearPairing();
    this.deps.session.close();
  }
}
