// Pairing flow driven by the popup (spec 6.4): start shows the six digit
// code, confirm is the user's "Les codes sont identiques". The record is
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
}

interface Pending {
  client: BridgeLike;
  done: Promise<PairingRecord>;
  decide: ((ok: boolean) => void) | undefined;
}

function quiet(p: Promise<unknown>): void {
  p.catch(() => undefined);
}

export class PairingFlow {
  private current: Pending | undefined;

  constructor(private readonly deps: PairingDeps) {}

  /** Start a pairing; resolves with the code to compare. Cancels any previous one. */
  async startPairing(): Promise<{ sas: string }> {
    this.cancelPairing();
    let client: BridgeLike;
    try {
      client = this.deps.newClient();
    } catch {
      throw new BgError("host_missing");
    }
    let gotSas!: (s: string) => void;
    const sasP = new Promise<string>((r) => (gotSas = r));
    const cur: Pending = { client, done: Promise.resolve() as unknown as Promise<PairingRecord>, decide: undefined };
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
      throw toBgError(e);
    }
  }

  /** The user confirmed the codes match: finish, store, open the session. */
  async confirmPairing(): Promise<void> {
    const cur = this.current;
    if (!cur?.decide) throw new BgError("invalid");
    cur.decide(true);
    let record: PairingRecord;
    try {
      record = await cur.done;
    } catch (e) {
      cur.client.close();
      throw toBgError(e);
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

  /** The user cancelled, or the popup closed. */
  cancelPairing(): void {
    const cur = this.current;
    if (!cur) return;
    this.current = undefined;
    cur.decide?.(false);
    cur.client.close();
  }

  /** Forget the pairing on this browser. */
  async forgetPairing(): Promise<void> {
    this.cancelPairing();
    // Cleared first: callers waiting on the session retry and find nothing.
    await this.deps.store.clearPairing();
    this.deps.session.close();
  }
}
