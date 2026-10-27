// Durable and session state of the service worker. An MV3 service worker
// can be stopped at any time, so nothing security-relevant lives only in
// memory.
//
// The pairing record (the only long-term secret) lives in IndexedDB of the
// extension origin, opened from the service worker: content scripts run in
// the page's origin and cannot reach it, whereas `storage.local` is readable
// and writable by content scripts unless restricted. Menu tokens (no secret)
// are mirrored in `storage.session`, which defaults to trusted contexts only.
import { type PairingRecord, recordFromJson, recordToJson } from "../bridge/pairing";
import type { BgExt, StorageArea } from "./ext";

/** Raw storage of the pairing record (its JSON form). */
export interface PairingStore {
  get(): Promise<unknown>;
  set(value: unknown): Promise<void>;
  clear(): Promise<void>;
}

const DB_NAME = "onepass";
const DB_STORE = "pairing";
const DB_KEY = "current";

function done<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexedDB request failed"));
  });
}

function committed(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(tx.error ?? new Error("indexedDB transaction aborted"));
    tx.onerror = () => reject(tx.error ?? new Error("indexedDB transaction failed"));
  });
}

/** IndexedDB of the extension origin (service worker only). */
export class IdbPairingStore implements PairingStore {
  private db: Promise<IDBDatabase> | undefined;

  constructor(private readonly factory: IDBFactory = globalThis.indexedDB) {}

  private open(): Promise<IDBDatabase> {
    if (!this.db) {
      const req = this.factory.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains(DB_STORE)) req.result.createObjectStore(DB_STORE);
      };
      this.db = done(req);
      // A failed open is retried by the next call.
      this.db.catch(() => {
        this.db = undefined;
      });
    }
    return this.db;
  }

  async get(): Promise<unknown> {
    const tx = (await this.open()).transaction(DB_STORE, "readonly");
    return done(tx.objectStore(DB_STORE).get(DB_KEY));
  }

  async set(value: unknown): Promise<void> {
    const tx = (await this.open()).transaction(DB_STORE, "readwrite");
    tx.objectStore(DB_STORE).put(value, DB_KEY);
    await committed(tx);
  }

  async clear(): Promise<void> {
    const tx = (await this.open()).transaction(DB_STORE, "readwrite");
    tx.objectStore(DB_STORE).delete(DB_KEY);
    await committed(tx);
  }
}

/** In-memory pairing store (tests, or a browser without IndexedDB). */
export class MemoryPairingStore implements PairingStore {
  value: unknown = undefined;
  async get(): Promise<unknown> {
    return this.value === undefined ? undefined : structuredClone(this.value);
  }
  async set(value: unknown): Promise<void> {
    this.value = structuredClone(value);
  }
  async clear(): Promise<void> {
    this.value = undefined;
  }
}

export class Store {
  constructor(
    private readonly ext: Pick<BgExt, "storage">,
    private readonly pairings: PairingStore,
  ) {}

  /**
   * Restrict `storage.local` to trusted contexts where supported (it keeps
   * non-secret settings). Unsupported or failing: ignored.
   */
  restrictLocal(): void {
    const local = this.ext.storage.local;
    try {
      const p = local.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" });
      p?.catch(() => undefined);
    } catch {
      // Not supported by this browser.
    }
  }

  /** The stored pairing; a missing or corrupt record reads as unpaired. */
  async getPairing(): Promise<PairingRecord | null> {
    const raw = await this.pairings.get();
    if (raw === undefined || raw === null) return null;
    try {
      return recordFromJson(raw);
    } catch {
      return null;
    }
  }

  async setPairing(r: PairingRecord): Promise<void> {
    await this.pairings.set(recordToJson(r));
  }

  async clearPairing(): Promise<void> {
    await this.pairings.clear();
  }

  /** Short-lived state (menu tokens), cleared when the browser closes. */
  get session(): StorageArea {
    return this.ext.storage.session;
  }
}
