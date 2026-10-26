// Durable and session state of the service worker. An MV3 service worker
// can be stopped at any time, so nothing security-relevant lives only in
// memory: the pairing is in `storage.local`, menu tokens are mirrored in
// `storage.session` (readable by trusted extension contexts only, never by
// content scripts). Secrets other than the pairing key are never stored.
import { type PairingRecord, recordFromJson, recordToJson } from "../bridge/pairing";
import type { BgExt, StorageArea } from "./ext";

export const PAIRING_KEY = "pairing";

export class Store {
  constructor(private readonly ext: Pick<BgExt, "storage">) {}

  /** The stored pairing; a missing or corrupt record reads as unpaired. */
  async getPairing(): Promise<PairingRecord | null> {
    const raw = (await this.ext.storage.local.get(PAIRING_KEY))[PAIRING_KEY];
    if (raw === undefined) return null;
    try {
      return recordFromJson(raw);
    } catch {
      return null;
    }
  }

  async setPairing(r: PairingRecord): Promise<void> {
    await this.ext.storage.local.set({ [PAIRING_KEY]: recordToJson(r) });
  }

  async clearPairing(): Promise<void> {
    await this.ext.storage.local.remove(PAIRING_KEY);
  }

  /** Short-lived state (menu tokens), cleared when the browser closes. */
  get session(): StorageArea {
    return this.ext.storage.session;
  }
}
