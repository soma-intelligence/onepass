import { describe, expect, it } from "vitest";
import { recordToJson } from "../../src/bridge/pairing";
import { createBackground } from "../../src/background/app";
import { LEGACY_PAIRING_KEY, MemoryPairingStore, Store } from "../../src/background/store";
import { record } from "./fake-client";
import { FakeExt } from "./fake-ext";

describe("pairing storage", () => {
  it("keeps the pairing out of storage.local", async () => {
    const ext = new FakeExt();
    const pairings = new MemoryPairingStore();
    const store = new Store(ext, pairings);
    await store.setPairing(record());
    expect(ext.local.data.size).toBe(0);
    expect(pairings.value).toEqual(recordToJson(record()));
    expect((await store.getPairing())?.key).toEqual(record().key);
    await store.clearPairing();
    expect(await store.getPairing()).toBeNull();
  });

  it("migrates a legacy storage.local record and deletes it", async () => {
    const ext = new FakeExt();
    await ext.local.set({ [LEGACY_PAIRING_KEY]: recordToJson(record()), theme: "dark" });
    const pairings = new MemoryPairingStore();
    const store = new Store(ext, pairings);
    expect((await store.getPairing())?.pairingId).toEqual(record().pairingId);
    expect(ext.local.data.has(LEGACY_PAIRING_KEY)).toBe(false);
    expect(ext.local.data.get("theme")).toBe("dark");
    expect(pairings.value).toEqual(recordToJson(record()));
  });

  it("a record already in the pairing store wins; a corrupt legacy one is dropped", async () => {
    const ext = new FakeExt();
    const newer = { ...record(), createdAt: 1_800_000_000_000 };
    const pairings = new MemoryPairingStore();
    await pairings.set(recordToJson(newer));
    await ext.local.set({ [LEGACY_PAIRING_KEY]: recordToJson(record()) });
    expect((await new Store(ext, pairings).getPairing())?.createdAt).toBe(1_800_000_000_000);
    expect(ext.local.data.has(LEGACY_PAIRING_KEY)).toBe(false);

    const ext2 = new FakeExt();
    await ext2.local.set({ [LEGACY_PAIRING_KEY]: { pairing_id: "!!", key: "x", created_at: 1 } });
    const empty = new MemoryPairingStore();
    expect(await new Store(ext2, empty).getPairing()).toBeNull();
    expect(ext2.local.data.size).toBe(0);
    expect(empty.value).toBeUndefined();
  });

  it("restricts storage.local to trusted contexts at worker start", () => {
    const ext = new FakeExt();
    createBackground(ext, { pairings: new MemoryPairingStore() }).install();
    expect(ext.local.accessLevels).toEqual(["TRUSTED_CONTEXTS"]);
  });

  it("ignores a browser without setAccessLevel, or one that rejects it", async () => {
    const ext = new FakeExt();
    const area = ext.local as { setAccessLevel?: unknown };
    area.setAccessLevel = undefined;
    expect(() => new Store(ext, new MemoryPairingStore()).restrictLocal()).not.toThrow();
    area.setAccessLevel = () => Promise.reject(new Error("unsupported"));
    expect(() => new Store(ext, new MemoryPairingStore()).restrictLocal()).not.toThrow();
    area.setAccessLevel = () => {
      throw new Error("unsupported");
    };
    expect(() => new Store(ext, new MemoryPairingStore()).restrictLocal()).not.toThrow();
    await new Promise((r) => setTimeout(r, 0));
  });
});
