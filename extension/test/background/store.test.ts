import { describe, expect, it } from "vitest";
import { recordToJson } from "../../src/bridge/pairing";
import { createBackground } from "../../src/background/app";
import { MemoryPairingStore, Store } from "../../src/background/store";
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

  it("ignores a record planted in storage.local", async () => {
    const ext = new FakeExt();
    await ext.local.set({ pairing: recordToJson(record()) });
    const pairings = new MemoryPairingStore();
    const store = new Store(ext, pairings);
    expect(await store.getPairing()).toBeNull();
    expect(pairings.value).toBeUndefined();
    await store.clearPairing();
    expect(await store.getPairing()).toBeNull();
    expect(pairings.value).toBeUndefined();
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
