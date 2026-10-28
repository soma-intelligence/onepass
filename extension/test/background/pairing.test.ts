import { describe, expect, it } from "vitest";
import { BridgeError } from "../../src/bridge/bytes";
import type { PairingRecord } from "../../src/bridge/pairing";
import { PairingFlow, browserName } from "../../src/background/pairing";
import { BgError, Session } from "../../src/background/session";
import { MemoryPairingStore, Store } from "../../src/background/store";
import { FakeClient, record } from "./fake-client";
import { FakeExt } from "./fake-ext";

function setup(pairImpl: (cb: (sas: string) => Promise<boolean>) => Promise<PairingRecord>) {
  const ext = new FakeExt();
  const store = new Store(ext, new MemoryPairingStore());
  const clients: FakeClient[] = [];
  const newClient = () => {
    const c = new FakeClient(() => ({ locked: false, account: "alex@atlas.dev", vaults: 1 }), undefined, pairImpl);
    clients.push(c);
    return c;
  };
  const session = new Session({ store, newClient });
  const flow = new PairingFlow({ store, session, newClient, browser: "Chrome" });
  return { ext, store, session, flow, clients };
}

describe("pairing flow", () => {
  it("shows the code, stores the record on confirm and reuses the port", async () => {
    const { ext, store, session, flow, clients } = setup(async (cb) => {
      if (!(await cb("042 917"))) throw new BridgeError("refused");
      return record();
    });
    expect(await flow.startPairing()).toEqual({ sas: "042 917" });
    expect(await store.getPairing()).toBeNull();
    await flow.confirmPairing();
    // Never in storage.local, which content scripts may read.
    expect(ext.local.data.size).toBe(0);
    expect((await store.getPairing())?.pairingId).toEqual(record().pairingId);
    expect(clients[0]?.openCalls).toBe(1);
    expect(await session.getClient()).toBe(clients[0]);
    expect(clients).toHaveLength(1);
  });

  it("cancel refuses the codes and stores nothing", async () => {
    let answered: boolean | undefined;
    const { ext, store, flow, clients } = setup(async (cb) => {
      answered = await cb("111 222");
      throw new BridgeError("refused");
    });
    await flow.startPairing();
    flow.cancelPairing();
    await new Promise((r) => setTimeout(r, 0));
    expect(answered).toBe(false);
    expect(clients[0]?.closed).toBe(true);
    expect(ext.local.data.has("pairing")).toBe(false);
    expect(await store.getPairing()).toBeNull();
    await expect(flow.confirmPairing()).rejects.toBeInstanceOf(BgError);
  });

  it("a popup closed after the codes were confirmed keeps waiting for the app", async () => {
    let approve!: () => void;
    const appAnswered = new Promise<void>((r) => (approve = r));
    const { store, flow, clients } = setup(async (cb) => {
      if (!(await cb("314 159"))) throw new BridgeError("refused");
      await appAnswered;
      return record();
    });
    await flow.startPairing();
    const confirmed = flow.confirmPairing();
    // Safari closes the popup when the user switches to the app to approve.
    flow.cancelPairing();
    expect(clients[0]?.closed).toBe(false);
    approve();
    await confirmed;
    expect((await store.getPairing())?.pairingId).toEqual(record().pairingId);
  });

  it("a pairing the app refuses says refused, not a generic error", async () => {
    const { flow } = setup(async (cb) => {
      await cb("271 828");
      throw new BridgeError("host", "not_allowed", "not_allowed");
    });
    await flow.startPairing();
    await expect(flow.confirmPairing()).rejects.toMatchObject({ code: "refused" });
  });

  it("confirming a pairing that already ended says it expired", async () => {
    const { flow } = setup(async (cb) => {
      await cb("161 803");
      return record();
    });
    await flow.startPairing();
    flow.cancelPairing();
    await expect(flow.confirmPairing()).rejects.toMatchObject({ code: "expired" });
  });

  it("a host that is missing fails the start with host_missing", async () => {
    const { flow } = setup(async () => {
      throw new BridgeError("transport", "Specified native messaging host not found.");
    });
    await expect(flow.startPairing()).rejects.toMatchObject({ code: "host_missing" });
  });

  it("forget clears the record and the session", async () => {
    const { store, session, flow } = setup(async (cb) => {
      await cb("000 001");
      return record();
    });
    await flow.startPairing();
    await flow.confirmPairing();
    await flow.forgetPairing();
    expect(await store.getPairing()).toBeNull();
    await expect(session.getClient()).rejects.toMatchObject({ code: "unpaired" });
  });

  it("names the browser family", () => {
    expect(browserName("Mozilla/5.0 (Macintosh) Gecko/20100101 Firefox/131.0")).toBe("Firefox");
    expect(browserName("Mozilla/5.0 AppleWebKit/537.36 Chrome/130.0 Safari/537.36")).toBe("Chrome");
    expect(browserName("Mozilla/5.0 AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15")).toBe("Safari");
  });
});
