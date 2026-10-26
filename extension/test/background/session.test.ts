import { describe, expect, it } from "vitest";
import { BridgeError } from "../../src/bridge/bytes";
import { BridgeAppError } from "../../src/bridge/client";
import { recordToJson } from "../../src/bridge/pairing";
import { BgError, RECONNECT_DELAYS_MS, Session, toBgError } from "../../src/background/session";
import { Store } from "../../src/background/store";
import { FakeClient, record } from "./fake-client";
import { FakeExt } from "./fake-ext";

async function paired(): Promise<{ ext: FakeExt; store: Store }> {
  const ext = new FakeExt();
  const store = new Store(ext);
  await ext.local.set({ pairing: recordToJson(record()) });
  return { ext, store };
}

async function rejection(p: Promise<unknown>): Promise<BgError> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(BgError);
    return e as BgError;
  }
  throw new Error("expected a rejection");
}

describe("Session", () => {
  it("unpaired without a stored record, no connection attempt", async () => {
    const ext = new FakeExt();
    let made = 0;
    const s = new Session({
      store: new Store(ext),
      newClient: () => {
        made++;
        return new FakeClient();
      },
    });
    expect((await rejection(s.getClient())).code).toBe("unpaired");
    expect(made).toBe(0);
  });

  it("opens with the stored pairing and reuses the open client", async () => {
    const { store } = await paired();
    const clients: FakeClient[] = [];
    const s = new Session({
      store,
      newClient: () => {
        const c = new FakeClient();
        clients.push(c);
        return c;
      },
    });
    const a = await s.getClient();
    const b = await s.getClient();
    expect(a).toBe(b);
    expect(clients).toHaveLength(1);
    expect(clients[0]?.openedWith?.pairingId).toEqual(record().pairingId);
  });

  it("concurrent callers share one open (no busy handshake)", async () => {
    const { store } = await paired();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const clients: FakeClient[] = [];
    const s = new Session({
      store,
      newClient: () => {
        const c = new FakeClient(() => ({}), () => gate);
        clients.push(c);
        return c;
      },
    });
    const all = Promise.all([s.getClient(), s.getClient(), s.getClient()]);
    await Promise.resolve();
    release();
    const [a, b, c] = await all;
    expect(a).toBe(b);
    expect(b).toBe(c);
    expect(clients).toHaveLength(1);
    expect(clients[0]?.openCalls).toBe(1);
  });

  it("session_reopens_after_port_close", async () => {
    const { store } = await paired();
    const clients: FakeClient[] = [];
    const s = new Session({
      store,
      newClient: () => {
        const c = new FakeClient((r) => (r.op === "status" ? { locked: false, account: "alex@atlas.dev", vaults: 1 } : {}));
        clients.push(c);
        return c;
      },
    });
    expect(await s.request({ op: "status" })).toEqual({ locked: false, account: "alex@atlas.dev", vaults: 1 });
    clients[0]?.drop();
    expect(await s.request({ op: "status" })).toEqual({ locked: false, account: "alex@atlas.dev", vaults: 1 });
    expect(clients).toHaveLength(2);
    expect(clients[1]?.isOpen).toBe(true);
  });

  it("host_missing_after_3_attempts (retries spaced 1, 2, 4 s)", async () => {
    const { store } = await paired();
    const slept: number[] = [];
    let made = 0;
    const s = new Session({
      store,
      newClient: () => {
        made++;
        return new FakeClient(undefined, async () => {
          throw new BridgeError("transport", "Specified native messaging host not found.");
        });
      },
      sleep: async (ms) => {
        slept.push(ms);
      },
    });
    expect((await rejection(s.getClient())).code).toBe("host_missing");
    expect(RECONNECT_DELAYS_MS).toEqual([1000, 2000, 4000]);
    expect(slept).toEqual([1000, 2000, 4000]);
    // The first try plus three retries.
    expect(made).toBe(4);
  });

  it("a throwing connectNative counts as a failed attempt", async () => {
    const { store } = await paired();
    let made = 0;
    const s = new Session({
      store,
      newClient: () => {
        made++;
        if (made < 3) throw new Error("no host");
        return new FakeClient();
      },
      sleep: async () => undefined,
    });
    await s.getClient();
    expect(made).toBe(3);
  });

  it("an unknown pairing is unpaired, without retry", async () => {
    const { store } = await paired();
    let made = 0;
    const s = new Session({
      store,
      newClient: () => {
        made++;
        return new FakeClient(undefined, async () => {
          throw new BridgeError("host", "unknown_pairing", "unknown_pairing");
        });
      },
      sleep: async () => undefined,
    });
    expect((await rejection(s.getClient())).code).toBe("unpaired");
    expect(made).toBe(1);
  });

  it("a bad host MAC is not retried", async () => {
    const { store } = await paired();
    let made = 0;
    const s = new Session({
      store,
      newClient: () => {
        made++;
        return new FakeClient(undefined, async () => {
          throw new BridgeError("bad_mac");
        });
      },
      sleep: async () => undefined,
    });
    expect((await rejection(s.getClient())).code).toBe("bad_mac");
    expect(made).toBe(1);
  });

  it("locked_translated", async () => {
    const { store } = await paired();
    let lockedSeen = 0;
    const s = new Session({
      store,
      newClient: () => new FakeClient(() => new BridgeAppError("locked", "vault is locked")),
    });
    s.onLocked(() => lockedSeen++);
    const e = await rejection(s.request({ op: "list_for_origin", ctx: "menu", origin: "https://atlas-cloud.test" }));
    expect(e.code).toBe("locked");
    // The host's raw message is never surfaced.
    expect(e.message).not.toContain("vault is locked");
    expect(lockedSeen).toBe(1);
  });

  it("an error reply with id null fails the pending request with its code", async () => {
    const { store } = await paired();
    const s = new Session({ store, newClient: () => new FakeClient(() => new BridgeAppError("invalid", "")) });
    expect((await rejection(s.request({ op: "status" }))).code).toBe("invalid");
  });

  it("close during an open does not install the client", async () => {
    const { store } = await paired();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const made: FakeClient[] = [];
    const s = new Session({
      store,
      newClient: () => {
        const c = new FakeClient(undefined, () => gate);
        made.push(c);
        return c;
      },
    });
    const p = s.getClient();
    while (made.length === 0) await new Promise((r) => setTimeout(r, 0));
    s.close();
    release();
    expect((await rejection(p)).code).toBe("unpaired");
    expect(made[0]?.closed).toBe(true);
  });
});

describe("toBgError", () => {
  it("maps protocol and host failures to stable codes", () => {
    expect(toBgError(new BridgeError("transport")).code).toBe("host_missing");
    expect(toBgError(new BridgeError("timeout")).code).toBe("timeout");
    expect(toBgError(new BridgeError("host", "x", "version")).code).toBe("version");
    expect(toBgError(new BridgeError("host", "x", "weird")).code).toBe("internal");
    expect(toBgError(new BridgeAppError("not_allowed", "")).code).toBe("not_allowed");
    expect(toBgError(new BridgeAppError("made_up", "")).code).toBe("internal");
    expect(toBgError(new Error("boom")).code).toBe("internal");
  });
});
