import { describe, expect, it } from "vitest";
import { isSafari, openTransport } from "../../src/background/native";
import { SAFARI_APP, randomConnId, safariTransport } from "../../src/background/safari";
import { FakeExt } from "./fake-ext";

const CONN = "0123456789abcdef0123456789abcdef";

/** A relay double: records requests, answers polls from a queue the test fills. */
class FakeRelay {
  readonly calls: { app: string; msg: Record<string, unknown> }[] = [];
  openReply: unknown = { ok: true, frames: [], closed: false };
  sendReply: unknown = { ok: true, frames: [], closed: false };
  private polls: ((r: unknown) => void)[] = [];

  sendNativeMessage = (app: string, msg: unknown): Promise<unknown> => {
    const m = msg as Record<string, unknown>;
    this.calls.push({ app, msg: m });
    switch (m.op) {
      case "open":
        return Promise.resolve(this.openReply);
      case "send":
        return Promise.resolve(this.sendReply);
      case "close":
        return Promise.resolve({ ok: true, frames: [], closed: true });
      default:
        return new Promise((r) => this.polls.push(r));
    }
  };

  /** Answer the waiting poll. */
  answer(reply: unknown): void {
    const p = this.polls.shift();
    if (!p) throw new Error("no poll waiting");
    p(reply);
  }

  get waiting(): number {
    return this.polls.length;
  }

  ops(): unknown[] {
    return this.calls.map((c) => c.msg.op);
  }
}

const tick = () => new Promise((r) => setTimeout(r, 0));

describe("safariTransport", () => {
  it("opens, sends envelopes as JSON text in order, and polls frames back", async () => {
    const relay = new FakeRelay();
    const t = safariTransport(relay, CONN);
    t.send({ v: 1, t: "hello", pairing_id: "AA==", pk: "AA==", n: "AA==" });
    t.send({ v: 1, t: "finish", mac: "AA==" });
    await tick();
    expect(relay.calls.every((c) => c.app === SAFARI_APP && c.msg.onepass === 1 && c.msg.conn === CONN)).toBe(true);
    // open first, then the poll loop and the sends in order.
    const sends = relay.calls.filter((c) => c.msg.op === "send").map((c) => JSON.parse(c.msg.frame as string).t);
    expect(relay.ops()[0]).toBe("open");
    expect(sends).toEqual(["hello", "finish"]);
    expect(relay.calls.find((c) => c.msg.op === "open")!.msg).toEqual({ onepass: 1, op: "open", conn: CONN });

    // A frame that arrives before a listener is registered is kept.
    relay.answer({ ok: true, frames: ['{"v":1,"t":"welcome"}'], closed: false });
    await tick();
    const got: unknown[] = [];
    t.onMessage((m) => got.push(m));
    relay.answer({ ok: true, frames: ['{"v":1,"t":"msg","n":0}', '{"v":1,"t":"msg","n":1}'], closed: false });
    await tick();
    expect(got).toEqual([
      { v: 1, t: "welcome" },
      { v: 1, t: "msg", n: 0 },
      { v: 1, t: "msg", n: 1 },
    ]);
    // Only one poll waits at a time.
    expect(relay.waiting).toBe(1);
    t.close();
    await tick();
    expect(relay.ops().at(-1)).toBe("close");
    expect(() => t.send({ v: 1, t: "finish", mac: "AA==" })).toThrow();
  });

  it("reports the host's end once, and drops later frames", async () => {
    const relay = new FakeRelay();
    const t = safariTransport(relay, CONN);
    const reasons: (string | undefined)[] = [];
    const got: unknown[] = [];
    t.onMessage((m) => got.push(m));
    t.onClose((e) => reasons.push(e?.message));
    await tick();
    relay.answer({ ok: true, frames: ['{"v":1,"t":"error","code":"unknown_pairing"}'], closed: true });
    await tick();
    expect(got).toEqual([{ v: 1, t: "error", code: "unknown_pairing" }]);
    expect(reasons).toEqual(["native host disconnected"]);
    expect(relay.waiting).toBe(0);
    expect(() => t.send({ v: 1, t: "finish", mac: "AA==" })).toThrow();
  });

  it("an app without a host closes with the relay's code", async () => {
    const relay = new FakeRelay();
    relay.openReply = { ok: false, error: "unavailable" };
    const t = safariTransport(relay, CONN);
    const reasons: (string | undefined)[] = [];
    t.onClose((e) => reasons.push(e?.message));
    await tick();
    expect(reasons).toEqual(["relay: unavailable"]);
    expect(relay.ops()).toEqual(["open", "close"]);
  });

  it("refuses malformed relay replies and frames", async () => {
    const bad: unknown[] = [
      null,
      "ok",
      [],
      { ok: true },
      { ok: true, frames: [{ v: 1 }], closed: false },
      { ok: true, frames: [], closed: "no" },
      { ok: "true", frames: [], closed: false },
      { ok: true, frames: ["not json"], closed: false },
    ];
    for (const reply of bad) {
      const relay = new FakeRelay();
      const t = safariTransport(relay, CONN);
      const reasons: string[] = [];
      const got: unknown[] = [];
      t.onMessage((m) => got.push(m));
      t.onClose((e) => reasons.push(e?.message ?? ""));
      await tick();
      relay.answer(reply);
      await tick();
      expect(reasons.length).toBe(1);
      expect(got).toEqual([]);
    }
  });

  it("never echoes a raw relay error text", async () => {
    const relay = new FakeRelay();
    relay.openReply = { ok: false, error: "<script>secret</script>" };
    const t = safariTransport(relay, CONN);
    const reasons: string[] = [];
    t.onClose((e) => reasons.push(e?.message ?? ""));
    await tick();
    expect(reasons).toEqual(["relay: unknown"]);
  });

  it("a failed send closes the transport", async () => {
    const relay = new FakeRelay();
    relay.sendReply = { ok: false, error: "unknown_conn" };
    const t = safariTransport(relay, CONN);
    const reasons: string[] = [];
    t.onClose((e) => reasons.push(e?.message ?? ""));
    t.send({ v: 1, t: "finish", mac: "AA==" });
    await tick();
    await tick();
    expect(reasons).toEqual(["relay: unknown_conn"]);
  });

  it("draws 128-bit lowercase hex connection ids", () => {
    const a = randomConnId();
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(randomConnId()).not.toBe(a);
  });
});

describe("openTransport", () => {
  it("uses native messaging outside Safari", () => {
    const ext = new FakeExt();
    expect(isSafari(ext.runtime)).toBe(false);
    openTransport(ext.runtime);
    expect(ext.ports.length).toBe(1);
  });

  it("uses the relay in Safari, never connectNative", async () => {
    const ext = new FakeExt();
    const relay = new FakeRelay();
    const runtime = {
      ...ext.runtime,
      getURL: (p: string) => `safari-web-extension://4B1E-UUID/${p}`,
      sendNativeMessage: relay.sendNativeMessage,
    };
    expect(isSafari(runtime)).toBe(true);
    openTransport(runtime);
    await tick();
    expect(ext.ports.length).toBe(0);
    expect(relay.ops()[0]).toBe("open");
  });

  it("Safari without sendNativeMessage throws (shown as app not found)", () => {
    const ext = new FakeExt();
    const runtime = { ...ext.runtime, getURL: (p: string) => `safari-web-extension://x/${p}` };
    expect(() => openTransport(runtime)).toThrow();
    expect(ext.ports.length).toBe(0);
  });
});
