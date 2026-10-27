// @vitest-environment node
// BridgeClient against an in-memory host that runs the host side of the
// session handshake (spec 6.5) with the client's own primitives.
import { afterEach, describe, expect, it, vi } from "vitest";
import { BridgeError, concat, fromB64, randomBytes, toB64 } from "../../src/bridge/bytes";
import { BridgeAppError, BridgeClient, type Transport } from "../../src/bridge/client";
import { Channel } from "../../src/bridge/channel";
import { expand, hmac } from "../../src/bridge/kdf";
import { decapsulate, encapsulate, generateKem } from "../../src/bridge/kem";
import { ExtPairing, PAIRING_TIMEOUT_MS, type PairingRecord } from "../../src/bridge/pairing";
import { TRANSCRIPT_LABEL, Transcript } from "../../src/bridge/transcript";
import { type Envelope, type MsgEnvelope, parseEnvelope } from "../../src/bridge/wire";

type Answer = (req: Record<string, unknown>) => unknown | undefined;

class FakeHost implements Transport {
  private onMsg: ((m: unknown) => void) | undefined;
  private onCl: ((e?: Error) => void) | undefined;
  closed = false;
  seen: Record<string, unknown>[] = [];
  channel: Channel | undefined;
  private pendingKeys: { t: Uint8Array; confirm: Uint8Array; e2h: Uint8Array; h2e: Uint8Array; sid: Uint8Array } | undefined;
  private chain: Promise<void> = Promise.resolve();

  constructor(
    readonly record: PairingRecord,
    private readonly answer: Answer,
    private readonly opts: { badWelcomeMac?: boolean; errorOnHello?: string } = {},
  ) {}

  send(env: Envelope): void {
    const copy = JSON.parse(JSON.stringify(env)) as unknown;
    this.chain = this.chain.then(() => this.handle(copy));
  }
  onMessage(cb: (m: unknown) => void): void {
    this.onMsg = cb;
  }
  onClose(cb: (e?: Error) => void): void {
    this.onCl = cb;
  }
  close(): void {
    this.closed = true;
  }
  deliver(m: unknown): void {
    queueMicrotask(() => this.onMsg?.(m));
  }
  dropConnection(): void {
    this.onCl?.(new Error("gone"));
  }

  private pairingHost:
    | { hello: Record<string, string>; kem: ReturnType<typeof generateKem>; nH: Uint8Array; id: Uint8Array }
    | undefined;
  pairedKey: Uint8Array | undefined;

  private async handle(raw: unknown): Promise<void> {
    const env = parseEnvelope(raw);
    if (env.t === "pair_hello") {
      const kem = generateKem();
      const nH = randomBytes(32);
      const id = randomBytes(16);
      this.pairingHost = { hello: env as unknown as Record<string, string>, kem, nH, id };
      this.deliver({ v: 1, t: "pair_offer", pairing_id: toB64(id), pk: toB64(kem.public), n: toB64(nH) });
    } else if (env.t === "pair_reveal") {
      const h = this.pairingHost!;
      const ct = fromB64(env.ct);
      const ss = await decapsulate(h.kem.secret, ct);
      const tr = new Transcript(TRANSCRIPT_LABEL);
      const enc = new TextEncoder();
      for (const f of [
        enc.encode(h.hello.ext_name),
        enc.encode(h.hello.browser),
        fromB64(h.hello.commit!),
        h.id,
        h.kem.public,
        h.nH,
        fromB64(env.pk),
        fromB64(env.n),
        ct,
      ]) {
        tr.push(f);
      }
      const t = await tr.hash();
      const confirm = await expand(t, ss, "onepass/bridge/pair-confirm/v1");
      this.pairedKey = await expand(t, ss, "onepass/bridge/pairing-key/v1");
      this.deliver({ v: 1, t: "pair_sas" });
      this.deliver({ v: 1, t: "pair_done", mac: toB64(await hmac(confirm, "host", t)) });
    } else if (env.t === "pair_confirm") {
      this.deliver({ v: 1, t: "pair_ok" });
    } else if (env.t === "hello") {
      if (this.opts.errorOnHello) {
        this.deliver({ v: 1, t: "error", code: this.opts.errorOnHello });
        return;
      }
      const pkE = fromB64(env.pk);
      const { ct, ss } = await encapsulate(pkE);
      const nH = randomBytes(32);
      const sid = randomBytes(16);
      const tr = new Transcript(TRANSCRIPT_LABEL);
      for (const f of [fromB64(env.pairing_id), pkE, fromB64(env.n), ct, nH, sid]) tr.push(f);
      const t = await tr.hash();
      const ikm = concat(ss, this.record.key);
      const keys = {
        t,
        sid,
        e2h: await expand(t, ikm, "onepass/bridge/session/e2h/v1"),
        h2e: await expand(t, ikm, "onepass/bridge/session/h2e/v1"),
        confirm: await expand(t, ikm, "onepass/bridge/session/confirm/v1"),
      };
      this.pendingKeys = keys;
      const mac = await hmac(keys.confirm, "host", t);
      if (this.opts.badWelcomeMac) mac[0] = (mac[0] ?? 0) ^ 1;
      this.deliver({ v: 1, t: "welcome", ct: toB64(ct), n: toB64(nH), session_id: toB64(sid), mac: toB64(mac) });
    } else if (env.t === "finish") {
      const k = this.pendingKeys!;
      const want = await hmac(k.confirm, "ext", k.t);
      expect(env.mac).toBe(toB64(want));
      this.channel = await Channel.create("host", k.sid, k.e2h, k.h2e);
    } else if (env.t === "msg") {
      const req = JSON.parse(new TextDecoder().decode(await this.channel!.open(env))) as Record<string, unknown>;
      this.seen.push(req);
      const reply = this.answer(req);
      if (reply !== undefined) await this.reply(reply);
    }
  }

  async reply(obj: unknown): Promise<void> {
    this.deliver(await this.channel!.seal(new TextEncoder().encode(JSON.stringify(obj))));
  }
}

const record = (): PairingRecord => ({ pairingId: randomBytes(16), key: randomBytes(32), createdAt: 0 });

async function rejection(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (e) {
    return e;
  }
  throw new Error("expected a rejection");
}

describe("BridgeClient", () => {
  it("opens a session, numbers requests from 1 and matches replies", async () => {
    const host = new FakeHost(record(), (r) => {
      if (r.op === "status") return { id: r.id, ok: { locked: false, account: "alex@atlas.dev", vaults: 2 } };
      if (r.op === "fill_card") {
        return {
          id: r.id,
          ok: { cardholder: "Alex Martin", number: "4242424242424242", exp_month: "04", exp_year: "2029", cvv: "123" },
        };
      }
      return { id: r.id, err: { code: "invalid", msg: "unsupported" } };
    });
    const client = new BridgeClient(host);
    await client.open(host.record);
    expect(client.isOpen).toBe(true);
    const [a, c] = await Promise.all([
      client.request({ op: "status" }),
      client.request({ op: "fill_card", ctx: "menu", item_id: "it_02", origin: "https://atlas-cloud.test" }),
    ]);
    expect(a).toEqual({ locked: false, account: "alex@atlas.dev", vaults: 2 });
    expect(c.exp_month).toBe("04");
    expect(c.exp_year).toBe("2029");
    const e = await rejection(client.request({ op: "vaults" }));
    expect(e).toBeInstanceOf(BridgeAppError);
    expect((e as BridgeAppError).code).toBe("invalid");
    expect(host.seen.map((r) => r.id)).toEqual([1, 2, 3]);
    expect(host.seen[1]).toEqual({
      id: 2,
      op: "fill_card",
      ctx: "menu",
      item_id: "it_02",
      origin: "https://atlas-cloud.test",
    });
    client.close();
    expect(host.closed).toBe(true);
    expect(((await rejection(client.request({ op: "status" }))) as BridgeError).code).toBe("closed");
  });

  it("an error reply with a null id fails the oldest pending request", async () => {
    const host = new FakeHost(record(), (r) => (r.id === 1 ? { id: null, err: { code: "invalid", msg: "x" } } : undefined));
    const client = new BridgeClient(host);
    await client.open(host.record);
    const e = await rejection(client.request({ op: "status" }));
    expect((e as BridgeAppError).code).toBe("invalid");
  });

  it("a timed out request burns its id; a late reply is dropped", async () => {
    const host = new FakeHost(record(), () => undefined);
    const client = new BridgeClient(host, { requestTimeoutMs: 30 });
    await client.open(host.record);
    // Request deadlines run on a fake clock: nothing expires by load alone.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      const first = rejection(client.request({ op: "status" }));
      await vi.advanceTimersByTimeAsync(30);
      expect(((await first) as BridgeError).code).toBe("timeout");
      // Created under the fake clock, this deadline never fires.
      const second = client.request({ op: "unlock" });
      vi.useRealTimers();
      await vi.waitFor(() => expect(host.seen.map((r) => r.id)).toEqual([1, 2]));
      await host.reply({ id: 1, ok: { locked: true } });
      await host.reply({ id: 2, ok: { locked: false } });
      expect(await second).toEqual({ locked: false });
      expect(client.isOpen).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("an unknown pairing error frame rejects open", async () => {
    const host = new FakeHost(record(), () => undefined, { errorOnHello: "unknown_pairing" });
    const client = new BridgeClient(host);
    const e = (await rejection(client.open(record()))) as BridgeError;
    expect(e.code).toBe("host");
    expect(e.hostCode).toBe("unknown_pairing");
    expect(host.closed).toBe(true);
  });

  it("a wrong welcome MAC rejects open", async () => {
    const host = new FakeHost(record(), () => undefined, { badWelcomeMac: true });
    const client = new BridgeClient(host);
    const e = (await rejection(client.open(host.record))) as BridgeError;
    expect(e.code).toBe("bad_mac");
    expect(host.closed).toBe(true);
  });

  it("a tampered or replayed reply closes everything", async () => {
    const host = new FakeHost(record(), () => undefined);
    const client = new BridgeClient(host);
    await client.open(host.record);
    const p = client.request({ op: "status" });
    // The host has opened the request: its channel is live.
    await vi.waitFor(() => expect(host.seen).toHaveLength(1));
    const frame = await host.channel!.seal(new TextEncoder().encode('{"id":1,"ok":{}}'));
    const d = fromB64(frame.d);
    d[0] = (d[0] ?? 0) ^ 1;
    host.deliver({ ...frame, d: toB64(d) } satisfies MsgEnvelope);
    expect(((await rejection(p)) as BridgeError).code).toBe("bad_mac");
    expect(client.isOpen).toBe(false);
    expect(host.closed).toBe(true);
  });

  it("a skipped counter closes everything", async () => {
    const host = new FakeHost(record(), () => undefined);
    const client = new BridgeClient(host);
    await client.open(host.record);
    const p = client.request({ op: "status" });
    // The host has opened the request: its channel is live.
    await vi.waitFor(() => expect(host.seen).toHaveLength(1));
    await host.channel!.seal(new TextEncoder().encode("{}"));
    await host.reply({ id: 1, ok: {} });
    expect(((await rejection(p)) as BridgeError).code).toBe("replay");
  });

  it("a version 2 frame closes everything", async () => {
    const host = new FakeHost(record(), () => undefined);
    const client = new BridgeClient(host);
    await client.open(host.record);
    const p = client.request({ op: "status" });
    host.deliver({ v: 2, t: "msg", c: 0, d: "AA==" });
    expect(((await rejection(p)) as BridgeError).code).toBe("version");
  });

  it("a closed transport fails pending requests", async () => {
    const host = new FakeHost(record(), () => undefined);
    const client = new BridgeClient(host);
    await client.open(host.record);
    const p = client.request({ op: "status" });
    host.dropConnection();
    expect(((await rejection(p)) as BridgeError).code).toBe("transport");
  });

  it("requests before a session are refused", async () => {
    const client = new BridgeClient(new FakeHost(record(), () => undefined));
    expect(((await rejection(client.request({ op: "status" }))) as BridgeError).code).toBe("closed");
  });
});

describe("BridgeClient pairing", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("pairs with a host that follows spec 6.4", async () => {
    const host = new FakeHost(record(), () => undefined);
    const client = new BridgeClient(host);
    let shown = "";
    const rec = await client.pair("OnePass", "Chromium", async (sas) => {
      shown = sas;
      return true;
    });
    expect(shown).toMatch(/^\d{3} \d{3}$/);
    expect(rec.key).toEqual(host.pairedKey);
  });

  /** Start a pairing whose user step never settles; resolves once the host MAC verified. */
  async function stuckAtUserStep(host: FakeHost) {
    const onDone = vi.spyOn(ExtPairing.prototype, "onDone");
    const abort = vi.spyOn(ExtPairing.prototype, "abort");
    const client = new BridgeClient(host);
    const p = client.pair("OnePass", "Chromium", () => new Promise<boolean>(() => undefined));
    const outcome = p.then(
      () => "resolved",
      (e: unknown) => e,
    );
    while (onDone.mock.results.length === 0) await new Promise((r) => setImmediate(r));
    await onDone.mock.results[0]!.value;
    const state = onDone.mock.contexts[0] as ExtPairing;
    expect(state.vectorKeys()).toBeDefined();
    return { outcome, abort, state };
  }

  it("a user step that never settles expires at 120 s and wipes the state", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const host = new FakeHost(record(), () => undefined);
    const { outcome, abort, state } = await stuckAtUserStep(host);
    await vi.advanceTimersByTimeAsync(PAIRING_TIMEOUT_MS - 1);
    expect(abort).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    const e = (await outcome) as BridgeError;
    expect(e).toBeInstanceOf(BridgeError);
    expect(e.code).toBe("expired");
    expect(abort).toHaveBeenCalled();
    expect(state.vectorKeys()).toBeUndefined();
    expect(host.closed).toBe(true);
  });

  it("a transport closing during the user step rejects the pairing", async () => {
    const host = new FakeHost(record(), () => undefined);
    const { outcome, abort, state } = await stuckAtUserStep(host);
    host.dropConnection();
    const e = (await outcome) as BridgeError;
    expect(e.code).toBe("transport");
    expect(abort).toHaveBeenCalled();
    expect(state.vectorKeys()).toBeUndefined();
  });

  it("a second concurrent handshake is refused with busy", async () => {
    const host = new FakeHost(record(), () => ({ id: 1, ok: { locked: false } }));
    const client = new BridgeClient(host);
    const first = client.open(host.record);
    const second = (await rejection(client.open(host.record))) as BridgeError;
    expect(second.code).toBe("busy");
    const third = (await rejection(client.pair("OnePass", "Chromium", async () => true))) as BridgeError;
    expect(third.code).toBe("busy");
    await first;
    expect(client.isOpen).toBe(true);
    expect(await client.request({ op: "unlock" })).toEqual({ locked: false });
  });
});
