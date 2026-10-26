// @vitest-environment node
import { createDecipheriv } from "node:crypto";
import { describe, expect, it } from "vitest";
import { BridgeError, toB64 } from "../../src/bridge/bytes";
import { Channel } from "../../src/bridge/channel";
import { kemFromSeeds } from "../../src/bridge/kem";
import { extHelloDeterministic } from "../../src/bridge/session";
import { type MsgEnvelope, type WelcomeEnvelope, parseEnvelope } from "../../src/bridge/wire";
import { type SessionVector, b, loadVector } from "./vectors";

const v = loadVector<SessionVector>("session");
const welcome = v.welcome as unknown as WelcomeEnvelope;
const record = () => ({ pairingId: b(v.pairing_id), key: b(v.pairing_key), createdAt: 0 });

function pending() {
  return extHelloDeterministic(
    record(),
    kemFromSeeds(b(v.ext_mlkem_seed), b(v.ext_x25519_secret)),
    b(v.ext_nonce),
  );
}

async function errCode(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    return e instanceof BridgeError ? e.code : String(e);
  }
  return "none";
}

/** Host end of the vector session, from the vector keys. */
function hostChannel(): Promise<Channel> {
  return Channel.create("host", b(v.session_id), b(v.key_e2h), b(v.key_h2e));
}

const h2e = (i: number) => v.frames_h2e[i]!.msg as unknown as MsgEnvelope;

describe("session vectors (spec 6.5, 6.6)", () => {
  it("hello matches", () => {
    expect(pending().hello).toEqual(v.hello);
  });

  it("welcome gives the vector transcript, keys and finish", async () => {
    const p = pending().pending;
    const keys = await p.vectorKeys(welcome);
    expect(toB64(keys.transcriptHash)).toBe(v.transcript_hash);
    expect(toB64(keys.e2h)).toBe(v.key_e2h);
    expect(toB64(keys.h2e)).toBe(v.key_h2e);
    expect(toB64(keys.confirm)).toBe(v.key_confirm);
    const { finish } = await pending().pending.onWelcome(welcome);
    expect(finish).toEqual(v.finish);
  });

  it("channel seals the e2h frames and opens the h2e frames", async () => {
    const { channel } = await pending().pending.onWelcome(welcome);
    for (const f of v.frames_e2h) {
      expect(await channel.seal(new TextEncoder().encode(f.plaintext))).toEqual(f.msg);
    }
    for (const f of v.frames_h2e) {
      const plain = await channel.open(f.msg as unknown as MsgEnvelope);
      expect(new TextDecoder().decode(plain)).toBe(f.plaintext);
    }
  });

  it("nonce and AAD layout match an independent AES-GCM open", async () => {
    const f = v.frames_e2h[1]!;
    const d = b((f.msg as { d: string }).d);
    const nonce = Buffer.alloc(12);
    nonce.writeBigUInt64BE(BigInt(f.counter), 4);
    const aad = Buffer.alloc(25);
    Buffer.from(b(v.session_id)).copy(aad, 0);
    aad[16] = 0;
    aad.writeBigUInt64BE(BigInt(f.counter), 17);
    const dec = createDecipheriv("aes-256-gcm", b(v.key_e2h), nonce);
    dec.setAAD(aad);
    dec.setAuthTag(d.slice(d.length - 16));
    const plain = Buffer.concat([dec.update(d.slice(0, d.length - 16)), dec.final()]);
    expect(plain.toString()).toBe(f.plaintext);
  });
});

describe("session and channel failures", () => {
  it("a wrong host MAC in welcome is refused", async () => {
    const mac = b(v.welcome.mac as string);
    mac[5] = (mac[5] ?? 0) ^ 1;
    const bad = { ...welcome, mac: toB64(mac) };
    expect(await errCode(pending().pending.onWelcome(bad))).toBe("bad_mac");
  });

  it("a welcome for another pairing key is refused", async () => {
    const other = { ...record(), key: new Uint8Array(32).fill(1) };
    const p = extHelloDeterministic(
      other,
      kemFromSeeds(b(v.ext_mlkem_seed), b(v.ext_x25519_secret)),
      b(v.ext_nonce),
    ).pending;
    expect(await errCode(p.onWelcome(welcome))).toBe("bad_mac");
  });

  it("a pending session is single use", async () => {
    const p = pending().pending;
    await p.onWelcome(welcome);
    expect(await errCode(p.onWelcome(welcome))).toBe("bad_frame");
  });

  it("a replayed frame closes the channel", async () => {
    const { channel } = await pending().pending.onWelcome(welcome);
    await channel.open(h2e(0));
    expect(await errCode(channel.open(h2e(0)))).toBe("replay");
    expect(channel.closed).toBe(true);
    expect(await errCode(channel.open(h2e(1)))).toBe("closed");
    expect(await errCode(channel.seal(new Uint8Array([1])))).toBe("closed");
  });

  it("a skipped counter closes the channel", async () => {
    const { channel } = await pending().pending.onWelcome(welcome);
    expect(await errCode(channel.open(h2e(1)))).toBe("replay");
    expect(channel.closed).toBe(true);
  });

  it("a tampered frame closes the channel", async () => {
    const { channel } = await pending().pending.onWelcome(welcome);
    const d = b(h2e(0).d);
    d[d.length - 1] = (d[d.length - 1] ?? 0) ^ 1;
    expect(await errCode(channel.open({ ...h2e(0), d: toB64(d) }))).toBe("bad_mac");
    expect(channel.closed).toBe(true);
  });

  it("a frame sealed for the other direction does not open", async () => {
    const { channel } = await pending().pending.onWelcome(welcome);
    const e2h = v.frames_e2h[0]!.msg as unknown as MsgEnvelope;
    expect(await errCode(channel.open(e2h))).toBe("bad_mac");
  });

  it("a version 2 frame is refused before the channel", () => {
    let code = "none";
    try {
      parseEnvelope({ ...h2e(0), v: 2 });
    } catch (e) {
      code = e instanceof BridgeError ? e.code : "other";
    }
    expect(code).toBe("version");
  });

  it("host and extension ends interoperate, both directions", async () => {
    const { channel } = await pending().pending.onWelcome(welcome);
    const host = await hostChannel();
    for (let i = 0; i < 3; i++) {
      const m = await channel.seal(new Uint8Array([i]));
      expect(m.c).toBe(i);
      expect(await host.open(m)).toEqual(new Uint8Array([i]));
    }
    // Host counter 0 is the first h2e frame.
    const back = await host.seal(new TextEncoder().encode(v.frames_h2e[0]!.plaintext));
    expect(back).toEqual(v.frames_h2e[0]!.msg);
    channel.close();
    expect(channel.closed).toBe(true);
  });
});
