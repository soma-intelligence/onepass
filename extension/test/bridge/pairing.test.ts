// @vitest-environment node
import { describe, expect, it } from "vitest";
import { BridgeError, toB64 } from "../../src/bridge/bytes";
import { kemFromSeeds } from "../../src/bridge/kem";
import {
  ExtPairing,
  PAIRING_TIMEOUT_MS,
  recordFromJson,
  recordToJson,
} from "../../src/bridge/pairing";
import type { PairDone, PairOffer } from "../../src/bridge/wire";
import { type PairingVector, b, loadVector } from "./vectors";

const v = loadVector<PairingVector>("pairing");

async function started(now: () => number = () => 0) {
  return ExtPairing.startDeterministic(
    v.ext_name,
    v.browser,
    kemFromSeeds(b(v.ext_mlkem_seed), b(v.ext_x25519_secret)),
    b(v.ext_nonce),
    { now },
  );
}

async function offered(now: () => number = () => 0) {
  const { state } = await started(now);
  const out = await state.onOfferDeterministic(
    v.pair_offer as unknown as PairOffer,
    b(v.encaps_mlkem_seed),
    b(v.encaps_x25519_eph),
  );
  return { state, ...out };
}

async function errCode(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    return e instanceof BridgeError ? e.code : String(e);
  }
  return "none";
}

describe("pairing vectors (spec 6.4)", () => {
  it("pair_hello carries the vector commitment", async () => {
    const { hello } = await started();
    expect(hello).toEqual(v.pair_hello);
  });

  it("pair_reveal, transcript, code and keys match", async () => {
    const { state, reveal, sas } = await offered();
    expect(reveal).toEqual(v.pair_reveal);
    expect(sas).toBe(v.sas);
    const keys = state.vectorKeys();
    expect(keys && toB64(keys.transcriptHash)).toBe(v.transcript_hash);
    expect(keys && toB64(keys.pairingKey)).toBe(v.pairing_key);
    expect(keys && toB64(keys.confirmKey)).toBe(v.confirm_key);
  });

  it("host MAC verifies, pair_confirm and record match", async () => {
    const { state } = await offered();
    await state.onDone(v.pair_done as unknown as PairDone);
    const { confirm, record } = await state.confirm();
    expect(confirm).toEqual(v.pair_confirm);
    expect(toB64(record.key)).toBe(v.pairing_key);
    expect(toB64(record.pairingId)).toBe(v.pairing_id);
    // Single use: the state is closed afterwards.
    expect(await errCode(state.confirm())).toBe("bad_frame");
  });

  it("random start gives fresh commitments", async () => {
    const a = await ExtPairing.start("OnePass", "Chromium");
    const c = await ExtPairing.start("OnePass", "Chromium");
    expect(a.hello.commit).not.toBe(c.hello.commit);
    expect(a.hello).toMatchObject({ v: 1, t: "pair_hello", ext_name: "OnePass", browser: "Chromium" });
  });
});

describe("pairing failures", () => {
  it("a wrong host MAC is refused and wipes the state", async () => {
    const { state } = await offered();
    const mac = b(v.mac_host);
    mac[0] = (mac[0] ?? 0) ^ 1;
    const bad = { ...v.pair_done, mac: toB64(mac) } as unknown as PairDone;
    expect(await errCode(state.onDone(bad))).toBe("bad_mac");
    expect(state.vectorKeys()).toBeUndefined();
    expect(await errCode(state.onDone(v.pair_done as unknown as PairDone))).toBe("bad_frame");
    expect(await errCode(state.confirm())).toBe("bad_frame");
  });

  it("out of order steps are refused", async () => {
    const { state } = await started();
    expect(await errCode(state.onDone(v.pair_done as unknown as PairDone))).toBe("bad_frame");
    expect(await errCode(state.confirm())).toBe("bad_frame");
  });

  it("the 120 s deadline expires the pairing", async () => {
    let t = 1_000;
    const { state } = await offered(() => t);
    t += PAIRING_TIMEOUT_MS + 1;
    expect(await errCode(state.onDone(v.pair_done as unknown as PairDone))).toBe("expired");
  });

  it("names are bounded and without control characters", async () => {
    for (const [name, browser] of [
      ["", "Chromium"],
      ["x".repeat(129), "Chromium"],
      ["é".repeat(65), "Chromium"],
      ["One\nPass", "Chromium"],
      ["OnePass", "Chro\u0085mium"],
    ] as const) {
      expect(await errCode(ExtPairing.start(name, browser)), JSON.stringify(name)).toBe("bad_frame");
    }
    await expect(ExtPairing.start("x".repeat(128), "é".repeat(64))).resolves.toBeDefined();
  });

  it("a tampered offer key is refused", async () => {
    const { state } = await started();
    const offer = { ...v.pair_offer, pk: toB64(new Uint8Array(1600).fill(0xff)) } as unknown as PairOffer;
    expect(await errCode(state.onOffer(offer))).toBe("bad_frame");
  });
});

describe("pairing record storage", () => {
  it("JSON round trip with base64 fields", () => {
    const rec = { pairingId: b(v.pairing_id), key: b(v.pairing_key), createdAt: 1_700_000_000_000 };
    const json = recordToJson(rec);
    expect(json).toEqual({ pairing_id: v.pairing_id, key: v.pairing_key, created_at: 1_700_000_000_000 });
    expect(recordFromJson(JSON.parse(JSON.stringify(json)))).toEqual(rec);
  });

  it("refuses malformed records", () => {
    for (const bad of [
      null,
      {},
      { pairing_id: "AA==", key: v.pairing_key, created_at: 0 },
      { pairing_id: v.pairing_id, key: "AA==", created_at: 0 },
      { pairing_id: v.pairing_id, key: v.pairing_key, created_at: "0" },
    ]) {
      expect(() => recordFromJson(bad)).toThrow(BridgeError);
    }
  });
});
