// @vitest-environment node
import { createHash, hkdfSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { concat, u32be, utf8 } from "../../src/bridge/bytes";
import { expand, hkdf32, hmac, sas, verifyHmac } from "../../src/bridge/kdf";
import { TRANSCRIPT_LABEL, Transcript } from "../../src/bridge/transcript";
import { type PairingVector, b, loadVector } from "./vectors";

const pv = loadVector<PairingVector>("pairing");

describe("kdf", () => {
  it("HKDF matches RFC 5869 case 1", async () => {
    const ikm = new Uint8Array(22).fill(0x0b);
    const salt = new Uint8Array(13).map((_, i) => i);
    const info = new Uint8Array(10).map((_, i) => 0xf0 + i);
    const okm = await hkdf32(salt, ikm, info);
    expect(Buffer.from(okm).toString("hex")).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
    );
  });

  it("expand uses the label as info", async () => {
    const a = await expand(utf8("salt"), utf8("ikm"), "onepass/bridge/sas/v1");
    const want = new Uint8Array(hkdfSync("sha256", "ikm", "salt", "onepass/bridge/sas/v1", 32));
    expect(a).toEqual(want);
  });

  it("SAS cases of the vectors, zero padded", () => {
    for (const c of pv.sas_cases) {
      expect(sas(b(c.code_key))).toBe(c.sas);
    }
  });

  it("HMAC role binding and constant-time verify", async () => {
    const key = new Uint8Array(32).fill(7);
    const t = new Uint8Array(32).fill(9);
    const tag = await hmac(key, "host", t);
    expect(await verifyHmac(key, "host", t, tag)).toBe(true);
    expect(await verifyHmac(key, "ext", t, tag)).toBe(false);
    for (const i of [0, 31]) {
      const bad = tag.slice();
      bad[i] = (bad[i] ?? 0) ^ 1;
      expect(await verifyHmac(key, "host", t, bad)).toBe(false);
    }
    expect(await verifyHmac(key, "host", t, tag.slice(0, 31))).toBe(false);
  });
});

describe("transcript", () => {
  it("known answer: label then length-prefixed fields", async () => {
    const t = new Transcript(TRANSCRIPT_LABEL);
    t.push(utf8("a"));
    const raw = concat(u32be(28), utf8(TRANSCRIPT_LABEL), u32be(1), utf8("a"));
    expect(await t.hash()).toEqual(new Uint8Array(createHash("sha256").update(raw).digest()));
  });

  it("length prefix is unambiguous", async () => {
    const h = async (fields: string[]) => {
      const t = new Transcript(TRANSCRIPT_LABEL);
      for (const f of fields) t.push(utf8(f));
      return t.hash();
    };
    expect(await h(["ab", "c"])).not.toEqual(await h(["a", "bc"]));
    expect(await h(["abc"])).not.toEqual(await h(["abc", ""]));
  });
});
