// @vitest-environment node
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { concat, utf8 } from "../../src/bridge/bytes";
import { hkdf32, sha256 } from "../../src/bridge/kdf";
import {
  CT_LEN,
  PUBLIC_LEN,
  decapsulate,
  encapsulate,
  encapsulateDeterministic,
  generateKem,
  kemFromSeeds,
  mlkemKeyIsValid,
  wipeKem,
} from "../../src/bridge/kem";
import { type KemVector, b, loadVector } from "./vectors";

const v = loadVector<KemVector>("kem");

describe("hybrid KEM (spec 6.2)", () => {
  it("seeded key pair gives the vector public key", () => {
    const kp = kemFromSeeds(b(v.mlkem_seed), b(v.x25519_secret));
    expect(kp.public.length).toBe(PUBLIC_LEN);
    expect(kp.public).toEqual(b(v.public));
  });

  it("deterministic encapsulation gives the vector ct and ss", async () => {
    const { ct, ss } = await encapsulateDeterministic(
      b(v.public),
      b(v.encaps_mlkem_seed),
      b(v.encaps_x25519_eph),
    );
    expect(ct).toEqual(b(v.ct));
    expect(ss).toEqual(b(v.ss));
  });

  it("decapsulating the vector ct with the vector secret gives the vector ss", async () => {
    const kp = kemFromSeeds(b(v.mlkem_seed), b(v.x25519_secret));
    expect(await decapsulate(kp.secret, b(v.ct))).toEqual(b(v.ss));
  });

  it("combiner recomputed from the vector parts", async () => {
    const ct = b(v.ct);
    const pkX = b(v.public).slice(1568);
    const ek = b(v.public).slice(0, 1568);
    const { cipherText, sharedSecret: ssM } = ml_kem1024.encapsulate(ek, b(v.encaps_mlkem_seed));
    expect(cipherText).toEqual(ct.slice(0, 1568));
    const ssX = x25519.getSharedSecret(b(v.encaps_x25519_eph), pkX);
    const info = await sha256(concat(ct, pkX));
    const want = await hkdf32(utf8("onepass/bridge/kem/v1"), concat(ssM, ssX), info);
    expect(want).toEqual(b(v.ss));
  });

  it("random round trip, fresh each time", async () => {
    const kp = generateKem();
    const a = await encapsulate(kp.public);
    const c = await encapsulate(kp.public);
    expect(a.ct.length).toBe(CT_LEN);
    expect(await decapsulate(kp.secret, a.ct)).toEqual(a.ss);
    expect(a.ct).not.toEqual(c.ct);
    expect(a.ss).not.toEqual(c.ss);
  });

  it("tampered ML-KEM half gives another secret", async () => {
    const kp = generateKem();
    const { ct, ss } = await encapsulate(kp.public);
    const bad = ct.slice();
    bad[10] = (bad[10] ?? 0) ^ 1;
    expect(await decapsulate(kp.secret, bad)).not.toEqual(ss);
  });

  it("bad lengths are refused", async () => {
    const kp = generateKem();
    const { ct } = await encapsulate(kp.public);
    for (const n of [0, 1568, 1599, 1601]) {
      await expect(decapsulate(kp.secret, new Uint8Array(n))).rejects.toThrow();
      await expect(encapsulate(new Uint8Array(n))).rejects.toThrow();
    }
    await expect(decapsulate(kp.secret, ct.slice(0, 1599))).rejects.toThrow();
  });

  it("modulus check refuses out of range ML-KEM coefficients", async () => {
    expect(mlkemKeyIsValid(b(v.public).slice(0, 1568))).toBe(true);
    const zero = new Uint8Array(1600);
    expect(mlkemKeyIsValid(zero.slice(0, 1568))).toBe(true);
    // First coefficient 0xD01 = 3329 = q, then the second (high nibbles) = q.
    const lo = b(v.public);
    lo[0] = 0x01;
    lo[1] = (lo[1]! & 0xf0) | 0x0d;
    await expect(encapsulate(lo)).rejects.toThrow(/kem public key/);
    const hi = b(v.public);
    hi[1] = (hi[1]! & 0x0f) | 0x10;
    hi[2] = 0xd0;
    await expect(encapsulate(hi)).rejects.toThrow(/kem public key/);
    // The seed part (rho) after t is not checked.
    const rho = b(v.public);
    rho[1540] = 0xff;
    expect(mlkemKeyIsValid(rho.slice(0, 1568))).toBe(true);
  });

  it("wipe zeroes the secret", () => {
    const kp = generateKem();
    wipeKem(kp);
    expect(kp.secret.mlkem.every((x) => x === 0)).toBe(true);
    expect(kp.secret.x25519.every((x) => x === 0)).toBe(true);
  });
});
