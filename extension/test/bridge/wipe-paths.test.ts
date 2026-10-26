// @vitest-environment node
// Secrets are wiped on error paths too (security hardening 6.3). `wipe` is
// observed through a snapshot taken before each call, so a test can tell a
// wiped secret from an array that was never filled.
import { beforeEach, describe, expect, it, vi } from "vitest";

const snaps: Uint8Array[] = [];
const fail = { sha256At: 0, expandAt: 0, sha256Calls: 0, expandCalls: 0 };

vi.mock("../../src/bridge/bytes", async (orig) => {
  const m = await orig<typeof import("../../src/bridge/bytes")>();
  return {
    ...m,
    wipe: (...arrays: (Uint8Array | undefined)[]) => {
      for (const a of arrays) if (a) snaps.push(a.slice());
      m.wipe(...arrays);
    },
  };
});

vi.mock("../../src/bridge/kdf", async (orig) => {
  const m = await orig<typeof import("../../src/bridge/kdf")>();
  return {
    ...m,
    sha256: (d: Uint8Array) => {
      if (++fail.sha256Calls === fail.sha256At) return Promise.reject(new Error("injected sha256"));
      return m.sha256(d);
    },
    expand: (s: Uint8Array, i: Uint8Array, l: string) => {
      if (++fail.expandCalls === fail.expandAt) return Promise.reject(new Error("injected expand"));
      return m.expand(s, i, l);
    },
  };
});

import { BridgeClient, type Transport } from "../../src/bridge/client";
import { decapsulate, encapsulate, generateKem, kemFromSeeds } from "../../src/bridge/kem";
import { ExtPairing } from "../../src/bridge/pairing";
import { extHelloDeterministic } from "../../src/bridge/session";
import type { PairOffer, WelcomeEnvelope } from "../../src/bridge/wire";
import { type PairingVector, type SessionVector, b, loadVector } from "./vectors";

const pv = loadVector<PairingVector>("pairing");
const sv = loadVector<SessionVector>("session");
const nonZero = (a: Uint8Array) => a.some((x) => x !== 0);
const same = (a: Uint8Array, c: Uint8Array) => a.length === c.length && a.every((x, i) => x === c[i]);
/** A non-zero secret of `len` bytes was wiped, other than the `known` ones. */
const wipedSecret = (len: number, ...known: Uint8Array[]) =>
  snaps.some((s) => s.length === len && nonZero(s) && !known.some((k) => same(s, k)));

beforeEach(() => {
  snaps.length = 0;
  Object.assign(fail, { sha256At: 0, expandAt: 0, sha256Calls: 0, expandCalls: 0 });
});

describe("wipe on error paths", () => {
  it("decapsulate wipes the ML-KEM secret when X25519 refuses the point", async () => {
    const kp = generateKem();
    const ct = new Uint8Array(1600); // all-zero X25519 half: low order point
    const x = kp.secret.x25519.slice();
    snaps.length = 0;
    await expect(decapsulate(kp.secret, ct)).rejects.toThrow();
    expect(wipedSecret(32, x)).toBe(true);
  });

  it("encapsulate wipes the ML-KEM secret when X25519 refuses the host key", async () => {
    const pk = generateKem().public.slice();
    pk.fill(0, 1568); // all-zero X25519 half
    snaps.length = 0;
    await expect(encapsulate(pk)).rejects.toThrow();
    // Both random inputs are wiped anyway; the ML-KEM secret is the third 32 byte value.
    expect(snaps.filter((x) => x.length === 32 && nonZero(x))).toHaveLength(3);
  });

  it("pairing offer wipes the shared secret when the transcript hash fails", async () => {
    const { state } = await ExtPairing.startDeterministic(
      pv.ext_name,
      pv.browser,
      kemFromSeeds(b(pv.ext_mlkem_seed), b(pv.ext_x25519_secret)),
      b(pv.ext_nonce),
      { now: () => 0 },
    );
    snaps.length = 0;
    fail.sha256At = fail.sha256Calls + 2; // the first hash is inside the encapsulation
    await expect(
      state.onOfferDeterministic(pv.pair_offer as unknown as PairOffer, b(pv.encaps_mlkem_seed), b(pv.encaps_x25519_eph)),
    ).rejects.toThrow("injected sha256");
    // ML-KEM and X25519 halves (wiped by `encaps`) plus the combined secret.
    const known = [b(pv.ext_x25519_secret), b(pv.ext_nonce)];
    const others = snaps.filter((x) => x.length === 32 && nonZero(x) && !known.some((k) => same(x, k)));
    expect(others).toHaveLength(3);
  });

  it("session welcome wipes the derived keys when a later derivation fails", async () => {
    const { pending } = extHelloDeterministic(
      { pairingId: b(sv.pairing_id), key: b(sv.pairing_key), createdAt: 0 },
      kemFromSeeds(b(sv.ext_mlkem_seed), b(sv.ext_x25519_secret)),
      b(sv.ext_nonce),
    );
    snaps.length = 0;
    fail.expandAt = fail.expandCalls + 2; // e2h derived, h2e fails
    await expect(pending.onWelcome(sv.welcome as unknown as WelcomeEnvelope)).rejects.toThrow("injected expand");
    expect(snaps.some((s) => s.length === 32 && Buffer.from(s).toString("base64") === sv.key_e2h)).toBe(true);
  });

  it("a decrypted reply that is not UTF-8 is wiped", async () => {
    const transport: Transport = { send: () => undefined, onMessage: () => undefined, onClose: () => undefined, close: () => undefined };
    const client = new BridgeClient(transport);
    const plain = new Uint8Array([0xff, 0xfe, 0x41, 0x42]);
    (client as unknown as { channel: unknown }).channel = { open: async () => plain, closed: false, close: () => undefined };
    await (client as unknown as { onMsg(m: unknown): Promise<void> }).onMsg({ v: 1, t: "msg", c: 0, d: "" });
    expect(Array.from(plain)).toEqual([0, 0, 0, 0]);
  });
});
