// @vitest-environment node
// WebAuthn ES256 assertion check of the lab relying party: a P-256 key drawn
// from the lab PRNG signs an assertion built here, then each verification
// rule (type, challenge, origin, rpId hash, user presence, signature,
// counter) is broken one at a time.
import { createHash, createPrivateKey, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { passkey } from "../../lab/gen/data.ts";
import { Rng } from "../../lab/gen/rng.ts";
import { verifyAssertion } from "../../lab/server/webauthn.ts";

const key = passkey(new Rng("webauthn-test"));
const RP = "amber-falcon-3.test";
const ORIGIN = `https://${RP}`;
const CHALLENGE = Buffer.from("0123456789abcdef0123456789abcdef").toString("base64url");
const b64u = (b: Buffer) => b.toString("base64url");

interface Build { type?: string; challenge?: string; origin?: string; rpId?: string; flags?: number; counter?: number }

function build(o: Build = {}) {
  const clientData = Buffer.from(JSON.stringify({
    type: o.type ?? "webauthn.get", challenge: o.challenge ?? CHALLENGE, origin: o.origin ?? ORIGIN, crossOrigin: false,
  }));
  const authData = Buffer.alloc(37);
  createHash("sha256").update(o.rpId ?? RP).digest().copy(authData, 0);
  authData[32] = o.flags ?? 0x01;
  authData.writeUInt32BE(o.counter ?? 7, 33);
  const priv = createPrivateKey({
    key: { kty: "EC", crv: "P-256", x: key.x, y: key.y, d: b64u(Buffer.from(key.d, "hex")) }, format: "jwk",
  });
  const data = Buffer.concat([authData, createHash("sha256").update(clientData).digest()]);
  const signature = sign("sha256", data, { key: priv, dsaEncoding: "der" });
  return {
    credentialId: key.credentialId, clientDataJSON: b64u(clientData), authenticatorData: b64u(authData), signature: b64u(signature),
  };
}

const expected = (prevCounter = 0) => ({ challenge: CHALLENGE, origin: ORIGIN, rpId: RP, publicKey: { x: key.x, y: key.y }, prevCounter });

describe("verifyAssertion", () => {
  it("valid_assertion", () => {
    expect(verifyAssertion(build(), expected())).toEqual({ ok: true, counter: 7 });
  });
  it("wrong_origin", () => {
    const r = verifyAssertion(build({ origin: "https://amber-falcon-3.test.evil.test" }), expected());
    expect(r).toEqual({ ok: false, reason: "wrong_origin" });
  });
  it("wrong_challenge", () => {
    const r = verifyAssertion(build({ challenge: b64u(Buffer.alloc(32, 1)) }), expected());
    expect(r).toEqual({ ok: false, reason: "wrong_challenge" });
  });
  it("wrong_type", () => {
    expect(verifyAssertion(build({ type: "webauthn.create" }), expected())).toEqual({ ok: false, reason: "wrong_type" });
  });
  it("wrong_rp_hash", () => {
    expect(verifyAssertion(build({ rpId: "other.test" }), expected())).toEqual({ ok: false, reason: "wrong_rp" });
  });
  it("tampered_signature", () => {
    const a = build();
    const sig = Buffer.from(a.signature, "base64url");
    sig[sig.length - 1]! ^= 0x01;
    expect(verifyAssertion({ ...a, signature: b64u(sig) }, expected())).toEqual({ ok: false, reason: "bad_signature" });
    // Tampered signed data (the counter) breaks the signature too.
    const ad = Buffer.from(a.authenticatorData, "base64url");
    ad[36]! ^= 0x01;
    expect(verifyAssertion({ ...a, authenticatorData: b64u(ad) }, expected())).toEqual({ ok: false, reason: "bad_signature" });
  });
  it("counter_not_increasing", () => {
    expect(verifyAssertion(build({ counter: 7 }), expected(7))).toEqual({ ok: false, reason: "counter_not_increasing" });
    expect(verifyAssertion(build({ counter: 8 }), expected(7))).toEqual({ ok: true, counter: 8 });
    // Authenticators without a counter always send 0: accepted while the stored counter is 0.
    expect(verifyAssertion(build({ counter: 0 }), expected(0))).toEqual({ ok: true, counter: 0 });
  });
  it("user_presence_flag_missing", () => {
    expect(verifyAssertion(build({ flags: 0x04 }), expected())).toEqual({ ok: false, reason: "user_not_present" });
  });
  it("malformed_input", () => {
    expect(verifyAssertion({ ...build(), clientDataJSON: "not-json" }, expected())).toEqual({ ok: false, reason: "bad_client_data" });
    expect(verifyAssertion({ ...build(), authenticatorData: "AAAA" }, expected())).toEqual({ ok: false, reason: "bad_authenticator_data" });
  });
});
