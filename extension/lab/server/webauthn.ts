// WebAuthn assertion check of the lab relying party (spec 5.1): an ES256
// assertion from `navigator.credentials.get` is accepted when its client data
// (type webauthn.get, challenge, origin), its authenticator data (SHA-256 of
// the rpId, user presence flag, increasing counter) and its DER signature
// over `authenticatorData || SHA-256(clientDataJSON)` all check out against
// the site's registered P-256 key. node:crypto only.
import { createHash, timingSafeEqual, verify } from "node:crypto";

export interface Assertion { credentialId: string; clientDataJSON: string; authenticatorData: string; signature: string /* base64url */ }
export interface ExpectedAssertion {
  challenge: string; origin: string; rpId: string; publicKey: { x: string; y: string }; prevCounter: number;
}
export type AssertionResult = { ok: true; counter: number } | { ok: false; reason: string };

const UP = 0x01; // authenticator data flag: user present

export function verifyAssertion(a: Assertion, expected: ExpectedAssertion): AssertionResult {
  const clientData = Buffer.from(a.clientDataJSON, "base64url");
  let parsed: { type?: unknown; challenge?: unknown; origin?: unknown };
  try {
    parsed = JSON.parse(clientData.toString("utf8")) as typeof parsed;
  } catch {
    return { ok: false, reason: "bad_client_data" };
  }
  if (parsed === null || typeof parsed !== "object") return { ok: false, reason: "bad_client_data" };
  if (parsed.type !== "webauthn.get") return { ok: false, reason: "wrong_type" };
  if (parsed.challenge !== expected.challenge || expected.challenge === "") return { ok: false, reason: "wrong_challenge" };
  if (parsed.origin !== expected.origin) return { ok: false, reason: "wrong_origin" };

  const authData = Buffer.from(a.authenticatorData, "base64url");
  if (authData.length < 37) return { ok: false, reason: "bad_authenticator_data" };
  const rpHash = createHash("sha256").update(expected.rpId).digest();
  if (!timingSafeEqual(authData.subarray(0, 32), rpHash)) return { ok: false, reason: "wrong_rp" };
  if ((authData[32]! & UP) === 0) return { ok: false, reason: "user_not_present" };

  const signed = Buffer.concat([authData, createHash("sha256").update(clientData).digest()]);
  let good = false;
  try {
    good = verify("sha256", signed, {
      key: { kty: "EC", crv: "P-256", x: expected.publicKey.x, y: expected.publicKey.y }, format: "jwk", dsaEncoding: "der",
    }, Buffer.from(a.signature, "base64url"));
  } catch {
    good = false;
  }
  if (!good) return { ok: false, reason: "bad_signature" };

  // Checked after the signature so a forged counter reads as a bad signature.
  const counter = authData.readUInt32BE(33);
  if ((counter !== 0 || expected.prevCounter !== 0) && counter <= expected.prevCounter) {
    return { ok: false, reason: "counter_not_increasing" };
  }
  return { ok: true, counter };
}
